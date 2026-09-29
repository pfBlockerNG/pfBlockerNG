<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_host_literal_reason(): a non-ASCII host is judged by what UTS46 maps it to, with the
 * CONTEXTJ check libcurl's IDN conversion applies.
 *
 * Every case seeds the resolver with an answer the guard would accept for the raw host, so a
 * helper that passes the host on as a name lets it through; only a refusal before any lookup
 * gives the expected reason.
 */
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_redirect_target')]
final class FeedHostIdnMappingTest extends TestCase
{
	private const PERCENT_REASON = 'feed host is percent-encoded';
	private const IDN_REASON     = 'feed host is not a valid IDN name';
	private const PUBLIC_ANSWER  = '203.0.113.5';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
	}

	private function answer(string $host): void
	{
		// A real resolver has no IDN handling, so seed the mapped ASCII spelling only.
		$ascii = preg_match('/[^\x00-\x7F]/', $host) === 1
		    ? idn_to_ascii($host, IDNA_CHECK_CONTEXTJ | IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46)
		    : $host;
		$GLOBALS['pfb_test_resolve_map']["{$ascii}."] = [['type' => 'A', 'data' => self::PUBLIC_ANSWER]];
	}

	/** @return array<string, array{string, string}> */
	public static function refusedHostProvider(): array
	{
		return [
			'fullwidth percent maps to %'   => ["10.0.0.\u{FF05}31", self::PERCENT_REASON],
			'zero-width non-joiner in label' => ["10.0.0.1\u{200C}", self::IDN_REASON],
			'zero-width joiner in label'     => ["10.0.0.1\u{200D}", self::IDN_REASON],
			'joiner inside a middle label'   => ["10.0.\u{200C}0.1", self::IDN_REASON],
			// Unmappable and containing '%': the IDN check runs before the '%' check.
			'unmappable with percent'        => ["\u{200C}%31.0.0.1", self::IDN_REASON],
		];
	}

	#[DataProvider('refusedHostProvider')]
	public function testHostIsRefusedByItsMappedForm(string $host, string $want): void
	{
		$this->answer($host);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([FALSE, $want, ''], [$allowed, $reason, $pinned], 'host ' . json_encode($host));
	}

	public function testRedirectToJoinerHostIsRejected(): void
	{
		$host = "10.0.0.1\u{200C}";
		$this->answer($host);
		$reason = '';
		$pinned = '';
		$target = pfb_feed_redirect_target("http://{$host}:8443/", 'https://feeds.example.com/list.txt', $reason, $pinned);
		$this->assertSame([FALSE, self::IDN_REASON, ''], [$target, $reason, $pinned]);
	}

	/** @return array<string, array{string}> */
	public static function allowedHostProvider(): array
	{
		return [
			'idn name'          => ['bücher.de'],
			'sharp s name'      => ['faß.de'],
			'punycode name'     => ['xn--bcher-kva.de'],
		];
	}

	#[DataProvider('allowedHostProvider')]
	public function testMappableNamesStayAllowed(string $host): void
	{
		$this->answer($host);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([TRUE, '', self::PUBLIC_ANSWER], [$allowed, $reason, $pinned], "host {$host}");
	}
}
