<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_host_allowed() / pfb_feed_redirect_target(): a numeric host that is not a canonical
 * dotted quad ('2130706433', '0x7f000001', '127.1', '0177.0.0.1') is rejected before any DNS
 * lookup.
 *
 * libcurl parses such a host as an IPv4 literal and connects to the decoded address without a
 * lookup, while PHP's is_ipaddr() does not recognise it, so the guard must not vet it as a name.
 *
 * Every case below seeds the resolver with an answer the guard would accept, so a guard that
 * still resolves the name passes the host; only a reject that runs first gives the new reason.
 */
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_redirect_target')]
final class FeedHostNumericLiteralTest extends TestCase
{
	private const REASON = 'feed host is a non-canonical IP literal';
	private const PUBLIC_ANSWER = '203.0.113.5';

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

	private function answer(string $host, string $ip): void
	{
		// A real resolver has no IDN handling, so seed the mapped ASCII spelling only.
		$ascii = preg_match('/[^\x00-\x7F]/', $host) === 1
		    ? idn_to_ascii($host, IDNA_CHECK_CONTEXTJ | IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46)
		    : $host;
		$GLOBALS['pfb_test_resolve_map']["{$ascii}."] = [['type' => 'A', 'data' => $ip]];
	}

	/** @return array<string, array{string}> */
	public static function nonCanonicalHostProvider(): array
	{
		return [
			'dword'                 => ['2130706433'],
			'hex dword'             => ['0x7f000001'],
			'upper hex dword'       => ['0X7F000001'],
			'short form'            => ['127.1'],
			'octal first part'      => ['0177.0.0.1'],
			'dotted hex'            => ['0xa.0.0.1'],
			'hex last label'        => ['10.0.0.0x1'],
			'dword trailing dot'    => ['167772161.'],
			'quad trailing dot'     => ['8.8.8.8.'],
			'invalid octal (08)'    => ['08.08.08.08'],
			'overflow'              => ['4294967296'],
			'space inside host'     => ['0x7f000001 1.2.3.4'],
			// libcurl with IDN (UTS46) maps fullwidth digits to ASCII before its IPv4 parse.
			'fullwidth last digit'  => ['10.0.0.１'],
			'fullwidth hex dword'   => ['０ｘ7f000001'],
			'fullwidth first label' => ['１２７.0.0.1'],
		];
	}

	#[DataProvider('nonCanonicalHostProvider')]
	public function testNonCanonicalNumericHostIsRejectedEvenWhenDnsWouldAnswer(string $host): void
	{
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame(
			[FALSE, self::REASON, ''],
			[$allowed, $reason, $pinned],
			"host {$host}: expected reject before DNS, got allowed=" . var_export($allowed, TRUE) .
			" reason='{$reason}' pinned='{$pinned}'"
		);
	}

	public function testNumericHostIsRejectedWhenTheAnswerIsAFirewallAddress(): void
	{
		$this->answer('167772161', '10.20.30.40');
		$GLOBALS['pfb_test_configured_ips'] = ['10.20.30.40'];
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed('167772161', $reason, $pinned);
		$this->assertSame([FALSE, self::REASON, ''], [$allowed, $reason, $pinned]);
	}

	public function testRedirectToNumericHostIsRejected(): void
	{
		$this->answer('0x7f000001', self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$target = pfb_feed_redirect_target('http://0x7f000001:8443/', 'https://feeds.example.com/list.txt', $reason, $pinned);
		$this->assertSame([FALSE, self::REASON, ''], [$target, $reason, $pinned]);
	}

	/** @return array<string, array{string, string}> */
	public static function unchangedHostProvider(): array
	{
		return [
			'canonical public quad' => ['1.2.3.4', '1.2.3.4'],
			'plain name'            => ['feeds.example.com', self::PUBLIC_ANSWER],
			'digit labels, alpha tld' => ['1.2.example.com', self::PUBLIC_ANSWER],
			'idn name'              => ['bücher.de', self::PUBLIC_ANSWER],
		];
	}

	#[DataProvider('unchangedHostProvider')]
	public function testCanonicalQuadsAndNamesKeepTheirPath(string $host, string $pinnedWant): void
	{
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([TRUE, '', $pinnedWant], [$allowed, $reason, $pinned], "host {$host}");
	}
}
