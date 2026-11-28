<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_host_allowed() / pfb_feed_host_literal_reason() — the feed-host guard's mapped
 * (ASCII) out-parameter. A refused host leaves it and the pin empty; an ASCII host comes
 * back untouched. The redirect helpers that once called this guard per 3xx hop were removed
 * with the Go cutover (#3977).
 *
 *   Background:
 *     Given the internal-address allowlist is empty (secure default)
 *     And the resolver is driven by $GLOBALS['pfb_test_resolve_map']
 */
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_host_literal_reason')]
final class FeedRedirectTargetTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map']);
	}

	/** @return array<string,array{0:string}> */
	public static function delimiterMappedHostProvider(): array
	{
		return [
			'fullwidth commercial at' => ["foo\u{FF20}bar.example"],
			'fullwidth solidus after name' => ["example.com\u{FF0F}x.example"],
			'fullwidth solidus after address' => ["10.0.0.1\u{FF0F}24"],
		];
	}

	#[DataProvider('delimiterMappedHostProvider')]
	public function testHostMappingToUrlDelimiterIsRefused(string $rawHost): void
	{
		// The raw spelling resolves; only the mapped form is the problem.
		$GLOBALS['pfb_test_resolve_map']["{$rawHost}."] = [
			['type' => 'A', 'data' => '203.0.113.43'],
		];
		$reason = '';
		$pinned = '';
		$ascii = 'unset';
		$this->assertFalse(pfb_feed_host_allowed($rawHost, $reason, $pinned, $ascii));
		$this->assertSame('', $ascii);
	}

	/** @return array<string,array{0:string,1:string}> */
	public static function refusedHostProvider(): array
	{
		return [
			'fullwidth digit' => ["10.0.0.\u{FF11}", 'feed host is a non-canonical IP literal'],
			'CONTEXTJ failure' => ["10.0.0.1\u{200C}", 'feed host is not a valid IDN name'],
			'maps to percent' => ["10.0.0.\u{FF05}31", 'feed host is percent-encoded'],
		];
	}

	#[DataProvider('refusedHostProvider')]
	public function testRefusedHostLeavesMappedOutParamEmpty(string $host, string $expectedReason): void
	{
		$reason = '';
		$pinned = '';
		$ascii  = 'unset';
		$this->assertFalse(pfb_feed_host_allowed($host, $reason, $pinned, $ascii));
		$this->assertSame($expectedReason, $reason);
		$this->assertSame('', $ascii);
		$this->assertSame('', $pinned, 'a refused host is never pinned');
	}

	public function testAsciiHostIsReturnedUntouchedInMappedOutParam(): void
	{
		$GLOBALS['pfb_test_resolve_map']['Feeds.Example.'] = [
			['type' => 'A', 'data' => '203.0.113.42'],
		];
		$reason = '';
		$pinned = '';
		$ascii  = '';
		$this->assertTrue(pfb_feed_host_allowed('Feeds.Example', $reason, $pinned, $ascii));
		$this->assertSame('Feeds.Example', $ascii);
	}
}
