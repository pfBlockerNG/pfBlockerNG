<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_redirect_target() / pfb_resolve_relative_url() — the per-hop decision a
 * feed download makes when a server returns an HTTP 3xx redirect. The redirect
 * target host is re-vetted by the feed-host guard before being followed, so a
 * redirect cannot send the fetch to a non-permitted address. A relative Location is
 * resolved against the URL it was returned from.
 *
 * Scenario: a redirect must be followed only to a routable public address, and the
 * caller re-pins the connection to the freshly vetted IP.
 *   Background:
 *     Given the internal-address allowlist is empty (secure default)
 *     And the resolver is driven by $GLOBALS['pfb_test_resolve_map']
 */
#[CoversFunction('pfb_feed_redirect_target')]
#[CoversFunction('pfb_resolve_relative_url')]
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

	/** Drive the helper, returning [result, reason, pinned]. */
	private function redirect(string $location, string $current): array
	{
		$reason = '';
		$pinned = '';
		$result = pfb_feed_redirect_target($location, $current, $reason, $pinned);
		return [$result, $reason, $pinned];
	}

	public function testAbsoluteRedirectToPublicHostIsFollowedAndPinned(): void
	{
		// Given the redirect target resolves to a public address
		$GLOBALS['pfb_test_resolve_map']['mirror.example.'] = [
			['type' => 'A', 'data' => '203.0.113.40'],
		];
		// When an absolute Location to that host is evaluated
		[$result, $reason, $pinned] = $this->redirect(
			'https://mirror.example/feed/list.txt',
			'https://feed.example/list.txt'
		);
		// Then the next URL is returned and the vetted public IP is pinned.
		$this->assertIsArray($result);
		$this->assertSame('https://mirror.example/feed/list.txt', $result['url']);
		$this->assertSame('mirror.example', $result['host']);
		$this->assertSame('https', $result['scheme']);
		$this->assertSame(443, $result['port']);
		$this->assertSame('203.0.113.40', $pinned);
		$this->assertSame('', $reason);
	}

	public function testRedirectToInternalHostIsRejected(): void
	{
		// Given the redirect target resolves to an internal address
		$GLOBALS['pfb_test_resolve_map']['internal.example.'] = [
			['type' => 'A', 'data' => '10.0.0.50'],
		];
		// When the redirect is evaluated / Then it is refused (fail-closed) with the
		// neutral guard reason and no pin.
		[$result, $reason, $pinned] = $this->redirect(
			'https://internal.example/secret',
			'https://feed.example/list.txt'
		);
		$this->assertFalse($result);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
		$this->assertSame('', $pinned);
	}

	public function testRelativeLocationIsResolvedAgainstCurrentUrl(): void
	{
		// Given a public host serving the current URL and an absolute-path Location
		$GLOBALS['pfb_test_resolve_map']['feed.example.'] = [
			['type' => 'A', 'data' => '203.0.113.7'],
		];
		// When a relative ('/v2/list.txt') Location is evaluated against the current URL
		[$result, , $pinned] = $this->redirect('/v2/list.txt', 'https://feed.example/v1/list.txt');
		// Then it resolves to the same host's absolute URL and re-vets that host.
		$this->assertIsArray($result);
		$this->assertSame('https://feed.example/v2/list.txt', $result['url']);
		$this->assertSame('203.0.113.7', $pinned);
	}

	public function testRelativePathLocationIsResolvedAgainstBaseDirectory(): void
	{
		// A bare relative-path Location ('list2.txt') resolves against the directory
		// of the current URL's path.
		$GLOBALS['pfb_test_resolve_map']['feed.example.'] = [
			['type' => 'A', 'data' => '203.0.113.7'],
		];
		[$result, , ] = $this->redirect('list2.txt', 'https://feed.example/dir/list.txt');
		$this->assertIsArray($result);
		$this->assertSame('https://feed.example/dir/list2.txt', $result['url']);
	}

	public function testNonHttpRedirectTargetIsRejected(): void
	{
		// A redirect to a non-http(s) scheme (e.g. file://) is refused.
		[$result, $reason] = $this->redirect('file:///etc/passwd', 'https://feed.example/list.txt');
		$this->assertFalse($result);
		$this->assertSame('feed redirect target is not an http(s) URL', $reason);
	}

	public function testEmptyLocationIsRejected(): void
	{
		[$result, $reason] = $this->redirect('', 'https://feed.example/list.txt');
		$this->assertFalse($result);
		$this->assertSame('feed redirect has no target', $reason);
	}

	/**
	 * A non-ASCII redirect host is handed back in its UTS 46 mapped (ASCII) form,
	 * the string libcurl keys its address lookup on; the URL is rebuilt to match.
	 * The resolver is seeded under the RAW spelling because the guard resolves the
	 * host as written.
	 *
	 * @return array<string,array{0:string,1:string,2:string,3:string}>
	 */
	public static function mappedHostProvider(): array
	{
		return [
			'plain mapped host with port' => ['http://bücher.example:8081/x', 'bücher.example', 'xn--bcher-kva.example', 'http://xn--bcher-kva.example:8081/x'],
			'userinfo, query kept, fragment dropped' => ['http://u:p@bücher.example:8081/x?q=a%20b#f', 'bücher.example', 'xn--bcher-kva.example', 'http://u:p@xn--bcher-kva.example:8081/x?q=a%20b'],
			'trailing dot kept' => ['http://bücher.example.:8081/x', 'bücher.example.', 'xn--bcher-kva.example.', 'http://xn--bcher-kva.example.:8081/x'],
			'uppercase lowercased' => ['http://BÜCHER.Example:8081/x', 'BÜCHER.Example', 'xn--bcher-kva.example', 'http://xn--bcher-kva.example:8081/x'],
			'mixed labels, no port' => ['http://ascii.bücher.example/x', 'ascii.bücher.example', 'ascii.xn--bcher-kva.example', 'http://ascii.xn--bcher-kva.example/x'],
			'empty path' => ['http://bücher.example:8081', 'bücher.example', 'xn--bcher-kva.example', 'http://xn--bcher-kva.example:8081'],
			'https scheme kept' => ['https://bücher.example/x', 'bücher.example', 'xn--bcher-kva.example', 'https://xn--bcher-kva.example/x'],
		];
	}

	#[DataProvider('mappedHostProvider')]
	public function testNonAsciiRedirectHostIsReturnedMapped(string $location, string $rawHost, string $mappedHost, string $mappedUrl): void
	{
		$GLOBALS['pfb_test_resolve_map']["{$rawHost}."] = [
			['type' => 'A', 'data' => '203.0.113.41'],
		];
		[$result, $reason, $pinned] = $this->redirect($location, 'https://feed.example/list.txt');
		$this->assertIsArray($result, "reason: {$reason}");
		$this->assertSame($mappedHost, $result['host']);
		$this->assertSame($mappedUrl, $result['url']);
		$this->assertSame('203.0.113.41', $pinned);
	}

	public function testMappedRedirectKeepsDefaultPortOfScheme(): void
	{
		$GLOBALS['pfb_test_resolve_map']['ascii.bücher.example.'] = [
			['type' => 'A', 'data' => '203.0.113.41'],
		];
		[$result] = $this->redirect('http://ascii.bücher.example/x', 'https://feed.example/list.txt');
		$this->assertIsArray($result);
		$this->assertSame(80, $result['port']);
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
