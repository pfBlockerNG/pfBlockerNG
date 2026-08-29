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
}
