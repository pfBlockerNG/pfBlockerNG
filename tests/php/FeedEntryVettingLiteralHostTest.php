<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A host that libcurl or PHP's URL wrappers treat as a literal must be refused by entry
 * vetting before the self-hosted check, in both escape modes and with the feed-host filter
 * on or off; the guard refuses bracketed IPv6 hosts.
 *
 * Every case below seeds the resolver with an answer the self-hosted check would accept
 * (the configured firewall address), so a path that still resolves the host as a name
 * passes it; only a reject that runs first gives the new reason.
 */
#[CoversFunction('pfb_filter')]
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_redirect_target')]
final class FeedEntryVettingLiteralHostTest extends TestCase
{
	private const CONFIGURED_IP = '10.20.30.40';
	private const NUMERIC_REASON = 'feed host is a non-canonical IP literal';
	private const BRACKET_REASON = 'feed host is a bracketed IPv6 literal';

	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	private $savedPfb;

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [self::CONFIGURED_IP];
		$GLOBALS['pfb_test_resolve_map'] = [];
		// Isolate from whatever a sibling test left in these globals.
		$this->savedPfb = $GLOBALS['pfb'] ?? null;
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb_test_configured_ips'], $GLOBALS['pfb_test_resolve_map']);
		if ($this->savedPfb === null) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function tempFile(string $prefix): string
	{
		$path = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($path, "could not create temp file for {$prefix}");
		$this->tmpfiles[] = $path;
		return $path;
	}

	/** Seed the resolver to answer ONLY the configured firewall address for $url's host. */
	private function answerHost(string $url): void
	{
		$host = parse_url($url, PHP_URL_HOST);
		if (is_string($host) && $host !== '') {
			$GLOBALS['pfb_test_resolve_map']["{$host}."] = [['type' => 'A', 'data' => self::CONFIGURED_IP]];
		}
	}

	// --- A: entry-vetting provider, feed-host filter ON ---

	/** @return array<string, array{string}> */
	public static function literalHostProvider(): array
	{
		return [
			'dword (127.0.0.1)'   => ['http://2130706433/list.txt'],
			'dword (10.0.0.1)'    => ['http://167772161/list.txt'],
			'hex dword'           => ['http://0x7f000001/list.txt'],
			'upper hex dword'     => ['http://0X7F000001/list.txt'],
			'short form'          => ['http://127.1/list.txt'],
			'dword trailing dot'  => ['http://2130706433./list.txt'],
			'bracketed ULA'       => ['http://[fd00::1]/list.txt'],
			'bracketed v4-mapped' => ['http://[::ffff:10.0.0.1]/list.txt'],
			'rsync scheme dword'  => ['rsync://2130706433/list.txt'],
		];
	}

	/**
	 * Scenario: a feed URL whose host libcurl or PHP's URL wrappers would treat as an IPv4
	 * or IPv6 literal is refused at entry vetting, before the self-hosted short-circuit,
	 * even though the resolver answers with the configured firewall address (which the
	 * self-hosted check would otherwise accept).
	 */
	#[DataProvider('literalHostProvider')]
	public function testEntryVettingRefusesLiteralHost(string $url): void
	{
		$this->answerHost($url);
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', TRUE), "escape=TRUE: {$url} must be refused");
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', FALSE), "escape=FALSE: {$url} must be refused");
	}

	// --- B: entry-vetting provider, feed-host filter OFF ---

	/** @return array<string, array{string}> */
	public static function literalHostFilterOffProvider(): array
	{
		return [
			'dword'         => ['http://2130706433/list.txt'],
			'bracketed ULA' => ['http://[fd00::1]/list.txt'],
		];
	}

	/**
	 * Scenario: the literal-host refusal is not gated by the feed-host internal-address
	 * filter -- it runs before parse_url()'s host is ever dialled, whether or not the
	 * separate internal-address allowlist check is enabled.
	 */
	#[DataProvider('literalHostFilterOffProvider')]
	public function testEntryVettingRefusesLiteralHostWithFeedFilterOff(string $url): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter', 'off');
		$this->answerHost($url);
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', TRUE), "escape=TRUE, filter off: {$url} must be refused");
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', FALSE), "escape=FALSE, filter off: {$url} must be refused");
	}

	// --- C: the shared guard itself ---

	/**
	 * Scenario: pfb_feed_host_allowed() refuses a bracketed IPv6 host outright -- valid
	 * ULA, v4-mapped, bracketed-public and non-IP alike -- rather than looking the
	 * bracketed string up as a DNS name.
	 */
	public function testGuardRefusesBracketedIpv6Hosts(): void
	{
		foreach (['[fd00::1]', '[::ffff:10.0.0.1]', '[192.0.2.1]', '[not-an-ip]'] as $h) {
			$GLOBALS['pfb_test_resolve_map']["{$h}."] = [['type' => 'A', 'data' => self::CONFIGURED_IP]];
			$reason = '';
			$pinned = '';
			$allowed = pfb_feed_host_allowed($h, $reason, $pinned);
			$this->assertSame(
				[FALSE, self::BRACKET_REASON, ''],
				[$allowed, $reason, $pinned],
				"host {$h}"
			);
		}
	}

	/**
	 * Scenario: a redirect Location whose host is a bracketed IPv6 literal is refused by
	 * pfb_feed_redirect_target(), which re-runs the same guard on every hop.
	 */
	public function testRedirectToBracketedIpv6HostIsRejected(): void
	{
		$GLOBALS['pfb_test_resolve_map']['[fd00::1].'] = [['type' => 'A', 'data' => self::CONFIGURED_IP]];
		$reason = '';
		$pinned = '';
		$target = pfb_feed_redirect_target('http://[fd00::1]:8080/x', 'https://feeds.example.com/list.txt', $reason, $pinned);
		$this->assertSame([FALSE, self::BRACKET_REASON, ''], [$target, $reason, $pinned]);
	}

	// --- D: controls (must pass before and after) ---

	public function testSelfHostedWebRootStaysAllowed(): void
	{
		$this->answerHost('http://feeds.example.com/list.txt');
		$this->assertTrue(pfb_filter('http://feeds.example.com/list.txt', PFB_FILTER_URL, 'probe', '', TRUE));
		$this->assertTrue(pfb_filter('http://feeds.example.com/list.txt', PFB_FILTER_URL, 'probe', '', FALSE));
	}

	public function testSelfHostedNestedPathStaysRefused(): void
	{
		$this->answerHost('http://feeds.example.com/sub/list.txt');
		$this->assertFalse(pfb_filter('http://feeds.example.com/sub/list.txt', PFB_FILTER_URL, 'probe', '', TRUE));
		$this->assertFalse(pfb_filter('http://feeds.example.com/sub/list.txt', PFB_FILTER_URL, 'probe', '', FALSE));
	}

	public function testLoopbackStaysAllowedForEscapeTrue(): void
	{
		$this->assertTrue(pfb_filter('http://127.0.0.1/list.txt', PFB_FILTER_URL, 'probe', '', TRUE));
	}

	/**
	 * @return array<string, array{string}>
	 *
	 * A fullwidth-digit host is a control here: FILTER_VALIDATE_URL refuses a
	 * non-ASCII URL as malformed before parse_url() ever runs, at both escape modes.
	 */
	public static function malformedOrNonAsciiUrlProvider(): array
	{
		return [
			'bracketed v4 (invalid URL syntax)' => ['http://[192.0.2.1]/x'],
			'unclosed bracket'                  => ['http://[fd00::1/x'],
			'empty brackets'                    => ['http://[]/x'],
			'fullwidth-digit host, non-ASCII URL rejected by FILTER_VALIDATE_URL' => ['http://10.0.0.１/list.txt'],
		];
	}

	#[DataProvider('malformedOrNonAsciiUrlProvider')]
	public function testMalformedOrNonAsciiUrlStaysRefused(string $url): void
	{
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', TRUE), "escape=TRUE: {$url}");
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', FALSE), "escape=FALSE: {$url}");
	}

	// --- E: log visibility ---

	/**
	 * Scenario: an entry-vetting reject of a non-canonical numeric literal writes the
	 * reason to the error log, the same way every other PFB_FILTER_URL reject does.
	 */
	public function testNumericLiteralRejectionLogsReasonToErrorLog(): void
	{
		$errlog = $this->tempFile('pfb_entry_literal_errlog_');
		$GLOBALS['pfb']['errlog'] = $errlog;

		$this->answerHost('http://2130706433/list.txt');
		pfb_filter('http://2130706433/list.txt', PFB_FILTER_URL, 'probe', '', FALSE);

		$logged = (string) file_get_contents($errlog);
		$this->assertStringContainsString(
			'Invalid URL (' . self::NUMERIC_REASON . ')',
			$logged,
			"expected the reject reason in the error log, got <{$logged}>"
		);
	}

	/**
	 * Scenario: an entry-vetting reject of a bracketed IPv6 literal writes the reason to
	 * the error log.
	 */
	public function testBracketedIpv6RejectionLogsReasonToErrorLog(): void
	{
		$errlog = $this->tempFile('pfb_entry_literal_errlog_');
		$GLOBALS['pfb']['errlog'] = $errlog;

		$this->answerHost('http://[fd00::1]/list.txt');
		pfb_filter('http://[fd00::1]/list.txt', PFB_FILTER_URL, 'probe', '', FALSE);

		$logged = (string) file_get_contents($errlog);
		$this->assertStringContainsString(
			'Invalid URL (' . self::BRACKET_REASON . ')',
			$logged,
			"expected the reject reason in the error log, got <{$logged}>"
		);
	}
}
