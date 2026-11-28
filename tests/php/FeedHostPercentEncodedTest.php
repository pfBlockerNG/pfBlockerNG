<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_host_literal_reason(): a percent-encoded feed host, or a non-ASCII host
 * idn_to_ascii() cannot map, is refused before any connection.
 *
 * libcurl percent-decodes a URL host and dials the decoded address directly,
 * ignoring CURLOPT_RESOLVE; parse_url() keeps the '%' bytes, so an unchecked helper
 * sees a name and the guard resolves the encoded string instead of refusing it. A
 * host idn_to_ascii() cannot map is fail-open the same way: the helper returns ''
 * today and the host goes on to be vetted as a name.
 *
 * Every G/hostile/T14/N row seeds the resolver with an answer the guard would
 * otherwise accept, so a guard that still resolves the host passes it; only a
 * reject that runs first gives the new reason.
 */
#[CoversFunction('pfb_feed_host_literal_reason')]
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_filter')]
final class FeedHostPercentEncodedTest extends TestCase
{
	private const PERCENT_REASON      = 'feed host is percent-encoded';
	private const IDN_REASON          = 'feed host is not a valid IDN name';
	private const BRACKET_REASON      = 'feed host is a bracketed IPv6 literal';
	private const PUBLIC_ANSWER       = '203.0.113.5';
	private const CONFIGURED_IP       = '10.20.30.40';

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
		$GLOBALS['pfb_test_resolve_map'][rtrim((string) $ascii, '.') . '.'] = [['type' => 'A', 'data' => $ip]];
	}

	// --- G: pfb_feed_host_allowed(), percent-encoded hosts (T1 + ADDENDUM A) ---

	/** @return array<string, array{string}> */
	public static function percentEncodedHostProvider(): array
	{
		return [
			'G1 escaped octet (127.0.0.1)'      => ['127.0.0.%31'],
			'G2 escaped dots, upper hex (.1)'   => ['127%2E0%2E0%2E1'],
			'G3 escaped dots, lower hex (.1)'   => ['127%2e0%2e0%2e1'],
			'G4 escaped DWORD (127.0.0.1)'      => ['%32%31%33%30%37%30%36%34%33%33'],
			'G5 escaped fullwidth digit'        => ['10.0.0.%EF%BC%91'],
			'G6 escaped dot inside a name'      => ['feeds%2Eexample.com'],
			'ADDENDUM A escaped DWORD (.2)'     => ['%32%31%33%30%37%30%36%34%33%34'],
			'ADDENDUM A escaped dots (.2)'      => ['127%2E0%2E0%2E2'],
		];
	}

	#[DataProvider('percentEncodedHostProvider')]
	public function testPercentEncodedHostIsRejectedBeforeDns(string $host): void
	{
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame(
			[FALSE, self::PERCENT_REASON, ''],
			[$allowed, $reason, $pinned],
			"host {$host}: expected reject before DNS, got allowed=" . var_export($allowed, TRUE) .
			" reason='{$reason}' pinned='{$pinned}'"
		);
	}

	public function testPercentEncodedHostRejectedWhenTheAnswerIsAFirewallAddress(): void
	{
		$this->answer('127.0.0.%31', self::CONFIGURED_IP);
		$GLOBALS['pfb_test_configured_ips'] = [self::CONFIGURED_IP];
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed('127.0.0.%31', $reason, $pinned);
		$this->assertSame([FALSE, self::PERCENT_REASON, ''], [$allowed, $reason, $pinned]);
	}

	/**
	 * G7: a host that is BOTH percent-encoded AND decodes to a numeric-shaped label
	 * must be refused with the percent reason -- the '%' check runs before the
	 * numeric check, not after it.
	 */
	public function testPercentCheckPrecedesNumericCheck(): void
	{
		$host = '%31%32%37.0.0.1';
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([FALSE, self::PERCENT_REASON, ''], [$allowed, $reason, $pinned]);
	}

	// --- Hostile rows for the '%' check itself ---

	/** @return array<string, array{string}> */
	public static function hostileEscapeProvider(): array
	{
		return [
			'bare percent'            => ['feeds%example.com'],
			'doubled percent'         => ['feeds%%example.com'],
			'truncated escape'        => ['feeds%2example.com'],
			'null-byte escape'        => ['feeds%00example.com'],
		];
	}

	#[DataProvider('hostileEscapeProvider')]
	public function testHostileEscapesAreRejected(string $host): void
	{
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([FALSE, self::PERCENT_REASON, ''], [$allowed, $reason, $pinned], "host {$host}");
	}

	// --- T12: zone-id IPv6 hosts -- the bracket check runs first, so the bracket
	// reason wins over the '%' check even though a zone id also contains '%'. ---

	/** @return array<string, array{string}> */
	public static function zoneIdHostProvider(): array
	{
		return [
			'link-local, zone id' => ['[fe80::1%25em0]'],
			'loopback, zone id'   => ['[::1%25lo]'],
		];
	}

	#[DataProvider('zoneIdHostProvider')]
	public function testZoneIdHostRefusedByGuard(string $host): void
	{
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([FALSE, self::BRACKET_REASON, ''], [$allowed, $reason, $pinned], "host {$host}");
	}

	// --- N: controls, unaffected by either new check ---

	/** @return array<string, array{string}> */
	public static function unaffectedHostProvider(): array
	{
		return [
			'plain name'   => ['feeds.example.com'],
			'canonical v4' => ['1.2.3.4'],
			'idn name'     => ['bücher.de'],
		];
	}

	#[DataProvider('unaffectedHostProvider')]
	public function testUnaffectedHostsStayAllowed(string $host): void
	{
		// An IP-literal host (e.g. '1.2.3.4') is used directly, never resolved, so
		// it pins to itself; a name is resolved and pins to the seeded answer.
		$pinnedWant = is_ipaddr($host) ? $host : self::PUBLIC_ANSWER;
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([TRUE, '', $pinnedWant], [$allowed, $reason, $pinned], "host {$host}");
	}

	// --- V1: entry vetting (pfb_filter) ---

	/**
	 * Controls: FILTER_VALIDATE_URL refuses the http-scheme URL outright (a raw '%'
	 * in the authority fails its syntax check), and the bare hostname filter refuses
	 * the scheme-less rsync ('host::module') form -- neither ever reaches the guard,
	 * so no resolver seeding is needed; both escape modes stay refused before and
	 * after the fix.
	 */
	public static function percentEncodedUrlControlProvider(): array
	{
		return [
			'http scheme'            => ['http://127.0.0.%31/list.txt'],
			'scheme-less rsync form' => ['127.0.0.%31::mod/list.txt'],
		];
	}

	#[DataProvider('percentEncodedUrlControlProvider')]
	public function testEntryVettingRefusesPercentEncodedHostControls(string $url): void
	{
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', TRUE), "escape=TRUE: {$url}");
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', FALSE), "escape=FALSE: {$url}");
	}

	/**
	 * Deviation from the brief's V1 row (see handoff Deviations): unlike the
	 * http-scheme URL, FILTER_VALIDATE_URL accepts an rsync-scheme URL whose host
	 * carries a raw '%', so this URL reaches parse_url() and the shared host check.
	 * escape=TRUE stays refused regardless (a publicly-resolving host is never
	 * self-hosted) -- a control. escape=FALSE is NOT a control: at head, a
	 * percent-encoded host that resolves to a public address is allowed through
	 * entry vetting (RED); only the literal-host fix closes it.
	 */
	public function testEntryVettingRefusesPercentEncodedHostViaRsyncScheme(): void
	{
		$url = 'rsync://127.0.0.%31/list.txt';
		$this->answer('127.0.0.%31', self::PUBLIC_ANSWER);
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', TRUE), 'escape=TRUE: control');
		$this->assertFalse(pfb_filter($url, PFB_FILTER_URL, 'probe', '', FALSE), 'escape=FALSE: expected refused after the fix');
	}

	// --- T14 (ADDENDUM A): a non-ASCII host idn_to_ascii() cannot map ---

	/** @return array<string, array{string}> */
	public static function unmappableIdnHostProvider(): array
	{
		return [
			'invalid UTF-8 bytes'        => ["\xff\xfe.1"],
			'disallowed code point (word joiner)' => ["\xe2\x81\xa0.com"],
		];
	}

	#[DataProvider('unmappableIdnHostProvider')]
	public function testUnmappableIdnHostIsRejected(string $host): void
	{
		$this->assertFalse(idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46), "test bootstrap: {$host} must fail idn_to_ascii on this PHP");
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([FALSE, self::IDN_REASON, ''], [$allowed, $reason, $pinned], 'host ' . bin2hex($host));
	}

	/** @return array<string, array{string}> */
	public static function idnControlProvider(): array
	{
		return [
			'plain IDN name'        => ['bücher.de'],
			'trailing dot'          => ['bücher.de.'],
			'already-punycode name' => ['xn--bcher-kva.de'],
		];
	}

	#[DataProvider('idnControlProvider')]
	public function testIdnHostsThatMapStayAllowed(string $host): void
	{
		$this->answer($host, self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		$this->assertSame([TRUE, '', self::PUBLIC_ANSWER], [$allowed, $reason, $pinned], "host {$host}");
	}
}
