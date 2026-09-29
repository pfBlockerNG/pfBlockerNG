<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

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
 * reject that runs first gives the new reason. E1/E2 drive the real pfb_download()
 * over two local `php -S` fixtures (one bound on 127.0.0.2, the decoded address of
 * the percent-encoded redirect target) so the assertion reads what curl actually
 * dialled, not a re-implementation.
 */
#[CoversFunction('pfb_feed_host_literal_reason')]
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_redirect_target')]
#[CoversFunction('pfb_filter')]
#[CoversFunction('pfb_download')]
final class FeedHostPercentEncodedTest extends TestCase
{
	private const PERCENT_REASON      = 'feed host is percent-encoded';
	private const IDN_REASON          = 'feed host is not a valid IDN name';
	private const BRACKET_REASON      = 'feed host is a bracketed IPv6 literal';
	private const NON_PERMITTED_REASON = 'feed host resolves to a non-permitted address';
	private const PUBLIC_ANSWER       = '203.0.113.5';
	private const CONFIGURED_IP       = '10.20.30.40';
	private const ORIGIN_HOST         = 'pct-origin-feed.example';

	/** @var array<int,resource> the php -S server processes (E1/E2 only) */
	private array $servers = [];

	private string $workdir = '';

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $savedPfb = [];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as $server) {
			if (is_resource($server)) {
				proc_terminate($server);
				proc_close($server);
			}
		}
		$this->servers = [];
		foreach ($this->savedPfb as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		$this->savedPfb = [];
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
		$this->workdir = '';
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

	// --- R1: the redirect hop re-runs the same guard ---

	public function testRedirectToPercentEncodedHostIsRejected(): void
	{
		$this->answer('127.0.0.%31', self::PUBLIC_ANSWER);
		$reason = '';
		$pinned = '';
		$target = pfb_feed_redirect_target('http://127.0.0.%31:8443/', 'https://feeds.example.com/list.txt', $reason, $pinned);
		$this->assertSame([FALSE, self::PERCENT_REASON, ''], [$target, $reason, $pinned]);
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

	#[DataProvider('zoneIdHostProvider')]
	public function testZoneIdHostRefusedByRedirectTarget(string $host): void
	{
		$reason = '';
		$pinned = '';
		$target = pfb_feed_redirect_target("http://{$host}:8080/x", 'https://feeds.example.com/list.txt', $reason, $pinned);
		$this->assertSame([FALSE, self::BRACKET_REASON, ''], [$target, $reason, $pinned], "host {$host}");
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

	// --- E1/E2: the real pfb_download(), a percent-encoded redirect target ---

	/** Start one php -S fixture bound on $bindHost; return its assigned port. */
	private function startOneServer(string $router, string $bindHost, string $label): int
	{
		$failures = [];
		for ($try = 0; $try < 10; $try++) {
			$nonce  = bin2hex(random_bytes(16));
			$stderr = "{$this->workdir}/server-{$label}-{$try}-{$nonce}.stderr";
			$proc   = proc_open(
				['php', '-S', "{$bindHost}:0", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->workdir,
				[
					'EVENT_LOG'      => "{$this->workdir}/events.log",
					'TARGET_BASE_FILE' => "{$this->workdir}/target_base.txt",
					'READY_TOKEN'    => $nonce,
					'PATH'           => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = "bind {$bindHost}: process=proc_open failed stderr=(unavailable)";
				continue;
			}
			$port = pfb_test_http_fixture_port($stderr, $bindHost);
			for ($i = 0; $i < 40; $i++) {
				if ($port > 0 && pfb_test_http_fixture_event_received($port, $nonce, $bindHost)) {
					$this->servers[$port] = $proc;
					return $port;
				}
				usleep(50000);
			}

			$status = proc_get_status($proc);
			if ($status['running']) {
				proc_terminate($proc);
			}
			$closeExit = proc_close($proc);
			$stderrText = trim((string) @file_get_contents($stderr));
			$failures[] = sprintf(
				'bind %s port %d: process[running=%s exit=%d close=%d] stderr=%s',
				$bindHost,
				$port,
				$status['running'] ? 'true' : 'false',
				$status['exitcode'],
				$closeExit,
				$stderrText === '' ? '(empty)' : $stderrText
			);
		}
		$this->fail("could not start the {$label} php -S fixture server on {$bindHost}; " . implode(' | ', $failures));
	}

	private function router(): string
	{
		$router    = "{$this->workdir}/router.php";
		$routerSrc = <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '';
if ($uri === '/__pfb_ready' || str_starts_with($uri, '/__pfb_ready/')) {
	if ($uri === '/__pfb_ready') {
		echo getenv('READY_TOKEN');
	}
	return;
}
file_put_contents(getenv('EVENT_LOG'), json_encode([
	(int) $_SERVER['SERVER_PORT'],
	$uri,
]) . PHP_EOL, FILE_APPEND);
$targetBase = (string) @file_get_contents(getenv('TARGET_BASE_FILE'));
if ($uri === '/redirect-percent') {
	header('Location: ' . str_replace('127.0.0.2', '127.0.0.%32', $targetBase) . '/list.txt', true, 302);
	return;
}
if ($uri === '/redirect-plain') {
	header('Location: ' . $targetBase . '/list.txt', true, 302);
	return;
}
header('Content-Length: 4');
echo 'BODY';
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));
		return $router;
	}

	/** @return array{int,int} [originPort, targetPort] */
	private function startFixtures(): array
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$workdir = tempnam(sys_get_temp_dir(), 'pfbpct');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']   = 'now';

		// A NAMED origin host, resolved to loopback (dialled) + a public address (so
		// the host is not self-only and the entry-vetting localfile short-circuit --
		// which treats a URL whose host is LITERALLY '127.0.0.1' as a pfSense-local
		// file read via file_get_contents(), never curl -- does not apply; the
		// redirect loop under test only runs on the curl path).
		$GLOBALS['pfb_test_resolve_map'][self::ORIGIN_HOST . '.'] = [
			['type' => 'A', 'data' => '127.0.0.1'],
			['type' => 'A', 'data' => '203.0.113.20'],
		];

		$router = $this->router();
		// Target FIRST: its port must be known before the origin's redirect is
		// requested. Bound on 127.0.0.2 -- the address the percent-encoded
		// redirect host ('127.0.0.%32') decodes to -- so a request that actually
		// lands here proves curl dialled the DECODED address, not the guard's
		// resolved (and pinned) one.
		$targetPort = $this->startOneServer($router, '127.0.0.2', 'target');
		$this->assertNotFalse(file_put_contents("{$workdir}/target_base.txt", "http://127.0.0.2:{$targetPort}"));
		$originPort = $this->startOneServer($router, '127.0.0.1', 'origin');

		return [$originPort, $targetPort];
	}

	private function downloadFailureMessage(PfbDownloadResult $result): string
	{
		$events = @file_get_contents("{$this->workdir}/events.log");
		$events = is_string($events) && trim($events) !== '' ? trim($events) : '(empty)';
		$log = @file_get_contents($GLOBALS['pfb']['log'] ?? '');
		$log = is_string($log) && trim($log) !== '' ? trim($log) : '(empty)';
		$metadata = json_encode($result->responseMeta, JSON_UNESCAPED_SLASHES);
		return sprintf(
			'success=%s metadata=%s; events=%s; pfBlockerNG log=%s',
			var_export($result->success, TRUE),
			is_string($metadata) ? $metadata : '(unavailable)',
			$events,
			$log
		);
	}

	/**
	 * E1: a 302 to a percent-encoded host must be refused before the redirect is
	 * ever dialled -- the target fixture (the decoded address) receives ZERO
	 * requests and the reason is logged.
	 */
	public function testDownloadRefusesRedirectToPercentEncodedHost(): void
	{
		[$originPort] = $this->startFixtures();

		// The guard's own resolver answers the encoded host with a PUBLIC address
		// (so, absent the fix, the guard approves and pins to it) -- yet libcurl
		// percent-decodes the URL host and dials 127.0.0.2 directly, ignoring the
		// pin. That is what the target fixture receiving the request would prove.
		$this->answer('127.0.0.%32', self::PUBLIC_ANSWER);

		$result = pfb_download(new PfbDownloadRequest(
			listUrl: "http://" . self::ORIGIN_HOST . ":{$originPort}/redirect-percent",
			downloadPath: "{$this->workdir}/feed.txt",
			flex: FALSE,
			header: 'FeedPctEncRdr',
			format: '',
			logType: 1,
			type: 'change_detect',
		));

		$this->assertFalse($result->success, $this->downloadFailureMessage($result));

		$events = (string) @file_get_contents("{$this->workdir}/events.log");
		$targetEvents = array_filter(
			array_filter(explode("\n", trim($events))),
			static fn (string $line): bool => str_contains($line, '/list.txt')
		);
		$this->assertSame([], array_values($targetEvents), 'the target fixture must receive zero requests: ' . $events);

		$log = (string) @file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringContainsString(self::PERCENT_REASON, $log, "expected the reject reason in the log, got <{$log}>");
	}

	/**
	 * E2 (control): a 302 to the SAME address spelled as a plain literal
	 * ('127.0.0.2', no percent-encoding) is refused too -- but for the
	 * pre-existing reason (a non-permitted/internal address), unaffected by this
	 * fix. Passes before and after.
	 */
	public function testDownloadRefusesRedirectToPlainNonPermittedHost(): void
	{
		[$originPort] = $this->startFixtures();

		$result = pfb_download(new PfbDownloadRequest(
			listUrl: "http://" . self::ORIGIN_HOST . ":{$originPort}/redirect-plain",
			downloadPath: "{$this->workdir}/feed.txt",
			flex: FALSE,
			header: 'FeedPlainRdr',
			format: '',
			logType: 1,
			type: 'change_detect',
		));

		$this->assertFalse($result->success, $this->downloadFailureMessage($result));

		$events = (string) @file_get_contents("{$this->workdir}/events.log");
		$targetEvents = array_filter(
			array_filter(explode("\n", trim($events))),
			static fn (string $line): bool => str_contains($line, '/list.txt')
		);
		$this->assertSame([], array_values($targetEvents), 'the target fixture must receive zero requests: ' . $events);

		$log = (string) @file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringContainsString(self::NON_PERMITTED_REASON, $log, "expected the reject reason in the log, got <{$log}>");
	}
}
