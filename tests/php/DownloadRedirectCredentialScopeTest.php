<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * pfb_download() Basic-credential scope across manual redirect hops (issue #1919).
 *
 * The manual redirect loop keeps CURLOPT_USERPWD/CURLOPT_HTTPAUTH configured on
 * the one cURL handle for every hop, so a credentialed feed that answers with a
 * CROSS-HOST redirect leaks the operator's Basic username and password to the
 * redirect target. Credentials must be scoped to the ORIGINAL feed origin —
 * host AND scheme AND port, libcurl's FOLLOWLOCATION policy since 7.83.0
 * (CVE-2022-27774): a cross-host or same-host-different-port hop gets no
 * Authorization, a hop back onto the origin regains it, and a same-origin
 * redirect keeps it.
 *
 * Exercised through the REAL pfb_download() against TWO local `php -S` fixture
 * servers on distinct hostnames (both resolved to 127.0.0.1 through the
 * $GLOBALS['pfb_test_resolve_map'] hook and admitted by the self-IP carve-out;
 * each map entry also lists a public address so the host is not classified
 * self-hosted, which would take the localfile path instead of the cURL loop
 * under test). Every request's PHP_AUTH_USER/PHP_AUTH_PW pair is recorded by
 * the servers, so the assertion reads what actually crossed the wire.
 */
#[CoversFunction('pfb_download')]
final class DownloadRedirectCredentialScopeTest extends TestCase
{
	private const ORIGIN_HOST = 'origin-feed.example';
	private const TARGET_HOST = 'rdr-target.example';

	/** @var array<int,resource> the php -S server processes */
	private array $servers = [];

	private string $workdir = '';
	private int $originPort = 0;
	private int $targetPort = 0;
	private int $altPort = 0;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$workdir = tempnam(sys_get_temp_dir(), 'pfbrdr');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		// Loopback FIRST (it becomes the pinned connection address, admitted by
		// the self-IP carve-out) plus a public address so neither host is
		// classified self-hosted.
		$GLOBALS['pfb_test_resolve_map'] = [
			self::ORIGIN_HOST . '.' => [
				['type' => 'A', 'data' => '127.0.0.1'],
				['type' => 'A', 'data' => '203.0.113.20'],
			],
			self::TARGET_HOST . '.' => [
				['type' => 'A', 'data' => '127.0.0.1'],
				['type' => 'A', 'data' => '203.0.113.21'],
			],
		];

		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']   = 'now';

		$this->startServers();
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as $server) {
			if (is_resource($server)) {
				proc_terminate($server);
				proc_close($server);
			}
		}
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
	}

	/**
	 * One shared router serves both servers (URIs are disjoint). Every request
	 * appends [server-port, uri] to EVENT_LOG. Non-readiness requests append
	 * [server-port, uri, PHP_AUTH_USER, PHP_AUTH_PW, HTTP_AUTHORIZATION,
	 * HTTP_X_FEED_PROBE] to AUTH_LOG (the raw Authorization header covers
	 * non-Basic credentials — the issue #1953 Bearer-token axis; X-Feed-Probe
	 * stands in for a non-credential extra header that must ride every hop).
	 *
	 *   /same     -> 302 /final          (same-origin redirect on the origin)
	 *   /cross    -> 302 TARGET/hop      (cross-host redirect to the target)
	 *   /hop      -> 302 ORIGIN/back     (target bounces back to the origin)
	 *   /portjump -> 302 ALT/land        (same host, DIFFERENT port)
	 *   other     -> 200 body
	 */
	private function startServers(): void
	{
		$router    = "{$this->workdir}/router.php";
		$routerSrc = <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '';
file_put_contents(getenv('EVENT_LOG'), json_encode([
	(int) $_SERVER['SERVER_PORT'],
	$uri,
]) . PHP_EOL, FILE_APPEND);
if (str_starts_with($uri, '/__pfb_ready/')) {
	if ($uri === '/__pfb_ready/' . getenv('READY_TOKEN')) {
		echo getenv('READY_TOKEN');
	}
	return;
}
file_put_contents(getenv('AUTH_LOG'), json_encode([
	(int) $_SERVER['SERVER_PORT'],
	$_SERVER['REQUEST_URI'] ?? '',
	$_SERVER['PHP_AUTH_USER'] ?? null,
	$_SERVER['PHP_AUTH_PW'] ?? null,
	$_SERVER['HTTP_AUTHORIZATION'] ?? null,
	$_SERVER['HTTP_X_FEED_PROBE'] ?? null,
]) . PHP_EOL, FILE_APPEND);
// Both bases come from a ports file written AFTER both servers are up (the
// second server's port is unknown when the first is spawned).
$bases = json_decode((string) file_get_contents(getenv('PORTS_FILE')), true);
if ($uri === '/same') {
	header('Location: /final', true, 302);
	return;
}
if ($uri === '/cross') {
	header('Location: ' . $bases['target'] . '/hop', true, 302);
	return;
}
if ($uri === '/hop') {
	header('Location: ' . $bases['origin'] . '/back', true, 302);
	return;
}
if ($uri === '/portjump') {
	header('Location: ' . $bases['alt'] . '/land', true, 302);
	return;
}
header('Content-Length: 4');
echo 'BODY';
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));

		$this->originPort = $this->startOneServer($router, self::ORIGIN_HOST);
		$this->targetPort = $this->startOneServer($router, self::TARGET_HOST);
		$this->altPort    = $this->startOneServer($router, self::ORIGIN_HOST . ' (alt port)');
		$this->assertNotFalse(file_put_contents("{$this->workdir}/ports.json", json_encode([
			'origin' => 'http://' . self::ORIGIN_HOST . ":{$this->originPort}",
			'target' => 'http://' . self::TARGET_HOST . ":{$this->targetPort}",
			'alt'    => 'http://' . self::ORIGIN_HOST . ":{$this->altPort}",
		])));
	}

	/** Start one php -S fixture on a free port; return the port. */
	private function startOneServer(string $router, string $label): int
	{
		$failures = [];
		for ($try = 0; $try < 10; $try++) {
			$port   = random_int(20000, 60000);
			$nonce  = bin2hex(random_bytes(16));
			$stderr = "{$this->workdir}/server-{$port}-{$try}.stderr";
			$proc   = proc_open(
				['php', '-S', "127.0.0.1:{$port}", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->workdir,
				[
					'AUTH_LOG'   => "{$this->workdir}/auth.log",
					'EVENT_LOG'  => "{$this->workdir}/events.log",
					'PORTS_FILE' => "{$this->workdir}/ports.json",
					'READY_TOKEN' => $nonce,
					'PATH'       => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = "port {$port}: process=proc_open failed stderr=(unavailable)";
				continue;
			}
			for ($i = 0; $i < 40; $i++) {
				if (pfb_test_http_fixture_event_received($port, $nonce)) {
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
				'port %d: process[running=%s exit=%d close=%d] stderr=%s',
				$port,
				$status['running'] ? 'true' : 'false',
				$status['exitcode'],
				$closeExit,
				$stderrText === '' ? '(empty)' : $stderrText
			);
		}
		$this->fail("could not start the {$label} php -S fixture server; " . implode(' | ', $failures));
	}

	/** Run one credentialed change_detect probe against $path on the origin server. */
	private function downloadFrom(
		string $path,
		string $username = 'user',
		string $password = 'secret',
		array $extraHeaders = []
	): PfbDownloadResult {
		return pfb_download(new PfbDownloadRequest(
			listUrl: 'http://' . self::ORIGIN_HOST . ":{$this->originPort}{$path}",
			downloadPath: "{$this->workdir}/feed.txt",
			flex: FALSE,
			header: 'RdrCredFeed',
			format: '',
			logType: 1,
			type: 'change_detect',
			username: $username,
			password: $password,
			extraHeaders: $extraHeaders,
		));
	}

	private function redirectFailureMessage(PfbDownloadResult $result): string
	{
		$events = @file_get_contents("{$this->workdir}/events.log");
		$events = is_string($events) ? trim($events) : '(missing)';
		if ($events === '') {
			$events = '(empty)';
		}

		$testLog = @file_get_contents("{$this->workdir}/pfblockerng.log");
		$testLog = is_string($testLog) ? trim($testLog) : '(missing)';
		if ($testLog === '') {
			$testLog = '(empty)';
		}

		$processes = [];
		foreach ($this->servers as $port => $server) {
			if (!is_resource($server)) {
				$processes[] = "port {$port} closed";
				continue;
			}
			$status = proc_get_status($server);
			$processes[] = sprintf(
				'port %d running=%s exit=%d',
				$port,
				$status['running'] ? 'true' : 'false',
				$status['exitcode']
			);
		}

		$metadata = json_encode($result->responseMeta, JSON_UNESCAPED_SLASHES);
		return sprintf(
			'redirected download must succeed; response status=%s metadata=%s; events=%s; ports=origin:%d target:%d alt:%d; processes=%s; pfBlockerNG log=%s',
			(string) ($result->responseMeta['status'] ?? '(missing)'),
			is_string($metadata) ? $metadata : '(unavailable)',
			$events,
			$this->originPort,
			$this->targetPort,
			$this->altPort,
			$processes === [] ? '(none)' : implode(', ', $processes),
			$testLog
		);
	}

	/** The Authorization header value cURL derives from the Basic credentials. */
	private function basicHeader(): string
	{
		return 'Basic ' . base64_encode('user:secret');
	}

	/** @return array<int,array{0:int,1:string,2:?string,3:?string,4:?string,5:?string}> decoded auth-log lines */
	private function authLog(): array
	{
		$lines = file("{$this->workdir}/auth.log", FILE_IGNORE_NEW_LINES);
		$this->assertIsArray($lines, 'fixture servers must record each request');
		return array_map(
			fn (string $line): array => json_decode($line, TRUE),
			$lines
		);
	}

	/**
	 * Scenario: a credentialed feed answers with a cross-host redirect chain.
	 * Given Basic credentials configured for the origin feed host,
	 * when the origin 302s to a DIFFERENT host and that host 302s back,
	 * then the cross-host hop receives NO credentials while both origin-host
	 * requests (initial and bounce-back) receive them.
	 */
	public function testCrossHostRedirectHopReceivesNoCredentials(): void
	{
		$result = $this->downloadFrom('/cross');
		$this->assertTrue($result->success, $this->redirectFailureMessage($result));
		$this->assertSame('200', $result->responseMeta['status'] ?? '', 'probe metadata must carry the final 200');

		$this->assertSame(
			[
				[$this->originPort, '/cross', 'user', 'secret', $this->basicHeader(), NULL],
				[$this->targetPort, '/hop', NULL, NULL, NULL, NULL],
				[$this->originPort, '/back', 'user', 'secret', $this->basicHeader(), NULL],
			],
			$this->authLog(),
			'the cross-host hop must see no Basic credentials; both origin-host hops must see them'
		);
	}

	/**
	 * Scenario: a feed authenticated via a caller-supplied Authorization header
	 * (the TOP1M Radar Bearer token, issue #1953) answers with a cross-host
	 * redirect chain.
	 * Given an extra "Authorization: Bearer" header configured for the feed,
	 * when the origin 302s to a DIFFERENT host and that host 302s back,
	 * then the cross-host hop receives NO Authorization header while both
	 * origin-host requests (initial and bounce-back) receive the token.
	 */
	public function testCrossHostRedirectHopReceivesNoAuthorizationHeader(): void
	{
		$result = $this->downloadFrom('/cross', '', '', ['Authorization: Bearer SECRET-TOKEN']);
		$this->assertTrue($result->success, $this->redirectFailureMessage($result));
		$this->assertSame('200', $result->responseMeta['status'] ?? '', 'probe metadata must carry the final 200');

		$this->assertSame(
			[
				[$this->originPort, '/cross', NULL, NULL, 'Bearer SECRET-TOKEN', NULL],
				[$this->targetPort, '/hop', NULL, NULL, NULL, NULL],
				[$this->originPort, '/back', NULL, NULL, 'Bearer SECRET-TOKEN', NULL],
			],
			$this->authLog(),
			'the cross-host hop must see no Authorization header; both origin-host hops must see the token'
		);
	}

	/**
	 * Scenario: the extra-header list mixes a credential and a non-credential
	 * header (the real shape: the Radar Bearer token beside an ADR-42
	 * conditional-GET header).
	 * Given both an Authorization header and a non-credential extra header,
	 * when the origin 302s cross-host and that host 302s back,
	 * then the off-origin hop keeps the non-credential header while losing
	 * ONLY the Authorization header (the filter must not drop the whole list).
	 */
	public function testCrossHostRedirectKeepsNonCredentialExtraHeaders(): void
	{
		$result = $this->downloadFrom('/cross', '', '', [
			'Authorization: Bearer SECRET-TOKEN',
			'X-Feed-Probe: keep',
		]);
		$this->assertTrue($result->success, $this->redirectFailureMessage($result));
		$this->assertSame('200', $result->responseMeta['status'] ?? '', 'probe metadata must carry the final 200');

		$this->assertSame(
			[
				[$this->originPort, '/cross', NULL, NULL, 'Bearer SECRET-TOKEN', 'keep'],
				[$this->targetPort, '/hop', NULL, NULL, NULL, 'keep'],
				[$this->originPort, '/back', NULL, NULL, 'Bearer SECRET-TOKEN', 'keep'],
			],
			$this->authLog(),
			'the off-origin hop must keep non-credential extra headers while losing only Authorization'
		);
	}

	/**
	 * Scenario: a credentialed feed answers with a same-host but
	 * DIFFERENT-PORT redirect (the CVE-2022-27774 axis: another port is a
	 * different trust domain even on the same host).
	 * Given Basic credentials configured for the origin feed origin,
	 * when the origin 302s to the SAME host on another port,
	 * then the different-port hop receives NO credentials.
	 */
	public function testSameHostDifferentPortHopReceivesNoCredentials(): void
	{
		$result = $this->downloadFrom('/portjump');
		$this->assertTrue($result->success, $this->redirectFailureMessage($result));
		$this->assertSame('200', $result->responseMeta['status'] ?? '', 'probe metadata must carry the final 200');

		$this->assertSame(
			[
				[$this->originPort, '/portjump', 'user', 'secret', $this->basicHeader(), NULL],
				[$this->altPort, '/land', NULL, NULL, NULL, NULL],
			],
			$this->authLog(),
			'a same-host different-port hop must see no Basic credentials'
		);
	}

	/**
	 * Scenario: a credentialed feed answers with a same-origin redirect.
	 * Given Basic credentials configured for the origin feed origin,
	 * when the origin 302s to another path on the SAME host and port,
	 * then both requests receive the credentials.
	 */
	public function testSameHostRedirectKeepsCredentials(): void
	{
		$result = $this->downloadFrom('/same');
		$this->assertTrue($result->success, $this->redirectFailureMessage($result));
		$this->assertSame('200', $result->responseMeta['status'] ?? '', 'probe metadata must carry the final 200');

		$this->assertSame(
			[
				[$this->originPort, '/same', 'user', 'secret', $this->basicHeader(), NULL],
				[$this->originPort, '/final', 'user', 'secret', $this->basicHeader(), NULL],
			],
			$this->authLog(),
			'a same-host redirect must keep sending the feed credentials'
		);
	}
}
