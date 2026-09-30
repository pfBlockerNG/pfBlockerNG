<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * Issue #3374 — a hop whose every cURL attempt failed is a failed download.
 *
 * When libcurl aborts after the response headers (error 18 short body, 28
 * timeout), it still reports the status of the response it cut short, so the
 * file holds a partial body next to a 200. pfb_download() used to fall through
 * on that status and publish the truncated body — as the ingest copy, or as the
 * change-detect probe body the detector hashes against the stored baseline.
 *
 * Drives the REAL pfb_download() against a local `php -S` server over the real
 * cURL path (the feed host is a non-local name resolved to loopback through
 * $GLOBALS['pfb_test_resolve_map']; a literal 127.0.0.1 URL takes the localfile
 * path and never reaches cURL). $GLOBALS['pfb']['curl_retry_sleep'] = 0 removes
 * the 5 s wait between attempts; it is the production test seam.
 *
 * R rows must fail without the fix and pass with it; C rows are controls that
 * pass either way and prove the refusal is a real branch, not always-reject.
 */
#[CoversFunction('pfb_download')]
final class DownloadCurlIncompleteTest extends TestCase
{
	private const FULL_BODY = 'ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP';
	private const SEED_ORIG = "SEEDED-ORIG-BASELINE\n";
	private const SEED_HASH = 'seeded-hash-baseline';
	private const SECRET    = 's3cret';

	/** @var resource|null the php -S server process */
	private $server = null;

	private string $workdir = '';
	private int $port = 0;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	/** @var array<string,mixed> saved fixture globals (absent key = was unset) */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$workdir = tempnam(sys_get_temp_dir(), 'pfbci');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['config', 'pfb_test_configured_ips', 'pfb_test_resolve_map'] as $g) {
			if (array_key_exists($g, $GLOBALS)) {
				$this->savedGlobals[$g] = $GLOBALS[$g];
			}
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		// Loopback first (the pinned connection address, admitted by the self-IP
		// carve-out) plus a public address so the host is not classified self-hosted.
		$GLOBALS['pfb_test_resolve_map'] = [
			'incomplete-feed.example.' => [
				['type' => 'A', 'data' => '127.0.0.1'],
				['type' => 'A', 'data' => '203.0.113.22'],
			],
		];

		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active', 'curl_retry_sleep'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']              = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']           = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']             = 'now';
		$GLOBALS['pfb']['curl_retry_sleep'] = 0;

		$this->startServer();
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
		}
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach (['config', 'pfb_test_configured_ips', 'pfb_test_resolve_map'] as $g) {
			if (array_key_exists($g, $this->savedGlobals)) {
				$GLOBALS[$g] = $this->savedGlobals[$g];
			} else {
				unset($GLOBALS[$g]);
			}
		}
		$this->savedGlobals = [];
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
	}

	/**
	 * Routes (every non-readiness request is appended to the request log):
	 *  /short       Content-Length 10, sends 'ab', closes         -> cURL 18
	 *  /stall       Content-Length 10, sends 'ab', holds the socket -> cURL 28
	 *  /full        complete 200
	 *  /flaky       first request short, later requests complete
	 *  /redir-short 302 -> /short          /redir-full 302 -> /full
	 *  /etag        304 when If-None-Match is "v1", else complete 200
	 * PHP_CLI_SERVER_WORKERS keeps the retries from queueing behind a stalled worker.
	 */
	private function startServer(): void
	{
		$router = "{$this->workdir}/router.php";
		$routerSrc = <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '';
if ($uri === '/__pfb_ready' || str_starts_with($uri, '/__pfb_ready/')) {
	if ($uri === '/__pfb_ready') {
		echo getenv('READY_TOKEN');
	}
	return;
}
file_put_contents(getenv('REQ_LOG'), $uri . PHP_EOL, FILE_APPEND);
$full = (string) getenv('FULL_BODY');
$host = $_SERVER['HTTP_HOST'] ?? '';
header('Content-Type: text/plain');
switch ($uri) {
case '/short':
	header('Content-Length: 10');
	echo 'ab';
	flush();
	exit;
case '/stall':
	header('Content-Length: 10');
	echo 'ab';
	flush();
	sleep(3);
	exit;
case '/flaky':
	$state = getenv('FLAKY_STATE');
	header('Content-Length: ' . (string) strlen($full));
	if (!file_exists($state)) {
		touch($state);
		echo 'ab';
		flush();
		exit;
	}
	echo $full;
	return;
case '/redir-short':
case '/redir-full':
	http_response_code(302);
	header('Location: http://' . $host . ($uri === '/redir-short' ? '/short' : '/full'));
	echo 'REDIRECT-BODY';
	return;
case '/etag':
	if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === '"v1"') {
		http_response_code(304);
		return;
	}
	header('ETag: "v1"');
	header('Content-Length: ' . (string) strlen($full));
	echo $full;
	return;
default:
	header('Content-Length: ' . (string) strlen($full));
	echo $full;
}
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));

		$failures = [];
		for ($try = 0; $try < 10; $try++) {
			$nonce  = bin2hex(random_bytes(16));
			$stderr = "{$this->workdir}/server-{$try}-{$nonce}.stderr";
			$proc   = proc_open(
				['php', '-S', '127.0.0.1:0', $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->workdir,
				[
					'REQ_LOG'                 => "{$this->workdir}/requests.log",
					'FLAKY_STATE'             => "{$this->workdir}/flaky.flag",
					'FULL_BODY'               => self::FULL_BODY,
					'READY_TOKEN'             => $nonce,
					'PHP_CLI_SERVER_WORKERS'  => '4',
					'PATH'                    => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = 'port 0: process=proc_open failed stderr=(unavailable)';
				continue;
			}
			$port = pfb_test_http_fixture_port($stderr);
			for ($i = 0; $i < 40; $i++) {
				if (pfb_test_http_fixture_event_received($port, $nonce)) {
					$this->server = $proc;
					$this->port = $port;
					return;
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
		$this->fail('could not start the php -S fixture server; ' . implode(' | ', $failures));
	}

	/** @return int fixture-server requests whose URI is $route (all routes when null) */
	private function requestCount(?string $route = null): int
	{
		$lines = @file("{$this->workdir}/requests.log", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		if (!is_array($lines)) {
			return 0;
		}
		return $route === null ? count($lines) : count(array_keys($lines, $route, TRUE));
	}

	private function logText(): string
	{
		return (string) @file_get_contents((string) $GLOBALS['pfb']['log']);
	}

	/** Change-detect probes get `{feed}.md5` (as the cron caller does), ingest gets `{feed}`. */
	private function downloadPath(string $type): string
	{
		return "{$this->workdir}/feed" . ($type === 'change_detect' ? '.md5' : '');
	}

	private function seedBaseline(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->workdir}/feed.orig", self::SEED_ORIG));
		$this->assertNotFalse(file_put_contents("{$this->workdir}/feed.orig.xxhash128", self::SEED_HASH));
	}

	private function fetch(string $route, string $type = '', int $timeout = 30, string $userinfo = ''): PfbDownloadResult
	{
		return pfb_download(new PfbDownloadRequest(
			listUrl: "http://{$userinfo}incomplete-feed.example:{$this->port}{$route}",
			downloadPath: $this->downloadPath($type),
			flex: FALSE,
			header: 'IncompleteFeed',
			format: '',
			logType: 1,
			versionType: '',
			timeout: $timeout,
			type: $type,
			username: '',
			password: '',
			sourceInterface: FALSE,
			extraHeaders: array(),
		));
	}

	/** The shared failure contract: no success, no partial body, baseline untouched, named log line. */
	private function assertFailedCleanly(PfbDownloadResult $result, string $type, int $curlCode): void
	{
		$dl = $this->downloadPath($type);
		$this->assertFalse($result->success, 'a hop whose every cURL attempt failed must not download successfully');
		$this->assertNull($result->responseMeta, 'a failed hop must carry no probe metadata the caller could act on');
		$this->assertFileDoesNotExist("{$dl}.raw", 'the partial body must not be left on disk');
		$this->assertFileDoesNotExist("{$this->workdir}/feed.md5.raw", 'no probe body may survive for the detector to hash');
		$this->assertSame(self::SEED_ORIG, (string) @file_get_contents("{$this->workdir}/feed.orig"),
			'the previously published .orig must be untouched');
		$this->assertSame(self::SEED_HASH, (string) @file_get_contents("{$this->workdir}/feed.orig.xxhash128"),
			'the previously stored hash baseline must be untouched');
		$log = $this->logText();
		$this->assertStringContainsString('stage=fetch reason=curl_incomplete', $log,
			'the refusal must be logged distinguishably; log was: ' . $log);
		$this->assertStringContainsString("curl={$curlCode}", $log,
			"the log must name the cURL error {$curlCode}; log was: " . $log);
	}

	/**
	 * R1 + R5. Given an ingest feed that announces 10 bytes and sends 2 then closes
	 * (cURL 18 on every attempt), when pfb_download() fetches it, then the download
	 * fails cleanly after exactly 3 attempts, and a credential in the URL is not
	 * written to the log.
	 */
	public function test_R1_ingest_short_body_fails_after_three_attempts(): void
	{
		$this->seedBaseline();
		$result = $this->fetch('/short', '', 30, 'user:' . self::SECRET . '@');

		$this->assertFailedCleanly($result, '', 18);
		$this->assertSame(3, $this->requestCount('/short'), 'the failing hop must be attempted exactly 3 times');
		$this->assertStringNotContainsString(self::SECRET, $this->logText(), 'URL userinfo must be redacted in the log');
	}

	/**
	 * R2. Given an ingest feed that sends 2 of 10 bytes then holds the socket
	 * (cURL 28 on every attempt, 1 s timeout), then the download fails cleanly.
	 */
	public function test_R2_ingest_stalled_body_fails(): void
	{
		$this->seedBaseline();
		$result = $this->fetch('/stall', '', 1);

		$this->assertFailedCleanly($result, '', 28);
	}

	/**
	 * R3. Given a change-detect probe against a short body, then the probe fails
	 * with no metadata and leaves no .md5.raw for the detector to hash.
	 */
	public function test_R3_change_detect_short_body_fails(): void
	{
		$this->seedBaseline();
		$result = $this->fetch('/short', 'change_detect');

		$this->assertFailedCleanly($result, 'change_detect', 18);
	}

	/**
	 * R4. Given the feed-host filter ON (default) and a 302 to a path whose final
	 * hop is short, then the download fails cleanly on the final hop.
	 */
	public function test_R4_redirect_to_short_final_hop_fails(): void
	{
		$this->seedBaseline();
		$result = $this->fetch('/redir-short');

		$this->assertFailedCleanly($result, '', 18);
	}

	/** C6. Control: a complete ingest 200 succeeds and publishes exactly the body. */
	public function test_C6_ingest_complete_body_succeeds(): void
	{
		$result = $this->fetch('/full');

		$this->assertTrue($result->success, 'a complete body must download; log was: ' . $this->logText());
		$this->assertSame(self::FULL_BODY, rtrim((string) @file_get_contents("{$this->workdir}/feed.orig"), "\n"));
	}

	/** C7. Control: a change-detect probe with a stored ETag gets 304 and succeeds. */
	public function test_C7_change_detect_conditional_304_succeeds(): void
	{
		pfb_validator_write(pfb_conditional_get_validator_base($this->downloadPath('change_detect')), '"v1"', FALSE);
		$result = $this->fetch('/etag', 'change_detect');

		$this->assertTrue($result->success, 'a 304 probe must succeed; log was: ' . $this->logText());
		$this->assertSame('304', $result->responseMeta['status'] ?? null);
	}

	/** C8. Control: a 302 then a complete 200 succeeds with only the final body. */
	public function test_C8_redirect_then_complete_body_succeeds(): void
	{
		$result = $this->fetch('/redir-full');

		$this->assertTrue($result->success, 'a followed redirect must download; log was: ' . $this->logText());
		$this->assertSame(self::FULL_BODY, rtrim((string) @file_get_contents("{$this->workdir}/feed.orig"), "\n"),
			'only the final hop body may be published, not the redirect page');
	}

	/** C9. Control: a first short attempt followed by a complete one is recovered by the retry. */
	public function test_C9_retry_recovers_after_short_first_attempt(): void
	{
		$result = $this->fetch('/flaky');

		$this->assertTrue($result->success, 'the retry must recover; log was: ' . $this->logText());
		$this->assertSame(2, $this->requestCount('/flaky'));
		$this->assertSame(self::FULL_BODY, rtrim((string) @file_get_contents("{$this->workdir}/feed.orig"), "\n"));
	}
}
