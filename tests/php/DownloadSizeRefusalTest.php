<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * Issue #2658 — an over-large feed body is refused at download, once.
 *
 * Drives the REAL pfb_download() against a local `php -S` server over the real
 * cURL path, with the ceiling lowered on $pfb['curl_defaults'] so a handful of
 * bytes is "over-large" (the shipped value is gigabytes; DownloadSizeCeilingTest
 * pins that value). What is under test here is behaviour, not wiring: libcurl
 * raises error 63, pfb_download() refuses instead of retrying, the partial body
 * is removed, and the refusal is logged distinguishably.
 *
 * The single-attempt assertion is the load-bearing one. Without the refusal
 * branch the retry loop treats 63 like any transient error and re-fetches the
 * same over-large body twice more, five seconds apart, before failing — and the
 * response code libcurl has already collected can be a 200, which would carry a
 * truncated body on to MIME validation as though it were the whole feed.
 *
 * The feed host is a non-local name resolved to 127.0.0.1 through the
 * $GLOBALS['pfb_test_resolve_map'] hook, mirroring DownloadRetryBodyResetTest:
 * a literal 127.0.0.1 URL takes the localfile path and never reaches cURL.
 */
#[CoversFunction('pfb_download')]
final class DownloadSizeRefusalTest extends TestCase
{
	/** Ceiling used for this test only — far below any body the fixture serves. */
	private const CEILING = 64;

	/** @var resource|null the php -S server process */
	private $server = null;

	private string $workdir = '';
	private int $port = 0;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	/** @var array<int,mixed> saved curl defaults entry (sentinel FALSE = was unset) */
	private $savedCeiling = FALSE;

	/** @var array<string,mixed> saved fixture globals (sentinel: absent key = was unset) */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$workdir = tempnam(sys_get_temp_dir(), 'pfbsz');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		// Save before replacing: a sibling test's fixture state must survive this one.
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
			'oversize-feed.example.' => [
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

		$this->savedCeiling = array_key_exists(CURLOPT_MAXFILESIZE_LARGE, $GLOBALS['pfb']['curl_defaults'] ?? [])
			? $GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE]
			: FALSE;
		$GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE] = self::CEILING;

		$this->startServer();
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
		}
		if ($this->savedCeiling === FALSE) {
			unset($GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE]);
		} else {
			$GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE] = $this->savedCeiling;
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
	 * Two routes, both far over the ceiling, one per enforcement shape:
	 * /declared announces its length up front; /streamed announces nothing and
	 * dribbles the body out, so only a mid-transfer check can stop it. Every
	 * request appends a line to the request log.
	 */
	private function startServer(): void
	{
		$router = "{$this->workdir}/router.php";
		$routerSrc = <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '';
if (str_starts_with($uri, '/__pfb_ready/')) {
	if ($uri === '/__pfb_ready/' . getenv('READY_TOKEN')) {
		echo getenv('READY_TOKEN');
	}
	return;
}
file_put_contents(getenv('REQ_LOG'), $uri . PHP_EOL, FILE_APPEND);
$chunk = str_repeat('A', 1024);
header('Content-Type: text/plain');
if (str_starts_with($uri, '/declared')) {
	header('Content-Length: ' . (string) (4 * 1024));
}
for ($i = 0; $i < 4; $i++) {
	echo $chunk;
	flush();
}
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));

		$failures = [];
		for ($try = 0; $try < 10; $try++) {
			$port = random_int(20000, 60000);
			$nonce = bin2hex(random_bytes(16));
			$stderr = "{$this->workdir}/server-{$port}-{$try}.stderr";
			$proc = proc_open(
				['php', '-S', "127.0.0.1:{$port}", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->workdir,
				[
					'REQ_LOG' => "{$this->workdir}/requests.log",
					'READY_TOKEN' => $nonce,
					'PATH' => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = "port {$port}: process=proc_open failed stderr=(unavailable)";
				continue;
			}
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

	/** @return int the number of requests the fixture server saw */
	private function requestCount(): int
	{
		$lines = @file("{$this->workdir}/requests.log", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		return is_array($lines) ? count($lines) : 0;
	}

	private function logText(): string
	{
		return (string) @file_get_contents((string) $GLOBALS['pfb']['log']);
	}

	private function fetch(string $route, string $header): PfbDownloadResult
	{
		return pfb_download(new PfbDownloadRequest(
			listUrl: "http://oversize-feed.example:{$this->port}{$route}",
			downloadPath: "{$this->workdir}/feed",
			flex: FALSE,
			header: $header,
			format: '',
			logType: 1,
			versionType: '',
			timeout: 30,
			type: '',
			username: '',
			password: '',
			sourceInterface: FALSE,
			extraHeaders: array(),
		));
	}

	/**
	 * Scenario: a body whose declared length is over the ceiling
	 *
	 * Given a feed that announces 4 KiB against a 64-byte ceiling
	 * When pfb_download() fetches it
	 * Then the download fails, the fixture server sees exactly ONE request (the
	 *   refusal is permanent, not retried), nothing is left behind in the
	 *   download file, and the log names the reason rather than showing a bare
	 *   cURL error number.
	 */
	public function test_declared_over_ceiling_body_is_refused_once(): void
	{
		$result = $this->fetch('/declared', 'OversizeDeclared');

		$this->assertFalse($result->success, 'an over-large body must not download successfully');
		$this->assertSame(1, $this->requestCount(),
			'an over-large body is a permanent refusal — it must not be re-fetched');
		$this->assertFileDoesNotExist("{$this->workdir}/feed.raw",
			'the partial body must not be left on disk');
		$this->assertStringContainsString('stage=size reason=download_too_large', $this->logText(),
			'the refusal must be logged distinguishably, not as a generic download failure');
	}

	/**
	 * Scenario: a body that announces no length at all
	 *
	 * Given a feed that streams 4 KiB with no Content-Length, so the ceiling can
	 *   only be enforced once bytes are already arriving
	 * When pfb_download() fetches it
	 * Then it is refused exactly as the declared-length case is — proving the
	 *   guard does not depend on a cooperative server announcing its size.
	 */
	public function test_streamed_over_ceiling_body_is_refused_once(): void
	{
		$result = $this->fetch('/streamed', 'OversizeStreamed');

		$this->assertFalse($result->success, 'an over-large streamed body must not download successfully');
		$this->assertSame(1, $this->requestCount(),
			'an over-large body is a permanent refusal — it must not be re-fetched');
		$this->assertFileDoesNotExist("{$this->workdir}/feed.raw",
			'the partial body must not be left on disk');
		$this->assertStringContainsString('stage=size reason=download_too_large', $this->logText(),
			'the refusal must be logged distinguishably, not as a generic download failure');
	}

	/**
	 * Scenario: a body under the ceiling is untouched
	 *
	 * Given the same fixture server and a ceiling above the body it serves
	 * When pfb_download() fetches it
	 * Then the download succeeds — proving the refusal above is a real branch
	 *   and not an always-reject path.
	 */
	public function test_body_under_the_ceiling_still_downloads(): void
	{
		$GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE] = 1024 * 1024;

		$result = $this->fetch('/declared', 'UnderCeiling');

		$this->assertTrue($result->success, 'a body under the ceiling must still download');
		$this->assertStringNotContainsString('reason=download_too_large', $this->logText());
		// The ingest path moves the body on from {feed}.raw once it validates (adding a
		// trailing newline), so the proof it arrived whole is the published copy.
		$this->assertSame(4 * 1024,
			substr_count((string) @file_get_contents("{$this->workdir}/feed.orig"), 'A'),
			'the whole body must reach the publication, not a truncated prefix');
	}
}
