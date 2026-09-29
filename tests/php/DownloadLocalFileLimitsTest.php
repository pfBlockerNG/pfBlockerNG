<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_download(): the self-hosted (local-file) fetch applies the same limits as
 * the cURL path (issues #3362, #3368). The size ceiling is the shared
 * PFB_DOWNLOAD_MAX_BYTES (test seam $pfb['local_max_bytes'], mirroring the rsync
 * seam); the request timeout bounds a stalled read; a body shorter than its
 * Content-Length is a failed download; only 200/221/226 succeed. Every refusal
 * leaves no .raw behind. Rows run the real pfb_download() against a loopback
 * raw-socket fixture that answers one request with a canned response.
 */
#[CoversFunction('pfb_download')]
final class DownloadLocalFileLimitsTest extends TestCase
{
	private const CEILING = 64;

	/** @var array<int,resource> */
	private array $servers = [];

	private string $workdir = '';

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $savedPfb = [];

	private string $savedSocketTimeout = '';

	protected function setUp(): void
	{
		$this->savedSocketTimeout = (string) ini_get('default_socket_timeout');
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		$workdir = tempnam(sys_get_temp_dir(), 'pfbll');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;
		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active', 'dbdir', 'local_max_bytes'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']   = 'now';
		$GLOBALS['pfb']['local_max_bytes'] = self::CEILING;
	}

	protected function tearDown(): void
	{
		ini_set('default_socket_timeout', $this->savedSocketTimeout);
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
		@rmdir("{$this->workdir}/feed.txt.raw");
		foreach ((array) glob("{$this->workdir}/*") as $f) {
			@unlink((string) $f);
		}
		@rmdir($this->workdir);
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
	}

	/**
	 * Answers one request with $response verbatim, then holds the connection open
	 * for $holdSeconds (hard cap, the process is also reaped in tearDown) before closing.
	 */
	private function startRawServer(string $response, int $holdSeconds = 0, int $dripMicros = 0, int $headerDelayMicros = 0, int $headerDripMicros = 0): int
	{
		$script = "{$this->workdir}/raw.php";
		$this->assertNotFalse(file_put_contents($script, <<<'PHP'
<?php
[, $portFile, $responseFile, $hold, $drip, $hdelay, $hdrip] = $argv;
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if ($server === FALSE) {
	exit(1);
}
$name = (string) stream_socket_get_name($server, FALSE);
file_put_contents("{$portFile}.tmp", substr($name, strrpos($name, ':') + 1));
rename("{$portFile}.tmp", $portFile);
while (($conn = @stream_socket_accept($server, 30)) !== FALSE) {
	while (($line = fgets($conn)) !== FALSE && rtrim($line, "\r\n") !== '') {
	}
	usleep((int) $hdelay);
	file_put_contents("{$portFile}.replied", '1');
	$resp = (string) file_get_contents($responseFile);
	if ((int) $hdrip > 0) {
		// Header lines one per $hdrip microseconds, then the body at once.
		$cut = strpos($resp, "\r\n\r\n") + 4;
		foreach (explode("\r\n", substr($resp, 0, $cut - 4)) as $hline) {
			usleep((int) $hdrip);
			@fwrite($conn, "{$hline}\r\n");
		}
		$resp = "\r\n" . substr($resp, $cut);
	}
	if ((int) $drip > 0) {
		// Headers at once, then the body one byte per $drip microseconds.
		$cut = strpos($resp, "\r\n\r\n") + 4;
		fwrite($conn, substr($resp, 0, $cut));
		foreach (str_split(substr($resp, $cut)) as $byte) {
			usleep((int) $drip);
			if (@fwrite($conn, $byte) === FALSE) {
				break;
			}
		}
	} else {
		fwrite($conn, $resp);
	}
	sleep((int) $hold);
	// Marker first: a fetch that waited for EOF must not be able to return before it exists.
	file_put_contents("{$portFile}.closed", '1');
	fclose($conn);
}
PHP));
		$this->assertNotFalse(file_put_contents("{$this->workdir}/response.bin", $response));
		$portFile = "{$this->workdir}/port";
		$proc = proc_open(
			['php', $script, $portFile, "{$this->workdir}/response.bin", (string) $holdSeconds, (string) $dripMicros, (string) $headerDelayMicros, (string) $headerDripMicros],
			[1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
			$pipes
		);
		$this->assertIsResource($proc);
		$this->servers[] = $proc;
		for ($i = 0; $i < 100 && !is_file($portFile); $i++) {
			usleep(50000);
		}
		$port = (int) @file_get_contents($portFile);
		$this->assertGreaterThan(0, $port, 'raw fixture server did not start');
		return $port;
	}

	private function serve(string $status, string $body, bool $withLength = TRUE, int $declared = -1, int $holdSeconds = 0, int $dripMicros = 0, int $headerDelayMicros = 0): int
	{
		$len = $withLength ? 'Content-Length: ' . ($declared >= 0 ? $declared : strlen($body)) . "\r\n" : '';
		return $this->startRawServer("HTTP/1.1 {$status}\r\n{$len}Connection: close\r\n\r\n{$body}", $holdSeconds, $dripMicros, $headerDelayMicros);
	}

	private function fetch(string $listUrl, int $timeout = 30): PfbDownloadResult
	{
		return pfb_download(new PfbDownloadRequest(
			listUrl: $listUrl,
			downloadPath: "{$this->workdir}/feed.txt",
			flex: FALSE,
			header: 'LocalFeed',
			format: '',
			logType: 1,
			type: 'change_detect',
			timeout: $timeout,
		));
	}

	private function logText(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	private function assertRefusedNothingSaved(PfbDownloadResult $result, string $why): void
	{
		$msg = sprintf('%s; log=%s', $why, $this->logText());
		$this->assertFalse($result->success, $msg);
		$this->assertFileDoesNotExist("{$this->workdir}/feed.txt.raw", $msg);
	}

	// ---- #3362: size ceiling ------------------------------------------------

	/** An over-ceiling body with a declared length is refused with the named size reason. */
	public function testOverCeilingDeclaredBodyIsRefused(): void
	{
		$port   = $this->serve('200 OK', str_repeat('A', self::CEILING + 1));
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, 'declared over-ceiling body');
		$this->assertStringContainsString('stage=size reason=local_too_large', $this->logText());
	}

	/** An over-ceiling body that announces no length is refused too: the guard needs no cooperation. */
	public function testOverCeilingStreamedBodyIsRefused(): void
	{
		$port   = $this->serve('200 OK', str_repeat('A', 4096), FALSE);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, 'streamed over-ceiling body');
		$this->assertStringContainsString('stage=size reason=local_too_large', $this->logText());
	}

	/** A plain local file over the ceiling is refused the same way. */
	public function testOverCeilingPlainFileIsRefused(): void
	{
		$GLOBALS['pfb']['dbdir'] = $this->workdir;
		$this->assertNotFalse(file_put_contents("{$this->workdir}/local.txt", str_repeat('A', self::CEILING + 1)));
		$result = $this->fetch("{$this->workdir}/local.txt");
		$this->assertRefusedNothingSaved($result, 'plain over-ceiling file');
		$this->assertStringContainsString('stage=size reason=local_too_large', $this->logText());
	}

	/** Control: a body exactly at the ceiling is saved whole. */
	public function testBodyAtCeilingIsSaved(): void
	{
		$body   = str_repeat('A', self::CEILING);
		$port   = $this->serve('200 OK', $body);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame($body, file_get_contents("{$this->workdir}/feed.txt.raw"));
		$this->assertStringNotContainsString('local_too_large', $this->logText());
	}

	/** Control: a small body is saved and reports status 200. */
	public function testSmallBodyIsSaved(): void
	{
		$port   = $this->serve('200 OK', "small\n");
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame("small\n", file_get_contents("{$this->workdir}/feed.txt.raw"));
		$this->assertSame('200', $result->responseMeta['status'] ?? NULL);
	}

	/** Control: a plain local file at the ceiling is saved. */
	public function testPlainFileAtCeilingIsSaved(): void
	{
		$GLOBALS['pfb']['dbdir'] = $this->workdir;
		$body = str_repeat('A', self::CEILING);
		$this->assertNotFalse(file_put_contents("{$this->workdir}/local.txt", $body));
		$result = $this->fetch("{$this->workdir}/local.txt");
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame($body, file_get_contents("{$this->workdir}/feed.txt.raw"));
	}

	// ---- #3368: complete body, timeout, status set --------------------------

	/** A body shorter than its declared Content-Length is a failed download. */
	public function testTruncatedBodyIsRefused(): void
	{
		$port   = $this->serve('200 OK', 'ab', TRUE, 10);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, 'body shorter than Content-Length');
		$this->assertStringContainsString('body incomplete (2 of 10 bytes)', $this->logText());
	}

	/** A read that stalls past the request timeout is a failed download. */
	public function testStalledBodyIsRefused(): void
	{
		// Holds the socket 5 s (hard cap); the 1 s request timeout must fire first.
		$port   = $this->serve('200 OK', 'ab', TRUE, 10, 5);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt", 1);
		$this->assertRefusedNothingSaved($result, 'stalled read');
		$this->assertStringContainsString('read timed out', $this->logText());
	}

	/**
	 * A body that keeps dripping under the per-read timeout but overruns the whole
	 * request timeout is refused, like cURL's CURLOPT_TIMEOUT. 20 bytes at 0.3 s
	 * each (about 6 s, hard cap) against a 1 s timeout; the length is complete and
	 * under the ceiling, so only the whole-transfer deadline can refuse it.
	 */
	public function testSlowDripBodyIsRefusedAtTheWholeTransferDeadline(): void
	{
		$port   = $this->serve('200 OK', str_repeat('A', 20), TRUE, -1, 0, 300000);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt", 1);
		$this->assertRefusedNothingSaved($result, 'slow drip past the request timeout');
		$this->assertStringContainsString('read timed out', $this->logText());
	}

	/** A declared length over the ceiling is refused on the header alone, even though the body sent is under it. */
	public function testOverCeilingDeclaredLengthWithSmallBodyIsRefused(): void
	{
		$port   = $this->serve('200 OK', 'ab', TRUE, self::CEILING + 1);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, 'declared length over the ceiling');
		$this->assertStringContainsString('stage=size reason=local_too_large', $this->logText());
	}

	/** @return array<string, array{string}> */
	public static function earlyFailureProvider(): array
	{
		return ['404' => ['404 Not Found'], '201' => ['201 Created']];
	}

	/** A refusal before any byte is read still leaves no stale .raw from an earlier run. */
	#[DataProvider('earlyFailureProvider')]
	public function testEarlyRefusalRemovesStaleRaw(string $status): void
	{
		$this->assertNotFalse(file_put_contents("{$this->workdir}/feed.txt.raw", 'STALE'));
		$port   = $this->serve($status, 'NO');
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, "early refusal {$status}");
	}

	/** @return array<string, array{string}> */
	public static function rejectedStatusProvider(): array
	{
		return [
			'201' => ['201 Created'],
			'202' => ['202 Accepted'],
			'204' => ['204 No Content'],
			'206' => ['206 Partial Content'],
		];
	}

	/** A 2xx outside 200/221/226 is refused, matching the cURL path. */
	#[DataProvider('rejectedStatusProvider')]
	public function testNonAcceptedSuccessStatusIsRefused(string $status): void
	{
		$port   = $this->serve($status, "BODY\n");
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, "status {$status}");
		$this->assertStringContainsString("local feed answered with HTTP/1.1 {$status}", $this->logText());
	}

	/** @return array<string, array{string}> */
	public static function acceptedStatusProvider(): array
	{
		return ['200' => ['200 OK'], '221' => ['221 Custom'], '226' => ['226 IM Used']];
	}

	/** Control: the cURL-accepted statuses are saved. */
	#[DataProvider('acceptedStatusProvider')]
	public function testAcceptedStatusIsSaved(string $status): void
	{
		$port   = $this->serve($status, "BODY\n");
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame("BODY\n", file_get_contents("{$this->workdir}/feed.txt.raw"));
	}

	/** Control: a not-found answer still fails and saves nothing. */
	public function testNotFoundKeepsFailing(): void
	{
		$port   = $this->serve('404 Not Found', 'NO');
		$result = $this->fetch("http://127.0.0.1:{$port}/missing");
		$this->assertRefusedNothingSaved($result, '404');
		$this->assertStringContainsString('HTTP/1.1 404', $this->logText());
	}

	/**
	 * A complete known-length body is saved as soon as its declared length has been
	 * read, without waiting for the peer to close (the peer holds the socket 5 s,
	 * hard cap, and writes `port.closed` when it lets go).
	 */
	public function testCompleteBodyOnAHeldOpenConnectionIsSavedWithoutWaitingForClose(): void
	{
		$port   = $this->serve('200 OK', "BODY\n", TRUE, -1, 5);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt", 1);
		$this->assertFileDoesNotExist("{$this->workdir}/port.closed", 'the fetch returned only after the peer closed');
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame("BODY\n", file_get_contents("{$this->workdir}/feed.txt.raw"));
	}

	/** Like cURL, reading stops at the declared Content-Length: surplus bytes are not saved. */
	public function testBytesPastTheDeclaredLengthAreNotSaved(): void
	{
		$port   = $this->serve('200 OK', 'abcdefghij', TRUE, 2);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame('ab', file_get_contents("{$this->workdir}/feed.txt.raw"));
	}

	/** Conflicting Content-Length headers are a failed download (a smaller second one must not mask truncation). */
	public function testConflictingContentLengthIsRefused(): void
	{
		$port   = $this->startRawServer("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab");
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, 'conflicting Content-Length');
		$this->assertStringContainsString('conflicting Content-Length', $this->logText());
	}

	/** Control: repeated but identical Content-Length headers are fine. */
	public function testIdenticalDuplicateContentLengthIsSaved(): void
	{
		$port   = $this->startRawServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab");
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame('ab', file_get_contents("{$this->workdir}/feed.txt.raw"));
	}

	/**
	 * The request timeout is one budget for the whole fetch: 1.2 s waiting for the
	 * headers leaves 0.8 s of a 2 s budget for a body that would arrive 4 s later
	 * (hard cap), so the fetch is refused near the timeout, not 2 s after the headers.
	 */
	public function testHeaderWaitCountsAgainstTheWholeTransferBudget(): void
	{
		$port  = $this->serve('200 OK', 'a', TRUE, -1, 0, 4000000, 1200000);
		$start = hrtime(TRUE);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt", 2);
		$elapsed = (hrtime(TRUE) - $start) / 1e9;
		$this->assertRefusedNothingSaved($result, 'header wait plus body wait over the request timeout');
		$this->assertStringContainsString('read timed out', $this->logText());
		$this->assertLessThan(3.0, $elapsed, 'refusal must come near the 2 s timeout, not after a second full budget');
	}

	/**
	 * Header lines dripping 0.6 s apart (each under the 1 s wait) reach the body phase with the
	 * 1 s budget already spent: the fetch is refused as timed out even though the body is
	 * complete and immediate. (A drip that lasts longer is still only cut once fopen returns: #3377.)
	 */
	public function testBudgetSpentOnHeadersRefusesBeforeReadingTheBody(): void
	{
		$port = $this->startRawServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: 1\r\nConnection: close\r\n\r\nab", 0, 0, 0, 600000);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt", 1);
		$this->assertRefusedNothingSaved($result, 'budget spent on the headers');
		$this->assertStringContainsString('read timed out', $this->logText());
	}

	/** A server that stays silent before the response headers is cut at the request timeout (the peer replies 3 s later, hard cap). */
	public function testSilenceBeforeTheHeadersIsCutAtTheRequestTimeout(): void
	{
		$port   = $this->serve('200 OK', 'ab', TRUE, -1, 0, 0, 3000000);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt", 1);
		$this->assertFileDoesNotExist("{$this->workdir}/port.replied", 'the fetch returned only after the peer replied');
		$this->assertRefusedNothingSaved($result, 'silence before the headers');
	}

	/**
	 * A degenerate timeout can never disable the bound (as the rsync path's max(1, budget)):
	 * timeout 0 behaves as 1 s, so a body stalled for 4 s (hard cap) is refused as timed out.
	 */
	public function testZeroTimeoutIsStillBounded(): void
	{
		$port   = $this->serve('200 OK', 'ab', TRUE, 10, 4);
		$start  = hrtime(TRUE);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt", 0);
		$elapsed = (hrtime(TRUE) - $start) / 1e9;
		$this->assertRefusedNothingSaved($result, 'timeout 0 must not lift the bound');
		$this->assertStringContainsString('read timed out', $this->logText());
		$this->assertLessThan(3.0, $elapsed);
	}

	/** With the test seam unset, the production default ceiling refuses a declared length one byte over PFB_DOWNLOAD_MAX_BYTES. */
	public function testDefaultCeilingIsTheSharedDownloadLimit(): void
	{
		unset($GLOBALS['pfb']['local_max_bytes']);
		$port   = $this->serve('200 OK', 'ab', TRUE, PFB_DOWNLOAD_MAX_BYTES + 1);
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertRefusedNothingSaved($result, 'declared length over the default ceiling');
		$this->assertStringContainsString('stage=size reason=local_too_large', $this->logText());
	}

	/** The size refusal logs the URL redacted: no userinfo, no query token. */
	public function testSizeRefusalLogRedactsTheUrl(): void
	{
		$port   = $this->serve('200 OK', str_repeat('A', self::CEILING + 1));
		$result = $this->fetch("http://feeduser:hunter2@127.0.0.1:{$port}/list.txt?token=SECRETTOKEN");
		$this->assertRefusedNothingSaved($result, 'over-ceiling body from a URL with credentials');
		$log = $this->logText();
		$this->assertStringContainsString('local_too_large', $log);
		$this->assertStringNotContainsString('hunter2', $log);
		$this->assertStringNotContainsString('SECRETTOKEN', $log);
	}

	/** When the .raw target cannot be opened for writing the download fails as "could not be saved". */
	public function testUnwritableRawTargetIsRefused(): void
	{
		$this->assertTrue(mkdir("{$this->workdir}/feed.txt.raw"));
		$port   = $this->serve('200 OK', "BODY\n");
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertFalse($result->success, $this->logText());
		$this->assertStringContainsString('could not be saved', $this->logText());
	}

	/** Control: a plain local file path is read as before. */
	public function testPlainFilePathIsSaved(): void
	{
		$GLOBALS['pfb']['dbdir'] = $this->workdir;
		$this->assertNotFalse(file_put_contents("{$this->workdir}/local.txt", "FILEBODY\n"));
		$result = $this->fetch("{$this->workdir}/local.txt");
		$this->assertTrue($result->success, $this->logText());
		$this->assertSame("FILEBODY\n", file_get_contents("{$this->workdir}/feed.txt.raw"));
	}
}
