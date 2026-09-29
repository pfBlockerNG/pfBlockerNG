<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * pfb_download(): the self-hosted (local-file) fetch applies the same redirect
 * validation as the cURL path. A 3xx answer is refused (logged as skipped, failure
 * result, nothing saved); a 2xx answer, a not-found answer and a plain file path
 * keep their behaviour. Rows run the real pfb_download() against a local `php -S`
 * fixture; its event log shows whether a redirect hop was followed.
 */
#[CoversFunction('pfb_download')]
final class DownloadLocalFileRedirectTest extends TestCase
{
	private const REASON = 'local feed answered with ';

	/** @var array<int,resource> */
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

	private function startOneServer(string $router): int
	{
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
					'EVENT_LOG'        => "{$this->workdir}/events.log",
					'READY_TOKEN'      => $nonce,
					'PATH'             => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = "bind: proc_open failed";
				continue;
			}
			$port = pfb_test_http_fixture_port($stderr, '127.0.0.1');
			for ($i = 0; $i < 40; $i++) {
				if ($port > 0 && pfb_test_http_fixture_event_received($port, $nonce, '127.0.0.1')) {
					$this->servers[$port] = $proc;
					return $port;
				}
				usleep(50000);
			}
			$status = proc_get_status($proc);
			if ($status['running']) {
				proc_terminate($proc);
			}
			proc_close($proc);
			$failures[] = "bind port {$port}: " . trim((string) @file_get_contents($stderr));
		}
		$this->fail("could not start the fixture server; " . implode(' | ', $failures));
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
if (preg_match('#^/redir-(\d{3})$#', $uri, $m) === 1) {
	header('Location: ' . '/list.txt', true, (int) $m[1]);
	echo 'REDIRBODY';
	return;
}
if ($uri === '/redir-nolocation') {
	http_response_code(302);
	echo 'REDIRBODY';
	return;
}
if ($uri === '/ok-with-location') {
	header('Location: /elsewhere');
	http_response_code(200);
	echo 'BODY';
	return;
}
if ($uri === '/boom') {
	http_response_code(500);
	echo 'BOOM';
	return;
}
if ($uri === '/missing') {
	http_response_code(404);
	echo 'NOTFOUND';
	return;
}
echo 'BODY';
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));
		return $router;
	}

	private function makeWorkdir(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfblf');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active', 'dbdir'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']   = 'now';
	}

	/** @return int the fixture server port */
	private function startFixtures(): int
	{
		$this->makeWorkdir();
		$router = $this->router();
		return $this->startOneServer($router);
	}

	private function fetch(string $listUrl): PfbDownloadResult
	{
		return pfb_download(new PfbDownloadRequest(
			listUrl: $listUrl,
			downloadPath: "{$this->workdir}/feed.txt",
			flex: FALSE,
			header: 'LocalFeed',
			format: '',
			logType: 1,
			type: 'change_detect',
		));
	}

	private function failureMessage(PfbDownloadResult $result): string
	{
		$events = @file_get_contents("{$this->workdir}/events.log");
		$events = is_string($events) && trim($events) !== '' ? trim($events) : '(empty)';
		$log = @file_get_contents($GLOBALS['pfb']['log'] ?? '');
		$log = is_string($log) && trim($log) !== '' ? trim($log) : '(empty)';
		return sprintf(
			'success=%s metadata=%s; events=%s; pfBlockerNG log=%s',
			var_export($result->success, TRUE),
			(string) json_encode($result->responseMeta, JSON_UNESCAPED_SLASHES),
			$events,
			$log
		);
	}

	private function assertRefused(string $path, string $code): void
	{
		$port   = $this->startFixtures();
		$result = $this->fetch("http://127.0.0.1:{$port}{$path}");
		$msg    = $this->failureMessage($result);

		$this->assertFalse($result->success, $msg);
		$events = (string) @file_get_contents("{$this->workdir}/events.log");
		$this->assertStringNotContainsString('/list.txt', $events, 'the redirect target must not be requested: ' . $msg);
		$this->assertStringContainsString(self::REASON . "HTTP/1.1 {$code}", (string) @file_get_contents($GLOBALS['pfb']['log']), $msg);
		$this->assertFileDoesNotExist("{$this->workdir}/feed.txt.raw", $msg);
	}

	/** @return array<string, array{string, string}> */
	public static function redirectStatusProvider(): array
	{
		return [
			'301' => ['/redir-301', '301'],
			'302' => ['/redir-302', '302'],
			'303' => ['/redir-303', '303'],
			'307' => ['/redir-307', '307'],
			'308' => ['/redir-308', '308'],
		];
	}

	#[DataProvider('redirectStatusProvider')]
	public function testRedirectStatusIsRefused(string $path, string $code): void
	{
		$this->assertRefused($path, $code);
	}

	/** A 3xx with no Location header is refused too: the status is the key. */
	public function testRedirectWithoutLocationIsRefused(): void
	{
		$this->assertRefused('/redir-nolocation', '302');
	}

	/** A 200 that carries a Location header is a success: the status is the key. */
	public function testSuccessWithLocationHeaderIsAccepted(): void
	{
		$port   = $this->startFixtures();
		$result = $this->fetch("http://127.0.0.1:{$port}/ok-with-location");
		$this->assertTrue($result->success, $this->failureMessage($result));
		$this->assertSame('BODY', file_get_contents("{$this->workdir}/feed.txt.raw"));
	}

	/** Control: a plain success is saved. */
	public function testSuccessIsSaved(): void
	{
		$port   = $this->startFixtures();
		$result = $this->fetch("http://127.0.0.1:{$port}/list.txt");
		$this->assertTrue($result->success, $this->failureMessage($result));
		$this->assertSame('BODY', file_get_contents("{$this->workdir}/feed.txt.raw"));
		$this->assertSame('200', $result->responseMeta['status'] ?? NULL, $this->failureMessage($result));
	}

	/** @return array<string, array{string, string}> */
	public static function failedReadProvider(): array
	{
		return [
			'404' => ['/missing', '404'],
			'500' => ['/boom', '500'],
		];
	}

	/** Control: a failed read fails, saves nothing and keeps the wrapper message (not the redirect one). */
	#[DataProvider('failedReadProvider')]
	public function testFailedReadKeepsWrapperMessage(string $path, string $code): void
	{
		$port   = $this->startFixtures();
		$result = $this->fetch("http://127.0.0.1:{$port}{$path}");
		$msg    = $this->failureMessage($result);
		$this->assertFalse($result->success, $msg);
		$this->assertFileDoesNotExist("{$this->workdir}/feed.txt.raw");
		$log = (string) @file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringNotContainsString(self::REASON, $log, $msg);
		$this->assertStringContainsString("HTTP/1.1 {$code}", $log, $msg);
	}

	/**
	 * Starts a raw-socket server that answers one request with $response verbatim
	 * (`php -S` normalises reason phrases, so it cannot serve control bytes).
	 */
	private function startRawServer(string $response): int
	{
		$this->makeWorkdir();
		$script = "{$this->workdir}/raw.php";
		$this->assertNotFalse(file_put_contents($script, <<<'PHP'
<?php
[, $portFile, $eventLog, $responseFile] = $argv;
$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if ($server === FALSE) {
	exit(1);
}
$name = (string) stream_socket_get_name($server, FALSE);
file_put_contents("{$portFile}.tmp", substr($name, strrpos($name, ':') + 1));
rename("{$portFile}.tmp", $portFile);
while (($conn = @stream_socket_accept($server, 30)) !== FALSE) {
	file_put_contents($eventLog, (string) fgets($conn), FILE_APPEND);
	while (($line = fgets($conn)) !== FALSE && rtrim($line, "\r\n") !== '') {
	}
	fwrite($conn, (string) file_get_contents($responseFile));
	fclose($conn);
}
PHP));
		$this->assertNotFalse(file_put_contents("{$this->workdir}/response.bin", $response));
		$portFile = "{$this->workdir}/port";
		$proc = proc_open(
			['php', $script, $portFile, "{$this->workdir}/events.log", "{$this->workdir}/response.bin"],
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

	/** A 3xx whose reason phrase carries control bytes is refused and logged as one clean line. */
	public function testRedirectReasonControlBytesAreStrippedFromLog(): void
	{
		$reason = "Found\r[ Other ] Downloading update .......... completed .\x1b[2J\x7f\x00\tTAIL";
		$port   = $this->startRawServer(
			"HTTP/1.1 302 {$reason}\r\nLocation: /list.txt\r\nContent-Length: 2\r\nConnection: close\r\n\r\nRB"
		);
		$result = $this->fetch("http://127.0.0.1:{$port}/redir-ctl");
		$msg    = $this->failureMessage($result);

		$this->assertFalse($result->success, $msg);
		$this->assertFileDoesNotExist("{$this->workdir}/feed.txt.raw", $msg);
		$this->assertStringNotContainsString('/list.txt', (string) @file_get_contents("{$this->workdir}/events.log"), $msg);

		$log   = (string) @file_get_contents($GLOBALS['pfb']['log']);
		$lines = array_values(array_filter(explode("\n", $log), static fn(string $l): bool => str_contains($l, self::REASON)));
		$this->assertCount(1, $lines, $msg);
		$this->assertStringContainsString(self::REASON . 'HTTP/1.1 302 Found', $lines[0], $msg);
		$this->assertStringEndsWith("TAIL \xe2\x80\x94 skipped", $lines[0], $msg);
		$this->assertDoesNotMatchRegularExpression('/[\x00-\x09\x0B-\x1F\x7F]/', $log, $msg);
	}

	/** Control: a plain file path under the data directory is read as before. */
	public function testPlainFilePathIsSaved(): void
	{
		$this->makeWorkdir();
		$GLOBALS['pfb']['dbdir'] = $this->workdir;
		$this->assertNotFalse(file_put_contents("{$this->workdir}/local.txt", "FILEBODY\n"));
		$result = $this->fetch("{$this->workdir}/local.txt");
		$this->assertTrue($result->success, $this->failureMessage($result));
		$this->assertSame("FILEBODY\n", file_get_contents("{$this->workdir}/feed.txt.raw"));
	}
}
