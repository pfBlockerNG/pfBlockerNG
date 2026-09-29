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
 * keep their behaviour. Rows run the real pfb_download() against local `php -S`
 * fixtures: a 127.0.0.1 origin (the self-hosted host) and a 127.0.0.2 target the
 * redirect points at, so the target's event log shows whether a hop was followed.
 */
#[CoversFunction('pfb_download')]
final class DownloadLocalFileRedirectTest extends TestCase
{
	private const REASON = 'local feed answered with a redirect';

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
					'EVENT_LOG'        => "{$this->workdir}/events.log",
					'TARGET_BASE_FILE' => "{$this->workdir}/target_base.txt",
					'READY_TOKEN'      => $nonce,
					'PATH'             => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = "bind {$bindHost}: proc_open failed";
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
			proc_close($proc);
			$failures[] = "bind {$bindHost} port {$port}: " . trim((string) @file_get_contents($stderr));
		}
		$this->fail("could not start the {$label} fixture server on {$bindHost}; " . implode(' | ', $failures));
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
if (preg_match('#^/redir-(\d{3})$#', $uri, $m) === 1) {
	header('Location: ' . $targetBase . '/list.txt', true, (int) $m[1]);
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

	/** @return int the origin (127.0.0.1) port */
	private function startFixtures(): int
	{
		$this->makeWorkdir();
		$router = $this->router();
		$targetPort = $this->startOneServer($router, '127.0.0.2', 'target');
		$this->assertNotFalse(file_put_contents("{$this->workdir}/target_base.txt", "http://127.0.0.2:{$targetPort}"));
		return $this->startOneServer($router, '127.0.0.1', 'origin');
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

	private function assertRefused(string $path): void
	{
		$port   = $this->startFixtures();
		$result = $this->fetch("http://127.0.0.1:{$port}{$path}");
		$msg    = $this->failureMessage($result);

		$this->assertFalse($result->success, $msg);
		$events = (string) @file_get_contents("{$this->workdir}/events.log");
		$this->assertStringNotContainsString('/list.txt', $events, 'the redirect target must not be requested: ' . $msg);
		$this->assertStringContainsString(self::REASON, (string) @file_get_contents($GLOBALS['pfb']['log']), $msg);
		$this->assertFileDoesNotExist("{$this->workdir}/feed.txt.raw", $msg);
	}

	/** @return array<string, array{string}> */
	public static function redirectStatusProvider(): array
	{
		return [
			'301' => ['/redir-301'],
			'302' => ['/redir-302'],
			'303' => ['/redir-303'],
			'307' => ['/redir-307'],
			'308' => ['/redir-308'],
		];
	}

	#[DataProvider('redirectStatusProvider')]
	public function testRedirectStatusIsRefused(string $path): void
	{
		$this->assertRefused($path);
	}

	/** A 3xx with no Location header is refused too: the status is the key. */
	public function testRedirectWithoutLocationIsRefused(): void
	{
		$this->assertRefused('/redir-nolocation');
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

	/** Control: a not-found answer fails and saves nothing. */
	public function testNotFoundFails(): void
	{
		$port   = $this->startFixtures();
		$result = $this->fetch("http://127.0.0.1:{$port}/missing");
		$this->assertFalse($result->success, $this->failureMessage($result));
		$this->assertFileDoesNotExist("{$this->workdir}/feed.txt.raw");
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
