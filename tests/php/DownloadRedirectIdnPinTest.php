<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * pfb_download() redirect hops to internationalized (non-ASCII) host names.
 *
 * Each hop is vetted, pinned and dialled under one host string: the UTS 46
 * mapped (ASCII) form the guard already applies, which is also the key libcurl
 * uses for its address lookup. A non-ASCII hop host therefore reaches the
 * address the guard vetted, exactly as its punycode spelling does, and the
 * origin-credential scope treats both spellings of one name as the same host.
 *
 * Exercised through the REAL pfb_download() against two local `php -S`
 * fixtures. Host names resolve through $GLOBALS['pfb_test_resolve_map'] under
 * the RAW spelling the guard looks up (loopback first, plus a public address so
 * the host is not classified self-hosted). Every request is recorded as
 * [port, uri, HTTP_HOST, PHP_AUTH_USER, PHP_AUTH_PW].
 */
#[CoversFunction('pfb_download')]
#[CoversFunction('pfb_feed_redirect_target')]
final class DownloadRedirectIdnPinTest extends TestCase
{
	private const ORIGIN_HOST = 'origin-feed.example';

	/** @var array<int,resource> the php -S server processes */
	private array $servers = [];

	private string $workdir = '';
	private int $originPort = 0;
	private int $targetPort = 0;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		if (!extension_loaded('curl') || !function_exists('idn_to_ascii')) {
			$this->markTestSkipped('curl and intl extensions required');
		}
		$workdir = tempnam(sys_get_temp_dir(), 'pfbidn');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		foreach ([self::ORIGIN_HOST, 'xn--bcher-kva.example', "b\u{FC}cher.example", "fa\u{DF}.example"] as $host) {
			$GLOBALS['pfb_test_resolve_map']["{$host}."] = [
				['type' => 'A', 'data' => '127.0.0.1'],
				['type' => 'A', 'data' => '203.0.113.21'],
			];
		}

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
	 * /redir?host=H&port=P answers 302 to http://H:P/list.txt (H percent-decoded
	 * by PHP, sent as raw UTF-8); any other path answers 200.
	 */
	private function startServers(): void
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
	$_SERVER['HTTP_HOST'] ?? null,
	$_SERVER['PHP_AUTH_USER'] ?? null,
	$_SERVER['PHP_AUTH_PW'] ?? null,
], JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND);
if (str_starts_with($uri, '/redir?')) {
	header('Location: http://' . $_GET['host'] . ':' . $_GET['port'] . '/list.txt', true, 302);
	return;
}
header('Content-Length: 4');
echo 'BODY';
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));

		$this->originPort = $this->startOneServer($router, 'origin');
		$this->targetPort = $this->startOneServer($router, 'target');
	}

	/** Start one php -S fixture on a free port; return the port. */
	private function startOneServer(string $router, string $label): int
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
					'EVENT_LOG'  => "{$this->workdir}/events.log",
					'READY_TOKEN' => $nonce,
					'PATH'       => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = 'port 0: process=proc_open failed stderr=(unavailable)';
				continue;
			}
			$port = pfb_test_http_fixture_port($stderr);
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

	/**
	 * Fetch through the origin's /redir, which redirects to $hopHost on $hopPort.
	 *
	 * @return array{0:PfbDownloadResult,1:array<int,array>} result and the recorded requests
	 */
	private function downloadVia(string $originHost, string $hopHost, int $hopPort, string $username = '', string $password = ''): array
	{
		$query  = http_build_query(['host' => $hopHost, 'port' => $hopPort]);
		$result = pfb_download(new PfbDownloadRequest(
			listUrl: "http://{$originHost}:{$this->originPort}/redir?{$query}",
			downloadPath: "{$this->workdir}/feed.txt",
			flex: FALSE,
			header: 'IdnPinFeed',
			format: '',
			logType: 1,
			type: 'change_detect',
			username: $username,
			password: $password,
		));
		$lines = @file("{$this->workdir}/events.log", FILE_IGNORE_NEW_LINES);
		$rows  = is_array($lines) ? array_map(fn (string $l): array => json_decode($l, TRUE), $lines) : [];
		return [$result, $rows];
	}

	private function failureMessage(PfbDownloadResult $result, array $rows): string
	{
		$log = @file_get_contents("{$this->workdir}/pfblockerng.log");
		return sprintf(
			'redirected download must succeed; status=%s; events=%s; ports=origin:%d target:%d; pfBlockerNG log=%s',
			(string) ($result->responseMeta['status'] ?? '(missing)'),
			json_encode($rows, JSON_UNESCAPED_UNICODE),
			$this->originPort,
			$this->targetPort,
			is_string($log) ? trim($log) : '(missing)'
		);
	}

	/** @return array<string,array{0:string,1:string}> */
	public static function hopHostProvider(): array
	{
		return [
			'non-ASCII host' => ["b\u{FC}cher.example", 'xn--bcher-kva.example'],
			'punycode host (control)' => ['xn--bcher-kva.example', 'xn--bcher-kva.example'],
			'sharp s, nontransitional mapping' => ["fa\u{DF}.example", 'xn--fa-hia.example'],
		];
	}

	#[DataProvider('hopHostProvider')]
	public function testHopIsDialledUnderTheMappedHost(string $hopHost, string $mappedHost): void
	{
		[$result, $rows] = $this->downloadVia(self::ORIGIN_HOST, $hopHost, $this->targetPort);
		$this->assertTrue($result->success, $this->failureMessage($result, $rows));
		$this->assertSame(
			[
				[$this->originPort, '/redir?' . http_build_query(['host' => $hopHost, 'port' => $this->targetPort]), self::ORIGIN_HOST . ":{$this->originPort}", NULL, NULL],
				[$this->targetPort, '/list.txt', "{$mappedHost}:{$this->targetPort}", NULL, NULL],
			],
			$rows,
			'the hop must reach the target under the mapped host name'
		);
	}

	public function testOnOriginHopSpelledInUnicodeKeepsCredentials(): void
	{
		// Origin is the punycode spelling; the hop names the same host in Unicode on the same port.
		[$result, $rows] = $this->downloadVia('xn--bcher-kva.example', "b\u{FC}cher.example", $this->originPort, 'user', 'secret');
		$this->assertTrue($result->success, $this->failureMessage($result, $rows));
		$this->assertCount(2, $rows, $this->failureMessage($result, $rows));
		$this->assertSame(
			[$this->originPort, '/list.txt', "xn--bcher-kva.example:{$this->originPort}", 'user', 'secret'],
			$rows[1],
			'the same host spelled in Unicode is on-origin and keeps the credentials'
		);
	}

	public function testOffOriginUnicodeHopReceivesNoCredentials(): void
	{
		[$result, $rows] = $this->downloadVia(self::ORIGIN_HOST, "b\u{FC}cher.example", $this->targetPort, 'user', 'secret');
		$this->assertTrue($result->success, $this->failureMessage($result, $rows));
		$this->assertCount(2, $rows, $this->failureMessage($result, $rows));
		$this->assertSame(
			[$this->targetPort, '/list.txt', "xn--bcher-kva.example:{$this->targetPort}", NULL, NULL],
			$rows[1],
			'a hop to a different host must carry no credentials'
		);
	}

	public function testUnicodeOriginFeedUrlIsRefusedAtEntryValidation(): void
	{
		// A non-ASCII host in the feed URL itself never reaches a fetch, so only redirect hops carry one.
		[$result, $rows] = $this->downloadVia("b\u{FC}cher.example", 'xn--bcher-kva.example', $this->targetPort);
		$this->assertFalse($result->success);
		$this->assertSame([], $rows, 'no request may reach either fixture');
		$errors = (string) @file_get_contents("{$this->workdir}/error.log");
		$this->assertStringContainsString(
			'[PFB_FILTER - ' . PFB_FILTER_URL . '] Invalid URL',
			$errors,
			'the refusal must come from the PFB_FILTER_URL entry gate, not a downstream fetch failure'
		);
	}
}
