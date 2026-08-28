<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_download() retry-attempt body reset (issue #1072).
 *
 * A failed curl_exec() attempt can leave a PARTIAL body in the download file
 * with the write offset at its end; the retry then APPENDS its (complete)
 * response after the garbage, and the corrupted concatenation is handed off as
 * the download. The retry loop now truncates + rewinds the handle before every
 * attempt (mirroring the existing per-hop redirect reset).
 *
 * Exercised through the REAL pfb_download() against a local `php -S` server
 * whose first response is truncated mid-body (Content-Length 64, 16 bytes
 * sent -> curl error 18) and whose second response is the full body. The
 * `type='change_detect'` probe mode returns right after the download loop,
 * before the MIME/decompress stages that are not off-appliance testable.
 * The feed host is a non-local name resolved to 127.0.0.1 through the
 * $GLOBALS['pfb_test_resolve_map'] hook: the self-IP carve-out admits it and
 * the fetch is pinned (CURLOPT_RESOLVE) to the loopback fixture server -- a
 * literal 127.0.0.1 URL would take the localfile (file_get_contents) path and
 * never reach the cURL retry loop under test.
 */
#[CoversFunction('pfb_download')]
final class DownloadRetryBodyResetTest extends TestCase
{
	private const FULL_BODY = 'ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP';

	/** @var resource|null the php -S server process */
	private $server = null;

	private string $workdir = '';
	private int $port = 0;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$workdir = tempnam(sys_get_temp_dir(), 'pfbdl');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		// Loopback FIRST (it becomes the pinned connection address, admitted by the
		// self-IP carve-out) plus a public address so the host is NOT classified
		// self-hosted (that classification would take the localfile path instead
		// of the cURL loop under test).
		$GLOBALS['pfb_test_resolve_map'] = [
			'flaky-feed.example.' => [
				['type' => 'A', 'data' => '127.0.0.1'],
				['type' => 'A', 'data' => '203.0.113.20'],
			],
		];

		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']   = 'now';

		$this->startFlakyServer();
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
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
	}

	/**
	 * First request: Content-Length 64 but only 16 bytes sent (curl error 18,
	 * the partial bytes already written through CURLOPT_FILE). Later requests:
	 * the full 64-byte body.
	 */
	private function startFlakyServer(): void
	{
		$router = "{$this->workdir}/router.php";
		$body   = self::FULL_BODY;
		$this->assertSame(64, strlen($body));
		$routerSrc = <<<PHP
<?php
\$authLog = getenv('AUTH_LOG');
if (str_starts_with(\$_SERVER['REQUEST_URI'] ?? '', '/auth')) {
	file_put_contents(\$authLog, json_encode([
		\$_SERVER['PHP_AUTH_USER'] ?? null,
		\$_SERVER['PHP_AUTH_PW'] ?? null,
	]) . PHP_EOL, FILE_APPEND);
	header('Content-Length: 64');
	echo '{$body}';
	return;
}
\$state = getenv('FLAKY_STATE');
header('Content-Length: 64');
if (!file_exists(\$state)) {
	touch(\$state);
	echo substr('{$body}', 0, 16);
	flush();
	exit;
}
echo '{$body}';
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));

		$descriptors = [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
		for ($try = 0; $try < 10; $try++) {
			$port = random_int(20000, 60000);
			$proc = proc_open(
				['php', '-S', "127.0.0.1:{$port}", $router],
				$descriptors,
				$pipes,
				$this->workdir,
				[
					'AUTH_LOG' => "{$this->workdir}/auth.log",
					'FLAKY_STATE' => "{$this->workdir}/state.flag",
					'PATH' => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				continue;
			}
			// Poll readiness instead of a fixed wait (up to ~2s).
			for ($i = 0; $i < 40; $i++) {
				$sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.05);
				if ($sock !== FALSE) {
					fclose($sock);
					$this->server = $proc;
					$this->port = $port;
					return;
				}
				usleep(50000);
			}
			proc_terminate($proc);
			proc_close($proc);
		}
		$this->fail('could not start the flaky php -S fixture server');
	}

	public function testRetryAfterPartialBodyYieldsExactFinalBody(): void
	{
		$file_dwn = "{$this->workdir}/feed.txt";
		$url      = "http://flaky-feed.example:{$this->port}/feed.txt";
		// When: the first attempt is cut mid-body (curl error 18) and the retry
		// succeeds. (The production retry path sleeps 5s once here.)
		$result = pfb_download(new PfbDownloadRequest(
			listUrl: $url,
			downloadPath: $file_dwn,
			flex: FALSE,
			header: 'RetryFeed',
			format: '',
			logType: 1,
			versionType: '',
			timeout: 30,
			type: 'change_detect',
			username: '',
			password: '',
			sourceInterface: FALSE,
			extraHeaders: array(),
		));

		// Then: the download succeeds and the file holds EXACTLY the final
		// response body -- before the fix it held the 16 partial bytes with the
		// full body appended after them (80 bytes of corrupted concatenation).
		$this->assertTrue($result->success, 'retry download must succeed');
		$this->assertSame('200', $result->responseMeta['status'] ?? '', 'probe metadata must carry the final 200');
		// pfb_download() writes the body to {file_dwn}.raw.
		$got = file_get_contents("{$file_dwn}.raw");
		$this->assertNotFalse($got);
		$this->assertSame(
			self::FULL_BODY,
			$got,
			'the retried download must contain only the final response body, got ' . strlen($got) . ' bytes'
		);
	}

	/**
	 * Scenario: HTTP Basic auth is enabled when either credential is present.
	 * Given literal "0", username-only, and empty-pair credential cases,
	 * when pfb_download() fetches each feed, the server sees every real value.
	 */
	public function testBasicAuthUsesAnyPresentCredentialWithoutDroppingZero(): void
	{
		$cases = [
			['0', 'secret', ['0', 'secret']],
			['feed', '0', ['feed', '0']],
			['token', '', ['token', NULL]],
			['', 'secret', ['', 'secret']],
			['', '', [NULL, NULL]],
		];

		foreach ($cases as $index => [$username, $password]) {
			$result = pfb_download(new PfbDownloadRequest(
				listUrl: "http://flaky-feed.example:{$this->port}/auth/{$index}",
				downloadPath: "{$this->workdir}/auth-{$index}.txt",
				flex: FALSE,
				header: "AuthFeed{$index}",
				format: '',
				logType: 1,
				type: 'change_detect',
				username: $username,
				password: $password,
			));
			$this->assertTrue($result->success, "auth case {$index} download must succeed");
		}

		$lines = file("{$this->workdir}/auth.log", FILE_IGNORE_NEW_LINES);
		$this->assertIsArray($lines, 'fixture server must record each request credential pair');
		$this->assertCount(count($cases), $lines, 'fixture server must record exactly one request per auth case');
		foreach ($cases as $index => [, , $expected]) {
			$this->assertSame(
				$expected,
				json_decode($lines[$index], TRUE),
				"auth case {$index} must reach the server as the expected credential pair"
			);
		}
	}
}
