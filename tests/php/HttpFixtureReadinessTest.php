<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HttpFixtureReadinessStreamSpy
{
	/** @var resource */
	public $context;
	public static ?string $url = NULL;
	/** @var array<string,mixed>|null */
	public static ?array $options = NULL;
	private static string $response = '';
	private int $offset = 0;

	public static function reset(string $response): void
	{
		self::$url = NULL;
		self::$options = NULL;
		self::$response = $response;
	}

	public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
	{
		self::$url = $path;
		self::$options = stream_context_get_options($this->context);
		return TRUE;
	}

	public function stream_read(int $count): string
	{
		$chunk = substr(self::$response, $this->offset, $count);
		$this->offset += strlen($chunk);
		return $chunk;
	}

	public function stream_eof(): bool
	{
		return $this->offset >= strlen(self::$response);
	}

	/** @return array<string,mixed> */
	public function stream_stat(): array
	{
		return [];
	}
}

final class HttpFixtureReadinessPortPollSpy
{
	/** @var list<string> */
	public static array $reads = [];
	/** @var list<int> */
	public static array $pauses = [];

	public static function reset(): void
	{
		self::$reads = [];
		self::$pauses = [];
	}

	public static function read(string $path): string
	{
		self::$reads[] = $path;
		return 'unmatched stderr';
	}

	public static function pause(int $microseconds): void
	{
		self::$pauses[] = $microseconds;
	}
}

/** Issue #2065: HTTP fixture readiness proves which process owns the selected port. */
final class HttpFixtureReadinessTest extends TestCase
{
	/** @var array<int,resource> */
	private array $servers = [];
	private string $workdir = '';

	protected function setUp(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfbready');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as $server) {
			if (is_resource($server)) {
				proc_terminate($server);
				proc_close($server);
			}
		}
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $path) {
				@unlink((string) $path);
			}
			rmdir($this->workdir);
		}
	}

	public function testProbeRejectsReflectiveForeignListener(): void
	{
		$this->requireReadinessHelper();
		$port = $this->startServer(<<<'PHP'
			<?php
			$uri = $_SERVER['REQUEST_URI'] ?? '';
			if ($uri === '/setup') {
				echo 'FOREIGN';
				return;
			}
			$path = parse_url($uri, PHP_URL_PATH);
			echo basename(is_string($path) ? $path : '');
			PHP, 'FOREIGN');

		$this->assertFalse(
			pfb_test_http_fixture_event_received($port, 'expected-readiness-token'),
			'a listener that reflects the disclosed request nonce must not count as the fixture owner'
		);
	}

	public function testProbeKeepsShortResponseTimeout(): void
	{
		$this->requireReadinessHelper();
		$token = bin2hex(random_bytes(12));
		$port = $this->startServer(<<<'PHP'
			<?php
			$uri = $_SERVER['REQUEST_URI'] ?? '';
			if ($uri === '/setup') {
				echo 'READY';
				return;
			}
			$token = getenv('READY_TOKEN');
			if ($uri === '/__pfb_ready') {
				usleep(1000000);
				echo $token;
				return;
			}
			http_response_code(404);
			PHP, 'READY', ['READY_TOKEN' => $token]);

		$this->assertFalse(
			pfb_test_http_fixture_event_received($port, $token),
			'a stalled readiness response must exceed the helper transport timeout'
		);
	}

	public function testProbeUsesExactTransportTimeout(): void
	{
		$this->requireReadinessHelper();
		$secret = 'owned-readiness-secret';
		HttpFixtureReadinessStreamSpy::reset($secret);
		$this->assertTrue(stream_wrapper_unregister('http'));
		try {
			$this->assertTrue(stream_wrapper_register('http', HttpFixtureReadinessStreamSpy::class));
			$this->assertTrue(
				pfb_test_http_fixture_event_received(1, $secret),
				'the default HTTP transport must return through the real readiness matcher'
			);
			$this->assertSame('http://127.0.0.1:1/__pfb_ready', HttpFixtureReadinessStreamSpy::$url);
			$this->assertSame(
				['timeout' => 0.05, 'ignore_errors' => TRUE],
				HttpFixtureReadinessStreamSpy::$options['http'] ?? NULL,
				'fixture readiness must consume the exact bounded HTTP options'
			);
		} finally {
			if (in_array('http', stream_get_wrappers(), TRUE)) {
				stream_wrapper_unregister('http');
			}
			$this->assertTrue(stream_wrapper_restore('http'));
		}
	}

	public function testProbeAcceptsMatchingFixtureEvent(): void
	{
		$this->requireReadinessHelper();
		$token = bin2hex(random_bytes(12));
		$port = $this->startServer(<<<'PHP'
			<?php
			$uri = $_SERVER['REQUEST_URI'] ?? '';
			if ($uri === '/setup') {
				echo 'READY';
				return;
			}
			$token = getenv('READY_TOKEN');
			if ($uri === '/__pfb_ready') {
				echo $token;
				return;
			}
			http_response_code(404);
			PHP, 'READY', ['READY_TOKEN' => $token]);

		$this->assertTrue(
			pfb_test_http_fixture_event_received($port, $token),
			'the fixture router must count as ready after it returns the child-owned secret'
		);
	}

	/** @return array<string,array{string,int}> */
	public static function bannerParserRows(): array
	{
		return [
			'php 8.4 banner' => [
				"[Mon Sep  7 12:13:20 2026] PHP 8.4.24 Development Server (http://127.0.0.1:38413) started\n",
				38413,
			],
			'pre-8.4 surrounding wording' => [
				"PHP 7.4.33 Development Server (http://127.0.0.1:8000) started\n",
				8000,
			],
			'unrelated stderr around the token' => [
				"Deprecated: some notice on line 3\n[Mon Sep  7 12:13:20 2026] PHP 8.4.24 Development Server (http://127.0.0.1:9001) started\nPHP Warning: trailing noise\n",
				9001,
			],
			'wrong host localhost' => ["PHP 8.4.24 Development Server (http://localhost:9001) started\n", 0],
			'wrong host 0.0.0.0' => ["PHP 8.4.24 Development Server (http://0.0.0.0:9001) started\n", 0],
			'wrong scheme https' => ["PHP 8.4.24 Development Server (https://127.0.0.1:9001) started\n", 0],
			'empty stderr' => ['', 0],
			'partial banner missing digits' => ["PHP 8.4.24 Development Server (http://127.0.0.1:", 0],
			'partial banner missing closing paren' => ["PHP 8.4.24 Development Server (http://127.0.0.1:38413", 0],
		];
	}

	/** Issue #3218: the port learner tolerates version-specific wording but never a truncated token. */
	#[DataProvider('bannerParserRows')]
	public function testFixturePortParserHandlesHostileBannerContent(string $stderrContent, int $expectedPort): void
	{
		$this->requireReadinessHelper();
		$stderr = "{$this->workdir}/banner-" . bin2hex(random_bytes(4)) . '.stderr';
		$this->assertNotFalse(file_put_contents($stderr, $stderrContent));
		$this->assertSame($expectedPort, pfb_test_http_fixture_port($stderr));
	}

	public function testFixturePortParserWaitsForAsynchronousBannerWrite(): void
	{
		$this->requireReadinessHelper();
		$stderr = "{$this->workdir}/async.stderr";
		$this->assertNotFalse(file_put_contents($stderr, ''));
		$code = sprintf(
			'usleep(200000); file_put_contents(%s, "[date] PHP 8.4.24 Development Server (http://127.0.0.1:24680) started\n");',
			var_export($stderr, TRUE)
		);
		$writer = proc_open(['php', '-r', $code], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
		$this->assertIsResource($writer);
		try {
			$this->assertSame(
				24680,
				pfb_test_http_fixture_port($stderr),
				'a banner written after the poll begins must still be learned within the bound'
			);
		} finally {
			proc_close($writer);
		}
	}

	public function testFixturePortParserReturnsZeroWhenStderrNeverAppears(): void
	{
		$this->requireReadinessHelper();
		$this->assertSame(0, pfb_test_http_fixture_port("{$this->workdir}/does-not-exist.stderr"));
	}

	public function testFixturePortParserKeepsExactFortyReadAndPauseBound(): void
	{
		$source = file_get_contents(__DIR__ . '/support/HttpFixtureReadiness.php');
		$this->assertIsString($source);
		$namespace = 'PfbIssue3218\\PortPoll' . bin2hex(random_bytes(6));
		$instrumentation = <<<PHP

namespace {$namespace};

function file_get_contents(string \$path): string
{
	return \HttpFixtureReadinessPortPollSpy::read(\$path);
}

function usleep(int \$microseconds): void
{
	\HttpFixtureReadinessPortPollSpy::pause(\$microseconds);
}
PHP;
		$source = str_replace(
			"declare(strict_types=1);\n",
			"declare(strict_types=1);{$instrumentation}\n",
			$source
		);
		$mirror = "{$this->workdir}/poll-helper.php";
		$this->assertNotFalse(file_put_contents($mirror, $source));
		HttpFixtureReadinessPortPollSpy::reset();
		require $mirror;

		$learner = "{$namespace}\\pfb_test_http_fixture_port";
		$this->assertSame(0, $learner('/fixture.stderr'));
		$this->assertSame(array_fill(0, 40, '/fixture.stderr'), HttpFixtureReadinessPortPollSpy::$reads);
		$this->assertSame(array_fill(0, 40, 50000), HttpFixtureReadinessPortPollSpy::$pauses);
	}

	private function requireReadinessHelper(): void
	{
		$helper = __DIR__ . '/support/HttpFixtureReadiness.php';
		$this->assertFileExists(
			$helper,
			'fixture readiness must use a nonce-bearing HTTP event instead of accepting raw port connectivity'
		);
		require_once $helper;
	}

	private function startServer(string $routerSource, string $setupResponse, array $environment = []): int
	{
		$router = "{$this->workdir}/router-" . count($this->servers) . '.php';
		$this->assertNotFalse(file_put_contents($router, $routerSource));
		$context = stream_context_create(['http' => ['timeout' => 0.05, 'ignore_errors' => TRUE]]);
		$failures = [];

		for ($try = 0; $try < 10; $try++) {
			$port = random_int(20000, 60000);
			$stderr = "{$this->workdir}/server-{$port}.stderr";
			$server = proc_open(
				['php', '-S', "127.0.0.1:{$port}", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->workdir,
				$environment + ['PATH' => (string) getenv('PATH')]
			);
			if (!is_resource($server)) {
				$failures[] = "port {$port}: proc_open failed";
				continue;
			}
			for ($attempt = 0; $attempt < 40; $attempt++) {
				$body = @file_get_contents("http://127.0.0.1:{$port}/setup", FALSE, $context);
				if ($body === $setupResponse) {
					$this->servers[] = $server;
					return $port;
				}
				usleep(50000);
			}
			proc_terminate($server);
			proc_close($server);
			$failures[] = "port {$port}: " . trim((string) @file_get_contents($stderr));
		}

		$this->fail('could not start readiness-test HTTP fixture; ' . implode(' | ', $failures));
	}
}
