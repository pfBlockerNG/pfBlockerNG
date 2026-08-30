<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

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

	public function testProbeRejectsReachableForeignListener(): void
	{
		$this->requireReadinessHelper();
		$port = $this->startServer(<<<'PHP'
			<?php
			if (($_SERVER['REQUEST_URI'] ?? '') === '/setup') {
				echo 'FOREIGN';
				return;
			}
			echo 'not-the-readiness-token';
			PHP, 'FOREIGN');

		$this->assertFalse(
			pfb_test_http_fixture_event_received($port, 'expected-readiness-token'),
			'a reachable listener that did not handle the nonce-bearing fixture event must not count as ready'
		);
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
			if ($uri === '/__pfb_ready/' . $token) {
				echo $token;
				return;
			}
			http_response_code(404);
			PHP, 'READY', ['READY_TOKEN' => $token]);

		$this->assertTrue(
			pfb_test_http_fixture_event_received($port, $token),
			'the fixture router must count as ready after it echoes the exact request nonce'
		);
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
