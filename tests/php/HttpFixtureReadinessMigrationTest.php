<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Issue #2904: every php -S fixture proves its own nonce event before use. */
final class HttpFixtureReadinessMigrationTest extends TestCase
{
	/** @var array<int,resource> */
	private array $servers = [];
	private string $workdir = '';

	protected function setUp(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfbready2904');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;
		require_once __DIR__ . '/support/HttpFixtureReadiness.php';
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

	/** @return array<string,array{class-string,file-string,string}> */
	public static function rawReadinessSites(): array
	{
		return [
			'extracted payload archive' => [DownloadExtractedPayloadSanityTest::class, __DIR__ . '/DownloadExtractedPayloadSanityTest.php', 'downloadArchive'],
			'rejected validator origin' => [DownloadRejectValidatorClearTest::class, __DIR__ . '/DownloadRejectValidatorClearTest.php', 'startOrigin'],
			'retry body reset origin' => [DownloadRetryBodyResetTest::class, __DIR__ . '/DownloadRetryBodyResetTest.php', 'startFlakyServer'],
			'download size refusal origin' => [DownloadSizeRefusalTest::class, __DIR__ . '/DownloadSizeRefusalTest.php', 'startServer'],
			'GeoIP ZIP publication' => [GeoipZipPublicationTest::class, __DIR__ . '/GeoipZipPublicationTest.php', 'downloadGeoip'],
			'TOP1M change-detect probe' => [Top1mDccDetectorTest::class, __DIR__ . '/Top1mDccDetectorTest.php', 'testChangeDetectUsesActualHttpProbeBodyAndMetadata'],
			'TOP1M DCC download' => [Top1mDccDetectorTest::class, __DIR__ . '/Top1mDccDetectorTest.php', 'downloadTop1m'],
			'TOP1M semantic validation' => [Top1mDownloadSemanticValidationTest::class, __DIR__ . '/Top1mDownloadSemanticValidationTest.php', 'downloadBody'],
			'TOP1M provider matrix' => [Top1mSemanticMatrixTest::class, __DIR__ . '/Top1mSemanticMatrixTest.php', 'downloadSource'],
		];
	}

	#[DataProvider('rawReadinessSites')]
	public function testFixtureSiteRequiresOwnedNonceEventAndBindDiagnostics(
		string $class,
		string $file,
		string $method
	): void {
		require_once $file;
		$reflection = new ReflectionMethod($class, $method);
		$lines = file($file);
		$this->assertIsArray($lines);
		$source = implode('', array_slice(
			$lines,
			$reflection->getStartLine() - 1,
			$reflection->getEndLine() - $reflection->getStartLine() + 1
		));

		$this->assertStringNotContainsString(
			'fsockopen(',
			$source,
			"{$file}::{$method} must not accept raw connectivity as fixture readiness"
		);
		$this->assertStringContainsString(
			'pfb_test_http_fixture_event_received(',
			$source,
			"{$file}::{$method} must wait for its router's exact nonce event"
		);
		$this->assertStringContainsString('READY_TOKEN', $source);
		$this->assertStringContainsString('/__pfb_ready/', $source);
		$this->assertStringContainsString('proc_get_status(', $source);
		$this->assertStringContainsString('stderr=', $source);
	}

	public function testReachableForeignListenerCannotSatisfyNonceReadiness(): void
	{
		$port = $this->startForeignServer();
		$socket = @stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 0.05);
		$this->assertIsResource($socket, 'planted listener must be reachable by a raw connection');
		fclose($socket);

		$this->assertFalse(
			pfb_test_http_fixture_event_received($port, bin2hex(random_bytes(16))),
			'a reachable listener without the exact fixture nonce event must be rejected'
		);
	}

	private function startForeignServer(): int
	{
		$router = "{$this->workdir}/foreign-router.php";
		$this->assertNotFalse(file_put_contents($router, <<<'PHP'
			<?php
			if (($_SERVER['REQUEST_URI'] ?? '') === '/setup') {
				echo 'FOREIGN';
				return;
			}
			echo 'wrong-owner';
			PHP));
		$context = stream_context_create(['http' => ['timeout' => 0.05, 'ignore_errors' => TRUE]]);

		for ($try = 0; $try < 10; $try++) {
			$port = random_int(20000, 60000);
			$server = proc_open(
				['php', '-S', "127.0.0.1:{$port}", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', "{$this->workdir}/foreign.stderr", 'w']],
				$pipes,
				$this->workdir,
				['PATH' => (string) getenv('PATH')]
			);
			if (!is_resource($server)) {
				continue;
			}
			for ($poll = 0; $poll < 40; $poll++) {
				if (@file_get_contents("http://127.0.0.1:{$port}/setup", FALSE, $context) === 'FOREIGN') {
					$this->servers[] = $server;
					return $port;
				}
				usleep(50000);
			}
			proc_terminate($server);
			proc_close($server);
		}

		$this->fail('could not start planted foreign HTTP fixture');
	}
}
