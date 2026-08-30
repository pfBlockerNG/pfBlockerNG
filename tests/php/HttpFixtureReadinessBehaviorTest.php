<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\SkippedTest;
use PHPUnit\Framework\TestCase;

/** Issue #2904: occupied-port retries keep nonce, bound, and bind diagnostics observable. */
final class HttpFixtureReadinessBehaviorTest extends TestCase
{
	/** @var resource|null */
	private $foreignServer = NULL;
	private string $workdir = '';
	private static int $foreignPort = 0;
	/** @var list<string> */
	private static array $probeNonces = [];
	/** @var list<int> */
	private static array $pollPauses = [];
	/** @var list<string> */
	private static array $stderrPaths = [];
	/** @var list<resource> */
	private static array $fixtureProcesses = [];
	/** @var list<resource> */
	private static array $terminatedFixtureProcesses = [];

	protected function setUp(): void
	{
		require_once __DIR__ . '/support/HttpFixtureReadiness.php';
		$workdir = tempnam(sys_get_temp_dir(), 'pfbready2904b');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;
		self::$probeNonces = [];
		self::$pollPauses = [];
		self::$stderrPaths = [];
		self::$fixtureProcesses = [];
		self::$terminatedFixtureProcesses = [];
		self::$foreignPort = $this->startForeignServer();
	}

	protected function tearDown(): void
	{
		if (is_resource($this->foreignServer)) {
			proc_terminate($this->foreignServer);
			proc_close($this->foreignServer);
		}
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			$this->removeTree($this->workdir);
		}
	}

	/** @return array<string,array{class-string,file-string,string,string,int,bool}> */
	public static function fixtureSites(): array
	{
		return [
			'redirect credential servers' => [DownloadRedirectCredentialScopeTest::class, __DIR__ . '/DownloadRedirectCredentialScopeTest.php', 'startOneServer', 'setup', 10, FALSE],
			'extracted payload archive' => [DownloadExtractedPayloadSanityTest::class, __DIR__ . '/DownloadExtractedPayloadSanityTest.php', 'downloadArchive', 'extracted', 10, FALSE],
			'rejected validator origin' => [DownloadRejectValidatorClearTest::class, __DIR__ . '/DownloadRejectValidatorClearTest.php', 'startOrigin', 'setup', 20, FALSE],
			'retry body reset origin' => [DownloadRetryBodyResetTest::class, __DIR__ . '/DownloadRetryBodyResetTest.php', 'startFlakyServer', 'setup', 10, FALSE],
			'download size refusal origin' => [DownloadSizeRefusalTest::class, __DIR__ . '/DownloadSizeRefusalTest.php', 'startServer', 'setup', 10, FALSE],
			'GeoIP ZIP publication' => [GeoipZipPublicationTest::class, __DIR__ . '/GeoipZipPublicationTest.php', 'downloadGeoip', 'geoip', 10, TRUE],
			'TOP1M change-detect probe' => [Top1mDccDetectorTest::class, __DIR__ . '/Top1mDccDetectorTest.php', 'testChangeDetectUsesActualHttpProbeBodyAndMetadata', 'method', 10, FALSE],
			'TOP1M DCC download' => [Top1mDccDetectorTest::class, __DIR__ . '/Top1mDccDetectorTest.php', 'downloadTop1m', 'dcc-download', 10, FALSE],
			'TOP1M semantic validation' => [Top1mDownloadSemanticValidationTest::class, __DIR__ . '/Top1mDownloadSemanticValidationTest.php', 'downloadBody', 'semantic', 10, TRUE],
			'TOP1M provider matrix' => [Top1mSemanticMatrixTest::class, __DIR__ . '/Top1mSemanticMatrixTest.php', 'downloadSource', 'matrix', 10, TRUE],
		];
	}

	#[DataProvider('fixtureSites')]
	public function testOccupiedPortExhaustionPreservesNonceBoundAndBindDiagnostics(
		string $class,
		string $file,
		string $method,
		string $entry,
		int $tries,
		bool $expectedSkip
	): void {
		$instrumentedClass = $this->loadInstrumentedFixture($class, $file);
		$reflection = new ReflectionClass($instrumentedClass);
		$testName = NULL;
		foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $candidate) {
			if (str_starts_with($candidate->getName(), 'test')) {
				$testName = $candidate->getName();
				break;
			}
		}
		$this->assertIsString($testName);
		$suite = $reflection->newInstance($testName);
		$failure = NULL;
		$setUp = $reflection->getMethod('setUp');
		$tearDown = $reflection->getMethod('tearDown');
		$savedGlobals = $this->saveFixtureGlobals();

		try {
			try {
				if ($entry === 'setup') {
					$setUp->invoke($suite);
				} else {
					$setUp->invoke($suite);
					$this->invokeStartupEntry($reflection, $suite, $method, $entry);
				}
			} catch (Throwable $error) {
				$failure = $error;
			}
		} finally {
			try {
				$tearDown->invoke($suite);
			} catch (Throwable $tearDownError) {
				$failure ??= $tearDownError;
			}
			$this->restoreFixtureGlobals($savedGlobals);
		}

		$this->assertNotNull($failure, "{$file}::{$method} adopted the planted foreign listener");
		$this->assertNotSame(
			[],
			self::$probeNonces,
			"{$file}::{$method} adopted the planted foreign listener without an owned nonce event"
		);
		$this->assertSame(
			$expectedSkip,
			$failure instanceof SkippedTest,
			"{$file}::{$method} changed its exhausted-startup verdict"
		);
		$message = $failure->getMessage();
		$this->assertStringContainsString('port ' . self::$foreignPort . ':', $message);
		$this->assertStringContainsString('process[running=', $message);
		$this->assertStringContainsString('exit=', $message);
		$this->assertStringContainsString('close=', $message);
		$this->assertStringContainsString('stderr=', $message);
		$this->assertStringContainsString('Failed to listen', $message);
		$this->assertCount($tries, self::$stderrPaths, "{$file}::{$method} changed the stderr file count");
		$this->assertCount($tries, array_unique(self::$stderrPaths), "{$file}::{$method} must use a fresh stderr file per attempt");
		$this->assertCount($tries, self::$fixtureProcesses, "{$file}::{$method} changed the child-process count");
		foreach (self::$fixtureProcesses as $process) {
			$this->assertFalse(is_resource($process), "{$file}::{$method} left a failed fixture child open");
		}
		$this->assertSame(
			[],
			self::$terminatedFixtureProcesses,
			"{$file}::{$method} tried to terminate an already-exited fixture child"
		);

		$expectedPolls = $tries * 40;
		$this->assertCount($expectedPolls, self::$probeNonces, "{$file}::{$method} changed the 40-poll bound");
		$this->assertCount($expectedPolls, self::$pollPauses, "{$file}::{$method} changed the poll pause count");
		foreach (self::$pollPauses as $pause) {
			$this->assertSame(50000, $pause, "{$file}::{$method} changed the poll pause");
		}

		$attemptNonces = [];
		for ($attempt = 0; $attempt < $tries; $attempt++) {
			$pollNonces = array_slice(self::$probeNonces, $attempt * 40, 40);
			$this->assertCount(1, array_unique($pollNonces), "{$file}::{$method} changed nonce inside one attempt");
			$attemptNonces[] = $pollNonces[0];
		}
		$this->assertCount($tries, array_unique($attemptNonces), "{$file}::{$method} must generate a fresh nonce per attempt");
	}

	public static function candidatePort(int $minimum, int $maximum): int
	{
		if (self::$foreignPort < $minimum || self::$foreignPort > $maximum) {
			throw new RuntimeException('planted foreign port is outside the fixture candidate range');
		}
		return self::$foreignPort;
	}

	public static function observeProbe(int $port, string $nonce): bool
	{
		if (self::$probeNonces === [] || self::$probeNonces[array_key_last(self::$probeNonces)] !== $nonce) {
			usleep(100000);
		}
		self::$probeNonces[] = $nonce;
		return pfb_test_http_fixture_event_received($port, $nonce);
	}

	public static function recordPollPause(int $microseconds): void
	{
		self::$pollPauses[] = $microseconds;
	}

	/** @return resource|false */
	public static function openFixtureProcess(
		array $command,
		array $descriptorSpec,
		&$pipes,
		?string $cwd,
		?array $environment,
		?array $options = NULL
	) {
		$stderr = $descriptorSpec[2][1] ?? NULL;
		if (is_string($stderr)) {
			self::$stderrPaths[] = $stderr;
		}
		$process = proc_open($command, $descriptorSpec, $pipes, $cwd, $environment, $options);
		if (is_resource($process)) {
			self::$fixtureProcesses[] = $process;
		}
		return $process;
	}

	/** @param resource $process */
	public static function terminateFixtureProcess($process, int $signal = 15): bool
	{
		self::$terminatedFixtureProcesses[] = $process;
		return proc_terminate($process, $signal);
	}

	private function loadInstrumentedFixture(string $class, string $file): string
	{
		$source = file_get_contents($file);
		$this->assertIsString($source);
		$namespace = 'PfbIssue2904\\Site' . bin2hex(random_bytes(6));
		$instrumentation = <<<PHP

namespace {$namespace};

function random_int(int \$minimum, int \$maximum): int
{
	return \\HttpFixtureReadinessBehaviorTest::candidatePort(\$minimum, \$maximum);
}

function usleep(int \$microseconds): void
{
	\\HttpFixtureReadinessBehaviorTest::recordPollPause(\$microseconds);
}

function pfb_test_http_fixture_event_received(int \$port, string \$nonce): bool
{
	return \\HttpFixtureReadinessBehaviorTest::observeProbe(\$port, \$nonce);
}

function proc_open(
	array \$command,
	array \$descriptorSpec,
	&\$pipes,
	?string \$cwd,
	?array \$environment,
	?array \$options = null
) {
	return \\HttpFixtureReadinessBehaviorTest::openFixtureProcess(
		\$command,
		\$descriptorSpec,
		\$pipes,
		\$cwd,
		\$environment,
		\$options
	);
}

/** @param resource \$process */
function proc_terminate(\$process, int \$signal = 15): bool
{
	return \\HttpFixtureReadinessBehaviorTest::terminateFixtureProcess(\$process, \$signal);
}

foreach (['PfbConfig', 'PfbDownloadRequest', 'PfbDownloadResult', 'PfbToggle'] as \$global) {
	if (class_exists(\$global) || enum_exists(\$global)) {
		class_alias(\$global, __NAMESPACE__ . '\\\\' . \$global);
	}
}

\\spl_autoload_register(static function (string \$name): void {
	\$prefix = __NAMESPACE__ . '\\\\';
	if (!str_starts_with(\$name, \$prefix)) {
		return;
	}
	\$global = substr(\$name, strlen(\$prefix));
	if (class_exists(\$global) || interface_exists(\$global) || enum_exists(\$global)) {
		class_alias(\$global, \$name);
	}
});
PHP;
		$source = str_replace("declare(strict_types=1);\n", "declare(strict_types=1);{$instrumentation}\n", $source);
		$source = preg_replace('/^require_once __DIR__ .*;\R/m', '', $source);
		$this->assertIsString($source);
		$mirror = "{$this->workdir}/mirror";
		$this->assertTrue(is_dir("{$mirror}/tests/php") || mkdir("{$mirror}/tests/php", 0700, TRUE));
		if ($class === Top1mDccDetectorTest::class) {
			$sourceDir = "{$mirror}/src/usr/local/www/pfblockerng";
			$this->assertTrue(is_dir($sourceDir) || mkdir($sourceDir, 0700, TRUE));
			$this->assertTrue(copy(
				dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php',
				"{$sourceDir}/pfblockerng.php"
			));
		}
		$path = "{$mirror}/tests/php/fixture-" . bin2hex(random_bytes(6)) . '.php';
		$this->assertNotFalse(file_put_contents($path, $source));
		require $path;

		return "{$namespace}\\{$class}";
	}

	private function invokeStartupEntry(
		ReflectionClass $reflection,
		object $suite,
		string $method,
		string $entry
	): void {
		$startup = $reflection->getMethod($method);
		$dirProperty = $reflection->hasProperty('dir') ? 'dir' : 'workdir';
		$dir = (string) $reflection->getProperty($dirProperty)->getValue($suite);

		switch ($entry) {
			case 'extracted':
				$startup->invoke($suite, 'gz', "192.0.2.1\n", "{$dir}/candidate.gz", PfbToggle::On);
				break;
			case 'geoip':
				$source = "{$dir}/source.zip";
				$this->assertNotFalse(file_put_contents($source, 'fixture'));
				$startup->invoke($suite, $source, "{$dir}/candidate.zip", "{$dir}/published");
				break;
			case 'method':
				$startup->invoke($suite);
				break;
			case 'dcc-download':
				$source = "{$dir}/source.csv";
				$this->assertNotFalse(file_put_contents($source, "1,example.test\n"));
				$startup->invoke($suite, $source, "{$dir}/candidate.csv", "{$dir}/active.csv");
				break;
			case 'semantic':
				$startup->invoke($suite, "1,example.test\n", "{$dir}/candidate.csv", "{$dir}/active.csv");
				break;
			case 'matrix':
				$source = "{$dir}/source.csv";
				$this->assertNotFalse(file_put_contents($source, "1,example.test\n"));
				$startup->invoke($suite, $source, "{$dir}/candidate.csv", "{$dir}/active.csv");
				break;
			default:
				throw new InvalidArgumentException("unknown fixture entry {$entry}");
		}
	}

	/** @return array<string,array{had:bool,value:mixed}> */
	private function saveFixtureGlobals(): array
	{
		$saved = [];
		foreach (['config', 'pfb', 'pfb_test_resolve_map', 'pfb_test_configured_ips'] as $name) {
			$saved[$name] = [
				'had' => array_key_exists($name, $GLOBALS),
				'value' => $GLOBALS[$name] ?? NULL,
			];
		}
		return $saved;
	}

	/** @param array<string,array{had:bool,value:mixed}> $saved */
	private function restoreFixtureGlobals(array $saved): void
	{
		foreach ($saved as $name => $state) {
			if ($state['had']) {
				$GLOBALS[$name] = $state['value'];
			} else {
				unset($GLOBALS[$name]);
			}
		}
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
			$path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
			echo basename(is_string($path) ? $path : '');
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
					$this->foreignServer = $server;
					return $port;
				}
				usleep(50000);
			}
			proc_terminate($server);
			proc_close($server);
		}

		$this->fail('could not start planted foreign HTTP fixture');
	}

	private function removeTree(string $path): void
	{
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($iterator as $item) {
			$item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
		}
		rmdir($path);
	}
}
