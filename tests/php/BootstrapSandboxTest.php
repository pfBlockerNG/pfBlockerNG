<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Process-level contracts for the PHPUnit bootstrap sandbox (issue #2836). */
final class BootstrapSandboxTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const SALVAGE_CAP_NS = 10_000_000_000;
	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_bootstrap_process_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmp);
	}

	/**
	 * Scenario: every bootstrap process owns fresh scratch state.
	 * Given a stale PID-only sandbox and two child bootstrap invocations,
	 * When both children exit,
	 * Then neither adopts the stale state, their roots differ, and both roots are removed.
	 */
	public function testEachBootstrapInvocationOwnsAFreshDisposableSandbox(): void
	{
		$first = $this->runBootstrap($this->tmp, TRUE);
		$this->assertSame(0, $first['status'], $first['stderr']);
		$firstRecord = json_decode($first['stdout'], TRUE, flags: JSON_THROW_ON_ERROR);
		$this->assertIsArray($firstRecord);

		$this->assertNotSame($first['legacy_root'], $firstRecord['root'],
			'a bootstrap must not adopt a stale PID-only sandbox');
		$this->assertSame('legacy sentinel', file_get_contents($first['legacy_root'] . '/sentinel'),
			'the bootstrap must not write into or clean a sandbox it does not own');
		$this->assertSandboxPaths($firstRecord);
		$this->assertDirectoryDoesNotExist($firstRecord['root'],
			'the first child must remove its whole sandbox at shutdown');

		$second = $this->runBootstrap($this->tmp);
		$this->assertSame(0, $second['status'], $second['stderr']);
		$secondRecord = json_decode($second['stdout'], TRUE, flags: JSON_THROW_ON_ERROR);
		$this->assertIsArray($secondRecord);
		$this->assertSandboxPaths($secondRecord);
		$this->assertNotSame($firstRecord['root'], $secondRecord['root'],
			'two bootstrap invocations must never share a sandbox root');
		$this->assertDirectoryDoesNotExist($secondRecord['root'],
			'the second child must remove its whole sandbox at shutdown');
	}

	public function testSandboxCreationFailureIsLoud(): void
	{
		$notDirectory = $this->tmp . '/not-a-directory';
		$this->assertSame(1, file_put_contents($notDirectory, 'x'));

		$result = $this->runBootstrap($notDirectory);

		$this->assertStringContainsString('mkdir()', $result['stderr'],
			'sandbox creation warnings must not be @-suppressed');
		$this->assertNotSame(0, $result['status'],
			'sandbox creation failure must stop the child before tests run');
	}

	public function testShutdownCleanupPreservesChildExitStatus(): void
	{
		$result = $this->runBootstrap($this->tmp, FALSE, 23);
		$record = json_decode($result['stdout'], TRUE, flags: JSON_THROW_ON_ERROR);
		$this->assertIsArray($record);

		$this->assertSame(23, $result['status'], $result['stderr']);
		$this->assertDirectoryDoesNotExist($record['root'],
			'shutdown cleanup must remove the sandbox without replacing the child status');
	}

	public function testForkedChildCannotRemoveParentSandbox(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('pcntl_waitpid')) {
			$this->markTestSkipped('pcntl is required to prove fork-inherited shutdown ownership.');
		}
		$result = $this->runBootstrap($this->tmp, FALSE, 0, TRUE);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$record = json_decode($result['stdout'], TRUE, flags: JSON_THROW_ON_ERROR);
		$this->assertIsArray($record);
		$this->assertDirectoryDoesNotExist($record['root'],
			'the owner process must remove its sandbox only when the owner exits');
	}

	/** @param array{root:string,db:string,log:string,tmp:string} $record */
	private function assertSandboxPaths(array $record): void
	{
		$this->assertStringStartsWith($this->tmp . '/pfb_php_unit_', $record['root']);
		$this->assertSame($record['root'] . '/db', $record['db']);
		$this->assertSame($record['root'] . '/log', $record['log']);
		$this->assertSame($record['root'] . '/tmp', $record['tmp']);
	}

	/**
	 * @return array{status:int,stdout:string,stderr:string,pid:int,legacy_root:string}
	 */
	private function runBootstrap(
	    string $tmpdir, bool $plantLegacy = FALSE, int $exitCode = 0, bool $forkChild = FALSE
	): array {
		$bootstrap = var_export(self::ROOT . '/tests/php/bootstrap.php', TRUE);
		$forkScript = '';
		if ($forkChild) {
			$forkScript = <<<'PHP'
$forkPid = pcntl_fork();
if ($forkPid === -1) {
	fwrite(STDERR, "pcntl_fork failed\n");
	exit(91);
}
if ($forkPid === 0) {
	exit(0);
}
pcntl_waitpid($forkPid, $forkStatus);
if (!is_dir($pfb_test_tmp)) {
	fwrite(STDERR, "forked child removed owner sandbox\n");
	exit(92);
}
PHP;
		}
		$script = <<<PHP
stream_get_contents(STDIN);
require {$bootstrap};
{$forkScript}
echo json_encode([
	'root' => \$pfb_test_tmp,
	'db' => \$GLOBALS['g']['vardb_path'],
	'log' => \$GLOBALS['g']['varlog_path'],
	'tmp' => \$GLOBALS['g']['tmp_path'],
], JSON_THROW_ON_ERROR);
exit({$exitCode});
PHP;
		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$environment = getenv();
		$this->assertIsArray($environment);
		$environment['TMPDIR'] = $tmpdir;
		$process = proc_open(
			[PHP_BINARY, '-d', 'display_errors=stderr', '-r', $script],
			$descriptors,
			$pipes,
			self::ROOT,
			$environment
		);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);

		$processStatus = proc_get_status($process);
		$pid = (int) $processStatus['pid'];
		$legacyRoot = "{$tmpdir}/pfb_php_unit_{$pid}";
		if ($plantLegacy) {
			$this->assertTrue(mkdir($legacyRoot, 0700, TRUE));
			$this->assertSame(15, file_put_contents($legacyRoot . '/sentinel', 'legacy sentinel'));
		}
		fclose($pipes[0]);

		$stdout = '';
		$stderr = '';
		$timedOut = FALSE;
		$closeStatus = -1;
		try {
			$deadline = hrtime(TRUE) + self::SALVAGE_CAP_NS;
			do {
				$read = [$pipes[1], $pipes[2]];
				$write = $except = NULL;
				@stream_select($read, $write, $except, 0, 100000);
				$stdout .= stream_get_contents($pipes[1]);
				$stderr .= stream_get_contents($pipes[2]);
				$processStatus = proc_get_status($process);
				if (!$processStatus['running']) {
					break;
				}
			} while (hrtime(TRUE) < $deadline);
			$timedOut = $processStatus['running'];
			if ($timedOut) {
				proc_terminate($process);
				usleep(50000);
				if (proc_get_status($process)['running']) {
					proc_terminate($process, 9);
				}
			}
		} finally {
			$stdout .= stream_get_contents($pipes[1]);
			$stderr .= stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$closeStatus = proc_close($process);
		}
		if ($timedOut) {
			$this->fail('STUCK/ENVIRONMENT: bootstrap child exceeded the 10-second salvage cap');
		}
		$status = $processStatus['exitcode'] !== -1 ? $processStatus['exitcode'] : $closeStatus;
		return [
			'status' => $status,
			'stdout' => $stdout,
			'stderr' => $stderr,
			'pid' => $pid,
			'legacy_root' => $legacyRoot,
		];
	}
}
