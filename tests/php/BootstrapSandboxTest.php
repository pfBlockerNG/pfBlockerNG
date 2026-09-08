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

	public function testOutsideRootDiagnosticNamesTrustedRoot(): void
	{
		$root = "{$this->tmp}/trusted";
		$this->assertTrue(mkdir($root, 0700));
		$error = NULL;

		try {
			pfb_test_preflight_path($root, "{$this->tmp}/outside", 'owned-path');
		} catch (RuntimeException $caught) {
			$error = $caught;
		}

		$this->assertInstanceOf(RuntimeException::class, $error);
		$this->assertStringEndsWith($root, $error->getMessage());
	}

	public function testDotDotDiagnosticNamesTrustedRoot(): void
	{
		$root = "{$this->tmp}/trusted";
		$this->assertTrue(mkdir($root, 0700));
		$error = NULL;

		try {
			pfb_test_preflight_path($root, "{$root}/../outside", 'owned-path');
		} catch (RuntimeException $caught) {
			$error = $caught;
		}

		$this->assertInstanceOf(RuntimeException::class, $error);
		$this->assertStringEndsWith($root, $error->getMessage());
	}

	public function testUnprivilegedHelperRejectsSymlinksWithoutChangingTheirTargets(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$external = "{$this->tmp}/external";
		$fixture = "{$this->tmp}/fixture";
		$this->assertTrue(mkdir($external, 0700));
		$this->assertTrue(mkdir($fixture, 0700));
		$sentinel = "{$external}/sentinel";
		$this->assertSame(4, file_put_contents($sentinel, 'safe'));
		$link = "{$fixture}/link";
		$this->assertTrue(symlink($external, $link));
		$owner = fileowner($sentinel);
		$error = NULL;

		try {
			pfb_test_as_unprivileged(static fn (): bool => TRUE, [$link]);
		} catch (RuntimeException $caught) {
			$error = $caught;
		}
		clearstatcache(TRUE, $sentinel);
		$ownerAfter = fileowner($sentinel);
		if ($ownerAfter !== $owner) {
			chown($sentinel, $owner);
		}

		$this->assertInstanceOf(RuntimeException::class, $error);
		$this->assertStringContainsString('symlink', $error->getMessage());
		$this->assertSame($owner, $ownerAfter,
			'rejecting an owned-path symlink must not chown its external target');
	}

	public function testUnprivilegedHelperRestoresPreparedOwnersAfterCallback(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$fixture = "{$this->tmp}/owned";
		$this->assertTrue(mkdir($fixture, 0700));
		$file = "{$fixture}/value";
		$this->assertSame(1, file_put_contents($file, 'x'));
		$owners = [$fixture => fileowner($fixture), $file => fileowner($file)];

		$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE, [$fixture]));
		clearstatcache();
		$ownersAfter = [$fixture => fileowner($fixture), $file => fileowner($file)];
		foreach ($owners as $path => $owner) {
			if ($ownersAfter[$path] !== $owner) {
				chown($path, $owner);
			}
		}

		$this->assertSame($owners, $ownersAfter,
			'every pre-existing fixture path must regain its original owner');
	}

	public function testUnprivilegedHelperRestoresOwnerWhenCallbackThrows(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$file = "{$this->tmp}/callback-owned";
		$this->assertSame(1, file_put_contents($file, 'x'));
		$owner = fileowner($file);
		$error = NULL;

		try {
			pfb_test_as_unprivileged(static function (): never {
				throw new LogicException('expected');
			}, [$file]);
		} catch (RuntimeException $caught) {
			$error = $caught;
		}
		clearstatcache(TRUE, $file);
		$ownerAfter = fileowner($file);
		if ($ownerAfter !== $owner) {
			chown($file, $owner);
		}

		$this->assertInstanceOf(RuntimeException::class, $error);
		$this->assertStringContainsString('LogicException: expected', $error->getMessage());
		$this->assertSame($owner, $ownerAfter,
			'a callback exception must not leak prepared ownership');
	}

	public function testUnprivilegedHelperRestoresOwnersAfterPreparationFailure(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$file = "{$this->tmp}/prepared";
		$this->assertSame(1, file_put_contents($file, 'x'));
		$owner = fileowner($file);
		$error = NULL;

		try {
			pfb_test_as_unprivileged(static fn (): bool => TRUE, [$file, "{$this->tmp}/missing"]);
		} catch (RuntimeException $caught) {
			$error = $caught;
		}
		clearstatcache(TRUE, $file);
		$ownerAfter = fileowner($file);
		if ($ownerAfter !== $owner) {
			chown($file, $owner);
		}

		$this->assertInstanceOf(RuntimeException::class, $error);
		$this->assertSame($owner, $ownerAfter,
			'a later preparation failure must roll back earlier ownership changes');
	}

	public function testUnprivilegedHelperMakesNestedTmpdirTraversableOnlyForItsChild(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$outer = "{$this->tmp}/private";
		$inner = "{$outer}/tmp";
		$this->assertTrue(mkdir($inner, 0777, TRUE));
		$this->assertTrue(chmod($outer, 0700));
		$marker = "{$inner}/marker";
		$this->assertSame(2, file_put_contents($marker, 'ok'));
		$script = 'require ' . var_export(self::ROOT . '/tests/php/bootstrap.php', TRUE) . ';'
			. '$marker=' . var_export($marker, TRUE) . ';'
			. '$tmp=' . var_export($inner, TRUE) . ';'
			. 'echo pfb_test_as_unprivileged(static fn (): string => (string) file_get_contents($marker), [$tmp]);';
		$command = escapeshellarg($GLOBALS['pfb']['timeout']) . ' 10 '
			. escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($script);
		$output = [];
		$status = 0;

		exec('TMPDIR=' . escapeshellarg($inner) . ' ' . $command . ' 2>&1', $output, $status);

		$this->assertSame(0, $status, implode("\n", $output));
		$this->assertSame(['ok'], $output);
		clearstatcache(TRUE, $outer);
		$this->assertSame(0700, fileperms($outer) & 0777,
			'ancestor search permission must be restored after the child exits');
	}

	public function testUnprivilegedHelperMakesOwnedPathParentTraversableAndRestoresMode(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$parent = "{$this->tmp}/restrictive-parent";
		$owned = "{$parent}/owned";
		$this->assertTrue(mkdir($owned, 0777, TRUE));
		$this->assertTrue(chmod($parent, 0700));
		$marker = "{$owned}/marker";
		$this->assertSame(2, file_put_contents($marker, 'ok'));
		$mode = fileperms($parent) & 07777;
		$result = NULL;
		$error = NULL;

		try {
			$result = pfb_test_as_unprivileged(static function () use ($marker): string {
				$value = @file_get_contents($marker);
				if ($value === FALSE) {
					throw new RuntimeException('owned-path parent is not traversable');
				}
				return $value;
			}, [$owned]);
		} catch (RuntimeException $caught) {
			$error = $caught;
		}
		clearstatcache(TRUE, $parent);
		$modeAfter = fileperms($parent) & 07777;
		if ($modeAfter !== $mode) {
			chmod($parent, $mode);
		}

		$this->assertSame($mode, $modeAfter,
			'an owned-path parent must regain its original mode');
		$this->assertNull($error, $error?->getMessage() ?? '');
		$this->assertSame('ok', $result);
	}

	public function testUnprivilegedHelperRejectsSymlinkedOwnedPathComponentsBeforeCallback(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$this->assertTrue(chmod($this->tmp, 0777));
		$external = "{$this->tmp}/external";
		$subdir = "{$external}/sub";
		$fixture = "{$this->tmp}/fixture";
		$this->assertTrue(mkdir($subdir, 0700, TRUE));
		$this->assertTrue(mkdir($fixture, 0777));
		$this->assertTrue(chmod($external, 0777));
		$sentinel = "{$subdir}/sentinel";
		$this->assertSame(4, file_put_contents($sentinel, 'safe'));
		$this->assertTrue(chmod($sentinel, 0600));
		$link = "{$fixture}/link";
		$this->assertTrue(symlink($external, $link));
		$owner = fileowner($sentinel);
		$mode = fileperms($sentinel) & 07777;
		$error = NULL;
		$result = NULL;

		try {
			$result = pfb_test_as_unprivileged(
				static fn (): int|false => file_put_contents("{$link}/sub/sentinel", 'changed'),
				["{$link}/sub"]
			);
		} catch (RuntimeException $caught) {
			$error = $caught;
		}
		clearstatcache(TRUE, $sentinel);
		$contentAfter = file_get_contents($sentinel);
		$ownerAfter = fileowner($sentinel);
		$modeAfter = fileperms($sentinel) & 07777;
		if ($contentAfter !== 'safe') {
			file_put_contents($sentinel, 'safe');
		}
		if ($ownerAfter !== $owner) {
			chown($sentinel, $owner);
		}
		if ($modeAfter !== $mode) {
			chmod($sentinel, $mode);
		}

		$this->assertSame('safe', $contentAfter,
			'an intermediate symlink must be rejected before the callback can change its target');
		$this->assertSame($owner, $ownerAfter,
			'an intermediate symlink must be rejected before its target is chowned');
		$this->assertSame($mode, $modeAfter,
			'an intermediate symlink must leave its target mode unchanged');
		$this->assertNull($result);
		$this->assertInstanceOf(RuntimeException::class, $error);
		$this->assertStringContainsString('symlink', $error->getMessage());
	}

	public function testUnprivilegedHelperRejectsSymlinkedNestedTmpdirBeforeOwnershipMutation(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->assertTrue(pfb_test_as_unprivileged(static fn (): bool => TRUE));
			return;
		}

		$external = "{$this->tmp}/external-tmp";
		$nested = "{$this->tmp}/nested";
		$link = "{$nested}/tmp";
		$this->assertTrue(mkdir($external, 0700));
		$this->assertTrue(mkdir($nested, 0755));
		$this->assertTrue(symlink($external, $link));
		$owner = fileowner($external);
		$mode = fileperms($external) & 07777;
		$bootstrap = var_export(self::ROOT . '/tests/php/bootstrap.php', TRUE);
		$script = 'require ' . $bootstrap . ';'
			. 'try { pfb_test_as_unprivileged(static fn (): bool => TRUE); }'
			. 'catch (RuntimeException $error) { echo $error->getMessage(); }';
		$command = 'TMPDIR=' . escapeshellarg($link) . ' '
			. escapeshellarg($GLOBALS['pfb']['timeout']) . ' 10 '
			. escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($script);
		$output = [];
		$status = 0;

		exec($command . ' 2>&1', $output, $status);
		clearstatcache(TRUE, $external);
		$ownerAfter = fileowner($external);
		$modeAfter = fileperms($external) & 07777;
		if ($ownerAfter !== $owner) {
			chown($external, $owner);
		}
		if ($modeAfter !== $mode) {
			chmod($external, $mode);
		}

		$this->assertSame($owner, $ownerAfter,
			'a symlinked TMPDIR must be rejected before its external target is chowned');
		$this->assertSame($mode, $modeAfter,
			'a symlinked TMPDIR must leave its external target mode unchanged');
		$this->assertSame(0, $status, implode("\n", $output));
		$this->assertStringContainsString('symlink', implode("\n", $output));
	}
}
