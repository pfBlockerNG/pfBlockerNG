<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Regression guard for issue #3018.
 *
 * Hand-rolled teardowns removed a fixture tree by naming the files they expected
 * to find — a glob, or a list of unlink() calls, followed by one rmdir(). Anything
 * else the test wrote (a dotfile, a nested directory) made that rmdir() fail, and
 * the whole tree survived every run until /tmp filled and unrelated tests began
 * failing with code-shaped errors.
 *
 * The suite already ships rmdir_recursive() (tests/php/pfsense_doubles.php), which
 * recurses with scandir() and so removes exactly what the hand-rolled versions miss.
 * This guard runs the previously-leaking files in a nested PHPUnit process with a
 * private TMPDIR and asserts that process left nothing behind.
 */
final class TempDirLeakGuardTest extends TestCase
{
	/**
	 * Test files whose teardown stranded its fixture directory before #3018.
	 * Measured leak per run on the parent commit: 22, 18, 7, 5, 4, 1, 1, 1.
	 *
	 * @var list<string>
	 */
	private const LEAKED_BEFORE_3018 = [
		'DueLedgerTest.php',
		'DnsblipMarkerFolderTest.php',
		'TickCronInstallTest.php',
		'TickCronTest.php',
		'QuietHoursApplyTest.php',
		'PfbSyncStatusLedgerTest.php',
		'IpRecomputeSnapshotTest.php',
		'CountryNetworksCountGuardTest.php',
	];

	public function testFixtureTeardownsLeaveNothingUnderTmpdir(): void
	{
		$root = dirname(__DIR__, 2);
		$tmp  = sys_get_temp_dir() . '/pfb_leak_guard_' . getmypid() . '_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($tmp, 0700, TRUE), "leak-guard TMPDIR creation failed: {$tmp}");

		$tests = [];
		foreach (self::LEAKED_BEFORE_3018 as $file) {
			$path = "{$root}/tests/php/{$file}";
			$this->assertFileExists($path, 'the guard names a test file that no longer exists');
			$tests[] = $path;
		}

		$command = array_merge([
			PHP_BINARY,
			"{$root}/vendor/bin/phpunit",
			'--configuration',
			"{$root}/phpunit.xml",
			'--do-not-cache-result',
		], $tests);

		try {
			// sys_get_temp_dir() reads TMPDIR, so the nested run allocates every
			// fixture below $tmp and its residue is exactly what survives teardown.
			$process = proc_open(
				$command,
				[1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
				$pipes,
				$root,
				array_merge(getenv(), ['TMPDIR' => $tmp])
			);
			$this->assertIsResource($process);
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$status = proc_close($process);

			$this->assertSame(0, $status, sprintf(
				"the nested fixture-teardown run FAILED; every name and message below belongs to "
				. "that nested run, not to this guard:\n%s\n%s",
				$stdout,
				$stderr
			));

			$residue = array_values(array_diff(scandir($tmp) ?: [], ['.', '..']));
			sort($residue);
			$this->assertSame([], $residue, sprintf(
				"fixture teardown stranded %d path(s) under TMPDIR (#3018). Use rmdir_recursive() "
				. "rather than a glob or a list of unlink() calls:\n  %s",
				count($residue),
				implode("\n  ", $residue)
			));
		} finally {
			rmdir_recursive($tmp);
		}
	}
}
