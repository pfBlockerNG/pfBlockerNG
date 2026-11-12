<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3900 -- the "is it already mounted?" checks run `/sbin/mount | grep <path> 2>&1`, where the
 * trailing `2>&1` binds to grep only. On a host without /sbin/mount (Linux CI) mount's own error went
 * straight to the process's stderr: 778 lines per PHPUnit job. A failed mount must still read as
 * "not mounted" (empty grep output), but nothing may reach stderr.
 */
#[CoversFunction('pfb_unbound_python_unmount')]
final class MountCheckStderrTest extends TestCase
{
	private const SALVAGE_SECONDS = 10;

	private string $dir = '';

	protected function setUp(): void
	{
		$dir = tempnam(sys_get_temp_dir(), 'pfbmount');
		$this->assertNotFalse($dir);
		$this->assertTrue(unlink($dir) && mkdir($dir, 0700));
		$this->dir = $dir;
	}

	protected function tearDown(): void
	{
		if ($this->dir !== '' && is_dir($this->dir)) {
			rmdir_recursive($this->dir);
		}
		$this->dir = '';
	}

	/**
	 * Given a fresh process whose grep reports nothing mounted,
	 * When the python mounts are checked for removal,
	 * Then nothing is unmounted and the process writes nothing to stderr.
	 */
	public function testMountCheckWritesNothingToStderr(): void
	{
		$grep = "{$this->dir}/grep_double";
		file_put_contents($grep, "#!/bin/sh\ncat >/dev/null\nexit 1\n");
		chmod($grep, 0755);
		$runner = "{$this->dir}/runner.php";
		file_put_contents($runner, "<?php\n"
			. 'require ' . var_export(__DIR__ . '/bootstrap.php', TRUE) . ";\n"
			. "\$GLOBALS['pfb']['grep'] = " . var_export($grep, TRUE) . ";\n"
			. "pfb_unbound_python_unmount();\n");

		$timeout = (string) ($GLOBALS['pfb']['timeout'] ?? '/usr/bin/timeout');
		$process = proc_open([$timeout, '-s', 'TERM', '-k', '2', (string) self::SALVAGE_SECONDS, PHP_BINARY, $runner],
			[0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$stdout = (string) stream_get_contents($pipes[1]);
		$stderr = (string) stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);

		$this->assertSame(0, $status, "the isolated runner must exit cleanly; stdout: {$stdout}; stderr: {$stderr}");
		$this->assertStringNotContainsString('Unmounting:', $stdout, 'nothing mounted: nothing to unmount');
		$this->assertSame('', $stderr, 'the mount check must not leak to stderr');
	}

	/**
	 * Given every `/sbin/mount | grep` check in the package sources (two of the four cannot be driven
	 *   off-appliance: the uninstall loop and the retired include's top-level hook),
	 * Then each discards mount's stderr before the pipe.
	 */
	public function testEveryMountPipelineDiscardsMountStderr(): void
	{
		$pkg = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng';
		$sites = 0;
		foreach (['pfblockerng.inc', 'pfb_unbound_include.inc'] as $file) {
			$src = (string) file_get_contents("{$pkg}/{$file}");
			$sites += preg_match_all('#/sbin/mount(?: 2>/dev/null)? \|#', $src);
			$this->assertSame(0, preg_match_all('#/sbin/mount \|#', $src), "{$file}: a `/sbin/mount |` check leaks mount's stderr");
		}
		$this->assertSame(4, $sites, 'the four mount checks of issue #3900');
	}
}
