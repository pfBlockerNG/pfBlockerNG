<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_pkg_exec')]
#[CoversFunction('pfb_repo_conf_regenerate')]
final class PkgCaHookDelegateTest extends TestCase
{
	private string $root;
	private string $hook;
	private string $log;
	private string $timeout;
	private bool $hadConfig;
	private mixed $originalConfig;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb-ca-hook-' . bin2hex(random_bytes(6));
		mkdir($this->root, 0o755, TRUE);
		$this->hook = $this->root . '/hook';
		$this->log = $this->root . '/calls.log';
		$timeout = trim((string) shell_exec('command -v timeout'));
		$this->timeout = escapeshellarg($timeout) . ' -s TERM -k 1 1';
		file_put_contents(
			$this->hook,
			"#!/bin/sh\nprintf '%s\\n' \"\$1\" >> " . escapeshellarg($this->log)
				. "\n[ \"\${PFB_HOOK_SLEEP:-0}\" = 1 ] && sleep 3\nexit \${PFB_HOOK_STATUS:-0}\n"
		);
		chmod($this->hook, 0o700);

		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		putenv('SSL_CA_CERT_PATH');
	}

	protected function tearDown(): void
	{
		putenv('PFB_HOOK_SLEEP');
		putenv('PFB_HOOK_STATUS');
		putenv('SSL_CA_CERT_PATH');
		@unlink($this->hook);
		@unlink($this->log);
		@rmdir($this->root);
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	public function testRepoConfRegenerateRunsTheHooksStartVerb(): void
	{
		// issue #2675: an upgrade must correct a conf written before the flip. The
		// hook ships from src/, so once the ports install it (follow-up) POST-INSTALL
		// runs it rather than waiting for the next boot -- the fingerprint and the
		// signed-repo conf land together. Until then this is a no-op on a box whose
		// package predates hook delivery, which is why an absent hook is not an error.
		$this->assertTrue(pfb_repo_conf_regenerate($this->hook, $this->timeout));
		$this->assertSame("onestart\n", file_get_contents($this->log));
	}

	public function testRepoConfRegenerateReportsAFailingHook(): void
	{
		putenv('PFB_HOOK_STATUS=3');
		$this->assertFalse(pfb_repo_conf_regenerate($this->hook, $this->timeout));
	}

	public function testRepoConfRegenerateSkipsAnAbsentHook(): void
	{
		// A box whose package predates hook delivery has no hook to run; that is not
		// an install failure.
		$this->assertFalse(pfb_repo_conf_regenerate($this->root . '/missing', $this->timeout));
		$this->assertFileDoesNotExist($this->log);
	}

	public function testRepoConfRegenerateBoundsAHangingHook(): void
	{
		putenv('PFB_HOOK_SLEEP=1');
		$this->assertFalse(pfb_repo_conf_regenerate($this->hook, $this->timeout));
	}

	public function testPkgExecRunsTheCommandDirectlyWithNoSyncGate(): void
	{
		$out = [];
		$ret = -1;
		pfb_pkg_exec('/usr/bin/printf ok', $out, $ret);
		$this->assertSame(['ok'], $out);
		$this->assertSame(0, $ret);
	}

	/**
	 * issue #2839 row 2: PFB_PKG_BIN was the file's one unguarded constant, so a harness
	 * could not point it away from the real appliance binary at all -- on a box that
	 * actually has pfBlockerNG installed, every pfb_pkg_*() query in a phpunit run would
	 * shell out to the real pkg(8).
	 */
	public function testPfbPkgBinIsOverriddenAwayFromTheShippedApplianceBinary(): void
	{
		$this->assertTrue(defined('PFB_PKG_BIN'));
		$this->assertNotSame('/usr/local/sbin/pkg', PFB_PKG_BIN,
			'the harness must override the shipped default with a harmless recorder, exactly '
			. 'like the daemon-start and mount-include boundaries');
		$this->assertTrue(is_executable(PFB_PKG_BIN),
			'the override must actually be runnable so pfb_pkg_*() consumers keep working');
	}

	/**
	 * Scenario: a real public pkg consumer must run through the overridden binary, never
	 * the real one, and its query-parsing behaviour must be unaffected by the seam.
	 *   Given PFB_PKG_BIN overridden (in an isolated process -- it is a constant) to a
	 *     double that answers the '%n' glob query with a real-shaped package name,
	 *   When pfb_pkg_installed_name() runs,
	 *   Then it returns that name (query parsing preserved) and the double -- never
	 *     /usr/local/sbin/pkg -- is what recorded receiving the query.
	 */
	public function testPkgInstalledNameParsesTheOverriddenBinarysOutputNotTheRealPkg(): void
	{
		$runner = "{$this->root}/pkg_bin_runner.php";
		$log = "{$this->root}/pkg-bin.log";
		$double = "{$this->root}/pkg-bin-double";
		file_put_contents($double, "#!/bin/sh\n"
			. 'printf \'%s\n\' "$*" >> ' . escapeshellarg($log) . "\n"
			. "printf 'pfSense-pkg-pfBlockerNG-devel\\n'\n"
			. "exit 0\n");
		chmod($double, 0o755);
		file_put_contents($runner, "<?php\n"
			. "define('PFB_PKG_BIN', " . var_export($double, TRUE) . ");\n"
			. 'require ' . var_export(__DIR__ . '/bootstrap.php', TRUE) . ";\n"
			. "echo pfb_pkg_installed_name(), \"\\n\";\n");

		$output = [];
		$status = 0;
		exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1', $output, $status);

		try {
			$this->assertSame(0, $status,
				'the isolated runner must exit cleanly: ' . implode("\n", $output));
			$this->assertSame('pfSense-pkg-pfBlockerNG-devel', trim((string) end($output)),
				'the consumer must still parse a real-shaped query answer correctly through the override');
			$this->assertStringContainsString(
				'query -g %n pfSense-pkg-pfBlockerNG*',
				(string) @file_get_contents($log),
				'the overridden double, never the real /usr/local/sbin/pkg, must receive the query'
			);
		} finally {
			@unlink($runner);
			@unlink($log);
			@unlink($double);
		}
	}
}
