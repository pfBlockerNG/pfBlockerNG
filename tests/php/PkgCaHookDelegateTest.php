<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_login_ca_command')]
#[CoversFunction('pfb_pkg_exec')]
#[CoversFunction('pfb_login_ca_apply')]
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

	public function testCommandRunsLoginCaVerbsAndPropagatesStatus(): void
	{
		$this->assertTrue(pfb_login_ca_command('login-ca-sync', $this->hook, $this->timeout));
		$this->assertTrue(pfb_login_ca_command('login-ca-revoke', $this->hook, $this->timeout));
		$this->assertSame("login-ca-sync\nlogin-ca-revoke\n", file_get_contents($this->log));
		putenv('PFB_HOOK_STATUS=7');
		$this->assertFalse(pfb_login_ca_command('login-ca-sync', $this->hook, $this->timeout));
	}

	public function testRepoConfRegenerateRunsTheHooksStartVerb(): void
	{
		// issue #2675: an upgrade must correct a conf written before the flip. The
		// package ships the hook, so POST-INSTALL runs it rather than waiting for the
		// next boot -- the fingerprint and the signed-repo conf land together.
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

	public function testCommandRefusesRetiredVerbsWithoutRunningTheHook(): void
	{
		$this->assertFalse(pfb_login_ca_command('ca-sync', $this->hook, $this->timeout));
		$this->assertFalse(pfb_login_ca_command('ca-revoke', $this->hook, $this->timeout));
		$this->assertFalse(pfb_login_ca_command('ca-state', $this->hook, $this->timeout));
		$this->assertFileDoesNotExist($this->log);
	}

	public function testCommandBoundsAHangingHook(): void
	{
		putenv('PFB_HOOK_SLEEP=1');
		$this->assertFalse(pfb_login_ca_command('login-ca-sync', $this->hook, $this->timeout));
	}

	public function testPkgExecRunsTheCommandDirectlyWithNoSyncGate(): void
	{
		$out = [];
		$ret = -1;
		pfb_pkg_exec('/usr/bin/printf ok', $out, $ret);
		$this->assertSame(['ok'], $out);
		$this->assertSame(0, $ret);
	}

	/*
	 * pfb_pkg_exec() no longer exports SSL_CA_CERT_PATH itself under any consent/CA-dir
	 * combination (issue #2623) -- that per-call putenv is superseded by install.sh
	 * restarting the webConfigurator once its login.conf carry lands, which reaches every
	 * later GUI-driven pkg call natively. A caller still passing a CA-dir hint (the
	 * retired 4th argument) proves the OLD contract would have exported here -- the new
	 * one silently ignores it. An ambient value the process environment already carried
	 * (what a restarted php-fpm inherits) must still pass through untouched, since
	 * pfb_pkg_exec is a plain exec() that never mutates the environment either way.
	 */
	public function testPkgExecNeverExportsCaPathItself(): void
	{
		$caDir = $this->root . '/ca';
		mkdir($caDir, 0o755, TRUE);
		// A CA hash directory (certctl rehash output) is populated with dangling
		// symlinks -- glob() still lists them, so a real directory always counts here.
		symlink('/nonexistent-target', $caDir . '/dead.0');

		$out = [];
		$ret = -1;

		// (a) consent ON + populated dir -- the retired contract exported here; the
		// current one must not.
		putenv('SSL_CA_CERT_PATH');
		PfbConfig::writeSystem('gen/pfb_pkg_ca_consent', PfbToggle::On);
		pfb_pkg_exec('printenv SSL_CA_CERT_PATH', $out, $ret, $caDir);
		$this->assertSame(1, $ret);
		$this->assertSame([], $out);

		// (b) an ambient value the process environment already carried passes through
		// untouched -- proving pfb_pkg_exec never unsets it either.
		putenv('SSL_CA_CERT_PATH=' . $caDir);
		pfb_pkg_exec('printenv SSL_CA_CERT_PATH', $out, $ret, $caDir);
		$this->assertSame(0, $ret);
		$this->assertSame([$caDir], $out);
	}

	public function testApplyMapsConsentTransitions(): void
	{
		$actions = [];
		$command = static function (string $action) use (&$actions): bool {
			$actions[] = $action;
			return TRUE;
		};
		$this->assertTrue(pfb_login_ca_apply('on', FALSE, $command));
		$this->assertTrue(pfb_login_ca_apply('', TRUE, $command));
		$this->assertTrue(pfb_login_ca_apply('', FALSE, $command));
		$this->assertSame(['login-ca-sync', 'login-ca-revoke'], $actions);
	}
}
