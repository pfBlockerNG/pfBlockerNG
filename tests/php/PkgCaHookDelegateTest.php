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
}
