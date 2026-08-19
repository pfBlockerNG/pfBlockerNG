<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_pkgconf_ca_command')]
#[CoversFunction('pfb_pkg_exec')]
#[CoversFunction('pfb_pkg_ca_is_plus')]
#[CoversFunction('pfb_pkgconf_ca_apply')]
final class PkgCaHookDelegateTest extends TestCase
{
	private string $root;
	private string $hook;
	private string $log;
	private string $timeout;

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
	}

	protected function tearDown(): void
	{
		putenv('PFB_HOOK_SLEEP');
		putenv('PFB_HOOK_STATUS');
		@unlink($this->hook);
		@unlink($this->log);
		@rmdir($this->root);
	}

	public function testCommandValidatesActionsAndPropagatesStatus(): void
	{
		$this->assertTrue(pfb_pkgconf_ca_command('ca-sync', $this->hook, $this->timeout));
		$this->assertTrue(pfb_pkgconf_ca_command('ca-revoke', $this->hook, $this->timeout));
		$this->assertFalse(pfb_pkgconf_ca_command('ca-state', $this->hook, $this->timeout));
		$this->assertSame("ca-sync\nca-revoke\n", file_get_contents($this->log));
		putenv('PFB_HOOK_STATUS=7');
		$this->assertFalse(pfb_pkgconf_ca_command('ca-sync', $this->hook, $this->timeout));
	}

	public function testCommandBoundsAHangingHook(): void
	{
		putenv('PFB_HOOK_SLEEP=1');
		$this->assertFalse(pfb_pkgconf_ca_command('ca-sync', $this->hook, $this->timeout));
	}

	public function testPkgExecSyncsAndFailsClosed(): void
	{
		$actions = [];
		$out = [];
		$ret = -1;
		pfb_pkg_exec('/usr/bin/printf ok', $out, $ret, static function (string $action) use (&$actions): bool {
			$actions[] = $action;
			return TRUE;
		});
		$this->assertSame(['ca-sync'], $actions);
		$this->assertSame(['ok'], $out);
		$this->assertSame(0, $ret);
		$forbidden = $this->root . '/forbidden-command-ran';
		pfb_pkg_exec('/usr/bin/touch ' . escapeshellarg($forbidden), $out, $ret, static fn (string $action): bool => FALSE);
		$this->assertSame([], $out);
		$this->assertSame(-1, $ret);
		$this->assertFileDoesNotExist($forbidden);
	}

	public function testApplyMapsConsentTransitions(): void
	{
		$actions = [];
		$command = static function (string $action) use (&$actions): bool {
			$actions[] = $action;
			return TRUE;
		};
		$this->assertTrue(pfb_pkgconf_ca_apply('on', FALSE, $command));
		$this->assertTrue(pfb_pkgconf_ca_apply('', TRUE, $command));
		$this->assertTrue(pfb_pkgconf_ca_apply('', FALSE, $command));
		$this->assertSame(['ca-sync', 'ca-revoke'], $actions);
	}

	public function testPlusDetectionAndSourceBoundary(): void
	{
		$product = $this->root . '/product_label';
		file_put_contents($product, "pfSense Plus\n");
		$this->assertTrue(pfb_pkg_ca_is_plus($product));
		file_put_contents($product, "pfSense Community Edition\n");
		$this->assertFalse(pfb_pkg_ca_is_plus($product));
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertSame(7, substr_count($source, 'pfb_pkg_exec('));
		foreach (['pfb_pkg_ca_env_prefix', 'pfb_pkgconf_ca_sync', 'pfb_pkgconf_write_atomic', 'pfb_pkgconf_ca_tick'] as $removed) {
			$this->assertStringNotContainsString("function {$removed}", $source);
		}
	}
}
