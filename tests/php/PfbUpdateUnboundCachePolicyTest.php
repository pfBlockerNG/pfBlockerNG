<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_update_unbound() owns the opt-in bulk DNSBL cache policy. A successful data
 * swap retains the cache by default; when enabled, the full flush happens only after
 * the applied-generation handshake. Restart fallback never issues a post-swap flush.
 */
#[CoversFunction('pfb_update_unbound')]
final class PfbUpdateUnboundCachePolicyTest extends TestCase
{
	private string $dir;
	private array $savedPfb = [];
	private array $savedG = [];
	private array $savedConfig = [];
	private bool $hadConfig = FALSE;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_update_unbound_cache_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		foreach ([
			'dnsbldir', 'dbdir', 'dnsbl_file', 'dnsdir', 'dnsbl_cache', 'unbound_py_count',
			'unbound_py_sources', 'unbound_py_rawdir', 'unbound_py_data', 'unbound_py_zone',
			'unbound_py_reject_stats', 'chroot_cmd', 'dnsbl_python_unmount', 'dnsbl_res_cache',
			'dnsbl_cache_flush',
			'enable', 'dnsbl', 'save', 'dnsbl_tld_wildcard', 'domain_update', 'reuse_dnsbl',
			'dnsbl_unlock', 'keep', 'install', 'errlog', 'log',
		] as $key) {
			$this->savedPfb[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$key] : FALSE;
		}
		$this->savedG['varrun_path'] = array_key_exists('varrun_path', $GLOBALS['g'] ?? [])
			? $GLOBALS['g']['varrun_path'] : FALSE;
		$this->hadConfig = array_key_exists('unbound', $GLOBALS['config'] ?? []);
		$this->savedConfig = $GLOBALS['config']['unbound'] ?? [];

		$dnsdir = "{$this->dir}/dnsdir";
		mkdir($dnsdir);
		$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'], [
			'dnsbldir' => $this->dir,
			'dbdir' => $this->dir,
			'dnsbl_file' => "{$this->dir}/pfb_dnsbl",
			'dnsdir' => $dnsdir,
			'dnsbl_cache' => "{$this->dir}/pfb_py_cache.sqlite",
			'unbound_py_count' => "{$this->dir}/pfb_py_count",
			'unbound_py_sources' => "{$this->dir}/pfb_py_sources.json",
			'unbound_py_rawdir' => "{$this->dir}/pfb_py_raw",
			'unbound_py_data' => "{$this->dir}/pfb_py_data",
			'unbound_py_zone' => "{$this->dir}/pfb_py_zone",
			'unbound_py_reject_stats' => "{$this->dir}/pfb_py_reject_stats.json",
			'chroot_cmd' => "{$this->dir}/unbound-control-recorder",
			'dnsbl_python_unmount' => FALSE,
			'dnsbl_res_cache' => PfbToggle::On,
			'dnsbl_cache_flush' => PfbToggle::Off,
			'enable' => PfbToggle::On,
			'dnsbl' => PfbToggle::On,
			'save' => TRUE,
			'dnsbl_tld_wildcard' => FALSE,
			'domain_update' => FALSE,
			'reuse_dnsbl' => '',
			'dnsbl_unlock' => "{$this->dir}/dnsbl_unlock",
			'keep' => PfbToggle::On,
			'install' => FALSE,
			'errlog' => "{$this->dir}/error.log",
			'log' => "{$this->dir}/pfblockerng.log",
		]);
		$GLOBALS['g']['varrun_path'] = $this->dir;
		$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];
		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "1\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"feeds":[]}');
		file_put_contents($GLOBALS['pfb']['unbound_py_reject_stats'], '[]');
		file_put_contents("{$this->dir}/unbound.conf", "python-script: pfb_unbound.py\n");
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "1\n");
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $key => $value) {
			if ($value === FALSE) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $value;
			}
		}
		foreach ($this->savedG as $key => $value) {
			if ($value === FALSE) {
				unset($GLOBALS['g'][$key]);
			} else {
				$GLOBALS['g'][$key] = $value;
			}
		}
		if ($this->hadConfig) {
			$GLOBALS['config']['unbound'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']['unbound']);
		}
		unset(
			$GLOBALS['pfb_test_process_running'],
			$GLOBALS['pfb_test_sysctl'],
			$GLOBALS['pfb_test_unbound_py_sentinel_published']
		);
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir("{$this->dir}/dnsdir");
		@rmdir($this->dir);
	}

	private function installRecorder(string $log): void
	{
		$marker = escapeshellarg("{$this->dir}/pfb_py_reload.applied");
		$runtime_log = escapeshellarg($GLOBALS['pfb']['log']);
		file_put_contents(
			$GLOBALS['pfb']['chroot_cmd'],
			"#!/bin/sh\n"
			. "if grep -q 'zero-downtime swap.*completed' {$runtime_log}; then completed=1; else completed=0; fi\n"
			. "printf '%s|applied=%s|completed=%s\\n' \"\$*\" \"\$(cat {$marker})\" \"\$completed\" >> "
			. escapeshellarg($log) . "\n"
		);
		chmod($GLOBALS['pfb']['chroot_cmd'], 0755);
	}

	private function installAppliedMarkerWatcher(): void
	{
		$sentinel = "{$this->dir}/pfb_py_reload";
		$applied = "{$this->dir}/pfb_py_reload.applied";
		file_put_contents($sentinel, "1\n");
		file_put_contents($applied, "1\n");
		$GLOBALS['pfb_test_unbound_py_sentinel_published'] = static function (string $path, int $generation) use ($sentinel, $applied): void {
			if ($path === $sentinel) {
				file_put_contents($applied, "{$generation}\n");
			}
		};
	}

	private function runUpdateIgnoringMacOsTempnamNotice(): void
	{
		set_error_handler(static function (int $severity, string $message): bool {
			return $severity === E_NOTICE && str_contains($message, 'tempnam(): file created in the system');
		});
		try {
			pfb_update_unbound('enabled', FALSE, FALSE);
		} finally {
			restore_error_handler();
		}
	}

	public function testDefaultDisabledBulkSwapRetainsResolverCache(): void
	{
		$log = "{$this->dir}/control.log";
		$this->installRecorder($log);
		$this->installAppliedMarkerWatcher();

		$this->runUpdateIgnoringMacOsTempnamNotice();

		$this->assertSame("2\n", file_get_contents("{$this->dir}/pfb_py_reload.applied"),
			'default-disabled assertion must follow a fresh generation application');
		$runtime_log = file_get_contents($GLOBALS['pfb']['log']);
		$this->assertNotFalse($runtime_log, 'bulk update must write its successful reload path');
		$this->assertStringContainsString('[ zero-downtime swap ] completed', $runtime_log,
			'default-disabled assertion must follow a completed data swap');
		$lines = file_exists($log) ? (file($log, FILE_IGNORE_NEW_LINES) ?: []) : [];
		$this->assertSame([], $lines,
			'default-disabled bulk cache clearing must retain Unbound cache after a successful swap');
	}

	public function testEnabledBulkSwapFlushesOnlyAfterAppliedGeneration(): void
	{
		$log = "{$this->dir}/control.log";
		$this->installRecorder($log);
		$this->installAppliedMarkerWatcher();
		$GLOBALS['pfb']['dnsbl_cache_flush'] = PfbToggle::On;
		$this->assertTrue(pfb_unbound_py_mode_active(), 'test setup must enable live Python mode');
		$this->assertTrue(pfb_unbound_py_swap_fits_ram(), 'test setup must allow the data swap');
		$this->assertTrue(is_process_running('unbound'), 'test setup must keep Unbound running');

		$this->runUpdateIgnoringMacOsTempnamNotice();

		$this->assertSame("2\n", file_get_contents("{$this->dir}/pfb_py_reload.applied"),
			'cache flush must follow a fresh generation application');
		$lines = file($log, FILE_IGNORE_NEW_LINES);
		$this->assertNotFalse($lines, 'bulk update must invoke the configured control command');
		$this->assertSame(['flush_zone +c .|applied=2|completed=1'], $lines,
			'full cache flush must be issued by the bulk caller after the applied marker is live');
	}

	public function testRestartFallbackDoesNotRestoreOrBulkFlushCache(): void
	{
		$log = "{$this->dir}/control.log";
		$this->installRecorder($log);
		$GLOBALS['pfb']['dnsbl_cache_flush'] = PfbToggle::On;
		$checks = 0;
		$GLOBALS['pfb_test_sysctl']['hw.usermem'] = '1';
		$GLOBALS['pfb_test_process_running']['unbound'] = static function () use (&$checks): bool {
			$checks++;
			return in_array($checks, [1, 3, 5], TRUE);
		};

		$this->runUpdateIgnoringMacOsTempnamNotice();

		$this->assertStringContainsString('RAM-constrained box', file_get_contents($GLOBALS['pfb']['log']) ?: '',
			'low-RAM data update must take the restart fallback');
		$lines = file_exists($log) ? (file($log, FILE_IGNORE_NEW_LINES) ?: []) : [];
		$commands = implode('\n', $lines);
		$this->assertStringNotContainsString('dump_cache', $commands,
			'data-path fallback must not dump the old cache before restart');
		$this->assertStringNotContainsString('load_cache', $commands,
			'data-path fallback must not restore stale cache after restart');
		$this->assertStringNotContainsString('flush_zone +c .', $commands,
			'a failed data swap must not issue the post-load bulk flush');
	}
}
