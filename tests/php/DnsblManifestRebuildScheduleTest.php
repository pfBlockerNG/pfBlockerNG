<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2607 — a DNSBL pass that finds the per-feed manifest GONE must leave the
 * rebuild queued for the next tick, and must never report a loaded-entry total it
 * no longer has.
 *
 * The defect this pins: a real `pkg delete` (a channel switch is one) tears the
 * manifest down, and the reinstall's resync runs as a config-save pass, whose
 * DNSBL feed section — including the pfb_dnsbl_manifest_missing() rebuild gate —
 * is guarded by !$pfb['save']. Unbound comes back up in Python mode with an empty
 * matcher and nothing scheduled the rebuild, so the box blocked nothing until its
 * next DUE FEED pass happened to run (hours, on a daily/weekly feed schedule).
 *
 * The rebuild is deliberately NOT run inline here: heavy work inside the package
 * lifecycle path is what hung the uninstall in issue #682. Queuing it for the
 * 15-minute tick is the whole contract.
 */
#[CoversFunction('pfb_update_unbound')]
final class DnsblManifestRebuildScheduleTest extends TestCase
{
	private string $dir;
	private array $savedPfb = [];
	private array $savedG = [];
	private array $savedConfig = [];
	private bool $hadConfig = FALSE;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_manifest_rebuild_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		foreach ([
			'dnsbldir', 'dbdir', 'dnsbl_file', 'dnsdir', 'dnsbl_cache', 'unbound_py_count',
			'unbound_py_sources', 'unbound_py_rawdir', 'unbound_py_reject_stats', 'chroot_cmd',
			'dnsbl_python_unmount', 'dnsbl_res_cache', 'dnsbl_cache_flush',
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
			'unbound_py_reject_stats' => "{$this->dir}/pfb_py_reject_stats.json",
			'chroot_cmd' => "{$this->dir}/unbound-control-recorder",
			'dnsbl_python_unmount' => FALSE,
			'dnsbl_res_cache' => PfbToggle::On,
			'dnsbl_cache_flush' => PfbToggle::Off,
			'enable' => PfbToggle::On,
			'dnsbl' => PfbToggle::On,
			// The install/uninstall resync pass: config-save only, no feed processing.
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

		// A live, healthy generation: manifest published, Python's emitted count on disk.
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "11732\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"feeds":[]}');
		file_put_contents($GLOBALS['pfb']['unbound_py_reject_stats'], '[]');
		file_put_contents("{$this->dir}/unbound.conf", "python-script: pfb_unbound.py\n");
		file_put_contents("{$this->dir}/pfb_py_reload", "1\n");
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "1\n");
		file_put_contents($GLOBALS['pfb']['chroot_cmd'], "#!/bin/sh\nexit 0\n");
		chmod($GLOBALS['pfb']['chroot_cmd'], 0755);
		$GLOBALS['pfb_test_unbound_py_sentinel_published'] = static function (string $path, int $generation): void {
			file_put_contents("{$path}.applied", "{$generation}\n");
		};
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
		rmdir_recursive($this->dir);
	}

	/** macOS tempnam() emits an E_NOTICE the atomic writer cannot avoid; it is not under test. */
	private function runUpdate(): void
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

	/** The last "DNSBL update [ ... ]" line the pass appended to the runtime log. */
	private function lastUpdateLine(): string
	{
		$log = (string) @file_get_contents($GLOBALS['pfb']['log']);
		$matches = [];
		$this->assertNotSame(0, preg_match_all('/DNSBL update \[[^\]]*\]/', $log, $matches),
			"the pass must log its DNSBL update line; log was:\n{$log}");
		return (string) end($matches[0]);
	}

	/**
	 * Scenario: the manifest is gone when a config-save pass runs (the reinstall).
	 *   Given a healthy pass with a published manifest, nothing is queued;
	 *   When the manifest has been torn down and the same pass runs again,
	 *   Then the rebuild is queued for the next tick.
	 */
	public function testAbsentManifestQueuesTheRebuildForTheNextTick(): void
	{
		$this->runUpdate();
		$this->assertFalse(
			pfb_due_ledger_is_pending('cron', $GLOBALS['pfb']['dbdir']),
			'before-state: a pass over a published manifest must queue no rebuild'
		);

		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']), 'the teardown removes the manifest');
		$this->runUpdate();

		$this->assertTrue(
			pfb_due_ledger_is_pending('cron', $GLOBALS['pfb']['dbdir']),
			'a pass that finds the manifest gone must queue the DNSBL rebuild for the next tick, '
			. 'instead of leaving the resolver empty until a feed happens to fall due'
		);
	}

	/**
	 * The rebuild is queued, never performed inline: the package lifecycle path must not
	 * run a DNSBL pass (issue #682). The queued marker is the only effect.
	 */
	public function testAbsentManifestDoesNotRebuildTheManifestInline(): void
	{
		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']));

		$this->runUpdate();

		$this->assertFileDoesNotExist(
			$GLOBALS['pfb']['unbound_py_sources'],
			'the manifest rebuild belongs to the next tick, not to this config-save pass'
		);
	}

	/**
	 * Scenario: the emitted count must not outlive the generation it describes.
	 *   Given a published manifest and Python's emitted count, the pass reports that count;
	 *   When both are gone (Python emits no count for a build that produced nothing),
	 *   Then the pass reports 0 loaded entries — never the previous generation's total.
	 *
	 * The stale value is not only a log lie: pfb_unbound_py_swap_fits_ram() sizes the
	 * zero-downtime swap's RAM projection from the same artifact.
	 */
	public function testLoadedCountIsNotCarriedOverFromAPreviousGeneration(): void
	{
		$this->runUpdate();
		$this->assertStringContainsString('loaded entries: 11732', $this->lastUpdateLine(),
			'before-state: the pass reports the emitted count while the generation is live');

		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']));
		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_count']));
		$this->runUpdate();

		$line = $this->lastUpdateLine();
		$this->assertStringNotContainsString('11732', $line,
			'a pass with nothing loaded must not report the previous generation\'s entry total');
		$this->assertStringContainsString('loaded entries: 0', $line,
			'no emitted count means nothing is loaded, and the log must say so');
	}
}
