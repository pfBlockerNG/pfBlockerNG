<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2607 — the loaded-entry total a DNSBL pass reports must belong to the
 * generation that pass is looking at, never to a previous one.
 *
 * pfb_py_count is written by Python only for a build that produced a snapshot, and
 * the manifest teardown now removes it along with everything else Python emits. So
 * "no emitted count" means "nothing is loaded", and the pass says 0. Before this, a
 * reinstall printed the pre-uninstall total on the line directly above
 * "DNSBL manifest not loaded: … DNSBL not loaded".
 *
 * The same artifact is the RAM basis pfb_unbound_py_swap_fits_ram() projects the
 * zero-downtime swap from, so a stale value is not merely a cosmetic log lie.
 */
#[CoversFunction('pfb_update_unbound')]
final class DnsblLoadedCountTest extends TestCase
{
	private const PFB_KEYS = [
		'dnsbldir', 'dbdir', 'dnsbl_file', 'dnsdir', 'dnsbl_cache', 'unbound_py_count',
		'unbound_py_sources', 'unbound_py_rawdir', 'unbound_py_reject_stats', 'chroot_cmd',
		'dnsbl_python_unmount', 'dnsbl_res_cache', 'dnsbl_cache_flush',
		'enable', 'dnsbl', 'save', 'dnsbl_tld_wildcard', 'domain_update', 'reuse_dnsbl',
		'dnsbl_unlock', 'keep', 'install', 'errlog', 'log',
	];

	private string $dir;
	/** @var array<string, array{0: bool, 1: mixed}> key => [existed, value] */
	private array $savedPfb = [];
	/** @var array{0: bool, 1: mixed} */
	private array $savedVarrun = [FALSE, NULL];
	/** @var array{0: bool, 1: mixed} */
	private array $savedUnboundConfig = [FALSE, NULL];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_loaded_count_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		// Track key EXISTENCE separately from value: several keys below are legitimately
		// boolean FALSE, so a FALSE sentinel would unset a sibling suite's real value on
		// teardown instead of restoring it.
		foreach (self::PFB_KEYS as $key) {
			$this->savedPfb[$key] = [
				array_key_exists($key, $GLOBALS['pfb'] ?? []),
				$GLOBALS['pfb'][$key] ?? NULL,
			];
		}
		$this->savedVarrun = [
			array_key_exists('varrun_path', $GLOBALS['g'] ?? []),
			$GLOBALS['g']['varrun_path'] ?? NULL,
		];
		$this->savedUnboundConfig = [
			array_key_exists('unbound', $GLOBALS['config'] ?? []),
			$GLOBALS['config']['unbound'] ?? NULL,
		];

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

		// Unbound is up throughout, so the pass an absent count forces (the RAM gate
		// failing closed) reaches the real restart fallback and its post-restart
		// confirmation branch, and the harness caps the stop-wait (issue #2613) -- this
		// double neither has to model the daemon dying nor to keep a call counter.
		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];

		// A live, healthy generation: manifest published, Python's emitted count on disk.
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "11732\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');
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
		foreach ($this->savedPfb as $key => [$existed, $value]) {
			if ($existed) {
				$GLOBALS['pfb'][$key] = $value;
			} else {
				unset($GLOBALS['pfb'][$key]);
			}
		}
		[$existed, $value] = $this->savedVarrun;
		if ($existed) {
			$GLOBALS['g']['varrun_path'] = $value;
		} else {
			unset($GLOBALS['g']['varrun_path']);
		}
		[$existed, $value] = $this->savedUnboundConfig;
		if ($existed) {
			$GLOBALS['config']['unbound'] = $value;
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
	 * Scenario: the emitted count must not outlive the generation it describes.
	 *   Given a published manifest and Python's emitted count, the pass reports that count;
	 *   When both are gone (Python emits no count for a build that produced nothing),
	 *   Then the pass reports 0 loaded entries — never the previous generation's total.
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
