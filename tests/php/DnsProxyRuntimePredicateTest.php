<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515, #3770 -- the DNSBL module lives in the DNS proxy process while pfB-DNS owns the Resolver (the Resolver is moved
 * aside: pfb_dns_proxy_saved() !== NULL) and DNSBL is on; Unbound never hosts it. Every "is the Python DNSBL runtime alive"
 * decision must follow the module host, so data swaps, ADR-61 retries and the manifest notice take the zero-downtime path
 * against the proxy and never against Unbound.
 *
 * Each row names its mode. A proxy-mode row keeps the Unbound process in the OPPOSITE state to the proxy (and unbound.conf
 * without pfb_unbound.py), so a verdict that still consults Unbound fails. A non-proxy row leaves the proxy pidfile in the
 * opposite state to Unbound, so a verdict that consults either one fails.
 */
#[CoversFunction('pfb_dns_proxy_running')]
#[CoversFunction('pfb_unbound_py_host_running')]
#[CoversFunction('pfb_dnsbl_converged')]
#[CoversFunction('pfb_dnsbl_apply_retry')]
#[CoversFunction('pfb_unbound_py_wait_applied')]
#[CoversFunction('pfb_reload_unbound')]
#[CoversFunction('pfb_update_unbound')]
final class DnsProxyRuntimePredicateTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const PROXY_PIDFILE = '/var/run/pfb_dns_proxy.pid';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';

	private string $dir;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'g'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_proxy_runtime_' . getmypid() . '_' . uniqid();
		mkdir("{$this->dir}/dnsdir", 0777, TRUE);

		$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $this->dir,
			'dbdir' => $this->dir,
			'dnsbl_file' => "{$this->dir}/pfb_dnsbl",
			'dnsdir' => "{$this->dir}/dnsdir",
			'dnsbl_cache' => "{$this->dir}/pfb_py_cache.sqlite",
			'unbound_py_count' => "{$this->dir}/pfb_py_count",
			'unbound_py_sources' => "{$this->dir}/pfb_py_sources.json",
			'unbound_py_rawdir' => "{$this->dir}/pfb_py_raw",
			'unbound_py_reject_stats' => "{$this->dir}/pfb_py_reject_stats.json",
			'chroot_cmd' => '/bin/echo',
			'dnsbl_python_unmount' => FALSE,

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
			'php' => PHP_BINARY,
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['g']['varrun_path'] = $this->dir;
		$GLOBALS['pfb_test_process_running'] = ['unbound' => FALSE];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		$this->clearProxyFiles();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		unset(
			$GLOBALS['pfb_test_process_running'],
			$GLOBALS['pfb_test_valid_pids'],
			$GLOBALS['pfb_test_file_notices'],
			$GLOBALS['pfb_test_swap_wait_s'],
			$GLOBALS['pfb_test_unbound_py_sentinel_published'],
			$GLOBALS['pfb_test_service_hook']
		);
		rmdir_recursive($this->dir);
	}

	/** config.xml as a proxy-On apply leaves it: a valid Resolver snapshot, no python keys on Unbound. */
	private function setProxyMode(bool $on): void
	{
		if (!$on) {
			return;
		}
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
	}

	private function setPythonKeys(bool $on): void
	{
		$GLOBALS['config']['unbound'] = $on
			? ['enable' => '', 'python' => 'on', 'python_script' => 'pfb_unbound']
			: ['enable' => '', 'python' => '', 'python_script' => ''];
	}

	private function setProxyUp(bool|callable $up): void
	{
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = $up;
	}

	/**
	 * A proxy the reload or the rollback starts comes up ready, as the real one does: its child and its ready marker. A stop
	 * leaves it stopped, with neither.
	 */
	private function proxyComesUpReadyWhenStarted(): void
	{
		$GLOBALS['pfb_test_service_hook'] = function (string $function, string $service): void {
			if ($service !== 'pfb_dns_proxy') {
				return;
			}
			if (in_array($function, ['start_service', 'restart_service'], TRUE)) {
				$this->proxyServes();
			} elseif ($function === 'stop_service') {
				$this->clearProxyFiles();
			}
		};
	}

	private function setUnboundUp(bool|callable $up): void
	{
		$GLOBALS['pfb_test_process_running']['unbound'] = $up;
	}

	/** Unbound answers "up" everywhere except inside its own stop/start, which the double models as a clean restart. */
	private function setUnboundUpExceptDuringRestart(): void
	{
		$this->setUnboundUp(static function (): bool {
			foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
				if (($frame['function'] ?? '') === 'pfb_stop_start_unbound') {
					return FALSE;
				}
			}
			return TRUE;
		});
	}

	private function writeGenerations(int $sentinel, int $applied): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload", "{$sentinel}\n");
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "{$applied}\n");
	}

	private function sentinel(): int
	{
		return pfb_unbound_py_marker_generation("{$this->dir}/pfb_py_reload");
	}

	private function writeUnboundConf(bool $referencesPfbUnbound): void
	{
		file_put_contents(
			"{$this->dir}/unbound.conf",
			$referencesPfbUnbound ? "python-script: pfb_unbound.py\n" : "server:\n\tmodule-config: \"validator iterator\"\n"
		);
	}

	/** A live generation for the swap path: RAM projection input, manifest, and a watcher that applies at once. */
	private function seedSwapFixture(): void
	{
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "10\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');
		file_put_contents($GLOBALS['pfb']['unbound_py_reject_stats'], '[]');
		$this->writeUnboundConf(TRUE);
	}

	private function applyEveryPublishedGeneration(): void
	{
		$GLOBALS['pfb_test_unbound_py_sentinel_published'] = static function (string $path, int $generation): void {
			file_put_contents("{$path}.applied", "{$generation}\n");
		};
	}

	/** Unbound start attempts the harness double has recorded so far (a restart reached pfb_stop_start_unbound). */
	private function startAttempts(): int
	{
		$log = (string) $GLOBALS['pfb_test_unbound_start_log'];
		return file_exists($log) ? count(file($log, FILE_IGNORE_NEW_LINES) ?: []) : 0;
	}

	private function logText(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	// -----------------------------------------------------------------------
	// The proxy's pid file
	// -----------------------------------------------------------------------

	public function testTheProxyIsRunningWhenItsPidfileNamesALiveProcessAndUnboundIsIrrelevant(): void
	{
		$this->assertSame('/var/run/pfb_dns_proxy.pid', PFB_DNS_PROXY_PIDFILE);

		$this->setProxyUp(FALSE);
		$this->setUnboundUp(TRUE);
		$this->assertFalse(pfb_dns_proxy_running(), 'dead proxy pid, Unbound up: the proxy is not running');

		$this->setProxyUp(TRUE);
		$this->setUnboundUp(FALSE);
		$this->assertTrue(pfb_dns_proxy_running(), 'live proxy pid, Unbound down: the proxy is running');
	}

	// -----------------------------------------------------------------------
	// P1 -- pfb_unbound_py_host_running(): with DNSBL off the proxy hosts nothing
	// -----------------------------------------------------------------------

	/** @return array<string, array{bool}> proxy pid valid */
	public static function proxyPidRows(): array
	{
		return ['proxy pid valid' => [TRUE], 'proxy pid invalid' => [FALSE]];
	}

	#[DataProvider('proxyPidRows')]
	public function testWithDnsblOffAMovedResolverHasNoModuleHostWhateverTheProxyAndUnboundDo(bool $proxyUp): void
	{
		// Given pfB-DNS fronting Unbound (a snapshot) with DNSBL off: the proxy only forwards and hosts no module.
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$this->setProxyMode(TRUE);
		$this->setPythonKeys(FALSE);
		$this->setProxyUp($proxyUp);
		$this->setUnboundUp(TRUE);

		// Then nothing hosts the module: neither the proxy's pid nor a live Unbound stands in for one.
		$this->assertFalse(pfb_unbound_py_host_running());
		$this->setUnboundUp(FALSE);
		$this->assertFalse(pfb_unbound_py_host_running());
	}

	// -----------------------------------------------------------------------
	// P2 -- pfb_unbound_py_host_running(): the full proxy-pid x Unbound x mode table
	// -----------------------------------------------------------------------

	/** @return array<string, array{bool, bool, bool}> proxy mode, proxy pid valid, Unbound up */
	public static function hostRunningRows(): array
	{
		$rows = [];
		foreach ([TRUE, FALSE] as $proxyMode) {
			foreach ([TRUE, FALSE] as $pidValid) {
				foreach ([TRUE, FALSE] as $unboundUp) {
					$name = ($proxyMode ? 'proxy mode' : 'no proxy') . ', proxy pid '
						. ($pidValid ? 'valid' : 'invalid') . ', Unbound ' . ($unboundUp ? 'up' : 'down');
					$rows[$name] = [$proxyMode, $pidValid, $unboundUp];
				}
			}
		}
		return $rows;
	}

	#[DataProvider('hostRunningRows')]
	public function testModuleHostIsTheProxyWhenItOwnsTheResolverAndNeverUnbound(
		bool $proxyMode,
		bool $pidValid,
		bool $unboundUp
	): void {
		$this->setProxyMode($proxyMode);
		$this->setProxyUp($pidValid);
		$this->setUnboundUp($unboundUp);

		$expected = $proxyMode && $pidValid;
		$this->assertSame($expected, pfb_unbound_py_host_running());
	}

	// -----------------------------------------------------------------------
	// P3 -- pfb_dnsbl_converged()
	// -----------------------------------------------------------------------

	public function testProxyModeConvergesOnTheProxyPidAloneNotOnUnboundNorItsConf(): void
	{
		$this->setProxyMode(TRUE);
		$this->writeGenerations(3, 3);
		$this->writeUnboundConf(FALSE);
		$this->setUnboundUp(FALSE);
		$this->setProxyUp(FALSE);
		$this->assertFalse(pfb_dnsbl_converged(), 'before-state: the proxy is down');

		$this->setProxyUp(TRUE);

		$this->assertTrue(pfb_dnsbl_converged(),
			'the proxy hosts the module: a live proxy pid converges even though Unbound is down and its conf has no pfb_unbound.py');
	}

	public function testProxyModeDoesNotConvergeWhileTheProxyIsDownEvenIfUnboundIsFullyWired(): void
	{
		$this->setProxyMode(TRUE);
		$this->writeGenerations(3, 3);
		$this->writeUnboundConf(TRUE);
		$this->setUnboundUp(TRUE);
		$this->setProxyUp(FALSE);

		$this->assertFalse(pfb_dnsbl_converged(),
			'a live Unbound wired to pfb_unbound.py is not the module host in proxy mode');
	}

	public function testProxyModeDoesNotConvergeWhileTheGenerationsDisagree(): void
	{
		$this->setProxyMode(TRUE);
		$this->writeGenerations(5, 3);
		$this->setProxyUp(TRUE);
		$this->assertFalse(pfb_dnsbl_converged(), 'sentinel 5 vs applied 3 is a swap in flight');

		$this->writeGenerations(5, 5);
		$this->assertTrue(pfb_dnsbl_converged(), 'the same box converges once the generations agree');
	}

	// The observer (pfb_upstream_observer.py) is the python module Unbound runs in proxy mode while it forwards. It
	// reports upstream answers to the proxy and never decides a block: its presence must not read as the DNSBL
	// module being hosted by Unbound.

	private function writeUnboundConfWithObserver(): void
	{
		file_put_contents(
			"{$this->dir}/unbound.conf",
			"server:\n\tmodule-config: \"python validator iterator\"\n\npython:\npython-script: pfb_upstream_observer.py\n"
		);
	}

	public function testTheObserversPythonKeysAloneDoNotMakeUnboundTheModuleHost(): void
	{
		// Given Unbound up and loading the observer (python keys and conf), no proxy snapshot (a stale state before the next apply)
		$GLOBALS['config']['unbound'] = ['enable' => '', 'python' => '', 'python_script' => 'pfb_upstream_observer', 'python_order' => 'pre_validator'];
		$this->setProxyMode(FALSE);
		$this->setProxyUp(TRUE);
		$this->setUnboundUp(TRUE);
		$this->writeUnboundConfWithObserver();

		// Then nothing hosts the module: the swap and the retries must not target a module nobody hosts
		$this->assertFalse(pfb_unbound_py_host_running());
	}

	public function testInProxyModeTheHostFollowsTheProxyWhateverUnboundConfRunsAsItsPythonScript(): void
	{
		$this->setProxyMode(TRUE);
		$this->writeUnboundConfWithObserver();
		$GLOBALS['config']['unbound'] = ['enable' => '', 'python' => '', 'python_script' => 'pfb_upstream_observer', 'python_order' => 'pre_validator'];

		$this->setProxyUp(FALSE);
		$this->assertFalse(pfb_unbound_py_host_running(), 'proxy down: no host, though Unbound loads the observer');
		$this->setProxyUp(TRUE);
		$this->assertTrue(pfb_unbound_py_host_running(), 'proxy up: the host, though the conf has no pfb_unbound.py');
	}

	// -----------------------------------------------------------------------
	// P4 -- pfb_dnsbl_apply_retry(): re-publish the sentinel only if the host is alive
	// -----------------------------------------------------------------------

	/** @return array<string, array{bool, bool, bool, bool}> proxy mode, proxy up, Unbound up, re-flips */
	public static function applyRetryRows(): array
	{
		return [
			'proxy mode, proxy up, Unbound down: re-flips' => [TRUE, TRUE, FALSE, TRUE],
			'proxy mode, proxy down, Unbound up: nothing could consume it' => [TRUE, FALSE, TRUE, FALSE],
			'no proxy, Unbound up, proxy pid dead: Unbound is no module host' => [FALSE, FALSE, TRUE, FALSE],
			'no proxy, Unbound down, proxy pid live: nothing could consume it' => [FALSE, TRUE, FALSE, FALSE],
		];
	}

	#[DataProvider('applyRetryRows')]
	public function testApplyRetryRepublishesTheSentinelOnlyWhileTheModuleHostIsAlive(
		bool $proxyMode,
		bool $proxyUp,
		bool $unboundUp,
		bool $reflips
	): void {
		$this->setProxyMode($proxyMode);
		$this->setPythonKeys(!$proxyMode);
		$this->setProxyUp($proxyUp);
		$this->setUnboundUp($unboundUp);
		$this->writeGenerations(5, 3);
		$this->assertSame(5, $this->sentinel(), 'before-state: a stuck swap, sentinel 5 applied 3');

		pfb_dnsbl_apply_retry();

		$this->assertSame($reflips ? 6 : 5, $this->sentinel());
	}

	// -----------------------------------------------------------------------
	// P5 -- pfb_reload_unbound(): the zero-downtime fast path follows the module host
	// -----------------------------------------------------------------------

	public function testProxyModeDataUpdateSwapsInPlaceWhileTheProxyIsUpEvenWithUnboundDown(): void
	{
		$this->setProxyMode(TRUE);
		$this->seedSwapFixture();
		$this->setUnboundUp(FALSE);
		$this->setProxyUp(FALSE);
		pfb_dnsbl_apply_ledger_update();
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'), 'before-state: a stale apply entry is open');
		$this->setProxyUp(TRUE);
		$this->applyEveryPublishedGeneration();
		$starts = $this->startAttempts();

		$swapped = pfb_reload_unbound('enabled', FALSE, TRUE);

		$this->assertTrue($swapped, 'the proxy applied the generation: the swap is confirmed');
		$this->assertSame(1, $this->sentinel(), 'the sentinel was flipped');
		$this->assertSame($starts, $this->startAttempts(), 'no Unbound restart on the zero-downtime path');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'),
			'the confirmed swap converges on the proxy and closes the apply entry');
	}

	public function testProxyModeDataUpdateRestartsWhenTheProxyIsDownEvenIfUnboundIsUp(): void
	{
		$this->setProxyMode(TRUE);
		$this->seedSwapFixture();
		$this->setUnboundUpExceptDuringRestart();
		$this->setProxyUp(FALSE);
		$this->proxyComesUpReadyWhenStarted();
		$this->applyEveryPublishedGeneration();
		$starts = $this->startAttempts();

		pfb_reload_unbound('enabled', FALSE, TRUE);

		$this->assertFileDoesNotExist("{$this->dir}/pfb_py_reload",
			'no module host to consume a generation: the sentinel must not be flipped');
		$this->assertGreaterThan($starts, $this->startAttempts(), 'the restart path ran');
	}

	public function testNoProxyDataUpdateIgnoresALiveProxyPidWhenUnboundIsDown(): void
	{
		$this->setProxyMode(FALSE);
		$this->setPythonKeys(TRUE);
		$this->seedSwapFixture();
		$this->setUnboundUp(FALSE);
		$this->setProxyUp(TRUE);
		$this->applyEveryPublishedGeneration();
		$starts = $this->startAttempts();

		pfb_reload_unbound('enabled', FALSE, TRUE);

		$this->assertFileDoesNotExist("{$this->dir}/pfb_py_reload",
			'pfB-DNS does not own the Resolver: a live proxy pid must not open the zero-downtime path');
		$this->assertGreaterThan($starts, $this->startAttempts(), 'the restart path ran');
	}

	public function testProxyModeSwapThatIsSlowButHostedStaysInFlightWithoutARestart(): void
	{
		$GLOBALS['pfb_test_swap_wait_s'] = 1;
		$this->setProxyMode(TRUE);
		$this->seedSwapFixture();
		$this->writeGenerations(0, 0);
		$this->setUnboundUp(FALSE);
		$this->setProxyUp(TRUE);
		$starts = $this->startAttempts();

		[$clock, $reload] = $this->clockedReload();
		$swapped = $reload('enabled', FALSE, TRUE);

		$this->assertSame(FALSE, $swapped, 'an unconfirmed swap reads as not swapped');
		$this->assertStringContainsString('swap still in flight', $this->logText(),
			'the proxy is alive: slowness is in flight, not broken');
		$this->assertSame($starts, $this->startAttempts(), 'a live module host is never restarted for being slow');
		$this->assertSame(array_fill(0, 5, 200000), $clock->sleeps, 'the swap waited its whole 1 s budget in 200 ms polls, then reported in flight');
	}

	public function testProxyModeSwapRecoversViaRestartWhenTheProxyDiesDuringTheSwap(): void
	{
		$GLOBALS['pfb_test_swap_wait_s'] = 3;
		$this->setProxyMode(TRUE);
		$this->seedSwapFixture();
		$this->writeGenerations(0, 0);
		$this->setUnboundUp(FALSE);
		$calls = 0;
		$this->setProxyUp(static function () use (&$calls): bool {
			$calls++;
			return $calls === 1;
		});
		$this->proxyComesUpReadyWhenStarted();
		$starts = $this->startAttempts();

		pfb_reload_unbound('enabled', FALSE, TRUE);

		$this->assertStringContainsString('recovering via restart', $this->logText(),
			'a dead module host can never apply the generation');
		$this->assertGreaterThan($starts, $this->startAttempts(), 'the restart path ran');
	}

	// -----------------------------------------------------------------------
	// P6 -- pfb_unbound_py_wait_applied(): the default liveness probe
	// -----------------------------------------------------------------------

	public function testProxyModeWaitFollowsTheProxyAndIgnoresUnbound(): void
	{
		$this->setProxyMode(TRUE);
		$this->writeGenerations(1, 0);
		$this->setUnboundUp(FALSE);
		$this->setProxyUp(function (): bool {
			file_put_contents("{$this->dir}/pfb_py_reload.applied", "1\n");
			return TRUE;
		});

		$this->assertTrue(pfb_unbound_py_wait_applied(1, 5),
			'the live proxy keeps the wait going until its applied marker lands');
	}

	public function testProxyModeWaitGivesUpAtOnceWhenTheProxyIsGoneWithoutAskingUnbound(): void
	{
		$this->setProxyMode(TRUE);
		$this->writeGenerations(1, 0);
		$this->setProxyUp(FALSE);
		$unboundProbes = 0;
		$this->setUnboundUp(static function () use (&$unboundProbes): bool {
			$unboundProbes++;
			return TRUE;
		});

		$this->assertFalse(pfb_unbound_py_wait_applied(1, 1));
		$this->assertSame(0, $unboundProbes, 'the Unbound process is not the consumer in proxy mode');
	}

	public function testWithoutTheProxyTheWaitGivesUpAtOnceAndAsksNeitherUnboundNorTheProxyPid(): void
	{
		$this->setProxyMode(FALSE);
		$this->writeGenerations(1, 0);
		$unboundProbes = 0;
		$this->setUnboundUp(static function () use (&$unboundProbes): bool {
			$unboundProbes++;
			return TRUE;
		});
		$proxyProbes = 0;
		$this->setProxyUp(static function () use (&$proxyProbes): bool {
			$proxyProbes++;
			return TRUE;
		});

		$this->assertFalse(pfb_unbound_py_wait_applied(1, 1), 'nothing hosts the module, so nothing can apply the generation');
		$this->assertSame(0, $unboundProbes, 'the Unbound process is never the consumer');
		$this->assertSame(0, $proxyProbes, 'the proxy pid is not the consumer when pfB-DNS does not own the Resolver');
	}

	// -----------------------------------------------------------------------
	// P8 -- callers that gate on pfb_dns_proxy_hosts_module()
	// -----------------------------------------------------------------------

	/** @return array<string, array{bool, bool, int}> proxy mode, python keys, notices expected */
	public static function manifestNoticeRows(): array
	{
		return [
			'proxy mode (keys absent)' => [TRUE, FALSE, 1],
			'python keys (no proxy): Unbound hosts no module' => [FALSE, TRUE, 0],
			'neither: no manifest contract to report' => [FALSE, FALSE, 0],
		];
	}

	#[DataProvider('manifestNoticeRows')]
	public function testAnUpdatePassReportsAFailedManifestOnlyWhileTheProxyHostsTheModule(
		bool $proxyMode,
		bool $keys,
		int $notices
	): void {
		$this->setProxyMode($proxyMode);
		$this->setPythonKeys($keys);
		$this->seedSwapFixture();
		$this->writeGenerations(1, 1);
		file_put_contents("{$this->dir}/pfb_py_status.json", json_encode([
			['facility' => 'dnsbl', 'item' => 'pfb_py_sources.json', 'stage' => 'parse',
				'message' => 'DNSBL manifest absent', 'first_seen' => 1, 'last_seen' => 2],
		]));
		$this->setUnboundUpExceptDuringRestart();
		$this->setProxyUp($proxyMode);
		$this->applyEveryPublishedGeneration();

		set_error_handler(static function (int $severity, string $message): bool {
			return $severity === E_NOTICE && str_contains($message, 'tempnam(): file created in the system');
		});
		try {
			pfb_update_unbound('enabled', FALSE, FALSE);
		} finally {
			restore_error_handler();
		}

		$manifest = array_filter(
			$GLOBALS['pfb_test_file_notices'],
			static fn (array $n): bool => str_starts_with((string) $n['notice'], 'DNSBL manifest not loaded')
		);
		$this->assertCount($notices, $manifest);
	}
}
