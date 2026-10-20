<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- in proxy mode the module lives in the DNS proxy, which re-reads the lists and the ini only
 * when it boots. Every pfb_reload_unbound() path that restarts the Resolver (a config change, a data update
 * the zero-downtime swap cannot take, a dead host) therefore restarts the proxy too, after Unbound is back;
 * the zero-downtime swap, which the proxy applies in place, never restarts it; and outside proxy mode the
 * proxy service is never touched.
 *
 * restart_service() returns before the new proxy has written its pidfile, so the apply ledger -- which reads
 * that pidfile -- must wait (bounded) for the proxy to come up before it decides whether the apply converged;
 * a proxy that never comes up opens the ledger entry, worded for the proxy, not for Unbound.
 *
 * A proxy-mode row is a Resolver whose saved snapshot exists (pfb_dns_proxy_saved() !== NULL). The restart
 * is observed through the restart_service() double: each call snapshots, at call time, how many Unbound
 * start attempts had happened and whether the proxy's rc script had been (re)generated.
 */
#[CoversFunction('pfb_reload_unbound')]
final class DnsProxyReloadRestartTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const PROXY_PIDFILE = '/var/run/pfb_dns_proxy.pid';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const GLOBALS = [
		'pfb', 'config', 'g', 'pfb_test_process_running', 'pfb_test_valid_pids', 'pfb_test_service_calls',
		'pfb_test_service_hook', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles', 'pfb_test_swap_wait_s',
		'pfb_test_unbound_py_sentinel_published', 'pfb_test_try_lock_fail', 'pfb_test_file_notices',
	];

	private string $dir;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_proxy_reload_' . getmypid() . '_' . uniqid();
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
			'dnsbl_res_cache' => PfbToggle::On,
			'dnsbl_cache_flush' => PfbToggle::Off,
			'enable' => PfbToggle::On,
			'dnsbl' => PfbToggle::On,
			'save' => TRUE,
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
		$GLOBALS['pfb_test_service_calls'] = [];
		unset($GLOBALS['pfb_test_rcfile_writes'], $GLOBALS['pfb_test_rcfiles'], $GLOBALS['pfb_test_service_hook'], $GLOBALS['pfb_test_try_lock_fail']);
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->clearProxyFiles();
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		$this->clearProxyFiles();
		rmdir_recursive($this->dir);
	}

	/** config.xml as a proxy-On apply leaves it: a valid Resolver snapshot. */
	private function setProxyMode(): void
	{
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
	}

	private function startAttempts(): int
	{
		$log = (string) $GLOBALS['pfb_test_unbound_start_log'];
		return file_exists($log) ? count(file($log, FILE_IGNORE_NEW_LINES) ?: []) : 0;
	}

	/**
	 * Record, at each service call, the Unbound start attempts so far and the proxy rc script's write count.
	 * The restarted proxy is up as soon as it is asked to restart, unless $proxyComesUp is FALSE.
	 */
	private function observeServiceCalls(array &$seen, bool $proxyComesUp = TRUE): void
	{
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen, $proxyComesUp): void {
			$seen[] = [
				'call'   => [$fn, $service],
				'starts' => $this->startAttempts(),
				'rcfile' => $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0,
			];
			if ($proxyComesUp) {
				$this->proxyServes();
			} else {
				$this->clearProxyFiles();
			}
		};
	}

	private function seedSwapFixture(): void
	{
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "10\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');
		file_put_contents($GLOBALS['pfb']['unbound_py_reject_stats'], '[]');
		file_put_contents("{$this->dir}/unbound.conf", "python-script: pfb_unbound.py\n");
	}

	private function applyEveryPublishedGeneration(): void
	{
		$GLOBALS['pfb_test_unbound_py_sentinel_published'] = static function (string $path, int $generation): void {
			file_put_contents("{$path}.applied", "{$generation}\n");
		};
	}

	public function testProxyModeRestartPathRestartsTheProxyAfterUnboundAndAfterRegeneratingItsScript(): void
	{
		// Given the Resolver is moved aside and the pass changed the module's config (restart path)
		$this->setProxyMode();
		$seen = [];
		$this->observeServiceCalls($seen);
		$before = $this->startAttempts();

		// When the Resolver is reloaded
		pfb_reload_unbound('enabled', FALSE, TRUE);

		// Then the proxy is restarted exactly once, after Unbound's start attempt, with a fresh rc script
		$this->assertCount(1, $seen, 'exactly one service call');
		$this->assertSame(['restart_service', 'pfb_dns_proxy'], $seen[0]['call']);
		$this->assertGreaterThan($before, $seen[0]['starts'], 'the proxy is restarted after Unbound was started');
		$this->assertSame(1, $seen[0]['rcfile'], 'the rc script was regenerated before the restart');
	}

	public function testARestartedProxyThatServesIsLoggedAsReadyAndNothingIsRolledBack(): void
	{
		// Given the restart path and a proxy that publishes its marker once restarted
		$this->setProxyMode();
		$seen = [];
		$this->observeServiceCalls($seen);

		// When the Resolver is reloaded
		pfb_reload_unbound('enabled', FALSE, TRUE);

		// Then the log says the proxy is ready, and no rollback ran (no notice, no second service call)
		$this->assertStringContainsString('the DNS proxy is ready', (string) file_get_contents($GLOBALS['pfb']['log']));
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
		$this->assertCount(1, $seen);
	}

	public function testProxyModeDataUpdateTheSwapCannotTakeRestartsTheProxyToo(): void
	{
		// Given a data update while the proxy host is down: no zero-downtime path
		$this->setProxyMode();
		$this->seedSwapFixture();
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = FALSE;
		$seen = [];
		$this->observeServiceCalls($seen);

		pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);

		$this->assertSame([['restart_service', 'pfb_dns_proxy']], array_column($seen, 'call'));
	}

	public function testProxyModeZeroDowntimeSwapNeverRestartsTheProxyOrUnbound(): void
	{
		// Given a data update the live proxy applies in place
		$this->setProxyMode();
		$this->seedSwapFixture();
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = TRUE;
		$this->applyEveryPublishedGeneration();
		$seen = [];
		$this->observeServiceCalls($seen);
		$before = $this->startAttempts();

		$swapped = pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);

		$this->assertTrue($swapped, 'before: the swap took the fast path');
		$this->assertSame([], $seen, 'the proxy applies the swap itself: no restart');
		$this->assertSame($before, $this->startAttempts());
	}

	public function testWithoutProxyModeTheRestartPathNeverTouchesTheProxyService(): void
	{
		// Given no snapshot: the Resolver is Unbound's, as today
		$seen = [];
		$this->observeServiceCalls($seen);
		$before = $this->startAttempts();

		pfb_reload_unbound('enabled', FALSE, TRUE);

		$this->assertGreaterThan($before, $this->startAttempts(), 'before: the restart path ran');
		$this->assertSame([], $GLOBALS['pfb_test_service_calls'], 'toggle off: not one call about the proxy');
		$this->assertArrayNotHasKey('pfb_dns_proxy.sh', $GLOBALS['pfb_test_rcfile_writes'] ?? [], 'nor its rc script');
	}

	public function testADisabledPassNeverRestartsTheProxyEvenIfASnapshotIsStillThere(): void
	{
		// Given a disabled pass (DNSBL off) that finds a leftover snapshot
		$this->setProxyMode();
		$seen = [];
		$this->observeServiceCalls($seen);
		$before = $this->startAttempts();

		pfb_reload_unbound('disabled', FALSE, TRUE);

		$this->assertGreaterThan($before, $this->startAttempts(), 'before: the restart path ran');
		$this->assertSame([], $seen, 'a Resolver being given back is not a reason to bring the proxy up');
	}

	public function testTheLedgerWaitsForTheProxyToPublishItsReadyMarkerBeforeItDecides(): void
	{
		// Given a restart-path apply, and a proxy that publishes its marker only a few probes after the
		// restart_service() call returned (the real start is asynchronous)
		$this->setProxyMode();
		$state = ['restarted' => FALSE, 'probes' => 0];
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = function () use (&$state): bool {
			if (!$state['restarted'] || ++$state['probes'] < 3) {
				return FALSE;
			}
			$this->proxyServes();
			return TRUE;
		};
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn) use (&$state): void {
			$state['restarted'] = $state['restarted'] || $fn === 'restart_service';
		};

		// When the Resolver is reloaded
		[$clock, $reload] = $this->clockedReload();
		$reload('enabled', FALSE, TRUE);

		// Then the ledger saw the serving proxy: no "not converged" entry is open
		$this->assertGreaterThanOrEqual(3, $state['probes'], 'the marker was waited for until it appeared');
		$this->assertSame([100000, 100000], $clock->sleeps, 'the ledger waited two ticks of 100 ms for the marker, then read it');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'), 'a proxy that came up converged');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'and nothing was rolled back');
	}

	public function testAProxyThatNeverComesUpAndCannotBeRolledBackOpensTheLedgerEntryWordedForTheProxy(): void
	{
		// Given a restart-path apply whose proxy never becomes ready, and a rollback that cannot start: another process holds
		// the config lock, so the Resolver stays moved and the proxy stays the host of the module
		$this->setProxyMode();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$seen = [];
		$this->observeServiceCalls($seen, FALSE);

		// When the Resolver is reloaded
		pfb_reload_unbound('enabled', FALSE, TRUE);

		// Then the apply is reported as not converged, and the message names the DNS proxy, not Unbound
		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open);
		$this->assertStringContainsString('not converged', $open[0]['message']);
		$this->assertStringContainsString('DNS proxy', $open[0]['message']);
		$this->assertStringNotContainsString('Unbound not fully live', $open[0]['message']);
	}

	public function testOutsideProxyModeTheNotConvergedMessageStillNamesUnbound(): void
	{
		// Given no snapshot and no Unbound start (the test double fails it): not converged, as today
		pfb_reload_unbound('enabled', FALSE, TRUE);

		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open, 'before: the apply did not converge');
		$this->assertStringContainsString('Unbound not fully live with pfb_unbound.py', $open[0]['message']);
		$this->assertStringNotContainsString('DNS proxy', $open[0]['message']);
	}
}
