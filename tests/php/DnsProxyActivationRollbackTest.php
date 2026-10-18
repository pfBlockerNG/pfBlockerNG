<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- a pfB-DNS activation whose proxy never becomes ready is rolled back, and the DNSBL that ran in Unbound
 * before keeps running there.
 *
 * The owner's choice: a failed activation must leave the Resolver as it was, with the DNSBL module still loaded by Unbound
 * when DNSBL is on, and must say so; it must not claim success, leave filtering silently off, or retry in a loop. "Failed"
 * means the proxy did not publish its ready marker within the startup budget (a bind or initialisation failure after the
 * Resolver was already moved), whichever call started it: the reload's restart, the apply's start of a proxy that died, or
 * a restart from the installer.
 *
 * Contract pinned here, each as its own scenario:
 *   - the requested pfB-DNS toggle is turned Off (so the next apply does not enable it again), the proxy is stopped, the
 *     Resolver gets exactly its saved settings back, the DNSBL module goes back into Unbound iff DNSBL is on, unbound.conf
 *     is regenerated and Unbound restarted, the call reports failure and the operator is told;
 *   - nothing is waited on under the config lock, and the proxy is neither restarted again nor started again in the same
 *     apply (the toggle is Off, so the apply's own start finds nothing moved);
 *   - when the proxy cannot be stopped, or the config lock stays taken, the snapshot and the moved Resolver are kept as
 *     they are, nothing destructive runs, and the notice says recovery is needed: the rollback never claims success;
 *   - a proxy that does become ready is left alone: no toggle write, no stop, no notice.
 */
#[CoversFunction('pfb_dns_proxy_roll_back')]
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_restart')]
final class DnsProxyActivationRollbackTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const TOGGLE = 'installedpackages/pfblockerngdns/config/0/pfb_dns';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const PFB_DNS = 'installedpackages/pfblockerngdns/config/0';
	private const GLOBALS = [
		'pfb', 'config', 'g', 'pfb_test_process_running', 'pfb_test_valid_pids', 'pfb_test_service_calls', 'pfb_test_service_hook',
		'pfb_test_rcfile_writes', 'pfb_test_rcfiles', 'pfb_test_write_config_calls', 'pfb_test_unbound_configure_calls',
		'pfb_test_unbound_configure_resolver', 'pfb_test_file_notices', 'pfb_test_try_lock_fail', 'pfb_test_lock_held',
		'pfb_test_lock_events', 'pfb_test_interface_ip', 'pfb_test_interface_info',
	];

	private string $tmp;
	private array $savedGlobals = [];
	/** @var list<string> what the proxy service was asked, in order: start_service, restart_service, stop_service */
	private array $proxyCalls = [];
	/** @var list<bool> whether the config lock was held at each liveness probe of the child while PHP waited for readiness */
	private array $lockHeldWhileWaiting = [];
	private string $behaviour = 'lives';
	private bool $survivesStop = FALSE;
	private string $originalStartDouble = '';

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_rollback_' . getmypid() . '_' . uniqid();
		mkdir("{$this->tmp}/dnsdir", 0777, TRUE);
		$GLOBALS['config'] = [];
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		$GLOBALS['g']['varrun_path'] = $this->tmp;
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'logdir' => $this->tmp, 'log' => "{$this->tmp}/pfb.log", 'errlog' => "{$this->tmp}/pfb.err",
			'dnsbldir' => $this->tmp, 'dbdir' => $this->tmp, 'dnsdir' => "{$this->tmp}/dnsdir",
			'dnsbl_file' => "{$this->tmp}/pfb_dnsbl", 'dnsbl_cache' => "{$this->tmp}/pfb_py_cache.sqlite",
			'dnsbl_unlock' => "{$this->tmp}/dnsbl_unlock",
			'unbound_py_conf' => "{$this->tmp}/pfb_unbound.ini", 'unbound_py_wh' => "{$this->tmp}/pfb_whitelist.txt",
			'unbound_py_sources' => "{$this->tmp}/pfb_sources.json", 'unbound_py_count' => "{$this->tmp}/pfb_py_count",
			'unbound_py_rawdir' => "{$this->tmp}/pfb_py_raw", 'unbound_py_reject_stats' => "{$this->tmp}/pfb_py_reject_stats.json",
			'unbound_py_module_src' => ["{$this->tmp}/absent_a.py", "{$this->tmp}/absent_b.py"],
			'unbound_py_module_applied' => "{$this->tmp}/pfb_py_module.applied",
			'chroot_cmd' => '/bin/echo', 'php' => PHP_BINARY,
			'dnsbl_res_cache' => PfbToggle::Off, 'dnsbl_cache_flush' => PfbToggle::Off,
			'keep' => PfbToggle::On,
		]);
		// Nothing of an apply pass's own state (save, install, reuse_dnsbl): a rollback runs from the installer and the Reports pages too
		unset($GLOBALS['pfb']['dnsbl_python_unmount'], $GLOBALS['pfb']['save'], $GLOBALS['pfb']['install'], $GLOBALS['pfb']['reuse_dnsbl']);
		$GLOBALS['pfb']['dnsbl_python_unmount'] = FALSE;
		$GLOBALS['pfb_test_process_running'] = ['unbound' => FALSE];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_unbound_configure_calls'] = [];
		$GLOBALS['pfb_test_unbound_configure_resolver'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
		$GLOBALS['pfb_test_lock_held'] = FALSE;
		unset($GLOBALS['pfb_test_try_lock_fail'], $GLOBALS['pfb_test_rcfile_writes'], $GLOBALS['pfb_test_rcfiles']);
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$this->proxyCalls = [];
		$this->lockHeldWhileWaiting = [];
		$this->behaviour = 'lives';
		$this->survivesStop = FALSE;
		$this->clearProxyFiles();

		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service): void {
			if ($service !== 'pfb_dns_proxy') {
				return;
			}
			$this->proxyCalls[] = $fn;
			if ($fn === 'stop_service') {
				if (!$this->survivesStop) {
					$this->clearProxyFiles();
				}
				return;
			}
			if ($this->behaviour === 'serves') {
				$this->proxyServes();
			} elseif ($this->behaviour === 'lives') {
				// Alive, as the supervisor keeps its child alive between restarts, and never publishing the marker; the probe
				// notes whether the config lock is held while PHP waits
				$this->proxyLivesButNeverServes();
				$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = function (): bool {
					$this->lockHeldWhileWaiting[] = !empty($GLOBALS['pfb_test_lock_held']);
					return TRUE;
				};
			} else {
				$this->clearProxyFiles();
			}
		};
		$this->useMountState(TRUE);
		// The bootstrap's Unbound start double fails (nothing may start Unbound under test); a rollback that restarts Unbound must
		// find the start succeed, or the reload's own recovery puts the pre-rollback unbound.conf back
		$this->originalStartDouble = (string) file_get_contents($this->startDouble());
		file_put_contents($this->startDouble(), "#!/bin/sh\nprintf '%s\\n' 'unit-test double: Unbound started' | tee -a \"\$1\"\nexit 0\n");
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
		file_put_contents($this->startDouble(), $this->originalStartDouble);
		rmdir_recursive($this->tmp);
	}

	/** The bootstrap's Unbound start command: it starts nothing and fails; this class swaps in one that logs and succeeds. */
	private function startDouble(): string
	{
		return dirname((string) $GLOBALS['pfb_test_unbound_start_log']) . '/unbound-start-double';
	}

	/** Answers the mount probe the python integration runs: "already mounted", or "nothing mounted". */
	private function useMountState(bool $mounted): void
	{
		file_put_contents("{$this->tmp}/grep_double", "#!/bin/sh\n" . ($mounted ? "printf '%s\\n' mounted" : 'exit 0') . "\n");
		chmod("{$this->tmp}/grep_double", 0755);
		$GLOBALS['pfb']['grep'] = "{$this->tmp}/grep_double";
	}

	/** The user's Resolver before pfB-DNS touched it. */
	private static function originalResolver(): array
	{
		return [
			'enable' => '', 'dnssec' => '', 'sslcertref' => 'cert123', 'tlsport' => '853', 'port' => '53',
			'active_interface' => 'lan,opt1', 'enablessl' => '',
			'custom_options' => base64_encode("do-ip6: no\nprefetch: yes"),
		];
	}

	private static function sorted(array $unbound): array
	{
		ksort($unbound);
		return $unbound;
	}

	/**
	 * The box as a first activation leaves it just before the proxy has to answer: pfBlockerNG on, DNSBL on or off, pfB-DNS
	 * on, the Resolver moved aside by the real pass (so the snapshot is the one the real writer made), the DNSBL module
	 * loaded by Unbound before that when DNSBL is on.
	 */
	private function activate(bool $dnsbl): void
	{
		PfbConfig::writeSectionSystem('installedpackages/pfblockerng/config/0', [
			'pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0', 'enable_cb' => 'on',
		]);
		PfbConfig::writeSectionSystem('installedpackages/pfblockerngipsettings/config/0', [
			'suppression' => '', 'database_cc' => '', 'asn_token' => '', 'maxmind_account' => '',
			'maxmind_key' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
		]);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		PfbConfig::writeSectionSystem(self::DNSBL, [
			'pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443',
			'top1m_enable' => '', 'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '',
			'pfb_cname' => '', 'tld_allow' => '', 'tld_wildcard' => '',
			'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'whitelist' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '',
			// auto-create mode: the DNSBL sinkhole VIP is the apply's to provision, so its validation does not force DNSBL off here
			'pfb_dnsbl' => $dnsbl ? 'on' : '', 'pfb_dnsvip_auto' => $dnsbl ? 'on' : '', 'dnsbl_interface' => 'lo0',
		]);
		PfbConfig::writeSectionSystem(self::PFB_DNS, ['pfb_dns' => 'on']);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;

		$GLOBALS['config']['unbound'] = self::originalResolver() + ($dnsbl
			? ['python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound']
			: []);
		$mode = $dnsbl ? 'enabled' : 'disabled';
		pfb_unbound_python($mode, TRUE);
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the Resolver was moved for the proxy');
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'before: the Resolver is on loopback');
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'), 'before: Unbound runs the observer, not the module');
		// The unbound.conf the proxy-mode Resolver runs with: the python module slot holds the observer, which the proxy's
		// takeover put there
		file_put_contents("{$this->tmp}/unbound.conf", "server:\nmodule-config: \"python validator iterator\"\npython:\npython-script: pfb_upstream_observer.py\n");
		$GLOBALS['pfb_test_unbound_configure_calls'] = [];
		$GLOBALS['pfb_test_unbound_configure_resolver'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
		$GLOBALS['pfb_test_process_running'] = ['unbound' => FALSE];
	}

	private function startAttempts(): int
	{
		$log = (string) $GLOBALS['pfb_test_unbound_start_log'];
		return file_exists($log) ? count(file($log, FILE_IGNORE_NEW_LINES) ?: []) : 0;
	}

	private function assertResolverIsTheOriginal(string $why): void
	{
		$unbound = config_get_path('unbound');
		unset($unbound['python'], $unbound['python_order'], $unbound['python_script']);
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted($unbound), "{$why}: exactly the saved Resolver settings");
		$this->assertNull(pfb_dns_proxy_saved(), "{$why}: the snapshot is consumed");
		$this->assertSame('', (string) config_get_path(self::SAVED, ''), "{$why}: the marker is cleared");
	}

	/** @return list<array<string,mixed>> */
	private function notices(): array
	{
		return $GLOBALS['pfb_test_file_notices'] ?? [];
	}

	private function pfbLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']) . (string) @file_get_contents($GLOBALS['pfb']['errlog']);
	}

	private function toggleStored(): string
	{
		return (string) config_get_path(self::TOGGLE, '');
	}

	// -----------------------------------------------------------------------
	// A -- a proxy that never becomes ready is rolled back to the old integration
	// -----------------------------------------------------------------------

	public function testAProxyThatNeverServesTurnsPfbDnsOffAndPutsTheDnsblModuleBackIntoUnbound(): void
	{
		// Given a first activation with DNSBL on: the Resolver is moved, and the proxy lives but never publishes its marker
		$this->activate(TRUE);
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is requested');

		// When the apply starts the proxy and waits for it
		$ok = pfb_dns_proxy_ensure_running();

		// Then the call reports failure ...
		$this->assertFalse($ok, 'the activation failed');

		// ... the requested toggle is Off, so the next apply does not enable it again ...
		$this->assertSame('', $this->toggleStored(), 'pfB-DNS is turned off');

		// ... the Resolver has exactly its saved settings back ...
		$this->assertResolverIsTheOriginal('rolled back');

		// ... the DNSBL module is back in Unbound, which is regenerated from the restored settings and restarted ...
		$this->assertTrue(config_path_enabled('unbound', 'python'));
		$this->assertSame('pfb_unbound', config_get_path('unbound/python_script'));
		$this->assertSame('pre_validator', config_get_path('unbound/python_order'));
		$seen = $GLOBALS['pfb_test_unbound_configure_resolver'];
		$this->assertNotEmpty($seen, 'unbound.conf was regenerated');
		$last = end($seen);
		$this->assertSame('lan,opt1', $last['active_interface'], 'rendered from the restored Resolver');
		$this->assertSame('pfb_unbound', $last['python_script'], 'with the module loaded by Unbound again');
		$this->assertGreaterThanOrEqual(1, $this->startAttempts(), 'and Unbound was started with it');
		$conf = (string) file_get_contents("{$this->tmp}/unbound.conf");
		$this->assertStringContainsString('python-script: pfb_unbound.py', $conf, 'the file Unbound starts from names the DNSBL module again');
		$this->assertStringNotContainsString('pfb_upstream_observer', $conf, 'and no longer the observer');

		// ... the proxy was started once, then stopped, and never restarted or started again ...
		$this->assertSame(['start_service', 'stop_service'], $this->proxyCalls);

		// ... and the operator is told what happened and what is running now
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('did not become ready', $notices[0]['notice']);
		$this->assertStringContainsString('turned off', $notices[0]['notice']);
		$this->assertStringContainsString('DNS Resolver was restored', $notices[0]['notice']);
		$this->assertStringContainsString('DNSBL', $notices[0]['notice'], 'DNSBL runs in the Resolver again');
		$this->assertSame(2, $notices[0]['priority']);
		$this->assertStringContainsString('did not become ready', $this->pfbLog());
	}

	public function testWithDnsblOffTheRollbackGivesTheResolverBackWithoutAnyPythonModule(): void
	{
		// Given a first activation with DNSBL off
		$this->activate(FALSE);
		$this->useMountState(FALSE);

		// When the proxy never serves
		$ok = pfb_dns_proxy_ensure_running();

		// Then the Resolver is the saved one, plain: neither the module nor the observer is left in it
		$this->assertFalse($ok);
		$this->assertSame('', $this->toggleStored());
		$this->assertResolverIsTheOriginal('rolled back');
		$this->assertFalse(config_path_enabled('unbound', 'python'), 'no python integration at all');
		$this->assertNotContains(config_get_path('unbound/python_script'), ['pfb_unbound', 'pfb_upstream_observer']);
		$last = end($GLOBALS['pfb_test_unbound_configure_resolver']);
		$this->assertSame('lan,opt1', $last['active_interface']);
		$conf = (string) file_get_contents("{$this->tmp}/unbound.conf");
		$this->assertStringNotContainsString('python-script', $conf, 'Unbound starts from a file with no python script at all');
		$this->assertStringContainsString('module-config: "validator iterator"', $conf);
		$this->assertSame(['start_service', 'stop_service'], $this->proxyCalls);
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('DNS Resolver was restored', $notices[0]['notice']);
		$this->assertStringNotContainsString('DNSBL', $notices[0]['notice'], 'DNSBL is off: no module to put back');
	}

	public function testTheReloadsProxyRestartFailsTheSameWayAndRestartsTheProxyOnlyOnce(): void
	{
		// Given DNSBL on, the Resolver moved, and a reload that restarts the Resolver and then the proxy
		$this->activate(TRUE);
		$before = $this->startAttempts();

		// When the proxy never becomes ready
		pfb_reload_unbound('enabled', FALSE, TRUE);

		// Then the activation is rolled back, as above ...
		$this->assertSame('', $this->toggleStored());
		$this->assertResolverIsTheOriginal('rolled back');
		$this->assertSame('pfb_unbound', config_get_path('unbound/python_script'));

		// ... the proxy was restarted once and stopped once: the rollback's own Resolver restart does not restart the proxy ...
		$this->assertSame(['restart_service', 'stop_service'], $this->proxyCalls);

		// ... Unbound was started again after the restore (the reload's own start, then the rollback's) ...
		$this->assertGreaterThanOrEqual($before + 2, $this->startAttempts());

		// ... and the reload's log says the proxy did not complete, never that it did
		$log = $this->pfbLog();
		$this->assertStringContainsString('Not completed: the DNS proxy did not become ready', $log);
		$this->assertStringNotContainsString('the DNS proxy is ready', $log, 'a proxy that never served is never reported ready');
	}

	public function testTheRestartThatTheInstallerRunsRollsBackAndReportsFailure(): void
	{
		// Given the same moved Resolver, and the installer's restart of the proxy
		$this->activate(TRUE);

		// When it never becomes ready
		$ok = pfb_dns_proxy_restart();

		// Then the restart reports failure and the rollback ran
		$this->assertFalse($ok);
		$this->assertSame('', $this->toggleStored());
		$this->assertResolverIsTheOriginal('rolled back');
		$this->assertSame(['restart_service', 'stop_service'], $this->proxyCalls);
	}

	public function testNothingIsWaitedOnUnderTheConfigLock(): void
	{
		// Given a proxy that lives and never serves: every liveness probe while PHP waits notes whether the lock is held
		$this->activate(TRUE);

		pfb_dns_proxy_ensure_running();

		$this->assertNotEmpty($this->lockHeldWhileWaiting, 'before: PHP did probe the proxy while waiting');
		$this->assertSame([], array_keys(array_filter($this->lockHeldWhileWaiting)), 'the lock was free at every probe of the wait');
		$locks = array_values(array_filter($GLOBALS['pfb_test_lock_events'], static fn (array $e): bool => $e[0] === 'try_lock'));
		$unlocks = array_values(array_filter($GLOBALS['pfb_test_lock_events'], static fn (array $e): bool => $e[0] === 'unlock'));
		$this->assertCount(count($locks), $unlocks, 'every lock taken by the rollback was released');
		$this->assertFalse((bool) $GLOBALS['pfb_test_lock_held'], 'and none is still held');
	}

	public function testTheSameApplyDoesNotEnableOrStartItAgainAfterTheRollback(): void
	{
		// Given a rolled-back activation
		$this->activate(TRUE);
		$this->assertFalse(pfb_dns_proxy_ensure_running());
		$calls = $this->proxyCalls;

		// When the apply goes on to its own start check once more, and the Resolver step asks for the move again
		$again = pfb_dns_proxy_ensure_running();

		// Then nothing starts the proxy: the toggle is Off and nothing is moved
		$this->assertTrue($again, 'nothing is moved, so there is nothing to be ready');
		$this->assertSame($calls, $this->proxyCalls, 'no start or restart after the rollback');
		$this->assertSame('', $this->toggleStored());
		$this->assertNull(pfb_dns_proxy_saved());
	}

	// -----------------------------------------------------------------------
	// B -- when the rollback itself cannot finish, nothing is lost and nothing is claimed
	// -----------------------------------------------------------------------

	public function testAProxyThatCannotBeStoppedKeepsTheSnapshotAndTheMovedResolverAndSaysRecoveryIsNeeded(): void
	{
		// Given a proxy that never serves and survives its stop too
		$this->activate(TRUE);
		$this->survivesStop = TRUE;
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = config_get_path('unbound');
		$before = $this->startAttempts();

		// When the activation fails
		$ok = pfb_dns_proxy_ensure_running();

		// Then the snapshot and the moved Resolver are exactly as they were: the backup is never lost ...
		$this->assertFalse($ok);
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the snapshot is kept byte for byte');
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')), 'the Resolver stays moved');
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'), 'the module is not put into Unbound while the proxy still hosts it');
		$this->assertSame($before, $this->startAttempts(), 'Unbound is not restarted over a proxy that still holds the Resolver\'s port');

		// ... the requested toggle is Off, so the next apply retries the restore instead of enabling it again ...
		$this->assertSame('', $this->toggleStored());

		// ... and the operator is told that recovery is needed, not that the old integration is back
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('could not be restored', $joined);
		$this->assertStringContainsString('kept', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined, 'no claim that the rollback worked');
		$this->assertSame(1, count(array_keys($this->proxyCalls, 'restart_service', TRUE)), 'the proxy that serves the moved Resolver is brought back once, not in a loop');
	}

	public function testAConfigLockThatStaysTakenAbortsEverythingDestructive(): void
	{
		// Given a proxy that never serves, and another process saving config.xml for as long as the rollback tries
		$this->activate(TRUE);
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = config_get_path('unbound');

		// When the activation fails
		$ok = pfb_dns_proxy_ensure_running();

		// Then nothing was stopped, written or restored, and the notice says what to do
		$this->assertFalse($ok);
		$this->assertSame(['start_service'], $this->proxyCalls, 'the proxy is not stopped without the lock');
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''));
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'no config.xml write without the lock');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('locked', $joined);
		$this->assertStringContainsString('could not be restored', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined);
	}

	// -----------------------------------------------------------------------
	// C -- a proxy that does serve is left alone
	// -----------------------------------------------------------------------

	public function testAProxyThatBecomesReadyIsLeftAloneAndTheObserverStaysInUnbound(): void
	{
		// Given a first activation whose proxy publishes its marker once started
		$this->activate(TRUE);
		$this->behaviour = 'serves';

		// When the apply starts it and waits for it
		$ok = pfb_dns_proxy_ensure_running();

		// Then the activation stands: no toggle write, no stop, no notice, the Resolver stays moved and Unbound keeps the
		// observer, never the matcher
		$this->assertTrue($ok, 'before: a ready proxy is success');
		$this->assertSame('on', $this->toggleStored(), 'no false Off');
		$this->assertSame(['start_service'], $this->proxyCalls);
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'));
		$this->assertSame([], $this->notices());
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testAHealthyProxyThatIsAlreadyServingNeedsNoStartAndIsNeverRolledBack(): void
	{
		// Given a proxy that serves since before this apply
		$this->activate(TRUE);
		pfb_dns_proxy_service();
		$this->proxyServes();
		$GLOBALS['pfb_test_service_calls'] = [];

		$ok = pfb_dns_proxy_ensure_running();

		$this->assertTrue($ok);
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame([], $this->notices());
	}

	public function testALiveProxyThatNeverPublishedItsMarkerIsNotTakenForServing(): void
	{
		// Given a live proxy whose script is unchanged (the old check was: the pidfile names a live process), no marker
		$this->activate(TRUE);
		pfb_dns_proxy_service();
		$this->proxyLivesButNeverServes();
		$GLOBALS['pfb_test_service_calls'] = [];

		// When the apply checks it
		$ok = pfb_dns_proxy_ensure_running();

		// Then it is not ready after the budget, and the activation is rolled back: a crash-looping listener is no proxy
		$this->assertFalse($ok);
		$this->assertSame('', $this->toggleStored());
		$this->assertResolverIsTheOriginal('rolled back');
	}

	public function testTheRollbackCalledDirectlyReportsWhetherTheOldIntegrationIsBack(): void
	{
		// Given a moved Resolver and a proxy that stops cleanly
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();

		$this->assertTrue(pfb_dns_proxy_roll_back(), 'restored: the old integration runs again');
		$this->assertResolverIsTheOriginal('rolled back');
	}

	// -----------------------------------------------------------------------
	// D -- every caller consumes the result
	// -----------------------------------------------------------------------

	public function testTheApplyAndTheInstallerConsumeTheResult(): void
	{
		$root = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng';
		$apply = (string) file_get_contents("{$root}/pfblockerng_apply.inc");
		$install = php_strip_whitespace("{$root}/pfblockerng_install.inc");

		$this->assertSame(1, substr_count($apply, 'pfb_dns_proxy_ensure_running('), 'one call site');
		$this->assertMatchesRegularExpression('/if \(!pfb_dns_proxy_ensure_running\(\)\) \{/', $apply,
			'the apply reads whether the proxy became ready');
		$this->assertMatchesRegularExpression('/if \(pfb_dns_proxy_saved\(\) !== NULL\) \{ if \(!pfb_dns_proxy_restart\(\)\) \{/', $install,
			'the installer reads whether the restarted proxy became ready');
	}

	public function testTheResolverRestoreDoesNotConfirmItsOwnRestartOfTheProxy(): void
	{
		// The restore that was abandoned (the proxy outlived its stop) restarts the proxy WITHOUT waiting for readiness or
		// rolling back: a rollback that waited for the proxy it restarts would recurse into itself
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$start = (int) strpos($source, 'function pfb_dns_proxy_resolver(bool $on)');
		$end = (int) strpos($source, 'function pfb_dns_proxy_directive_text', $start);
		$body = substr($source, $start, $end - $start);

		$this->assertStringNotContainsString('pfb_dns_proxy_restart()', $body);
		$this->assertStringNotContainsString('pfb_dns_proxy_confirm_ready', $body);
		$this->assertStringNotContainsString('pfb_dns_proxy_roll_back', $body);
		$this->assertStringContainsString("restart_service('pfb_dns_proxy')", $body, 'it still brings the proxy that serves the moved Resolver back');
	}
}
