<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
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
 *   - a proxy that does become ready is left alone: no toggle write, no stop, no notice;
 *   - a restore that config.xml refuses, or that finds the proxy alive after its stop, leaves the moved Resolver served: the proxy
 *     is started again through its rc script, whether or not pfSense has a service entry for it (issue #3561).
 *
 * The same rollback, and the same restore, serve two later failures (owner, 2026-10): an unsafe Custom Options line
 * (`interface:`, `port:` or `include:`) the admin adds after the move rolls pfB-DNS back like a failed activation, the line
 * kept in the restored Custom Options and named in the one notice; and a DNS Resolver disabled while pfB-DNS fronts it makes
 * the next apply or tick stop pfB-DNS, restore the saved settings (the Resolver stays disabled), turn pfB-DNS off and say so
 * once, instead of leaving the proxy answering SERVFAIL for every allowed name.
 *
 * pfB-DNS is turned off only if config.xml takes the write that says so (pfSense's write_config() answers FALSE when it
 * refuses one and -1 when it did not write): a refused write is reported as a failure, this process holds the stored toggle
 * again, and nothing that follows the toggle (the proxy's stop, the restore, a notice that says "turned off") runs.
 */
#[CoversFunction('pfb_dns_proxy_roll_back')]
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_restart')]
#[CoversFunction('pfblockerng_tick')]
final class DnsProxyActivationRollbackTest extends TestCase
{
	use DnsProxyReadySeedTrait;
	use ConfigXmlDiskTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const TOGGLE = 'installedpackages/pfblockerngdns/config/0/pfb_dns';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const PFB_DNS = 'installedpackages/pfblockerngdns/config/0';
	private const GLOBALS = [
		'pfb', 'config', 'g', 'pfb_test_process_running', 'pfb_test_valid_pids', 'pfb_test_service_calls', 'pfb_test_service_hook',
		'pfb_test_rcfile_writes', 'pfb_test_rcfiles', 'pfb_test_write_config_calls', 'pfb_test_unbound_configure_calls',
		'pfb_test_unbound_configure_resolver', 'pfb_test_file_notices', 'pfb_test_try_lock_fail', 'pfb_test_lock_held',
		'pfb_test_lock_events', 'pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_interfaces', 'pfb_test_write_config_hook',
		'pfb_test_write_config_result', 'pfb_test_config_read_hook', 'pfb_test_config_read_calls', 'pfb_test_config_read_lock_held',
		'pfb_test_write_config_args', 'pfb_test_rcfile_dir',
		'pfb_test_mwexec', 'pfb_test_mwexec_hook',
		'pfb_test_lock_holders', 'pfb_test_try_lock_fail_names', 'pfb_test_try_lock_busy_for', 'pfb_test_config_read_fails',
		'pfb_test_config_read_fails_for',
	];

	private string $tmp;
	private array $savedGlobals = [];
	/** @var list<string> what the proxy was asked, in order: start_service, restart_service, stop_service; "rc stop" and "rc start" are the rc script's own, "<call> (no entry)" a call pfSense ignored, "<rc call> (no script)" one that found no script to run */
	private array $proxyCalls = [];
	/** @var list<bool> whether the config lock was held at each liveness probe of the child while PHP waited for readiness */
	private array $lockHeldWhileWaiting = [];
	private string $behaviour = 'lives';
	private bool $survivesStop = FALSE;
	/** Whether pfSense has a service entry for the proxy: while FALSE its start_service(), stop_service() and restart_service() do nothing. */
	private bool $registered = TRUE;
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
		DnsProxyCertificateFixtures::seedResolver($this->tmp);
		$GLOBALS['pfb_test_lock_held'] = FALSE;
		unset($GLOBALS['pfb_test_try_lock_fail'], $GLOBALS['pfb_test_rcfile_writes'], $GLOBALS['pfb_test_rcfiles']);
		$GLOBALS['pfb_test_lock_holders'] = [];
		unset($GLOBALS['pfb_test_try_lock_fail_names'], $GLOBALS['pfb_test_try_lock_busy_for'], $GLOBALS['pfb_test_config_read_fails'],
			$GLOBALS['pfb_test_config_read_fails_for']);
		// The Resolver the proxy took over listened on lan and opt1: both are configured, up and addressed, so a healthy start has
		// no warning for the startup check to report
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE], 'opt1' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => '', 'opt1' => ''];
		$this->proxyCalls = [];
		$this->lockHeldWhileWaiting = [];
		$this->behaviour = 'lives';
		$this->survivesStop = FALSE;
		$this->registered = TRUE;
		unset($GLOBALS['pfb_test_mwexec']);
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n");
		$this->clearProxyFiles();

		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service): void {
			if ($service !== 'pfb_dns_proxy') {
				return;
			}
			if (!$this->registered) {
				$this->proxyCalls[] = "{$fn} (no entry)";
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
		$GLOBALS['pfb_test_mwexec_hook'] = function (string $command): int {
			if (in_array($command, [PFB_DNS_PROXY_RCFILE . ' stop', PFB_DNS_PROXY_RCFILE . ' start'], TRUE) && !file_exists(PFB_DNS_PROXY_RCFILE)) {
				// The shell finds no script: nothing runs, and mwexec() answers with the shell's "command not found"
				$this->proxyCalls[] = str_replace(PFB_DNS_PROXY_RCFILE, 'rc', $command) . ' (no script)';
				return 127;
			}
			if ($command === PFB_DNS_PROXY_RCFILE . ' stop') {
				$this->proxyCalls[] = 'rc stop';
				if (!$this->survivesStop) {
					$this->clearProxyFiles();
					unset($GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE]);
				}
			} elseif ($command === PFB_DNS_PROXY_RCFILE . ' start') {
				$this->proxyCalls[] = 'rc start';
				// A pair that still serves is kept; anything less is replaced by one that serves
				if (!isvalidpid(PFB_DNS_PROXY_PIDFILE) || !isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE)) {
					$this->proxyServes();
					$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
				}
			}
			return 0;
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
		@unlink(PFB_DNS_PROXY_RCFILE);
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
		$before = $this->startAttempts();

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
		$this->assertSame($before + 1, $this->startAttempts(), 'and Unbound was started once with it');
		$conf = (string) file_get_contents("{$this->tmp}/unbound.conf");
		$this->assertStringContainsString('python-script: pfb_unbound.py', $conf, 'the file Unbound starts from names the DNSBL module again');
		$this->assertStringNotContainsString('pfb_upstream_observer', $conf, 'and no longer the observer');

		// ... the proxy was started once, then stopped, and never restarted or started again ...
		$this->assertSame(['start_service', 'rc stop'], $this->proxyCalls);

		// ... and the operator is told what happened and what is running now
		$this->assertSame(['pfBlockerNG DNS Proxy startup', 'pfBlockerNG DNS Proxy'], array_column($this->notices(), 'id'), 'the startup check names the failure, then the rollback notice says what was done');
		$notices = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy'));
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('did not become ready', $notices[0]['notice']);
		$this->assertStringContainsString('turned off', $notices[0]['notice']);
		$this->assertStringContainsString('DNS Resolver was restored', $notices[0]['notice']);
		$this->assertStringContainsString('DNSBL', $notices[0]['notice'], 'DNSBL runs in the Resolver again');
		$this->assertSame(2, $notices[0]['priority']);
		$this->assertStringContainsString('did not become ready', $this->pfbLog());
	}

	public function testADeciderThatExitsAtEveryStartIsRolledBackWithNoSupervisorLeftWhileTheServiceEntryIsAbsent(): void
	{
		// Given a moved Resolver, no service entry for the proxy (an install runs this before pfSense registers it), and the
		// supervisor alive between two failed starts: its pidfile is valid, the child's is empty, and no marker was published
		$this->activate(TRUE);
		$this->registered = FALSE;
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		file_put_contents($this->proxyPidfile(), '');
		@unlink($this->proxyMarker());
		$this->assertFalse(pfb_dns_proxy_running(), 'before: no child is alive');
		$this->assertTrue(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), 'before: the supervisor is');

		// When the apply starts the proxy and waits for it
		$ok = pfb_dns_proxy_ensure_running();

		// Then the activation failed, and the rollback stopped the supervisor itself: pfSense did nothing for either call
		$this->assertFalse($ok, 'the activation failed');
		$this->assertSame(['start_service (no entry)', 'rc stop'], $this->proxyCalls);
		$this->assertFalse(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), 'no supervisor is left to respawn the decider');

		// ... and the Resolver is the original, pfB-DNS is off, and the operator is told it was restored
		$this->assertResolverIsTheOriginal('rolled back');
		$this->assertSame('', $this->toggleStored(), 'pfB-DNS is turned off');
		$notices = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy'));
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('DNS Resolver was restored', $notices[0]['notice']);
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
		$this->assertSame(['start_service', 'rc stop'], $this->proxyCalls);
		$this->assertSame(['pfBlockerNG DNS Proxy startup', 'pfBlockerNG DNS Proxy'], array_column($this->notices(), 'id'), 'the startup check names the failure, then the rollback notice says what was done');
		$notices = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy'));
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
		$this->assertSame(['restart_service', 'rc stop'], $this->proxyCalls);

		// ... Unbound was started again after the restore (the reload's own start, then the rollback's) ...
		$this->assertSame($before + 2, $this->startAttempts(), 'the reload and the rollback each started Unbound once');

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
		$this->assertSame(['restart_service', 'rc stop'], $this->proxyCalls);
	}

	/**
	 * The state a package upgrade runs the install command in (issue #3562): delete_package_xml() deleted the package's service
	 * registrations and wrote config.xml, install_package_xml() adds them back only after the command, and pfSense's
	 * start_service() and stop_service() act only on a registered service. config.xml is a file from here on, so a fresh read
	 * (the rollback's, under the DNS config lock) sees only what was written.
	 */
	private function upgradeInstallState(): void
	{
		$GLOBALS['config']['installedpackages']['service'] = [['name' => 'squid', 'rcfile' => 'squid.sh']];
		$this->configXmlOnDisk();
		unset($GLOBALS['pfb_test_rcfile_writes'], $GLOBALS['pfb_test_write_config_args']);
		$proxy = $GLOBALS['pfb_test_service_hook'];
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn, string $service) use ($proxy): void {
			if (in_array($service, array_column(config_get_path('installedpackages/service', []), 'name'), TRUE)) {
				$proxy($fn, $service);
			}
		};
	}

	/** The installer's DNS proxy block, cut out of the shipped file between its anchors and run as shipped. */
	private function runInstallProxyBlock(): void
	{
		$install = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$from = strpos($install, '// Create DNS proxy service once its runtime files are staged');
		$to = strpos($install, 'if ($ufound) {', (int) $from);
		$this->assertIsInt($from, 'test bootstrap: the installer\'s proxy block lost its start anchor');
		$this->assertIsInt($to, 'test bootstrap: the installer\'s proxy block lost its end anchor');
		(static function (string $code): void {
			global $pfb;
			eval($code);
		})(substr($install, $from, $to - $from));
	}

	public function testAnUpgradeInstallRestartsTheProxyThatPfSenseUnregisteredBeforeTheInstallCommand(): void
	{
		// Given a moved Resolver and a proxy that serves once started, in the state an upgrade runs the install command in
		$this->activate(TRUE);
		$this->behaviour = 'serves';
		$this->upgradeInstallState();

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the proxy was restarted and serves: pfB-DNS stays on, the Resolver stays moved, nothing is rolled back
		$this->assertSame(['restart_service'], $this->proxyCalls, 'the restart reached a registered service');
		$this->assertTrue(pfb_dns_proxy_ready());
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is not turned off');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the Resolver stays moved');
		$this->assertSame([], $this->notices());
		$this->assertContains('pfb_dns_proxy', array_column($this->onDisk('installedpackages/service', []), 'name'),
			'the registration is in config.xml, so a fresh read keeps it');
		$this->assertSame([['pfBlockerNG: registered the package services before the DNS proxy restart', FALSE, TRUE]],
			$GLOBALS['pfb_test_write_config_args'], 'one write, of config.xml only: no backup, CARP sync or package plugins');
	}

	public function testAnUpgradeInstallWhoseProxyNeverServesStopsItAndGivesTheResolverBack(): void
	{
		// Given the same upgrade, and a proxy that lives and never publishes its marker
		$this->activate(TRUE);
		$this->upgradeInstallState();

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the restart reaches the service and the rollback, which reads config.xml afresh, stops the proxy through its rc
		// script: the proxy is stopped and the Resolver has its saved settings back
		$this->assertSame(['restart_service', 'rc stop'], $this->proxyCalls, 'the restart reached the service and the rollback\'s rc stop ran');
		$this->assertSame('', $this->toggleStored());
		$this->assertResolverIsTheOriginal('rolled back');
	}

	#[DataProvider('refusedWrites')]
	public function testAnUpgradeInstallWhoseRegistrationIsNotWrittenStillRestartsTheProxyAndSaysSo(mixed $answer): void
	{
		// Given the same upgrade, a proxy that serves once started, and config.xml refusing the registration's write
		$this->activate(TRUE);
		$this->behaviour = 'serves';
		$this->upgradeInstallState();
		$this->configXmlOnDisk($answer, 'registered the package services');

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the restart still reaches the service this process registered (stopping instead would leave the moved Resolver
		// unserved), and the log says the registration is not in config.xml, so a rollback could not stop the proxy
		$this->assertSame(['restart_service'], $this->proxyCalls);
		$this->assertSame('on', $this->toggleStored());
		$this->assertStringContainsString('the package services could not be written to config.xml', $this->pfbLog());
	}

	public function testAnUpgradeInstallWithTheResolverNotMovedStopsTheProxyService(): void
	{
		// Given no Resolver snapshot (pfB-DNS off), in the state an upgrade runs the install command in
		$this->activate(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		config_set_path(self::SAVED, '');
		$this->upgradeInstallState();

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the proxy's rc script is written and its service stopped, nothing started
		$this->assertSame(['stop_service'], $this->proxyCalls);
		$this->assertArrayHasKey('pfb_dns_proxy.sh', $GLOBALS['pfb_test_rcfile_writes'] ?? [], 'the rc script is written');
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

		// The toggle as config.xml holds it at each write, not only the in-memory copy
		$committed = [];
		$GLOBALS['pfb_test_write_config_hook'] = function () use (&$committed): void {
			$committed[] = $this->toggleStored();
		};

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
		$this->assertContains('', $committed, 'Off was written to config.xml, not only held in memory');

		// ... and the operator is told that recovery is needed, not that the old integration is back
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('could not be restored', $joined);
		$this->assertStringContainsString('kept', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined, 'no claim that the rollback worked');
		$this->assertSame(1, count(array_keys($this->proxyCalls, 'rc start', TRUE)), 'the proxy that serves the moved Resolver is brought back once, not in a loop');
	}

	/** @return array<string,array{bool,mixed}> whether pfSense has a service entry for the proxy, and write_config()'s answer to the refused write */
	public static function entryAndRefusedWrite(): array
	{
		$rows = [];
		foreach (['the service entry is registered' => TRUE, 'the service entry is absent' => FALSE] as $entry => $registered) {
			foreach (self::refusedWrites() as $write => [$answer]) {
				$rows["{$entry}, {$write}"] = [$registered, $answer];
			}
		}
		return $rows;
	}

	#[DataProvider('entryAndRefusedWrite')]
	public function testARestoreThatConfigXmlRefusesLeavesTheProxyServingTheMovedResolver(bool $registered, mixed $answer): void
	{
		// Given a moved Resolver, the healthy proxy that serves it, and a config.xml that refuses the restore's write
		$this->activate(TRUE);
		$this->registered = $registered;
		$this->behaviour = 'serves';
		$this->proxyServes();
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		$this->configXmlOnDisk($answer, 'Restored the DNS Resolver');
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));
		$this->assertTrue(pfb_dns_proxy_ready(), 'before: the proxy serves');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'before: config.xml holds the snapshot');

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore is reported as no change, config.xml keeps the snapshot and the moved Resolver, and the proxy the
		// restore stopped serves them again
		$this->assertFalse($changed);
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'config.xml keeps the snapshot');
		$this->assertSame($moved, self::sorted($this->onDisk('unbound')), 'and the moved Resolver');
		$this->assertTrue(pfb_dns_proxy_ready(), 'the proxy serves the moved Resolver again');
	}

	public function testTheRecoveryDoesNotReplaceAProxyThatOutlivedItsStop(): void
	{
		// Given a moved Resolver, no service entry, and a healthy proxy (child 7001) that its stop does not remove
		$this->activate(TRUE);
		$this->registered = FALSE;
		$this->survivesStop = TRUE;
		$this->proxyServes('7001');
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore is refused (the proxy still holds the port) and the same child and supervisor serve it
		$this->assertFalse($changed);
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the snapshot is kept');
		$this->assertSame($moved, self::sorted(config_get_path('unbound')), 'the Resolver stays moved');
		$this->assertSame("7001\n", (string) file_get_contents($this->proxyPidfile()), 'the same child serves');
		$this->assertSame("7001\n", (string) file_get_contents($this->proxyMarker()), 'with the marker it published');
		$this->assertTrue(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), 'under the same supervisor');
		$this->assertTrue(pfb_dns_proxy_ready());
	}

	public function testARestoreOnABoxThatNeverMovedTheResolverRunsNeitherAStopNorAStart(): void
	{
		// Given a Resolver pfB-DNS never touched: no snapshot, no block of ours, no proxy
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertNull(pfb_dns_proxy_saved(), 'before: no snapshot');
		$this->assertFalse(pfb_dns_proxy_block_present(), 'before: no block of ours');

		// When the restore is asked for
		$this->assertFalse(pfb_dns_proxy_resolver(FALSE));

		// Then nothing was stopped or started
		$this->assertSame([], $this->proxyCalls, 'no rc stop, no rc start, no service call');
		$this->assertFalse(pfb_dns_proxy_running(), 'and no proxy exists');
	}

	/** @return array<string,array{bool,int}> whether a healthy proxy runs, and how many writes the restore makes before it ends */
	public static function recoveryWithNoRcScript(): array
	{
		return [
			'a healthy proxy that cannot be stopped without the script: abandoned before any write' => [TRUE, 0],
			'no proxy running: the restore reaches its write and config.xml refuses it' => [FALSE, 1],
		];
	}

	#[DataProvider('recoveryWithNoRcScript')]
	public function testTheRecoveryWritesTheRcScriptItStartsTheProxyWith(bool $healthy, int $writes): void
	{
		// Given a moved Resolver, no service entry, no rc script on disk (a /var that came up empty), and a config.xml that refuses the restore's write
		$this->activate(TRUE);
		$this->registered = FALSE;
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		unlink(PFB_DNS_PROXY_RCFILE);
		if ($healthy) {
			$this->proxyServes();
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		}
		$this->configXmlOnDisk(FALSE, 'Restored the DNS Resolver');
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'before: no rc script');
		$this->assertSame($healthy, pfb_dns_proxy_ready(), 'before: the proxy serves only in the healthy row');

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore changed nothing, and the script the start runs was written first, so the proxy serves the moved Resolver
		$this->assertFalse($changed);
		$this->assertCount($writes, $GLOBALS['pfb_test_write_config_calls'], 'the path the row stands for ran');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'config.xml keeps the snapshot');
		$this->assertSame($moved, self::sorted($this->onDisk('unbound')), 'and the moved Resolver');
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE, 'the recovery regenerated the rc script');
		$this->assertNotContains('rc start (no script)', $this->proxyCalls, 'so its start found the script');
		$this->assertTrue(pfb_dns_proxy_ready(), 'the proxy serves the moved Resolver');
	}

	#[DataProvider('recoveryWithNoRcScript')]
	public function testTheRecoveryRunsNoRcScriptThatAListenPortConflictLeftUnwritten(bool $healthy, int $writes): void
	{
		// Given a moved Resolver whose Listen Port the admin set to the proxy's own port after the move (the generator then writes no
		// script), no service entry, no rc script on disk, and a config.xml that refuses the restore's write
		$this->activate(TRUE);
		$this->registered = FALSE;
		config_set_path('unbound/port', '5353');
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		unlink(PFB_DNS_PROXY_RCFILE);
		if ($healthy) {
			$this->proxyServes();
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		}
		$this->configXmlOnDisk(FALSE, 'Restored the DNS Resolver');
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));
		$this->assertSame('5353', $this->onDisk('unbound/port'), 'before: config.xml holds the conflicting Listen Port');
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'before: no rc script');

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore changed nothing, no script was written, and nothing was run against the script that is not there
		$this->assertFalse($changed);
		$this->assertCount($writes, $GLOBALS['pfb_test_write_config_calls'], 'the path the row stands for ran');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'config.xml keeps the snapshot');
		$this->assertSame($moved, self::sorted($this->onDisk('unbound')), 'and the moved Resolver');
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'the generator wrote no script');
		$this->assertSame([], $this->proxyCalls, 'no stop and no start was run against a missing script');
	}

	public function testAReadinessRollbackWhoseProxySurvivesItsStopSaysNothingAnswersDnsUntilTheRestoreSucceeds(): void
	{
		// Given a proxy that never serves and survives its stop too
		$this->activate(TRUE);
		$this->survivesStop = TRUE;

		// When the activation fails and the restore is refused
		$this->assertFalse(pfb_dns_proxy_ensure_running(), 'before: the activation failed');

		// Then the last notice names the state: the Resolver is moved aside for a proxy that is not ready
		$texts = array_column($this->notices(), 'notice');
		$this->assertStringContainsString('nothing answers DNS', (string) end($texts));
		$this->assertStringContainsString('turned off', (string) end($texts));
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
		// Given a proxy that serves since before this apply, with the Resolver's certificate it was given (nothing to push to it)
		$this->activate(TRUE);
		pfb_dns_proxy_service();
		$this->proxyServes();
		file_put_contents(pfb_dns_proxy_certificate_pushed_path(), hash('sha256', (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert'])));
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

	public function testTheRollbackCalledDirectlyReportsFailureWhileTheSnapshotIsKept(): void
	{
		// Given a moved Resolver and a proxy that is still alive after its stop, so the restore is abandoned
		$this->activate(TRUE);
		$this->survivesStop = TRUE;
		$this->proxyLivesButNeverServes();

		$this->assertFalse(pfb_dns_proxy_roll_back(), 'not restored: the caller is told the old integration is not back');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept for the next restore');
	}

	// -----------------------------------------------------------------------
	// E -- an unsafe Custom Options line added after the move rolls pfB-DNS back like a failed activation
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:string}> the admin's own lines that can take a listener, a second port or another file */
	public static function unsafeLines(): array
	{
		return [
			'a port line'                     => ['port: 5300'],
			'an interface on the Listen Port' => ['interface: 0.0.0.0@53'],
			'an interface on the proxy port'  => ['interface: 192.0.2.1@5353'],
			'an include'                      => ['include: /tmp/extra.conf'],
		];
	}

	private function customText(): string
	{
		return (string) base64_decode((string) config_get_path('unbound/custom_options'), TRUE);
	}

	/** @return list<string> the non-blank lines of Custom Options */
	private function customLines(): array
	{
		return array_values(array_filter(array_map('trim', explode("\n", $this->customText())), 'strlen'));
	}

	/** The admin edits Custom Options on the Resolver page: the text stays, a line is appended after our block. */
	private function adminAppends(string $line): void
	{
		config_set_path('unbound/custom_options', base64_encode($this->customText() . "\nserver:\n{$line}\n"));
	}

	#[DataProvider('unsafeLines')]
	public function testAnUnsafeLineAddedAfterTheMoveTurnsPfbDnsOffRestoresTheResolverAndKeepsTheLine(string $line): void
	{
		// Given a moved Resolver with DNSBL on, and an admin who then adds an unsafe line to its Custom Options
		$this->activate(TRUE);
		$this->proxyServes();
		$this->adminAppends($line);
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is on');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the Resolver is moved');
		$before = $this->startAttempts();

		// When the next apply runs
		$changed = pfb_unbound_python('enabled', TRUE);

		// Then pfB-DNS is off and the Resolver is back to its saved settings: the admin's line is kept, our block is gone
		$this->assertSame('', $this->toggleStored(), 'pfB-DNS is turned off');
		$this->assertNull(pfb_dns_proxy_saved(), 'the snapshot is consumed');
		$unbound = config_get_path('unbound');
		unset($unbound['python'], $unbound['python_order'], $unbound['python_script']);
		unset($unbound['custom_options']);
		$expected = self::originalResolver();
		unset($expected['custom_options']);
		$this->assertSame(self::sorted($expected), self::sorted($unbound), 'every other key is exactly as saved');
		$this->assertSame(['do-ip6: no', 'prefetch: yes', 'server:', $line], $this->customLines(), "the admin's line is kept, in their own text");
		$this->assertStringNotContainsString('pfBlockerNG DNS proxy', $this->customText(), 'our block is gone');

		// ... the proxy was stopped once, the DNSBL module is back in Unbound, which was regenerated and restarted once ...
		$this->assertSame(['rc stop'], $this->proxyCalls);
		$this->assertSame('pfb_unbound', config_get_path('unbound/python_script'));
		$last = end($GLOBALS['pfb_test_unbound_configure_resolver']);
		$this->assertSame('lan,opt1', $last['active_interface'], 'unbound.conf is rendered from the restored Resolver');
		$this->assertSame($before + 1, $this->startAttempts(), 'Unbound was started once with it');
		$this->assertFalse($changed, 'the rollback already regenerated and restarted: the apply has nothing left to signal');

		// ... and the operator is told once, with the line, that it was kept
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringContainsString($line, $notices[0]['notice']);
		$this->assertStringContainsString('Custom Options', $notices[0]['notice']);
		$this->assertStringContainsString('kept', $notices[0]['notice']);
		$this->assertStringContainsString('turned off', $notices[0]['notice']);
		$this->assertStringContainsString('DNS Resolver was restored', $notices[0]['notice']);
		$this->assertSame(2, $notices[0]['priority']);
	}

	public function testTheApplyAfterAnUnsafeLineRollbackRaisesNothingAndLeavesTheLine(): void
	{
		// Given an unsafe line that was rolled back
		$this->activate(TRUE);
		$this->proxyServes();
		$this->adminAppends('interface: 0.0.0.0@53');
		pfb_unbound_python('enabled', TRUE);
		$this->assertSame('', $this->toggleStored(), 'before: rolled back');
		$calls = $this->proxyCalls;
		$notices = count($this->notices());
		$text = $this->customText();

		// When the next apply runs
		pfb_unbound_python('enabled');

		// Then nothing happens again: no second notice, no proxy call, the admin's text byte for byte
		$this->assertCount($notices, $this->notices());
		$this->assertSame($calls, $this->proxyCalls);
		$this->assertSame($text, $this->customText());
		$this->assertSame('', $this->toggleStored());
	}

	public function testALineThatIsNotUnsafeAddedAfterTheMoveLeavesPfbDnsRunning(): void
	{
		// Given a moved Resolver and an admin who adds a harmless line to Custom Options
		$this->activate(TRUE);
		$this->proxyServes();
		$this->adminAppends('local-data: "x.example. A 192.0.2.1"');

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then pfB-DNS keeps the Resolver: no rollback, no notice, nothing stopped
		$this->assertSame('on', $this->toggleStored());
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
	}

	public function testWithDnsblOffTheUnsafeLineRollbackPutsNoModuleBack(): void
	{
		// Given a moved Resolver with DNSBL off and an unsafe line added after the move
		$this->activate(FALSE);
		$this->useMountState(FALSE);
		$this->proxyServes();
		$this->adminAppends('port: 5300');

		// When the next apply runs
		pfb_unbound_python('disabled', TRUE);

		// Then the Resolver is back with the line, plain: no python module or observer, and the notice does not mention DNSBL
		$this->assertSame('', $this->toggleStored());
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertSame(['do-ip6: no', 'prefetch: yes', 'server:', 'port: 5300'], $this->customLines());
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringNotContainsString('DNSBL', $notices[0]['notice']);
	}

	public function testAnUnsafeLineRollbackThatCannotStopTheProxyKeepsTheLineInTheSnapshotAndSaysRecoveryIsNeeded(): void
	{
		// Given an unsafe line, and a proxy that survives its stop
		$this->activate(TRUE);
		$this->proxyServes();
		$this->survivesStop = TRUE;
		$this->adminAppends('include: /tmp/extra.conf');
		$moved = config_get_path('unbound');

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then pfB-DNS is off (the next apply retries the restore), the moved Resolver and its snapshot are kept, and the snapshot
		// holds the admin's line so the retry keeps it too
		$this->assertSame('', $this->toggleStored());
		$saved = pfb_dns_proxy_saved();
		$this->assertNotNull($saved, 'the snapshot is kept');
		$this->assertStringContainsString('include: /tmp/extra.conf', (string) base64_decode($saved['custom_options']['value'], TRUE));
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')), 'the moved Resolver is untouched');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('could not be restored', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined, 'no claim that the rollback worked');
		$this->assertStringNotContainsString('did not become ready', $joined, 'an unsafe line is no readiness failure');
		$this->assertStringNotContainsString('nothing answers DNS', $joined, 'the proxy served until its stop');

		// And once the proxy can be stopped, the next apply's ordinary restore puts the Resolver back with the line
		$this->survivesStop = FALSE;
		pfb_unbound_python('enabled');
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertSame(['do-ip6: no', 'prefetch: yes', 'server:', 'include: /tmp/extra.conf'], $this->customLines());
	}

	// -----------------------------------------------------------------------
	// E2 -- a Listen Port set to the proxy's own port after the move rolls pfB-DNS back the same way
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:string,1:bool}> the proxy's own loopback ports, each with DNSBL on and off */
	public static function reservedListenPorts(): array
	{
		return [
			'5353 with DNSBL on'  => ['5353', TRUE],
			'5353 with DNSBL off' => ['5353', FALSE],
			'5354 with DNSBL on'  => ['5354', TRUE],
			'5354 with DNSBL off' => ['5354', FALSE],
		];
	}

	#[DataProvider('reservedListenPorts')]
	public function testAListenPortSetOnTheMovedResolverRollsPfbDnsBackAndKeepsThatPort(string $port, bool $dnsbl): void
	{
		// Given a moved Resolver with DNSBL on or off, a proxy that serves, and an admin who then sets its Listen Port to the proxy's own port
		$this->activate($dnsbl);
		if (!$dnsbl) {
			$this->useMountState(FALSE);
		}
		$this->proxyServes();
		config_set_path('unbound/port', $port);
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is on');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the Resolver is moved');
		$before = $this->startAttempts();
		$rc = $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0;

		// When the next apply runs
		$changed = pfb_unbound_python($dnsbl ? 'enabled' : 'disabled', TRUE);

		// Then pfB-DNS is off and the proxy is stopped once: every saved key is back, and the Listen Port is the admin's
		$this->assertSame('', $this->toggleStored(), 'pfB-DNS is turned off');
		$this->assertSame(['rc stop'], $this->proxyCalls);
		$this->assertNull(pfb_dns_proxy_saved(), 'the snapshot is consumed');
		$expected = self::originalResolver();
		$expected['port'] = $port;
		$unbound = config_get_path('unbound');
		unset($unbound['python'], $unbound['python_order'], $unbound['python_script']);
		$this->assertSame(self::sorted($expected), self::sorted($unbound), 'the saved keys are back and the Listen Port stays as the admin set it');

		// And DNSBL is back in the Resolver only when it is on; Unbound was regenerated and started once, and no regenerated
		// config carries the proxy's clause or the proxy's rc script is written again
		if ($dnsbl) {
			$this->assertSame('pfb_unbound', config_get_path('unbound/python_script'));
		} else {
			$this->assertFalse(config_path_enabled('unbound', 'python'));
		}
		$this->assertSame($before + 1, $this->startAttempts(), 'Unbound was started once');
		$this->assertNotEmpty($GLOBALS['pfb_test_unbound_configure_resolver']);
		foreach ($GLOBALS['pfb_test_unbound_configure_resolver'] as $rendered) {
			$this->assertStringNotContainsString('pfBlockerNG DNS proxy',
				(string) base64_decode((string) ($rendered['custom_options'] ?? ''), TRUE), 'the proxy\'s clause is not rendered again');
		}
		$this->assertSame($rc, $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0, 'the proxy\'s rc script is not written again');
		$this->assertFalse($changed, 'the rollback already regenerated and restarted: the apply has nothing left to signal');

		// And the operator is told once, naming the Listen Port and its port, and nothing about a Custom Options line
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('Listen Port', $notices[0]['notice']);
		$this->assertStringContainsString($port, $notices[0]['notice']);
		$this->assertStringContainsString('turned off', $notices[0]['notice']);
		$this->assertStringContainsString('DNS Resolver was restored', $notices[0]['notice']);
		$this->assertStringNotContainsString('Custom Options', $notices[0]['notice']);
		$this->assertStringNotContainsString('kept', $notices[0]['notice']);
		if ($dnsbl) {
			$this->assertStringContainsString('DNSBL runs in the DNS Resolver again', $notices[0]['notice']);
		} else {
			$this->assertStringNotContainsString('DNSBL', $notices[0]['notice']);
		}
		$this->assertSame(2, $notices[0]['priority']);

		// When the next apply runs again, and a readiness check of the proxy follows
		$calls = $this->proxyCalls;
		$this->assertTrue(pfb_dns_proxy_ensure_running(), 'nothing is moved, so there is nothing to wait for');
		pfb_unbound_python($dnsbl ? 'enabled' : 'disabled');

		// Then nothing starts or restarts the proxy again, pfB-DNS stays off, and the operator is not told a second time
		$this->assertSame($calls, $this->proxyCalls, 'no resurrection of the proxy');
		$this->assertSame('', $this->toggleStored());
		$this->assertCount(1, $this->notices());
		$this->assertSame($port, config_get_path('unbound/port'));
	}

	public function testAListenPortRollbackThatCannotStopTheProxyKeepsTheMovedResolverAndSaysRecoveryIsNeeded(): void
	{
		// Given a Listen Port of 5353 set after the move, and a proxy that survives its stop
		$this->activate(TRUE);
		$this->proxyServes();
		$this->survivesStop = TRUE;
		config_set_path('unbound/port', '5353');
		$moved = self::sorted(config_get_path('unbound'));

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then pfB-DNS is off, the moved Resolver and its snapshot are kept as they were, and the operator is told recovery is needed
		$this->assertSame('', $this->toggleStored());
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertSame($moved, self::sorted(config_get_path('unbound')), 'the moved Resolver is untouched');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('could not be restored', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined, 'no claim that the rollback worked');

		// And once the proxy can be stopped, the next apply restores the saved keys and keeps the Listen Port
		$this->survivesStop = FALSE;
		pfb_unbound_python('enabled');
		$this->assertNull(pfb_dns_proxy_saved(), 'the snapshot is consumed by the ordinary restore');
		$this->assertSame('lan,opt1', config_get_path('unbound/active_interface'));
		$this->assertSame('5353', config_get_path('unbound/port'));
	}

	public function testAListenPortRollbackWhoseConfigLockIsTakenChangesNothingAndSaysSo(): void
	{
		// Given a moved Resolver whose Listen Port the admin set to 5353, and another process saving config.xml throughout
		$this->activate(TRUE);
		$this->proxyServes();
		config_set_path('unbound/port', '5353');
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$calls = $this->proxyCalls;
		$moved = self::sorted(config_get_path('unbound'));

		// When the rollback runs
		$restored = pfb_dns_proxy_roll_back("the DNS Resolver's Listen Port is 5353, a loopback port the DNS proxy gives Unbound, after pfB-DNS took the Resolver");

		// Then nothing is stopped, written or restored: pfB-DNS stays on, the snapshot and the moved Resolver are kept, and the notice says so
		$this->assertFalse($restored);
		$this->assertSame($calls, $this->proxyCalls, 'the proxy is not stopped without the lock');
		$this->assertSame('on', $this->toggleStored());
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertSame($moved, self::sorted(config_get_path('unbound')), 'the moved Resolver is untouched');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('locked', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined);
	}

	public function testAValidListenPortSetAfterTheMoveLeavesPfbDnsRunning(): void
	{
		// Given a moved Resolver and an admin who sets its Listen Port to 5300, a port the proxy does not use
		$this->activate(TRUE);
		$this->proxyServes();
		config_set_path('unbound/port', '5300');

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then pfB-DNS keeps the Resolver: no rollback, no notice, nothing stopped, and the port is the admin's
		$this->assertSame('on', $this->toggleStored());
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame('5300', config_get_path('unbound/port'));
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
	}

	// -----------------------------------------------------------------------
	// E3 -- a Listen Port set after the move never moves the gateway onto a proxy port while the rollback cannot finish
	// -----------------------------------------------------------------------

	/** The port the gateway's rc script serves, from its start command (`--port N`). */
	private function servedPort(): ?string
	{
		$rc = (string) ($GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh']['start'] ?? '');
		return preg_match('/--port (\d+) /', $rc, $m) === 1 ? $m[1] : NULL;
	}

	public function testALockedConfigCannotMoveTheGatewayOntoAListenPortSetAfterTheMove(): void
	{
		// Given a moved Resolver whose gateway serves the port it had at the move, and an admin who then sets the Listen Port to 5353
		// while another save holds config.xml for the whole apply
		$this->activate(TRUE);
		$this->proxyServes();
		$served = $this->servedPort();
		config_set_path('unbound/port', '5353');
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When the apply runs its Resolver pass and then its proxy check
		pfb_unbound_python('enabled', TRUE);
		pfb_dns_proxy_ensure_running();

		// Then the gateway still serves the port it had: its rc script is not rewritten onto the Listen Port, and nothing restarts it
		$this->assertSame('53', $served, 'before: the gateway serves the port the Resolver had');
		$this->assertSame('53', $this->servedPort(), 'the gateway keeps serving the port it had');
		$this->assertSame([], $this->proxyCalls, 'the proxy is neither stopped nor restarted');
		$this->assertSame('on', $this->toggleStored(), 'the lock kept the rollback from turning pfB-DNS off');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
	}

	public function testAProxyThatOutlivesTheRollbackKeepsItsServingPortWhenTheListenPortIsSetAfterTheMove(): void
	{
		// Given a moved Resolver whose gateway serves the port it had at the move, a Listen Port of 5353 set after the move,
		// and a proxy that survives the rollback's stop
		$this->activate(TRUE);
		$this->proxyServes();
		$served = $this->servedPort();
		config_set_path('unbound/port', '5353');
		$this->survivesStop = TRUE;
		// A restart brings the proxy back serving, as a live one does: the check below must find it ready, not a new failure
		$this->behaviour = 'serves';

		// When the apply runs its Resolver pass, which rolls back and fails, and then its proxy check
		pfb_unbound_python('enabled', TRUE);
		$calls = $this->proxyCalls;
		pfb_dns_proxy_ensure_running();

		// Then the proxy check neither restarts nor rewrites the gateway: it keeps serving the port it had
		$this->assertSame('53', $served, 'before: the gateway serves the port the Resolver had');
		$this->assertSame($served, $this->servedPort(), 'the gateway keeps serving the port it had');
		$this->assertSame($calls, $this->proxyCalls, 'the proxy check after the failed rollback does not restart the proxy');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
	}

	// -----------------------------------------------------------------------
	// F -- a Resolver disabled underneath pfB-DNS: stand down
	// -----------------------------------------------------------------------

	/** The admin disables the DNS Resolver in Services > DNS Resolver while pfB-DNS fronts it. */
	private function disableTheResolver(): void
	{
		config_del_path('unbound/enable');
		$this->assertFalse(config_path_enabled('unbound'), 'before: the Resolver is disabled');
	}

	public function testADisabledResolverIsStoodDownOnTheNextApply(): void
	{
		// Given pfB-DNS on and serving, and the Resolver then disabled
		$this->activate(TRUE);
		$this->proxyServes();
		$this->disableTheResolver();
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is on');
		$before = $this->startAttempts();

		// When the next apply runs
		$changed = pfb_unbound_python('');

		// Then pfB-DNS is stopped and off, the Resolver has its saved settings and stays disabled, once and announced once
		$this->assertTrue($changed);
		$this->assertSame('', $this->toggleStored(), 'pfB-DNS is turned off');
		$this->assertSame(['rc stop'], $this->proxyCalls, 'the proxy is stopped');
		$this->assertNull(pfb_dns_proxy_saved(), 'the snapshot is consumed');
		$this->assertFalse(config_path_enabled('unbound'), 'the Resolver stays disabled');
		$unbound = config_get_path('unbound');
		unset($unbound['python'], $unbound['python_order'], $unbound['python_script']);
		$expected = self::originalResolver();
		unset($expected['enable']);
		$this->assertSame(self::sorted($expected), self::sorted($unbound), 'exactly the saved settings');
		$this->assertSame($before, $this->startAttempts(), 'nothing starts a Resolver the admin disabled');
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('DNS Resolver is disabled', $notices[0]['notice']);
		$this->assertStringContainsString('turned off', $notices[0]['notice']);
		$this->assertStringContainsString('restored', $notices[0]['notice']);
		$this->assertSame(2, $notices[0]['priority']);
	}

	public function testTheApplyAfterTheStandDownRaisesNoSecondNotice(): void
	{
		// Given a stood-down Resolver
		$this->activate(TRUE);
		$this->proxyServes();
		$this->disableTheResolver();
		pfb_unbound_python('');
		$this->assertSame('', $this->toggleStored(), 'before: stood down');
		$calls = $this->proxyCalls;

		// When the next apply runs
		$changed = pfb_unbound_python('');

		// Then nothing happens again
		$this->assertFalse($changed);
		$this->assertCount(1, $this->notices(), 'one notice for the one stand-down');
		$this->assertSame($calls, $this->proxyCalls);
	}

	public function testADisabledPfBlockerNgIsAnOrdinaryRestoreThatLeavesTheToggleAlone(): void
	{
		// Given pfB-DNS on and a moved Resolver, with pfBlockerNG itself disabled and the Resolver disabled too
		$this->activate(TRUE);
		$this->proxyServes();
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::Off);
		$this->disableTheResolver();

		// When the pass runs
		pfb_unbound_python('disabled');

		// Then the Resolver is restored as for any disabled package: the toggle the admin set stays, and there is no stand-down notice
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame([], $this->notices());
	}

	public function testADisabledResolverWithPfbDnsAlreadyOffIsAnOrdinaryRestoreWithoutANotice(): void
	{
		// Given a Resolver that is still moved (an earlier restore was abandoned), pfB-DNS off, and the Resolver disabled
		$this->activate(TRUE);
		$this->proxyServes();
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		$this->disableTheResolver();

		// When the next apply runs
		pfb_unbound_python('');

		// Then the ordinary restore finishes the job without announcing a stand-down
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertSame('', $this->toggleStored());
		$this->assertSame([], $this->notices());
	}

	public function testAStandDownThatCannotStopTheProxyKeepsTheSnapshotAndTheNextApplyFinishesTheRestore(): void
	{
		// Given a disabled Resolver and a proxy that survives its stop
		$this->activate(TRUE);
		$this->proxyServes();
		$this->survivesStop = TRUE;
		$this->disableTheResolver();

		// When the next apply runs
		pfb_unbound_python('');

		// Then pfB-DNS is off and the snapshot is kept, and the notices say the restore is pending
		$this->assertSame('', $this->toggleStored());
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('turned off', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined, 'no claim that the restore worked');

		// And once the proxy can be stopped, the next apply restores without a second stand-down notice
		$notices = count($this->notices());
		$this->survivesStop = FALSE;
		pfb_unbound_python('');
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertCount($notices, $this->notices());
	}

	public function testAStandDownWhileConfigXmlIsLockedChangesNothing(): void
	{
		// Given a disabled Resolver and another process saving config.xml for as long as the apply tries
		$this->activate(TRUE);
		$this->proxyServes();
		$this->disableTheResolver();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$moved = config_get_path('unbound');
		$writes = count($GLOBALS['pfb_test_write_config_calls']);

		// When the next apply runs
		pfb_unbound_python('');

		// Then nothing was stopped, written or restored: pfB-DNS stays on and the next apply or tick retries
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame([], $this->proxyCalls);
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')));
		$this->assertCount($writes, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testAPassNeverStartsAResolverTheAdminDisabled(): void
	{
		// Given a Resolver with nothing of ours moved, and Unbound stopped; first enabled: a restart starts it once
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$before = $this->startAttempts();
		$started = pfb_stop_start_unbound('');
		$this->assertSame(0, $started['retval']);
		$this->assertSame($before + 1, $this->startAttempts(), 'before: an enabled Resolver is started by the restart');

		// When the admin disables the Resolver (the stand-down above leaves it so) and a pass restarts Unbound again
		config_del_path('unbound/enable');
		$disabled = pfb_stop_start_unbound('');

		// Then nothing is started, and the restart reports no failure
		$this->assertSame($before + 1, $this->startAttempts(), 'a disabled Resolver is not started');
		$this->assertTrue($disabled['start_completed']);
		$this->assertSame(0, $disabled['retval']);
		$this->assertStringContainsString('disabled', $this->pfbLog());
	}

	public function testADnsblReloadWithPfbDnsOffRestartsAnEnabledResolverAndLeavesADisabledOneStopped(): void
	{
		// Given pfB-DNS off and nothing moved (the DNSBL-only path), and Unbound stopped
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertSame('', $this->toggleStored(), 'before: pfB-DNS is off');
		$this->assertNull(pfb_dns_proxy_saved(), 'before: nothing is moved');
		$before = $this->startAttempts();

		// When the DNSBL reload restarts Unbound with the Resolver enabled, then again with it disabled
		pfb_reload_unbound('enabled', FALSE, TRUE);
		$enabled = $this->startAttempts();
		config_del_path('unbound/enable');
		pfb_reload_unbound('', FALSE, TRUE);

		// Then only the enabled Resolver was started
		$this->assertSame($before + 1, $enabled, 'an enabled Resolver is restarted as before');
		$this->assertSame($enabled, $this->startAttempts(), 'a disabled Resolver is left stopped');
	}

	/**
	 * A moved Resolver whose snapshot is lost cannot be put back: the rollback reports the old integration is not back, and no
	 * notice says the Resolver was restored.
	 */
	public function testAnOrphanedResolverIsNeverReportedRestoredByTheRollback(): void
	{
		// Given the activation moved the Resolver and the snapshot is then lost while our block stays
		$this->activate(TRUE);
		config_set_path(self::SAVED, '');

		// When the rollback runs
		$restored = pfb_dns_proxy_roll_back();

		// Then the rollback fails, and its notice names the hand recovery instead of a restore
		$this->assertFalse($restored, 'the Resolver cannot be put back from a snapshot that is gone');
		$texts = array_column($this->notices(), 'notice');
		$this->assertNotEmpty($texts, 'the operator is told');
		foreach ($texts as $text) {
			$this->assertStringNotContainsString('to its previous settings', $text, 'no restore is claimed');
		}
		$this->assertStringContainsString('manual recovery required', end($texts));
	}

	/** @return array<string,array{string}> a stored marker that is no snapshot */
	public static function unconfirmedMarkers(): array
	{
		return [
			'the single character 0'           => ['0'],
			'the text of an interrupted write' => ['!!!truncated-snapshot!!!'],
			'base64 of text that is not JSON'  => [base64_encode('not json')],
		];
	}

	/**
	 * A saved state that cannot be confirmed (a marker that is no snapshot, none of our block in Custom Options) is never reported
	 * as a restore: nothing can be put back from it, and nothing says what the Resolver was before.
	 */
	#[DataProvider('unconfirmedMarkers')]
	public function testAMarkerThatIsNoSnapshotIsNeverReportedRestoredByTheRollback(string $marker): void
	{
		// Given the activation moved the Resolver, and the saved copy and our block are then both gone from config.xml
		$this->activate(TRUE);
		config_set_path(self::SAVED, $marker);
		config_set_path('unbound/custom_options', base64_encode("do-ip6: no\nprefetch: yes"));
		$this->assertNull(pfb_dns_proxy_saved(), 'before: the marker is no snapshot');
		$this->assertFalse(pfb_dns_proxy_block_present(), 'before: no block of ours');

		// When the rollback runs
		$restored = pfb_dns_proxy_roll_back();

		// Then it fails, the marker is kept as stored, and the notice asks for a manual repair instead of claiming a restore
		$this->assertFalse($restored, 'nothing can be put back from a marker that is no snapshot');
		$this->assertSame($marker, (string) config_get_path(self::SAVED, ''), 'the marker is kept verbatim');
		$texts = array_column($this->notices(), 'notice');
		$this->assertNotEmpty($texts, 'the operator is told');
		foreach ($texts as $text) {
			$this->assertStringNotContainsString('to its previous settings', $text, 'no restore is claimed');
		}
		$this->assertStringContainsString('manual repair required', end($texts));
		$this->assertStringNotContainsString('still carries', end($texts));
		$this->assertStringNotContainsString('see the notice before this one', end($texts), 'no restore was tried, so no earlier notice exists');
	}

	public function testAConfigLockHeldForOneWaitIsRetriedOnceAndTheRollbackStillRestoresTheResolver(): void
	{
		// Given a proxy that never serves, and a save that holds config.xml for longer than one lock wait but not two
		$this->activate(TRUE);
		$GLOBALS['pfb_test_try_lock_busy_for'] = PFB_DNS_CONFIG_LOCK_WAIT + 5;

		// When the activation fails and the rollback runs
		$ok = pfb_dns_proxy_ensure_running();

		// Then the rollback retried the lock once, after the save released it, and put the Resolver back
		$this->assertFalse($ok, 'the activation failed');
		$this->assertSame('', $this->toggleStored(), 'pfB-DNS is turned off');
		$this->assertResolverIsTheOriginal('rolled back');
	}

	public function testTheProxysRcScriptNamesTheSnapshotWhenUnboundIsRegeneratedForTheMove(): void
	{
		// Given Unbound regenerated for the move: pfSense's boot hook runs the proxy's rc script at that moment
		$seen = NULL;
		$GLOBALS['pfb_test_unbound_configure_hook'] = static function () use (&$seen): void {
			$seen ??= $GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh'] ?? NULL;
		};

		// When the proxy takes the Resolver
		$this->activate(TRUE);
		unset($GLOBALS['pfb_test_unbound_configure_hook']);

		// Then the script that Unbound's boot hook runs names the snapshot: generated for it, not the install-time one that
		// refuses to start ("not a valid snapshot")
		$this->assertNotNull($seen, 'Unbound was regenerated for the move with the proxy\'s rc script already written');
		pfb_dns_proxy_service();
		$this->assertSame($GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh'], $seen, 'the script is the one for the moved Resolver\'s snapshot');
	}

	public function testARollbackFromAProcessThatDidNotRunTheAppliesLoaderKeepsTheDecisionCacheCapTheApplyWrote(): void
	{
		// Given a decision cache cap of 777 in the stored DNSBL settings, and the module's ini as the apply wrote it
		$this->activate(TRUE);
		config_set_path(self::DNSBL . '/pfb_py_cache_max', '777');
		pfb_global();
		pfb_dnsbl_ini_inputs();
		file_put_contents($GLOBALS['pfb']['unbound_py_conf'], pfb_unbound_python_ini('enabled'));
		$this->assertStringContainsString("decisiondb_max\t= 777", (string) file_get_contents($GLOBALS['pfb']['unbound_py_conf']),
			'before: the ini carries the cap the apply wrote');

		// And the process that rolls back did not run the apply's loader: nothing holds the cap's value in $pfb
		unset($GLOBALS['pfb']['dnsbl_decisiondb_max']);

		// When the proxy never serves and the activation is rolled back
		$ok = pfb_dns_proxy_ensure_running();

		// Then the module's ini is written again with the cap the stored settings hold, not the default
		$this->assertFalse($ok, 'the activation failed');
		$this->assertStringContainsString("decisiondb_max\t= 777", (string) file_get_contents($GLOBALS['pfb']['unbound_py_conf']),
			'the rollback writes the cap the stored settings hold');
	}

	// -----------------------------------------------------------------------
	// G -- config.xml does not take the write that turns pfB-DNS off or that keeps the admin's line
	// -----------------------------------------------------------------------

	#[DataProvider('refusedWrites')]
	public function testATurnOffWhoseWriteIsRefusedIsNotReportedAndLeavesTheToggleAsStored(mixed $answer): void
	{
		// Given pfB-DNS on with the Resolver moved, and a config.xml that does not take the write
		$this->activate(TRUE);
		$this->configXmlOnDisk($answer);
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is requested');

		// When pfB-DNS is turned off
		$turnedOff = pfb_dns_proxy_turn_off('the proxy did not become ready');

		// Then it is not reported as turned off: the toggle is On in config.xml, and this process holds that stored toggle
		$this->assertFalse($turnedOff);
		$this->assertSame('on', $this->onDisk(self::TOGGLE), 'config.xml still requests pfB-DNS');
		$this->assertSame('on', $this->toggleStored(), 'and the copy held here is the stored one: nothing written next puts Off in config.xml half way');
		$this->assertFalse(!empty($GLOBALS['pfb_test_lock_held']), 'the config lock is released');
	}

	#[DataProvider('refusedWrites')]
	public function testARollbackWhoseTurnOffWriteIsRefusedChangesNothingAndNeverSaysPfbDnsWasTurnedOff(mixed $answer): void
	{
		// Given a moved Resolver and a proxy that never serves, and a config.xml that refuses the write that turns pfB-DNS off
		// (and takes every other: a rollback that went on would write the restored Resolver with pfB-DNS still On)
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk($answer, 'pfB-DNS turned off');
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = config_get_path('unbound');
		$this->assertSame($moved, $this->onDisk('unbound'), 'before: config.xml holds the moved Resolver');

		// When the activation is rolled back
		$ok = pfb_dns_proxy_roll_back();

		// Then the rollback says it did not work, and nothing was stopped, restored or written behind that refusal
		$this->assertFalse($ok);
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls'], 'the refused write is the only write: no restore persists pfB-DNS On beside the old Resolver');
		$this->assertSame('on', $this->onDisk(self::TOGGLE), 'config.xml still requests pfB-DNS');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'and keeps the snapshot');
		$this->assertSame($moved, $this->onDisk('unbound'), 'and the moved Resolver');
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the copy held here is the stored one');
		$this->assertNotContains('rc stop', $this->proxyCalls, 'the proxy that serves the moved Resolver is not stopped');
		$this->assertNotContains('stop_service', $this->proxyCalls, 'nor through pfSense\'s stop_service()');

		// And the operator is told pfB-DNS could not be turned off, never that it was
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('could not be turned off', $joined);
		$this->assertStringContainsString('could not be written', $joined);
		$this->assertStringNotContainsString('was turned off', $joined);
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined);
	}

	#[DataProvider('refusedWrites')]
	public function testAStandDownWhoseWritesAreRefusedClaimsNothingAndConfigXmlStillHoldsTheMovedResolver(mixed $answer): void
	{
		// Given pfB-DNS on with the Resolver moved, then disabled by the admin, and a config.xml that refuses every write
		$this->activate(TRUE);
		$this->proxyServes();
		$this->disableTheResolver();
		$this->configXmlOnDisk($answer);
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the next apply runs
		pfb_unbound_python('');

		// Then config.xml is as the admin left it: pfB-DNS On and the snapshot kept, and no notice says otherwise
		$this->assertSame('on', $this->onDisk(self::TOGGLE));
		$this->assertSame($snapshot, $this->onDisk(self::SAVED));
		$this->assertSame('lo0', $this->onDisk('unbound/active_interface'), 'the Resolver is still moved');
		$this->assertSame('on', $this->toggleStored(), 'and this process holds the stored toggle');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringNotContainsString('was turned off', $joined, 'nothing says pfB-DNS was turned off');
		$this->assertStringNotContainsString('DNS Resolver was restored', $joined, 'nothing says the Resolver was restored');
		$this->assertStringNotContainsString('restored to its previous settings', $joined);
		$this->assertStringContainsString('could not be turned off', $this->pfbLog(), 'the log says pfB-DNS could not be turned off, so the retry is understood');
	}

	#[DataProvider('refusedWrites')]
	public function testAnUnsafeLineWhoseKeepWriteIsRefusedIsNotRolledBackSoTheAdminsLineSurvives(mixed $answer): void
	{
		// Given a moved Resolver, an admin who then added an unsafe line, and a config.xml that refuses the write that keeps
		// that line in the saved settings (it takes every other: the rollback would turn pfB-DNS off and restore the old text)
		$this->activate(TRUE);
		$this->proxyServes();
		$this->adminAppends('port: 5300');
		$this->configXmlOnDisk($answer, 'kept the admin');
		$text = $this->customText();
		$snapshot = (string) config_get_path(self::SAVED, '');
		$this->assertStringContainsString('port: 5300', $text, 'before: the admin\'s line is in Custom Options');

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then the admin's line was not dropped by a restore from a snapshot that does not hold it, and pfB-DNS was not turned off
		$this->assertSame('on', $this->onDisk(self::TOGGLE), 'pfB-DNS is still requested');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'the snapshot is kept');
		$this->assertSame($text, $this->customText(), 'the Resolver\'s Custom Options are as the admin saved them');
		$this->assertSame([], $this->proxyCalls, 'the proxy is not stopped');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('could not be written', $joined, 'the operator is told why nothing was changed');
		$this->assertStringNotContainsString('was turned off', $joined);
	}

	// -----------------------------------------------------------------------
	// B -- the boot check and the cron tick roll back like an apply (issue #3556)
	// -----------------------------------------------------------------------

	/** The cron tick with every scheduled job behind a seam, so only its pfB-DNS check acts; its ledger and state stay in the sandbox. */
	private function tick(): void
	{
		$GLOBALS['pfb']['schedule_state_dir'] = $this->tmp;
		$GLOBALS['pfb']['runlog'] = "{$this->tmp}/run.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->tmp}/extras.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->tmp}/pfb_pending_changes";
		pfblockerng_tick(
			[], static function (): void {}, NULL, 5.0, static function (): void {}, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			static function (): void {},
			static fn (): bool => TRUE
		);
	}

	/** The boot hook's `dns_check` arm, as the CLI runs it: its own statements, in order, up to the exit that ends that process. */
	private function dnsCheckArm(string $size): void
	{
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertSame(1, preg_match("~\\belseif \\(\\\$argv\\[1\\] == 'dns_check'\\) \\{(.*?)\\bexit\\(0\\);\\s*\\}~s", $source, $arm), 'the dns_check arm');
		(static function (array $argv) use ($arm): void {
			eval($arm[1]);
		})(['pfblockerng.inc', 'dns_check', $size]);
	}

	/** What a rollback leaves: pfB-DNS off, the saved Resolver back, the startup notice then the rollback notice, the proxy stopped and never started. */
	private function assertRolledBackWithNotices(string $why): void
	{
		$this->assertSame('', $this->toggleStored(), "{$why}: pfB-DNS is turned off");
		$this->assertResolverIsTheOriginal($why);
		$this->assertSame(['pfBlockerNG DNS Proxy startup', 'pfBlockerNG DNS Proxy'], array_column($this->notices(), 'id'), "{$why}: the startup notice, then the rollback notice");
		$rollback = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy'));
		$this->assertCount(1, $rollback, "{$why}: one rollback notice");
		$this->assertStringContainsString('did not become ready', $rollback[0]['notice']);
		$this->assertStringContainsString('DNS Resolver was restored', $rollback[0]['notice']);
		// And the proxy is down, with no supervisor left to restart it: the state the stop leaves, not the call that made it
		$this->assertFalse(pfb_dns_proxy_running(), "{$why}: the proxy is not running");
		$this->assertFalse(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), "{$why}: no supervisor is left");
	}

	/** @return array<string,array{string}> the gateway process that lives and never publishes its marker */
	public static function aliveGateways(): array
	{
		return [
			'the child lives and never publishes its marker' => ['child'],
			'only the supervisor lives, its child between restarts' => ['supervisor'],
		];
	}

	#[DataProvider('aliveGateways')]
	public function testTheTickRollsBackAProxyThatIsAliveButNeverBecomesReady(string $alive): void
	{
		// Given pfB-DNS on with the Resolver moved, and a gateway process alive that never becomes ready
		$this->activate(TRUE);
		if ($alive === 'child') {
			$this->proxyLivesButNeverServes();
			$this->assertTrue(pfb_dns_proxy_running(), 'before: the child is alive');
		} else {
			// alive until the rollback's rc stop, which unsets it: the stop double models the supervisor's exit there
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
			$this->assertTrue(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), 'before: the supervisor is alive');
		}
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is requested');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the snapshot is stored');

		// When the cron tick runs
		$this->tick();

		// Then the tick rolls the activation back as an apply does
		$this->assertRolledBackWithNotices('rolled back by the tick');
	}

	public function testTheTickWaitsForNothingAndRollsNothingBackWhenNoGatewayProcessLives(): void
	{
		// Given pfB-DNS on with the Resolver moved, and no gateway process alive; the readiness predicate counts its probes
		$this->activate(TRUE);
		$probes = 0;
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = static function () use (&$probes): bool {
			$probes++;
			return FALSE;
		};

		// When the cron tick runs
		$this->tick();

		// Then the tick neither waits for the proxy nor files or changes anything
		// the certificate sync looks at readiness once on every tick (a single probe, no wait); a start-budget wait would poll again
		$this->assertSame(1, $probes, 'the certificate sync looks at readiness once per tick; a start-budget wait would poll again');
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is still requested');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testTheTickLeavesAReadyProxyAlone(): void
	{
		// Given pfB-DNS on with the Resolver moved, and a proxy that serves
		$this->activate(TRUE);
		$this->proxyServes();
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is requested');

		// When the cron tick runs
		$this->tick();

		// Then nothing is rolled back and no rollback notice is filed
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is still on');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
		$this->assertSame([], $this->proxyCalls, 'the proxy is neither stopped nor started');
	}

	public function testTheBootCheckRollsBackAStartThatNeverBecomesReady(): void
	{
		// Given pfB-DNS on with the Resolver moved, and the backgrounded start left a gateway that lives and never serves
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->assertTrue(pfb_dns_proxy_running(), 'before: the start left a live child');
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is requested');

		// When the boot check runs
		$this->dnsCheckArm('0');

		// Then the check rolls the activation back as an apply does
		$this->assertRolledBackWithNotices('rolled back by the boot check');
	}

	public function testTheBootCheckDoesNothingWithoutASnapshot(): void
	{
		// Given a box whose pfB-DNS was turned off and its Resolver restored since, so no snapshot is stored
		$this->activate(TRUE);
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		pfb_unbound_python('enabled', FALSE);
		$this->assertNull(pfb_dns_proxy_saved(), 'before: nothing is stored to roll back to');
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$this->proxyCalls = [];

		// When the boot check runs
		$this->dnsCheckArm('0');

		// Then nothing is written, stopped or reported
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testTheBootCheckLeavesAReadyProxyAlone(): void
	{
		// Given pfB-DNS on with the Resolver moved, and a proxy that serves
		$this->activate(TRUE);
		$this->proxyServes();

		// When the boot check runs
		$this->dnsCheckArm('0');

		// Then nothing is rolled back and no rollback notice is filed
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is still on');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
		$this->assertSame([], $this->proxyCalls, 'the proxy is neither stopped nor started');
	}

	// -----------------------------------------------------------------------
	// F -- a recovery never acts on a copy of config.xml that predates another write (issue #3572). The sequential cases use
	// this class's fixture; the race cases run the owner and the contender as two real processes (raceTheRecovery()).
	// -----------------------------------------------------------------------

	/** Another process's write to config.xml, which this process has not read: the disk takes $value at $path. */
	private function diskWrites(string $path, mixed $value): void
	{
		$memory = $GLOBALS['config'];
		$GLOBALS['config'] = $this->disk;
		config_set_path($path, $value);
		$this->disk = $GLOBALS['config'];
		$GLOBALS['config'] = $memory;
	}

	/** config.xml after the admin restored the Resolver: pfB-DNS off, no snapshot, the Resolver as the admin saved it. */
	private function diskRestoredByTheAdmin(): void
	{
		$this->diskWrites(self::TOGGLE, '');
		$this->diskWrites(self::SAVED, '');
		$this->diskWrites('unbound', self::originalResolver());
	}

	/** A second valid snapshot, as another activation stores it: the one this box holds, with another Listen Port. */
	private function snapshotB(): string
	{
		$saved = pfb_dns_proxy_saved();
		$saved['port'] = ['present' => TRUE, 'value' => '5300'];
		return base64_encode(json_encode($saved, JSON_THROW_ON_ERROR));
	}

	public function testAStaleConfirmerAfterTheRollbackIsDoneSaysNothingAndChangesNothing(): void
	{
		// Given a proxy that never serves: the first confirmation rolls the activation back, and this process keeps the copy it read before
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$stale = $GLOBALS['config'];
		$this->assertFalse(pfb_dns_proxy_confirm_ready(), 'before: the first confirmation rolls the activation back');
		$this->assertResolverIsTheOriginal('before: rolled back');
		$writes = $GLOBALS['pfb_test_write_config_calls'];
		$calls = $this->proxyCalls;
		$notices = $this->notices();

		// When the stale copy, which still holds the snapshot, confirms the proxy once more
		$GLOBALS['config'] = $stale;
		$ready = pfb_dns_proxy_confirm_ready();

		// Then it never says ready, and nothing is written, stopped, restarted or announced again
		$this->assertFalse($ready);
		$this->assertSame($writes, $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame($calls, $this->proxyCalls);
		$this->assertSame($notices, $this->notices());
	}

	public function testAnAdminRestoreWhileTheReadinessWaitRunsLeavesTheConfirmerQuiet(): void
	{
		// Given a proxy that never serves, and this process holding the snapshot it read before the admin's restore
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$probed = FALSE;
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = function () use (&$probed): bool {
			// The admin's restore lands on config.xml while the wait probes the proxy
			$probed = TRUE;
			$this->diskRestoredByTheAdmin();
			$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = TRUE;
			return TRUE;
		};
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->proxyCalls = [];

		// When the confirmation finds the proxy not ready
		$ready = pfb_dns_proxy_confirm_ready();

		// Then it is quiet: no write, no stop, no start, no notice, and the admin's Off stays
		$this->assertTrue($probed, 'before: the wait probed the proxy, so the admin wrote during it');
		$this->assertFalse($ready);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame([], $this->notices());
		$this->assertSame('', (string) $this->onDisk(self::TOGGLE, 'on'), 'the admin\'s Off stays');
	}

	public function testADifferentValidSnapshotStoredWhileTheWaitRunsIsKeptAndTheStaleRecoveryDoesNothing(): void
	{
		// Given a proxy that never serves, and another valid snapshot B that lands on config.xml while the wait probes the proxy
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$b = $this->snapshotB();
		$probed = FALSE;
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = function () use (&$probed, $b): bool {
			$probed = TRUE;
			$this->diskWrites(self::SAVED, $b);
			$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = TRUE;
			return TRUE;
		};
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->proxyCalls = [];

		// When the confirmation of the snapshot A it read finds the proxy not ready
		$ready = pfb_dns_proxy_confirm_ready();

		// Then B, pfB-DNS and the proxy are kept, and nothing of the stale recovery runs
		$this->assertTrue($probed, 'before: the wait probed the proxy, so B landed during it');
		$this->assertFalse($ready);
		$this->assertSame($b, (string) $this->onDisk(self::SAVED, ''), 'B stays on config.xml');
		$this->assertSame('on', (string) $this->onDisk(self::TOGGLE, ''), 'pfB-DNS stays on');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $this->proxyCalls, 'the proxy is neither stopped nor restarted');
		$this->assertSame([], $this->notices());
	}

	public function testAFailedRollbackThatCannotStopTheProxyIsRetriedByAFreshRecoveryWhichRestoresTheResolver(): void
	{
		// Given a rollback whose proxy survives its stop: the snapshot is kept and Off is stored
		$this->activate(TRUE);
		$this->survivesStop = TRUE;
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$this->assertFalse(pfb_dns_proxy_roll_back(), 'before: the first attempt cannot finish');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the snapshot is kept');
		$this->assertSame('', $this->toggleStored(), 'before: Off is stored');

		// When the proxy stops on the next, fresh attempt
		$this->survivesStop = FALSE;
		$this->assertTrue(pfb_dns_proxy_roll_back(), 'the fresh attempt restores the Resolver');

		// Then the Resolver is restored and the snapshot consumed
		$this->assertResolverIsTheOriginal('retried');
	}

	public function testAnOperationLockHeldElsewhereStopsTheRecoveryBeforeAnyWriteStopOrRestore(): void
	{
		// Given a moved Resolver and a proxy that never serves, while another recovery holds the operation lock
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$GLOBALS['pfb_test_try_lock_fail_names'] = ['pfb_dns_proxy_rollback' => TRUE];
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = config_get_path('unbound');

		// When this recovery is asked to roll back
		$ok = pfb_dns_proxy_roll_back();

		// Then it says so and does nothing: no write, no stop, no restore, no success claim
		$this->assertFalse($ok);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the snapshot is kept');
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')), 'the Resolver stays moved');
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is not turned off by a recovery that did not run');
		$this->assertSame(['pfBlockerNG DNS Proxy'], array_column($this->notices(), 'id'), 'the refusal is filed under the recovery notice id');
		$texts = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringNotContainsString('was restored', $texts);
		$this->assertStringNotContainsString('turned off', $texts);
	}

	/** @return array<string,array{string}> the fault that keeps this process from reading config.xml under the config lock */
	public static function configXmlNotReadUnderTheLock(): array
	{
		return [
			'the config lock stays taken' => ['lock'],
			'the fresh read fails' => ['read'],
		];
	}

	#[DataProvider('configXmlNotReadUnderTheLock')]
	public function testAProxyThatNeverBecameReadyWithNoConfigXmlReadIsNotDiagnosedAndNothingIsDestroyed(string $fault): void
	{
		// Given a proxy that never serves, and config.xml that this process cannot read under the config lock
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		if ($fault === 'lock') {
			$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		} else {
			$GLOBALS['pfb_test_config_read_fails_for'] = 2; // the lock's own retry reads again
		}
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = config_get_path('unbound');

		// When the confirmation runs
		$ready = pfb_dns_proxy_confirm_ready();

		// Then the only notice is the recovery's failure: ownership was never validated, so nothing is diagnosed, stopped or written
		$this->assertFalse($ready);
		$this->assertSame(['pfBlockerNG DNS Proxy'], array_column($this->notices(), 'id'), 'the recovery failure only');
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the snapshot is kept');
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')), 'the Resolver stays moved');
		$this->assertStringNotContainsString('was restored', implode("\n", array_column($this->notices(), 'notice')));
	}

	public function testAStandDownWhoseResolverIsAlreadyRestoredOnDiskIsQuietAndWritesNothing(): void
	{
		// Given pfB-DNS fronting a Resolver the admin disabled, and config.xml already holding its restore
		$this->activate(TRUE);
		$this->proxyServes();
		$this->disableTheResolver();
		$this->configXmlOnDisk();
		$this->diskRestoredByTheAdmin();
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->proxyCalls = [];

		// When the stand-down runs on this process's copy, which still holds the snapshot
		$stood = pfb_dns_proxy_stand_down();

		// Then nothing is done and nothing is announced
		$this->assertFalse($stood);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame([], $this->notices());
		$this->assertSame('', (string) $this->onDisk(self::TOGGLE, 'on'));
	}

	public function testATurnOffAskedToRetireASnapshotAnotherProcessReplacedWritesNothingAndSaysSo(): void
	{
		// Given the snapshot A this process holds, and config.xml on which another process has stored B
		$this->activate(TRUE);
		$this->configXmlOnDisk();
		$a = (string) config_get_path(self::SAVED, '');
		$b = $this->snapshotB();
		$this->diskWrites(self::SAVED, $b);
		$GLOBALS['pfb_test_write_config_calls'] = [];

		// When the turn-off asked to retire A runs
		$turned = pfb_dns_proxy_turn_off('the test', $a);

		// Then nothing is written: B is not this recovery's to retire
		$this->assertNull($turned);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame($b, (string) $this->onDisk(self::SAVED, ''));
		$this->assertSame('on', (string) $this->onDisk(self::TOGGLE, ''));
	}

	public function testATurnOffWithNoOwnershipAndNoRecoveryToDoIsNullAndWritesNothing(): void
	{
		// Given config.xml and this process agree that the Resolver is restored: no snapshot and no block of ours
		$this->activate(TRUE);
		$this->configXmlOnDisk();
		$this->diskRestoredByTheAdmin();
		$GLOBALS['config'] = $this->disk;
		$GLOBALS['pfb_test_write_config_calls'] = [];

		// When a turn-off runs
		$turned = pfb_dns_proxy_turn_off('the test');

		// Then there is nothing to turn off: NULL, and nothing is written
		$this->assertNull($turned);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame('', $this->onDisk(self::TOGGLE, 'missing'));
	}

	public function testATurnOffThatIsPersistedIsTrueAndTheToggleIsOffOnDisk(): void
	{
		// Given a box still owned by pfB-DNS: the snapshot is stored and the Resolver moved
		$this->activate(TRUE);
		$this->configXmlOnDisk();

		// When the turn-off writes config.xml
		$this->assertTrue(pfb_dns_proxy_turn_off('the test'));

		// Then the toggle is Off on disk, and the snapshot is still there for the restore
		$this->assertSame('', (string) $this->onDisk(self::TOGGLE, 'on'));
		$this->assertNotNull(pfb_dns_proxy_saved());
	}

	#[DataProvider('refusedWrites')]
	public function testATurnOffWhoseWriteIsRefusedIsFalseAndTheStoredSnapshotAndToggleAreKept(mixed $answer): void
	{
		// Given a box still owned by pfB-DNS, and config.xml that refuses the write that turns it off
		$this->activate(TRUE);
		$this->configXmlOnDisk($answer);

		// When the turn-off runs
		$this->assertFalse(pfb_dns_proxy_turn_off('the test'));

		// Then the snapshot and the stored toggle are as they were
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame('on', (string) $this->onDisk(self::TOGGLE, 'on'));
	}

	/** @return array<string,array{string,string,int,string}> the gateway lines an older start logged, the lines this start logged after the size was taken, the quote its notice carries */
	public static function gatewayErrorsAroundTheStart(): array
	{
		return [
			'an error of an older start and none from this start' => [['pfb_dns_gateway: old error'], ['listening udp+tcp 127.0.0.1:53'], ''],
			'an error of an older start and this start\'s own' => [['pfb_dns_gateway: old error'], ['pfb_dns_gateway: this start'], ' (last gateway error: pfb_dns_gateway: this start)'],
		];
	}

	#[DataProvider('gatewayErrorsAroundTheStart')]
	public function testAFailedConfirmationQuotesOnlyTheGatewayErrorOfItsOwnStartAndRollsBack(array $before, array $after, string $quote): void
	{
		// Given a log with an error of an older start, the size taken, and what this start logged after it
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$log = $GLOBALS['pfb']['dns_proxy_log'];
		try {
			file_put_contents($log, implode("\n", $before) . "\n");
			$since = pfb_dns_proxy_log_size();
			file_put_contents($log, implode("\n", $after) . "\n", FILE_APPEND);

			// When the confirmation of this start finds the proxy not ready
			$ready = pfb_dns_proxy_confirm_ready($since);
		} finally {
			@unlink($log);
		}

		// Then the activation is rolled back, and the startup notice names only this start's own gateway error
		$this->assertFalse($ready);
		$this->assertResolverIsTheOriginal('rolled back');
		$startup = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy startup'));
		$this->assertCount(1, $startup, 'one startup notice');
		$this->assertStringNotContainsString('old error', $startup[0]['notice'], 'an older start\'s error is never blamed on this one');
		if ($quote === '') {
			$this->assertStringNotContainsString('last gateway error', $startup[0]['notice']);
		} else {
			$this->assertStringContainsString($quote, $startup[0]['notice']);
		}
	}

	public function testAStandDownWithANewerSnapshotLeavesTheNewActivationUntouched(): void
	{
		// Given pfB-DNS serving, a Resolver this process sees as disabled, and config.xml holding a newer valid snapshot B with the
		// Resolver enabled again: this process's copy predates that activation
		$this->activate(TRUE);
		$this->proxyServes();
		$this->disableTheResolver();
		$this->assertFalse(config_path_enabled('unbound'), 'before: this process sees the Resolver disabled');
		$this->configXmlOnDisk();
		$b = $this->snapshotB();
		$this->diskWrites(self::SAVED, $b);
		$this->diskWrites('unbound/enable', '');
		$this->assertNotSame($b, (string) config_get_path(self::SAVED, ''), 'before: this process holds snapshot A, config.xml holds B');
		$this->assertTrue(pfb_dns_proxy_running(), 'before: the proxy is serving');
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->proxyCalls = [];

		// When the stand-down runs on this process's copy
		$stood = pfb_dns_proxy_stand_down();

		// Then nothing is written, stopped or announced, and the newer activation stays as config.xml holds it
		$this->assertFalse($stood);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'no write');
		$this->assertSame([], $this->proxyCalls, 'no stop');
		$this->assertSame([], $this->notices(), 'no notice');
		$this->assertSame($b, (string) $this->onDisk(self::SAVED, ''), 'snapshot B kept');
		$this->assertSame('on', (string) $this->onDisk(self::TOGGLE, ''), 'pfB-DNS still on');
		$this->assertTrue(pfb_dns_proxy_running(), 'the proxy still serves');
	}

	public function testADirectRollbackAfterAnotherRecoveryDoesNothingAndReturnsFalse(): void
	{
		// Given a proxy that never serves: the first confirmation rolls the activation back in full, while this process's copy
		// still holds the snapshot it read before that
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$stale = $GLOBALS['config'];
		$this->assertFalse(pfb_dns_proxy_confirm_ready(), 'before: the first confirmation fails and rolls back');
		$this->assertResolverIsTheOriginal('before: the first recovery restored the Resolver');
		$GLOBALS['config'] = $stale;
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: this process still holds the snapshot');
		$writes = $GLOBALS['pfb_test_write_config_calls'];
		$calls = $this->proxyCalls;
		$notices = $this->notices();
		$starts = $this->startAttempts();

		// When a direct rollback runs on that copy
		$restored = pfb_dns_proxy_roll_back();

		// Then it does not claim a restore, and nothing else is written, stopped, started or announced
		$this->assertFalse($restored, 'a rollback that did nothing never says it restored the Resolver');
		$this->assertSame($writes, $GLOBALS['pfb_test_write_config_calls'], 'no further write');
		$this->assertSame($calls, $this->proxyCalls, 'no further proxy action');
		$this->assertSame($notices, $this->notices(), 'no further notice');
		$this->assertSame($starts, $this->startAttempts(), 'no further Unbound start');
		$this->assertResolverIsTheOriginal('the first recovery\'s restore stands');
	}

	public function testAFailedStartReportsSnapshotDependentListenerWarningsBeforeRestoring(): void
	{
		// Given a valid snapshot that names lan and opt1, a proxy that never serves, and opt1 now configured but down with no address
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$GLOBALS['pfb_test_interface_ip']['opt1'] = '';
		$GLOBALS['pfb_test_interface_info']['opt1'] = ['status' => 'down', 'enable' => TRUE];
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the snapshot is stored');

		// When the activation confirms the start, which fails
		$this->assertFalse(pfb_dns_proxy_confirm_ready());

		// Then the startup notice names the interface whose listener only the snapshot defines, and the Resolver is restored
		$startup = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy startup'));
		$this->assertCount(1, $startup, 'one startup notice');
		$this->assertStringContainsString('opt1', $startup[0]['notice'], 'the startup notice names the interface whose listener the snapshot defines');
		$this->assertResolverIsTheOriginal('rolled back after the diagnosis');
	}

	public function testOnlyTheOwnerRestoresAndTheContenderWaitsForItsCompletion(): void
	{
		// Given two recoveries of this box that run concurrently, with the owner held after its Off write
		$this->activate(TRUE);
		$snapshot = (string) config_get_path(self::SAVED, '');
		$race = $this->raceTheRecovery(1);
		$this->assertOwnerHeld($race, '', $snapshot, 'after its Off write and config unlock');
		$this->assertContenderWaitedAndDidNothing($race);
	}

	public function testAContenderThatConfirmedWhileTheOwnerWasHeldAfterTheSnapshotWasConsumedWaitsForTheOwnerAndDoesNothing(): void
	{
		// Given two recoveries of this box, with the owner held after the snapshot is consumed, before its Unbound restart
		$this->activate(TRUE);
		$race = $this->raceTheRecovery(2);
		$this->assertOwnerHeld($race, '', '', 'after the snapshot is consumed and config unlocked, before its Unbound restart');
		$this->assertContenderWaitedAndDidNothing($race);
	}

	/**
	 * Two recoveries of this box, each a real process (support/DnsProxyRecoveryWorker.php), so the locks are the kernel's:
	 * the owner runs the recovery and is held after its $pause-th DNS config unlock; then the contender, which holds the copy
	 * of config.xml it read before the owner ran, confirms the proxy while the owner is held; then the owner is released.
	 * Every worker is reaped before this returns. Nothing waits on the clock: each step is a line a worker writes, read
	 * within a deadline that is never read as a verdict.
	 *
	 * @return array{paused: ?string, first: ?string, ownerDone: ?string, contenderDone: ?string, events: list<string>, disk: array, stderr: string}
	 */
	private function raceTheRecovery(int $pause): array
	{
		$this->proxyLivesButNeverServes();
		$dir = sys_get_temp_dir() . '/pfb_dns_race_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$this->writeRaceState($dir);
		$race = ['paused' => NULL, 'first' => NULL, 'ownerDone' => NULL, 'contenderDone' => NULL, 'events' => [], 'disk' => [], 'stderr' => ''];
		$workers = [];
		try {
			$owner = $this->startWorker($dir, 'owner', $pause);
			$workers[] = $owner;
			$ownerBuffer = '';
			$line = $this->readLine($owner, $ownerBuffer, ['PAUSED ', 'DONE '], 15.0);
			if (str_starts_with((string) $line, 'DONE ')) {
				$race['ownerDone'] = $line;
			} elseif ($line !== NULL) {
				$race['paused'] = $line;
				$contender = $this->startWorker($dir, 'contender', 0);
				$workers[] = $contender;
				$contenderBuffer = '';
				$race['first'] = $this->readLine($contender, $contenderBuffer, ['BLOCKED ', 'DONE '], 15.0);
				if (str_starts_with((string) $race['first'], 'DONE ')) {
					$race['contenderDone'] = $race['first'];
				}
				fwrite($owner[1][0], "RELEASE\n");
				$race['ownerDone'] = $this->readLine($owner, $ownerBuffer, ['DONE '], 20.0);
				$race['contenderDone'] ??= $this->readLine($contender, $contenderBuffer, ['DONE '], 20.0);
			}
		} finally {
			foreach ($workers as $worker) {
				if (is_resource($worker[1][0])) {
					fclose($worker[1][0]);
				}
				try {
					$race['stderr'] .= pfb_test_finish_process($worker, 5.0)['stderr'];
				} catch (RuntimeException $stuck) {
					$race['stderr'] .= $stuck->getMessage();
				}
			}
			$race['events'] = array_values(array_filter(explode("\n", (string) @file_get_contents("{$dir}/events.log")), 'strlen'));
			$race['disk'] = json_decode((string) @file_get_contents("{$dir}/disk.json"), TRUE) ?? [];
			rmdir_recursive($dir);
		}
		return $race;
	}

	/** The state the workers start from: the config the owner and the contender both read at start, and the shared disk. */
	private function writeRaceState(string $dir): void
	{
		file_put_contents("{$dir}/memory.json", json_encode($GLOBALS['config'], JSON_THROW_ON_ERROR));
		file_put_contents("{$dir}/disk.json", json_encode($GLOBALS['config'], JSON_THROW_ON_ERROR));
		file_put_contents("{$dir}/pfb.ser", serialize([
			'pfb' => $GLOBALS['pfb'],
			'g' => $GLOBALS['g'],
			'doubles' => array_intersect_key($GLOBALS, array_flip(['pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_interfaces', 'pfb_test_process_running'])),
		]));
		file_put_contents("{$dir}/unbound-start", "#!/bin/sh\nprintf '%s unbound_start\\n' \"\$1\" >> \"\$2\"\nexit 0\n");
		chmod("{$dir}/unbound-start", 0755);
		file_put_contents("{$dir}/events.log", '');
	}

	/** @return array{0: resource, 1: array<int, resource>, 2: string} a worker: its stdin takes RELEASE, its output is read without blocking */
	private function startWorker(string $dir, string $role, int $pause): array
	{
		$command = [PHP_BINARY, __DIR__ . '/support/DnsProxyRecoveryWorker.php', $role, $dir, (string) $pause, PFB_DNS_PROXY_RCFILE];
		$process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		if (!is_resource($process)) {
			throw new RuntimeException("test bootstrap: could not start the {$role} worker");
		}
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);
		return [$process, $pipes, implode(' ', $command)];
	}

	/**
	 * The first line the worker writes that starts with one of $prefixes, or NULL when none comes within $seconds. A worker
	 * that never writes one is reported by the caller; the wait is never read as a verdict. $buffer keeps what was read past the line.
	 *
	 * @param array{0: resource, 1: array<int, resource>, 2: string} $worker
	 */
	private function readLine(array $worker, string &$buffer, array $prefixes, float $seconds): ?string
	{
		$deadline = microtime(TRUE) + $seconds;
		$out = $worker[1][1];
		while (TRUE) {
			while (($newline = strpos($buffer, "\n")) !== FALSE) {
				$line = substr($buffer, 0, $newline);
				$buffer = (string) substr($buffer, $newline + 1);
				foreach ($prefixes as $prefix) {
					if (str_starts_with($line, $prefix)) {
						return $line;
					}
				}
			}
			$left = $deadline - microtime(TRUE);
			if ($left <= 0) {
				return NULL;
			}
			$read = [$out];
			$write = [];
			$except = [];
			if (stream_select($read, $write, $except, (int) floor($left), (int) (($left - floor($left)) * 1000000)) === FALSE) {
				return NULL;
			}
			if ($read === []) {
				continue;
			}
			$chunk = fread($out, 8192);
			if ($chunk === FALSE || ($chunk === '' && feof($out))) {
				return NULL;
			}
			$buffer .= $chunk;
		}
	}

	/** @param array{paused: ?string, first: ?string, ownerDone: ?string, contenderDone: ?string, events: list<string>, disk: array, stderr: string} $race */
	private function assertOwnerHeld(array $race, string $toggle, string $saved, string $where): void
	{
		$this->assertNotNull($race['paused'], "the owner was not held {$where}: {$race['stderr']}");
		[, , $json] = explode(' ', (string) $race['paused'], 3);
		$this->assertSame(['toggle' => $toggle, 'saved' => $saved], json_decode($json, TRUE), "the owner is held {$where}");
	}

	/** @param array{paused: ?string, first: ?string, ownerDone: ?string, contenderDone: ?string, events: list<string>, disk: array, stderr: string} $race */
	private function assertContenderWaitedAndDidNothing(array $race): void
	{
		$log = 'events: ' . implode(' | ', $race['events']);

		// The contender changed nothing while the owner was held: no write, service call, stop or Unbound restart
		$effects = array_values(array_filter(
			$race['events'],
			static fn (string $event): bool => preg_match('/^contender (write|svc|rc_stop|unbound_start)\b/', $event) === 1
		));
		$this->assertSame([], $effects, "the contender changed nothing while the owner was held; {$log}");

		// One restoration and one Unbound restart in total, both the owner's
		$restarts = array_values(array_filter($race['events'], static fn (string $event): bool => $event === 'owner unbound_start'));
		$this->assertCount(1, $restarts, "one restoration and one Unbound restart in total; {$log}");

		// The contender waited for the owner's operation lock rather than finishing while the owner was held
		$this->assertNotNull($race['first'], "the contender neither waited nor finished: {$race['stderr']}; {$log}");
		$this->assertTrue(
			str_starts_with((string) $race['first'], 'BLOCKED '),
			"the contender finished while the owner was held (first: {$race['first']}); {$log}"
		);

		// Both completed, the contender only after the owner's restart, and quietly: not ready, nothing to say
		$this->assertNotNull($race['ownerDone'], "the owner did not complete after its release: {$race['stderr']}");
		$this->assertNotNull($race['contenderDone'], "the contender did not complete after the owner: {$race['stderr']}");
		$ownerRestart = array_search('owner unbound_start', $race['events'], TRUE);
		$contenderDone = array_search('contender done', $race['events'], TRUE);
		$this->assertIsInt($ownerRestart, 'the owner restarted Unbound');
		$this->assertIsInt($contenderDone, 'the contender finished');
		$this->assertGreaterThan($ownerRestart, $contenderDone, 'the contender finished only after the owner restarted Unbound');
		$this->assertSame(['confirmed' => FALSE], json_decode(substr((string) $race['contenderDone'], strlen('DONE ')), TRUE), 'the contender quietly said not ready');

		// And config.xml holds the admin's Resolver: the snapshot consumed, pfB-DNS off
		$this->disk = $race['disk'];
		$this->assertSame('', (string) $this->onDisk(self::SAVED, 'stored'), 'the snapshot is consumed on config.xml');
		$this->assertSame('', (string) $this->onDisk(self::TOGGLE, 'stored'), 'pfB-DNS is off on config.xml');
		$this->assertSame('lan,opt1', (string) $this->onDisk('unbound/active_interface'), 'the Resolver is the admin\'s again');
	}
}
