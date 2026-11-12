<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/support/ProcessRunner.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';

/**
 * The box the pfB-DNS no-automatic-restore tests share: pfBlockerNG on, pfB-DNS on, the Resolver moved aside by the real pass (so the
 * snapshot is the one the real writer made), a stand-in proxy whose behaviour a test picks (never serves, serves, exits), and the
 * doubles that record every proxy call, config.xml write and Unbound regeneration. Nothing here knows what restores the Resolver:
 * a test says what must and must not.
 */
trait DnsProxyMovedResolverFixtureTrait
{
	use DnsProxyReadySeedTrait;
	use ConfigXmlDiskTrait;
	use LiveListenerStandIn;

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
		'pfb_test_lock_holders', 'pfb_test_try_lock_busy_for', 'pfb_test_config_read_fails',
		'pfb_test_config_read_fails_for', 'pfb_test_unbound_configure_hook',
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
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_moved_resolver_' . getmypid() . '_' . uniqid();
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
			'chroot_cmd' => '/bin/echo', 'php' => PHP_BINARY,
			'dnsbl_cache_flush' => PfbToggle::Off,
			'keep' => PfbToggle::On,
		]);
		// Nothing of an apply pass's own state (save, install, reuse_dnsbl): a restore runs from the installer and the Reports pages too
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
		PfbConfig::write('dns/pfb_dns_name', 'fw.example.lan');
		$GLOBALS['pfb_test_lock_held'] = FALSE;
		unset($GLOBALS['pfb_test_try_lock_fail'], $GLOBALS['pfb_test_rcfile_writes'], $GLOBALS['pfb_test_rcfiles']);
		$GLOBALS['pfb_test_lock_holders'] = [];
		unset($GLOBALS['pfb_test_try_lock_busy_for'], $GLOBALS['pfb_test_config_read_fails'],
			$GLOBALS['pfb_test_config_read_fails_for']);
		// The Resolver the proxy took over listened on lan and opt1: both are configured, up and addressed, so a healthy start has
		// no warning for the startup check to report
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE], 'opt1' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => '', 'opt1' => ''];
		@unlink($GLOBALS['pfb']['dns_proxy_backend_blocked']);
		@unlink($GLOBALS['pfb']['dns_proxy_scan_failed']);
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
				$this->seedRunningGateway();
			} elseif ($this->behaviour === 'lives') {
				// Alive, as the supervisor keeps its child alive between restarts, and never publishing the marker; each probe of the
				// readiness wait notes whether the config lock is held (the budget is 0 under test, so a wait probes once and only its
				// caller tells it from a one-shot recheck under the lock)
				$this->proxyLivesButNeverServes();
				$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = function (): bool {
					if (in_array('pfb_dns_proxy_await_ready', array_column(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS), 'function'), TRUE)) {
						$this->lockHeldWhileWaiting[] = !empty($GLOBALS['pfb_test_lock_held']);
					}
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
					$this->seedRunningGateway();
					$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
				}
			}
			return 0;
		};
		$this->useMountState(TRUE);
		// The bootstrap's Unbound start double fails (nothing may start Unbound under test); a restore that restarts Unbound must
		// find the start succeed, or the reload's own recovery puts the pre-restore unbound.conf back
		$this->originalStartDouble = (string) file_get_contents($this->startDouble());
		file_put_contents($this->startDouble(), "#!/bin/sh\nprintf '%s\\n' 'unit-test double: Unbound started' | tee -a \"\$1\"\nexit 0\n");
		$this->setUpUpstreamFixture();
	}

	protected function tearDown(): void
	{
		@unlink($GLOBALS['pfb']['dns_proxy_backend_blocked']);
		$this->standInsStop();
		$this->tearDownUpstreamFixture();
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
	 * on, the Resolver moved aside by the real pass (so the snapshot is the one the real writer made); with DNSBL on, Unbound
	 * stored the legacy DNSBL module keys before that, as an upgraded box does (the pass takes them out).
	 *
	 * @param array<string,string> $resolver keys of the user's Resolver that differ from originalResolver()
	 * @param bool $takeover FALSE leaves the Resolver as the user had it, for a test that drives the takeover itself
	 */
	private function activate(bool $dnsbl, array $resolver = [], bool $takeover = TRUE): void
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
			'top1m_enable' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '',
			'pfb_cname' => '', 'tld_allow' => '', 'tld_wildcard' => '',
			'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'whitelist' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '',
			// auto-create mode: the DNSBL sinkhole VIP is the apply's to provision, so its validation does not force DNSBL off here
			'pfb_dnsbl' => $dnsbl ? 'on' : '', 'pfb_dnsvip_auto' => $dnsbl ? 'on' : '', 'dnsbl_interface' => 'lo0',
		]);
		PfbConfig::writeSectionSystem(self::PFB_DNS, ['pfb_dns' => 'on', 'pfb_dns_name' => 'fw.example.lan']);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;

		$GLOBALS['config']['unbound'] = array_merge(self::originalResolver(), $resolver) + ($dnsbl
			? ['python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound']
			: []);
		if ($takeover) {
			$mode = $dnsbl ? 'enabled' : 'disabled';
			pfb_unbound_python($mode, TRUE);
			$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the Resolver was moved for the proxy');
			$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'before: the Resolver is on loopback');
			$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'), 'before: Unbound runs the observer, not the module');
		}
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



	/**
	 * The state a package upgrade runs the install command in (issue #3562): delete_package_xml() deleted the package's service
	 * registrations and wrote config.xml, install_package_xml() adds them back only after the command, and pfSense's
	 * start_service() and stop_service() act only on a registered service. config.xml is a file from here on, so a fresh read
	 * (a restore's, under the DNS config lock) sees only what was written.
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

	/** The port the gateway's rc script serves, from its start command (`--port N`). */
	private function servedPort(): ?string
	{
		$rc = (string) ($GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh']['start'] ?? '');
		return preg_match('/--port (\d+) /', $rc, $m) === 1 ? $m[1] : NULL;
	}

	/** The admin disables the DNS Resolver in Services > DNS Resolver while pfB-DNS fronts it. */
	private function disableTheResolver(): void
	{
		config_del_path('unbound/enable');
		$this->assertFalse(config_path_enabled('unbound'), 'before: the Resolver is disabled');
	}

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

}
