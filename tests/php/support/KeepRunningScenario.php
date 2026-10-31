<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/DnsProxyReadySeedTrait.php';

/**
 * issue #3566 -- the box a package upgrade leaves behind, as real files under one directory: a moved Resolver (the snapshot), a
 * proxy that serves, its rc script, the gateway binary the package installs and the gateway's record of the binary it runs, the
 * decider's files and its record, a pending-restart marker or none. krApply() makes one such state, quiet by default (nothing
 * differs, so nothing restarts) and changed only by what a scenario names; the service calls pfSense would get are recorded.
 * The box also has a process table that the `ps` double answers (krPs()): the supervisor, the gateway and the decider, with their RSS.
 *
 * Used by the in-process tests and by support/KeepRunningWorker.php, which runs the same state under a pkg(8) ancestor.
 */
trait KeepRunningScenario
{
	use DnsProxyReadySeedTrait;

	private string $krDir = '';
	private string $krProxyDir = '';
	/** @var list<array{string,string}> the service calls the proxy got, in order: [function, service] */
	private array $krCalls = [];

	private function krSeed(string $dir): void
	{
		$this->krDir = $dir;
		$this->krProxyDir = "{$dir}/dns_proxy";
		mkdir("{$dir}/dnsdir", 0777, TRUE);
		mkdir("{$dir}/decider", 0777, TRUE);
		$this->krPsDouble();
		$GLOBALS['pfb_test_ps_output'] = "{$dir}/gateway.ps";
		$decider = [];
		foreach (['pfb_dns_proxy.py', 'decision_service.py', 'dns_reply_log.py', 'dnswire.py', 'unbound_shim.py', 'pfb_unbound.py', 'pfb_dnsbl_regex_rules.py'] as $name) {
			$decider[] = "{$dir}/decider/{$name}";
		}
		$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $dir, 'dbdir' => $dir, 'dnsdir' => "{$dir}/dnsdir", 'dnsbl_file' => "{$dir}/pfb_dnsbl",
			'dnsbl_cache' => "{$dir}/pfb_py_cache.sqlite", 'unbound_py_count' => "{$dir}/pfb_py_count",
			'unbound_py_sources' => "{$dir}/pfb_py_sources.json", 'unbound_py_rawdir' => "{$dir}/pfb_py_raw",
			'unbound_py_reject_stats' => "{$dir}/pfb_py_reject_stats.json", 'dnsbl_unlock' => "{$dir}/dnsbl_unlock",
			'chroot_cmd' => '/bin/echo', 'dnsbl_python_unmount' => FALSE, 'dnsbl_res_cache' => PfbToggle::On,
			'dnsbl_cache_flush' => PfbToggle::Off, 'enable' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'save' => TRUE,
			'keep' => PfbToggle::On, 'install' => FALSE, 'errlog' => "{$dir}/error.log", 'log' => "{$dir}/pfblockerng.log",
			'php' => PHP_BINARY, 'ps' => "{$dir}/ps",
			'dns_proxy_restart_pending' => "{$dir}/restart.pending", 'dns_proxy_gateway_applied' => "{$dir}/gateway.sha256",
			'dns_proxy_decider_applied' => "{$dir}/decider.applied", 'dns_proxy_decider_src' => $decider,
			'dns_proxy_ctl' => "{$dir}/ctl.sock", 'dns_proxy_rc_kept' => "{$dir}/rc.kept", 'dns_proxy_log' => "{$dir}/dns_proxy.log",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['g']['varrun_path'] = $dir;
		$GLOBALS['pfb_test_process_running'] = ['unbound' => FALSE];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		unset($GLOBALS['pfb_test_rcfile_writes'], $GLOBALS['pfb_test_rcfiles'], $GLOBALS['pfb_test_try_lock_fail'], $GLOBALS['pfb_test_sysctl']);
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		// The Resolver the proxy took over listened on lan: configured, up and addressed, so a healthy start has no warning to report
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => ''];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$this->krCalls = [];
		$this->krPs(self::krPsTable([self::krPsSupervisor(), self::krPsGateway(), self::krPsDecider()]));
		$this->clearProxyFiles();
		@unlink(PFB_DNS_PROXY_RCFILE);
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service): void {
			$this->krCalls[] = [$fn, $service];
			// A started or restarted proxy is up at once, as the readiness wait's first probe finds it
			if ($fn !== 'stop_service') {
				$this->proxyServes();
				$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
				$this->seedRunningGateway();
			}
		};
	}

	/** The globals krSeed() touches, for a test's setUp()/tearDown() to save and restore. */
	private static function krGlobals(): array
	{
		return [
			'pfb', 'config', 'g', 'pfb_test_process_running', 'pfb_test_valid_pids', 'pfb_test_service_calls', 'pfb_test_service_hook',
			'pfb_test_rcfile_writes', 'pfb_test_rcfiles', 'pfb_test_rcfile_dir', 'pfb_test_try_lock_fail', 'pfb_test_file_notices',
			'pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_interfaces', 'pfb_test_swap_wait_s', 'pfb_test_configured_ipv6',
			'pfb_test_unbound_py_sentinel_published', 'pfb_test_sysctl',
			'pfb_test_ps_output',
		];
	}

	/** The `ps` the code under test runs ($pfb['ps']): it answers its full-table list from ps.out, fails when there is none, and exits 1 after it when ps.fail exists; the gateway's single-pid list (-ww -o args= -p PID) answers from gateway.ps, the PID command line rows the seed helpers write there, exit 1 with no output when the pid is absent; any other list exits 2. */
	private function krPsDouble(): void
	{
		$out = escapeshellarg("{$this->krDir}/ps.out");
		$fail = escapeshellarg("{$this->krDir}/ps.fail");
		$gw = escapeshellarg("{$this->krDir}/gateway.ps");
		file_put_contents("{$this->krDir}/ps", "#!/bin/sh\ncase \"\$*\" in\n'-axww -o pid= -o ppid= -o rss= -o args=') [ -f {$out} ] || exit 1; cat {$out}; [ ! -f {$fail} ] ;;\n'-ww -o args= -p '[0-9]*) [ \$# -eq 5 ] || exit 2; [ -f {$gw} ] || exit 1; awk -v p=\"\$5\" '\$1 == p { sub(/^[^ ]+ /, \"\"); print; found = 1 } END { exit(found ? 0 : 1) }' {$gw} ;;\n*) exit 2 ;;\nesac\n");
		chmod("{$this->krDir}/ps", 0755);
	}

	/** The box's process table, as the `ps` double prints it; NULL = ps fails with no output; $fails = it prints the table, then exits 1. */
	private function krPs(?string $table, bool $fails = FALSE): void
	{
		if ($table === NULL) {
			@unlink("{$this->krDir}/ps.out");
		} else {
			file_put_contents("{$this->krDir}/ps.out", $table);
		}
		if ($fails) {
			touch("{$this->krDir}/ps.fail");
		} else {
			@unlink("{$this->krDir}/ps.fail");
		}
	}

	/** One line of `ps -o pid= -o ppid= -o rss= -o args=`: the numbers right-aligned, a space between the columns. */
	private static function krPsRow(string $pid, string $ppid, string $rss, string $args): string
	{
		return sprintf('%5s %5s %6s %s', $pid, $ppid, $rss, $args);
	}

	/** @param list<string> $rows */
	private static function krPsTable(array $rows): string
	{
		return implode("\n", $rows) . "\n";
	}

	/** The daemon(8) supervisor of the gateway. */
	private static function krPsSupervisor(): string
	{
		return self::krPsRow('1001', '1', '1500', 'daemon: pfb_dns_proxy[4242] (daemon)');
	}

	/** The gateway, pid 4242 as proxyServes() writes it; its own args name pfb_dns_proxy.py, the script it launches. */
	private static function krPsGateway(): string
	{
		return self::krPsRow('4242', '1001', '22412', '/usr/local/pkg/pfblockerng/dns_proxy/bin/freebsd-amd64/pfb-dns --listen 127.0.0.1 --port 53 -- /usr/local/pkg/pfblockerng/pfb_python.sh -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py --decision-fd 3 --module-dir /var/unbound --user unbound');
	}

	/** A decider: by default pid 4243 under the gateway, 240580 KiB resident. */
	private static function krPsDecider(string $pid = '4243', string $ppid = '4242', string $rss = '240580'): string
	{
		return self::krPsRow($pid, $ppid, $rss, 'python3.11 -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py --decision-fd 3 --module-dir /var/unbound --user unbound');
	}

	/**
	 * The scenario's state. Keys (defaults make a quiet box):
	 *   snapshot  bool            the Resolver is moved aside (pfB-DNS on); FALSE = pfB-DNS off
	 *   proxy     serves | dead
	 *   rc        same | stale    the rc script on disk equals what the next pass writes | differs from it
	 *   marker    ?string         the pending-restart marker's content, NULL = none
	 *   gateway   equal | equal_one_of_two | different | absent | unreadable | none
	 *             the record of the binary the gateway runs against the installed pfb-dns binaries (none = nothing installed)
	 *   decider   equal | different | absent | unreadable_member
	 *             the record of the decider's code against the installed files (unreadable_member = one is missing)
	 *   ctl       ?string         the control socket's path, NULL = nobody listens
	 *   dot       bool            a DoT listener on lan (192.0.2.1:853) is configured
	 *   port      ?string         the plain DNS port the rc script is written with (unbound/port), NULL = 53
	 *   lan       ?string         the IPv4 address lan has when the NEXT pass runs; the rc script on disk was written with 192.0.2.1, NULL = it still has it
	 *   lan6      ?string         the IPv6 address lan has when the next pass runs (the rc script on disk was written with none), NULL = none
	 */
	private function krApply(array $s): void
	{
		// serving: the Unbound backend answers too, so a full confirmation can pass; a worker passes FALSE, and its package rows prove a deferred pass needs no confirmation
		$s += ['snapshot' => TRUE, 'proxy' => 'serves', 'rc' => 'same', 'marker' => NULL, 'gateway' => 'equal', 'decider' => 'equal', 'ctl' => NULL, 'serving' => TRUE, 'dot' => FALSE, 'port' => NULL, 'lan' => NULL, 'lan6' => NULL];
		// The rc script bakes the control socket's path in: it is set before the script is written
		if ($s['ctl'] !== NULL) {
			$GLOBALS['pfb']['dns_proxy_ctl'] = $s['ctl'];
		}
		if ($s['port'] !== NULL) {
			config_set_path('unbound/port', $s['port']);
		}
		if ($s['snapshot']) {
			$keys = [];
			foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
				$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
			}
			config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode($keys)));
		}
		if ($s['proxy'] === 'serves') {
			$this->proxyServes();
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		} elseif ($s['proxy'] === 'lives') {
			// Alive, and never publishing its marker: a listener that failed to start
			$this->proxyLivesButNeverServes();
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		} else {
			$this->clearProxyFiles();
		}
		if ($s['serving']) {
			// The Unbound backend answers, and a gateway that serves forwards to it: a full confirmation needs both
			$this->seedUnbound();
			if ($s['proxy'] === 'serves') {
				$this->seedRunningGateway();
			}
		}
		if ($s['dot']) {
			$this->krEnableDot();
		}
		if ($s['rc'] === 'same') {
			pfb_dns_proxy_service($this->krProxyDir);
		} else {
			file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n# the rc script an older package wrote\n");
		}
		if ($s['lan'] !== NULL) {
			$GLOBALS['pfb_test_interface_ip'] = ['lan' => $s['lan']];
		}
		if ($s['lan6'] !== NULL) {
			$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => $s['lan6']];
		}
		if ($s['marker'] !== NULL) {
			file_put_contents($GLOBALS['pfb']['dns_proxy_restart_pending'], "{$s['marker']}\n");
		}
		$this->krGateway($s['gateway']);
		$this->krDecider($s['decider']);
	}

	/** A DoT listener on lan (192.0.2.1:853), configured as the pfB-DNS page configures it: the gateway's log decides whether it is reported. */
	private function krEnableDot(): void
	{
		// A stored plain interface list: without one, the one-time seed (pfb_dns_proxy_seed_values()) turns DoT off
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_interface', 'lan');
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_dot', 'on');
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_dot_interface', 'lan');
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_dot_port', '853');
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
	}

	private function krGateway(string $mode): void
	{
		$record = $GLOBALS['pfb']['dns_proxy_gateway_applied'];
		$installed = ['freebsd-amd64' => 'gateway binary, amd64'];
		if ($mode === 'equal_one_of_two' || $mode === 'different') {
			$installed['freebsd-arm64'] = 'gateway binary, arm64';
		}
		if ($mode !== 'none') {
			foreach ($installed as $arch => $bytes) {
				mkdir("{$this->krProxyDir}/bin/{$arch}", 0777, TRUE);
				file_put_contents("{$this->krProxyDir}/bin/{$arch}/pfb-dns", $bytes);
			}
		}
		$hash = hash('sha256', 'gateway binary, ' . ($mode === 'equal_one_of_two' ? 'arm64' : 'amd64'));
		match ($mode) {
			'equal', 'equal_one_of_two' => file_put_contents($record, "{$hash}\n"),
			'different', 'none' => file_put_contents($record, str_repeat('0', 64) . "\n"),
			'unreadable' => mkdir($record),
			'absent' => NULL,
		};
	}

	private function krDecider(string $mode): void
	{
		$sources = $GLOBALS['pfb']['dns_proxy_decider_src'];
		foreach ($sources as $path) {
			file_put_contents($path, 'decider member ' . basename($path));
		}
		$record = $GLOBALS['pfb']['dns_proxy_decider_applied'];
		match ($mode) {
			'equal' => file_put_contents($record, pfb_unbound_py_module_fingerprint($sources)),
			'different' => file_put_contents($record, str_repeat('0', 32 * count($sources))),
			'absent' => NULL,
			'unreadable_member' => (static function () use ($sources): void {
				unlink($sources[6]);
			})(),
		};
	}

	private function krEnsure(): bool
	{
		return pfb_dns_proxy_ensure_running($this->krProxyDir);
	}

	/** The cron tick with every scheduled job behind a seam, so only its pfB-DNS check acts; its ledger and state stay under krDir. */
	private function krTick(array $ps = []): void
	{
		$GLOBALS['pfb']['schedule_state_dir'] = $this->krDir;
		$GLOBALS['pfb']['runlog'] = "{$this->krDir}/run.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->krDir}/extras.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->krDir}/pfb_pending_changes";
		// The tick ends with pfb_log_mgmt(), which reads these back through pfb_global(): a stored value each, so that it has nothing to warn about
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '0');
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport', '8081');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport_ssl', '8443');
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		pfblockerng_tick(
			$ps, static function (): void {}, NULL, 5.0, static function (): void {}, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			static function (): void {},
			static fn (): bool => TRUE
		);
	}

	private function krMarker(): ?string
	{
		$text = @file_get_contents($GLOBALS['pfb']['dns_proxy_restart_pending']);
		return $text === FALSE ? NULL : rtrim($text, "\n");
	}

	private function krLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']) . (string) @file_get_contents($GLOBALS['pfb']['errlog']);
	}

	/** @return list<string> the calls the proxy got, as "function service" */
	private function krProxyCalls(): array
	{
		return array_map(static fn (array $call): string => "{$call[0]} {$call[1]}", array_values(array_filter($this->krCalls, static fn (array $call): bool => $call[1] === 'pfb_dns_proxy')));
	}
}
