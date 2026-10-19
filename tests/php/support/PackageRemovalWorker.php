<?php

declare(strict_types=1);

/**
 * Child process for DnsProxyUninstallAbortTest: runs a package removal the way pkg(8) and pfSense run it, against the shipped
 * .inc over the PHPUnit doubles. The process is a private sandbox: after the bootstrap its file access is narrowed to its
 * own temporary directory, the state directory, the result directory and the repository. argv: scenario JSON, result file.
 *
 * What runs, in pkg's order: pfSense's delete_package_xml() work BEFORE the package's hook (worker_core_prelude(): stop each
 * registered service, unlink its rc script, delete its registration and the menu entry, write config.xml -- ported from
 * pfSense master 9363ac5b8651a1c7a333180425ce7719070f95f9 pkg-utils.inc 1002-1058 and RELENG_2_7_2 ec956d34 993-1050), then
 * the hook as pfSense's eval_once() runs it (@eval of the XML text, so the package boundary is the shipped one).
 *
 * pfSense's start_service()/stop_service()/restart_service() act only on a REGISTERED service whose rc script exists
 * (service-utils.inc), which the shared doubles do not model: this worker defines faithful ones, with a process model (a
 * `running.<service>` file per live service) so that "the proxy answers again" is something a test can observe.
 *
 * config.xml is a JSON file in the state directory: write_config() persists the whole in-memory copy (as pfSense does) and
 * a fresh config_read_file() replaces the in-memory copy with the file. The state directory outlives the process, so a
 * second run of the same scenario (the retry) continues from what the first left on disk.
 *
 * Scenario: `failure` (lock | read | survivor | none: why the Resolver cannot be restored, none = it can), `keep` (on | off:
 * Keep Settings), `stored` (full | dnsbl_off | disabled: what config.xml says is on), `permanent` (the lock or the read keeps
 * failing for good, not only through the removal's own attempt), `state` (the directory), `iniGone` (the module's ini is missing
 * when the hook starts), and two ways the proxy's start can go wrong: `startThrows` (the service handler throws) and
 * `proxyWontStart` (the rc script returns and nothing serves). `unmigratedPolicy`: the DNSBL logging policy was never migrated
 * (no apply has run since the key was introduced) and the Resolver is enabled, so the disable pass's policy upgrade turns the
 * uninstall's disable back off and the pass moves the Resolver again. `lockAfterMove`: another save holds the config lock from
 * the moment the Resolver was moved again until the recovery announces itself.
 */

$workerArgv = $argv;
$scenario = json_decode((string) $workerArgv[1], TRUE, 8, JSON_THROW_ON_ERROR);
$resultFile = (string) $workerArgv[2];
$repo = dirname(__DIR__, 3);
$state = (string) $scenario['state'];
$paths = [];
$returned = FALSE;

// Defined before the bootstrap, whose seams and doubles are all guarded: the rc scripts live in the state directory.
define('WORKER_STATE', $state);
define('RCFILEPREFIX', "{$state}/rc.d/");
define('PFB_DNS_PROXY_RCFILE', RCFILEPREFIX . 'pfb_dns_proxy.sh');
@mkdir(RCFILEPREFIX, 0777, TRUE);
// The events are this run's: a retry continues from the files the first run left, not from its events.
@unlink("{$state}/events.log");

const WORKER_FOREIGN_SERVICE = [
	'name' => 'squid', 'rcfile' => 'squid.sh', 'executable' => 'squid', 'description' => 'Squid proxy',
	'custom_php_service_status_command' => 'return TRUE;',
];
const WORKER_PROXY_PID = 4242;
const WORKER_FOREIGN_MENU = ['name' => 'Squid', 'section' => 'Services', 'url' => '/pkg_edit.php?xml=squid.xml'];

function worker_event(string $event): void
{
	file_put_contents(WORKER_STATE . '/events.log', $event . "\n", FILE_APPEND);
}

function worker_persist(): void
{
	file_put_contents(WORKER_STATE . '/config.json', json_encode($GLOBALS['config'], JSON_THROW_ON_ERROR));
}

/** config.xml as it is on disk, which is all that survives the process. */
function worker_disk(): array
{
	return json_decode((string) file_get_contents(WORKER_STATE . '/config.json'), TRUE, 512, JSON_THROW_ON_ERROR);
}

/** service-utils.inc: the registered entry a service name resolves to, NULL when none (the call is then a no-op). */
function worker_registered(string $name): ?array
{
	foreach (config_get_path('installedpackages/service', []) as $service) {
		if (!empty($service) && strtolower((string) ($service['name'] ?? '')) === strtolower($name)) {
			return $service;
		}
	}
	return NULL;
}

function worker_rc_present(array $service): bool
{
	return !empty($service['rcfile']) && file_exists(RCFILEPREFIX . $service['rcfile']);
}

/**
 * A service coming up. The proxy comes up as the real one does (a start over a live one keeps it): its child pidfile, then the
 * marker the proxy publishes once it serves, naming that same PID; pfb_dns_proxy_ready() reads both.
 */
function worker_service_up(string $name): void
{
	if ($name === 'pfb_dns_proxy' && !file_exists(WORKER_STATE . '/running.pfb_dns_proxy')) {
		file_put_contents($GLOBALS['pfb']['dns_proxy_pidfile'], WORKER_PROXY_PID . "\n");
		file_put_contents($GLOBALS['pfb']['dns_proxy_ready'], WORKER_PROXY_PID . "\n");
	}
	touch(WORKER_STATE . "/running.{$name}");
}

/** The service stopped: the proxy's stop removes its pidfile and the marker naming the process it stopped. */
function worker_service_down(string $name): void
{
	@unlink(WORKER_STATE . "/running.{$name}");
	if ($name === 'pfb_dns_proxy') {
		@unlink($GLOBALS['pfb']['dns_proxy_pidfile']);
		@unlink($GLOBALS['pfb']['dns_proxy_ready']);
	}
}

/** The hook's progress line. The recovery's announcement is when the save that held the config lock (lockAfterMove) finishes. */
function update_status($status)
{
	if (!empty($GLOBALS['worker_scenario']['lockAfterMove']) && str_contains((string) $status, 'restoring the DNS proxy')) {
		$GLOBALS['pfb_test_try_lock_fail'] = FALSE;
	}
}

function start_service($name, $after_sync = FALSE)
{
	$service = worker_registered((string) $name);
	if ($service === NULL || !worker_rc_present($service)) {
		worker_event("start:{$name}:ignored");
		return;
	}
	if ($name === 'pfb_dns_proxy' && !empty($GLOBALS['worker_scenario']['startThrows'])) {
		throw new RuntimeException('start exploded');
	}
	worker_event("start:{$name}");
	// The rc scripts: a start over a live service keeps it, else it comes up.
	if (!($name === 'pfb_dns_proxy' && !empty($GLOBALS['worker_scenario']['proxyWontStart']))) {
		worker_service_up($name);
	}
}

function stop_service($name)
{
	$service = worker_registered((string) $name);
	if ($service === NULL || !worker_rc_present($service)) {
		worker_event("stop:{$name}:ignored");
		return;
	}
	worker_event("stop:{$name}");
	if (!($name === 'pfb_dns_proxy' && ($GLOBALS['worker_survivor'] ?? FALSE))) {
		worker_service_down($name);
	}
}

function restart_service($name, string $pid = '', int $timeout = 1)
{
	if (is_service_running($name)) {
		stop_service($name);
	}
	start_service($name);
}

function is_service_running($service, $ps = [])
{
	return file_exists(WORKER_STATE . "/running.{$service}");
}

/**
 * Running an rc script by its path (`<dir>/pfb_dns_proxy.sh start`): what a start that does not go through pfSense's service
 * handler amounts to. It needs no registration, so it is the one start a missing registration cannot stop.
 */
function mwexec_bg($command, $clearsigmask = FALSE)
{
	if (preg_match('#(?:^|/)([a-z_]+)\.sh start$#', (string) $command, $m) === 1 && file_exists(RCFILEPREFIX . "{$m[1]}.sh")) {
		worker_event("direct start:{$m[1]}");
		worker_service_up($m[1]);
	}
}

/** pfSense's delete_package_xml() before the hook (the removal's pre-hook half): what pkg's DEINSTALL step finds already done. */
function worker_core_prelude(): void
{
	$pkg_config = parse_xml_config_pkg(PFB_PACKAGE_XML, 'packagegui');
	$services = config_get_path('installedpackages/service', []);
	if (is_array($pkg_config['menu'] ?? NULL)) {
		$menus = config_get_path('installedpackages/menu', []);
		foreach ($pkg_config['menu'] as $menu) {
			foreach ($menus as $key => $amenu) {
				if ((trim($amenu['name']) == trim($menu['name'])) && ($amenu['section'] == $menu['section'])) {
					unset($menus[$key]);
					break;
				}
			}
		}
		config_set_path('installedpackages/menu', $menus);
	}
	if (is_array($pkg_config['service'] ?? NULL) && is_array($services)) {
		foreach ($pkg_config['service'] as $service) {
			if (empty($service)) {
				continue;
			}
			foreach ($services as $key => $instservice) {
				if (empty($instservice) || ($instservice['name'] != $service['name'])) {
					continue;
				}
				stop_service($service['name']);
				if ($service['rcfile']) {
					unlink_if_exists(RCFILEPREFIX . $service['rcfile']);
				}
				config_del_path("installedpackages/service/{$key}");
			}
		}
	}
	write_config('Intermediate config write during package removal for pfBlockerNG.', FALSE, TRUE);
	// Core then loads the package's include: its load-time block (pfblockerng.inc, "Create Firewall filter service" and
	// "Create DNSBL service") writes the two rc scripts it finds missing. The proxy's rc script has no such writer.
	$GLOBALS['pfb_test_rcfile_dir'] = rtrim(RCFILEPREFIX, '/');
	foreach (['pfb_filter.sh' => 'pfb_filter_service', 'pfb_dnsbl.sh' => 'pfb_dnsbl_service'] as $rcfile => $writer) {
		if (!file_exists(RCFILEPREFIX . $rcfile)) {
			$writer();
		}
	}
}

/** install_package_xml()'s menu and service registration (pkg-utils.inc master 916-952), the seed's registered state. */
function worker_core_register(): void
{
	$pkg_config = parse_xml_config_pkg(PFB_PACKAGE_XML, 'packagegui');
	$menus = config_get_path('installedpackages/menu', []);
	foreach ($pkg_config['menu'] as $menu) {
		foreach ($menus as $amenu) {
			if ((trim($amenu['name']) == trim($menu['name'])) && ($amenu['section'] == $menu['section'])) {
				continue 2;
			}
		}
		$menus[] = $menu;
	}
	config_set_path('installedpackages/menu', $menus);
	$services = config_get_path('installedpackages/service', []);
	foreach ($pkg_config['service'] as $service) {
		foreach ($services as $aservice) {
			if (trim($aservice['name']) == trim($service['name'])) {
				continue 2;
			}
		}
		$services[] = $service;
	}
	config_set_path('installedpackages/service', $services);
}

/** The DNSBL module's inputs the apply pass loads (pfblockerng_apply.inc), which the baseline apply would have left in $pfb. */
function worker_dnsbl_inputs(): void
{
	pfb_dnsbl_ini_inputs();
}

register_shutdown_function(static function () use ($resultFile, &$paths, &$returned, $state): void {
	$canary = static fn (string $key): bool => isset($paths[$key]) && file_exists($paths[$key]);
	$disk = is_file("{$state}/config.json") ? worker_disk() : [];
	$services = $disk['installedpackages']['service'] ?? [];
	$menus = $disk['installedpackages']['menu'] ?? [];
	$baseline = is_file("{$state}/baseline.json") ? json_decode((string) file_get_contents("{$state}/baseline.json"), TRUE) : [];
	$stripStamp = static fn (string $ini): string => (string) preg_replace('/^; pfb_unbound\.ini \[ File created:.*\]$/m', '', $ini);
	$rc = (string) @file_get_contents(PFB_DNS_PROXY_RCFILE);
	$ini = (string) @file_get_contents("{$state}/pfb_unbound.ini");
	file_put_contents($resultFile, json_encode([
		'returned'  => $returned,
		// What survived on disk: the only thing that outlives the process
		'snapshot'  => ($disk['installedpackages']['pfblockerngdns']['config'][0]['pfb_dns_saved'] ?? '') !== '',
		'interface' => $disk['unbound']['active_interface'] ?? NULL,
		'sections'  => array_keys($disk['installedpackages'] ?? []),
		'services'  => array_values(array_map(static fn (array $s): string => (string) ($s['name'] ?? ''), $services)),
		'menus'     => array_values(array_map(static fn (array $m): string => ($m['section'] ?? '') . ':' . ($m['name'] ?? ''), $menus)),
		'foreign'   => in_array(WORKER_FOREIGN_SERVICE, $services, TRUE) && in_array(WORKER_FOREIGN_MENU, $menus, TRUE),
		'pending'   => $canary('pending'),
		'dbCanary'  => $canary('db'),
		'logCanary' => $canary('log'),
		'rawFeed'   => $canary('raw'),
		'manifest'  => file_exists("{$state}/pfb_py_sources.json"),
		'rcScript'  => $rc !== '',
		'rcSameAsBaseline' => $rc !== '' && $rc === ($baseline['rc'] ?? NULL),
		'noModule'  => str_contains($rc, '--no-module'),
		'iniSameAsBaseline' => $ini !== '' && $stripStamp($ini) === $stripStamp((string) ($baseline['ini'] ?? '')),
		'ini'       => $stripStamp($ini),
		'running'   => array_values(array_map(static fn (string $f): string => substr(basename($f), 8), glob("{$state}/running.*") ?: [])),
		'events'    => is_file("{$state}/events.log") ? array_values(array_filter(explode("\n", (string) file_get_contents("{$state}/events.log")))) : [],
		'lockHeld'  => !empty($GLOBALS['pfb_test_lock_held']),
		'notices'   => array_column($GLOBALS['pfb_test_file_notices'] ?? [], 'notice'),
		'writes'    => $GLOBALS['pfb_test_write_config_calls'] ?? [],
	], JSON_THROW_ON_ERROR));
});

require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/SyncPrereqSeedTrait.php';

final class PackageRemovalWorkerSeeder
{
	use SyncPrereqSeedTrait;

	public function seed(): void
	{
		$this->seedSyncPrereqs();
	}
}

global $pfb, $g;
$tmp = $GLOBALS['pfb_test_tmp'];
$g['unbound_chroot_path'] = "{$tmp}/unbound";
mkdir($g['unbound_chroot_path'], 0777, TRUE);
$GLOBALS['worker_survivor'] = $scenario['failure'] === 'survivor';
$GLOBALS['worker_scenario'] = $scenario;
$GLOBALS['pfb_test_rcfile_dir'] = rtrim(RCFILEPREFIX, '/');
$GLOBALS['pfb_test_write_config_hook'] = static function (string $desc): void {
	worker_persist();
	// lockAfterMove: another save takes the config lock just after the Resolver was moved again
	if (!empty($GLOBALS['worker_scenario']['lockAfterMove']) && str_contains($desc, 'Moved the DNS Resolver')) {
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
	}
};
$GLOBALS['pfb_test_config_read_hook'] = static function (): void {
	$last = end($GLOBALS['pfb_test_config_read_calls']);
	if ($last[1] === FALSE && empty($GLOBALS['pfb_test_config_read_fails'])) {
		$GLOBALS['config'] = worker_disk();
	}
};
// The proxy's readiness files (child pidfile, listener-ready marker) are state a retry's process finds as the first one left it
$pfb['dns_proxy_pidfile'] = "{$state}/pfb_dns_proxy.pid";
$pfb['dns_proxy_ready'] = "{$state}/pfb_dns_ready";
$alive = static fn (): bool => file_exists(WORKER_STATE . '/running.pfb_dns_proxy');
$GLOBALS['pfb_test_valid_pids'] = [
	PFB_DNS_PROXY_PIDFILE        => $alive,
	PFB_DNS_PROXY_DAEMON_PIDFILE => $alive,
	$pfb['dns_proxy_pidfile']    => $alive,
];
// The sinkhole VIP pfSense knows (every run: the retry's config.xml names it too)
$GLOBALS['pfb_test_vip_list'] = ['_vip_test_a' => '10.10.10.1'];

if (is_file("{$state}/config.json")) {
	// A retry: the state the aborted removal left on disk
	$GLOBALS['config'] = worker_disk();
} else {
	$GLOBALS['config'] = [];
	(new PackageRemovalWorkerSeeder())->seed();
	$stored = $scenario['stored'] ?? 'full';
	config_set_path('installedpackages/pfblockerng/config/0/enable_cb', $stored === 'disabled' ? '' : 'on');
	// Keep Settings: the registered toggle's Off token is the empty string.
	config_set_path('installedpackages/pfblockerng/config/0/pfb_keep', $scenario['keep'] === 'on' ? 'on' : '');
	// DNSBL in VIP mode: a manual sinkhole VIP, reply logging and the control integration on
	$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
	config_set_path("{$dnsbl}/pfb_dnsbl", $stored === 'full' ? 'on' : '');
	config_set_path("{$dnsbl}/dnsbl_interface", 'opt-double');
	config_set_path("{$dnsbl}/pfb_dnsvip4", '_vip_test_a');
	config_set_path("{$dnsbl}/pfb_py_reply", 'on');
	config_set_path("{$dnsbl}/pfb_control", 'on');
	config_set_path("{$dnsbl}/pfb_py_cache_max", '777');	// a cap the apply writes into the ini: the recovery must not reset it to the default
	// The DNSBL logging policy an earlier apply already migrated (issue #3288): without the key the disable pass's policy
	// upgrade calls pfb_global() again, which re-reads enable_cb and turns the uninstall's disable back on (unmigratedPolicy).
	if (empty($scenario['unmigratedPolicy'])) {
		config_set_path("{$dnsbl}/global_log_mode", 'default');
	}
	config_set_path('virtualip/vip', [['uniqid' => '_test_a', 'subnet' => '10.10.10.1']]);
	config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns', 'on');
	config_set_path('installedpackages/package', [['name' => 'pfBlockerNG-devel', 'internal_name' => 'pfblockerng', 'configurationfile' => 'pfblockerng.xml']]);

	// The Resolver as the DNS proxy leaves it, with the copy of the user's settings it saved.
	$GLOBALS['config']['unbound'] = [
		'port'             => '53',
		'active_interface' => 'lo0',
		'custom_options'   => base64_encode("do-ip6: no\nserver:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\n"
			. "interface: ::1@5353\nproxy-protocol-port: 5353\n# end pfBlockerNG DNS proxy"),
	];
	if (!empty($scenario['unmigratedPolicy'])) {
		// The re-enabled pass asks for pfB-DNS only while the Resolver is enabled (pfb_dns_wanted())
		$GLOBALS['config']['unbound']['enable'] = '';
	}
	$saved = [];
	foreach (['active_interface' => 'lan,opt1', 'enablessl' => '', 'custom_options' => base64_encode('do-ip6: no')] as $key => $value) {
		$saved[$key] = ['present' => TRUE, 'value' => $value];
	}
	config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode($saved)));

	// The package installed next to another package's service and menu entry, before and after its own
	config_set_path('installedpackages/service', [WORKER_FOREIGN_SERVICE]);
	config_set_path('installedpackages/menu', [WORKER_FOREIGN_MENU]);
	worker_core_register();
	$GLOBALS['config']['installedpackages']['service'][] = ['name' => 'zeek', 'rcfile' => 'zeek.sh', 'executable' => 'zeek', 'description' => 'Zeek'];
	worker_persist();
}

pfb_global();
// The scheduler's dispatcher lock is a file in the state directory here, so the disable pass takes it as on the appliance
// and runs its teardown; at its /usr/local/etc default the pass returns at the lock before touching anything.
$pfb['schedule_state_dir'] = $state;
$pfb['unbound_py_conf'] = "{$state}/pfb_unbound.ini";
$pfb['unbound_py_sources'] = "{$state}/pfb_py_sources.json";
$pfb['unbound_py_rawdir'] = "{$state}/pfb_py_raw";
$paths = ['pending' => "{$tmp}/pending", 'db' => "{$pfb['dbdir']}/canary.txt", 'log' => "{$pfb['logdir']}/canary.txt",
	'raw' => "{$pfb['unbound_py_rawdir']}/canary.txt"];
$pfb['pending_marker'] = $paths['pending'];
pfb_mark_pending_changes();
foreach (['db', 'log', 'raw'] as $dir) {
	@mkdir(dirname($paths[$dir]), 0777, TRUE);
	file_put_contents($paths[$dir], 'user data');
}

if (!is_file("{$state}/baseline.json")) {
	// The baseline: what the last apply left behind while pfB-DNS served -- the proxy's rc script and the DNSBL module's
	// ini, both from the settings config.xml stores, the module's manifest, and the services running
	worker_dnsbl_inputs();
	pfb_dns_proxy_service();
	pfb_filter_service();
	pfb_dnsbl_service();
	if (pfb_dnsbl_active()) {
		file_put_contents($pfb['unbound_py_conf'], pfb_unbound_python_ini('enabled', 'BASELINE'));
	}
	file_put_contents($pfb['unbound_py_sources'], '{"manifest":true}');
	file_put_contents("{$state}/baseline.json", json_encode([
		'rc'  => (string) file_get_contents(PFB_DNS_PROXY_RCFILE),
		'ini' => (string) @file_get_contents($pfb['unbound_py_conf']),
	], JSON_THROW_ON_ERROR));
	foreach (['pfb_dns_proxy', 'pfb_filter', 'pfb_dnsbl', 'squid', 'zeek'] as $running) {
		worker_service_up($running);
	}
	unset($pfb['dnsbl_tld_wildcard'], $pfb['dnsbl_control'], $pfb['dnsbl_control_legacy'], $pfb['dnsbl_decisiondb_max']);
}
if (!empty($scenario['iniGone'])) {
	// The module's ini is not there when the hook starts (a RAM-disk /var that was rebuilt, say)
	@unlink($pfb['unbound_py_conf']);
}

// The removal's core prelude has run when the hook starts
worker_core_prelude();

switch ($scenario['failure']) {
	case 'lock':
		if (!empty($scenario['permanent'])) {
			$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		} else {
			// Another save holds the lock for 15 s: the removal's restore waits its 10 s and gives up, and the lock is free
			// for the 5 s the recovery's own wait outlasts.
			$GLOBALS['pfb_test_try_lock_busy_for'] = 15;
		}
		break;
	case 'read':
		if (!empty($scenario['permanent'])) {
			$GLOBALS['pfb_test_config_read_fails'] = TRUE;
		} else {
			// config.xml does not parse for the removal's restore, then does for the recovery's read
			$GLOBALS['pfb_test_config_read_fails_for'] = 1;
		}
		break;
	case 'survivor':
		// the proxy outlives every stop, core's included: see stop_service()
		break;
}

// The one include the hook requires that the shared doubles do not shim.
mkdir("{$tmp}/inc");
touch("{$tmp}/inc/config.inc");
set_include_path("{$tmp}/inc" . PATH_SEPARATOR . get_include_path());
ini_set('open_basedir', "{$tmp}:{$state}:" . dirname($resultFile) . ":{$repo}:/usr/share/php:/dev/null:/dev/urandom");

$xml = simplexml_load_file($repo . '/src/usr/local/pkg/pfblockerng.xml');
@eval((string) $xml->custom_php_pre_deinstall_command);
$returned = TRUE;
