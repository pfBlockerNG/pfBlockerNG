<?php
// probe.php <cmd> [args]: the real-pkg removal oracle's driver. The pinned pfSense core (core.php, extracted from the real files),
// the repo's own production code and the shipped package XML over a file-backed config.xml ($RACE_DIR/config.json) with real locks.
//   seed          pfB-DNS serving: the Resolver moved, the package registered, module staged, rc scripts written by production
//   start         start the proxy the way pfSense does (pinned start_service())
//   rc_packages   pfSense's rc.packages for pkg's DEINSTALL / POST-DEINSTALL scripts: the pinned delete_package_xml(), which
//                 stops and deregisters the services BEFORE it evaluates the shipped custom_php_pre_deinstall_command
//   state         one JSON line: what is registered, what runs, which rc scripts exist
// Nothing here is part of the package.
$dir = (string) getenv('RACE_DIR');
$probe_args = $argv;   // tests/php/bootstrap.php clears $argv to keep the package's daemon dispatch dormant
$cmd = $probe_args[1] ?? '';
require_once __DIR__ . '/prelude.php';
require_once __DIR__ . '/core.php';
$repo = (string) (getenv('ORACLE_REPO') ?: '/repo');
define('PFB_DNS_PROXY_START_WAIT', 30);
require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/SyncPrereqSeedTrait.php';
final class ProbeSeeder { use SyncPrereqSeedTrait; public function seed(): void { $this->seedSyncPrereqs(); } }

global $pfb, $g;
$g['product_label'] = 'pfSense';
$g['unbound_chroot_path'] = '/var/unbound';
$g['varetc_path'] = '/etc';
// The proxy here is a real process on the appliance's paths and startup budget: the bootstrap points both at its PHPUnit sandbox
// and gives readiness one second, and the rc script's daemon writes the pidfile and the --ready-file marker where production says
$pfb['dns_proxy_pidfile'] = PFB_DNS_PROXY_PIDFILE;
$pfb['dns_proxy_ready'] = '/var/unbound/pfb_dns_ready';
$cfgfile = race_path('config.json');
// A sinkhole VIP pfSense knows: the shared doubles resolve ids of this shape
$GLOBALS['pfb_test_vip_list'] = ['_vip_test_a' => '10.10.10.1'];
const ORACLE_MODULE_DIR = '/var/unbound';

function oracle_load_config(): void
{
	global $cfgfile, $pfb;
	$GLOBALS['config'] = json_decode((string) file_get_contents($cfgfile), TRUE);
	pfb_global();
	$pfb['logdir'] = $GLOBALS['pfb_test_tmp'];
	$pfb['schedule_state_dir'] = $GLOBALS['pfb_test_tmp'];   // the dispatcher lock is a real file here, as on the appliance: the disable pass runs
}

/** install_package_xml()'s registration blocks (pkg-utils.inc "sidebar items", "services"): what the seed's install left registered. */
function oracle_register(): void
{
	$pkg_config = parse_xml_config_pkg(PFB_PACKAGE_XML, 'packagegui');
	$menus = config_get_path('installedpackages/menu', []);
	foreach ($pkg_config['menu'] as $menu) {
		$menus[] = $menu;
	}
	config_set_path('installedpackages/menu', $menus);
	$services = config_get_path('installedpackages/service', []);
	foreach ($pkg_config['service'] as $service) {
		$services[] = $service;
	}
	config_set_path('installedpackages/service', $services);
}

function oracle_state(): string
{
	$services = array_values(array_map(static fn ($s): string => (string) ($s['name'] ?? '?'), array_filter(config_get_path('installedpackages/service', []))));
	$menus = array_values(array_map(static fn ($m): string => ($m['section'] ?? '') . ':' . ($m['name'] ?? '?'), array_filter(config_get_path('installedpackages/menu', []))));
	$rc = array_map('basename', glob(RCFILEPREFIX . 'pfb_*.sh') ?: []);
	return json_encode([
		'registered_services' => $services, 'registered_menu' => $menus, 'rc_scripts' => $rc,
		'proxy_running' => isvalidpid(PFB_DNS_PROXY_PIDFILE), 'supervisor_running' => isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE),
		'snapshot' => pfb_dns_proxy_saved() !== NULL, 'resolver_interface' => config_get_path('unbound/active_interface'),
		'package_entry' => count(config_get_path('installedpackages/package', [])),
		'manifest' => file_exists(ORACLE_MODULE_DIR . '/pfb_py_sources.json'),
		'rc_no_module' => str_contains((string) @file_get_contents(PFB_DNS_PROXY_RCFILE), '--no-module'),
	]);
}

if ($cmd !== 'seed') {
	oracle_load_config();
}
switch ($cmd) {
	case 'seed':
		$GLOBALS['config'] = [];
		(new ProbeSeeder())->seed();
		config_set_path('installedpackages/package', [['name' => 'pfBlockerNG-devel', 'internal_name' => 'pfblockerng', 'configurationfile' => 'pfblockerng.xml']]);
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');
		config_set_path('installedpackages/pfblockerng/config/0/pfb_keep', 'on');
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		config_set_path("{$dnsbl}/pfb_dnsbl", 'on');
		config_set_path("{$dnsbl}/dnsbl_interface", 'opt-double');
		config_set_path("{$dnsbl}/pfb_dnsvip4", '_vip_test_a');
		config_set_path("{$dnsbl}/pfb_py_reply", 'on');
		// The DNSBL logging policy an earlier apply already migrated (issue #3288): without the key the disable pass's policy
		// upgrade calls pfb_global() again, which re-reads enable_cb and turns the uninstall's disable back on.
		config_set_path("{$dnsbl}/global_log_mode", 'default');
		config_set_path('virtualip/vip', [['uniqid' => '_test_a', 'subnet' => '10.10.10.1']]);
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns', 'on');
		config_set_path('unbound/enable', '');
		config_set_path('unbound/port', '53');
		config_set_path('unbound/active_interface', '127.0.0.1');
		config_set_path('unbound/custom_options', base64_encode('do-ip6: no'));
		oracle_register();
		write_config('seed');
		oracle_load_config();
		if (pfb_dns_proxy_resolver(TRUE) !== TRUE) {
			fwrite(STDERR, "seed: the Resolver move was refused\n");
			exit(3);
		}
		// The module the proxy hosts: shipped code, the ini the production generator writes, a manifest and one raw feed
		foreach (['pfb_unbound.py', 'pfb_dnsbl_regex_rules.py'] as $shipped) {
			@unlink(ORACLE_MODULE_DIR . "/{$shipped}");
			symlink("/usr/local/pkg/pfblockerng/{$shipped}", ORACLE_MODULE_DIR . "/{$shipped}");
		}
		@mkdir(ORACLE_MODULE_DIR . '/pfb_py_raw', 0755, TRUE);
		file_put_contents(ORACLE_MODULE_DIR . '/pfb_py_raw/feed.txt', "blocked.example\n");
		file_put_contents(ORACLE_MODULE_DIR . '/pfb_py_sources.json', json_encode([
			'version' => 1, 'config' => new stdClass(),
			'feeds' => [['raw' => 'pfb_py_raw/feed.txt', 'feed' => 'TestFeed', 'group' => 'TestGroup', 'log_flag' => '1']],
		]));
		$pfb['dnsbl_tld_wildcard'] = $pfb['dnsblconfig']['tld_wildcard'] ?? '';
		$pfb['dnsbl_control'] = pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_control'] ?? '');
		$pfb['dnsbl_control_legacy'] = pfb_cfg_toggle_read($pfb['dnsblconfig']['pfb_control_legacy'] ?? '');
		file_put_contents($pfb['unbound_py_conf'], pfb_unbound_python_ini('enabled', 'BASELINE'));
		pfb_dns_proxy_service();
		pfb_filter_service();
		pfb_dnsbl_service();
		echo 'seeded; ', oracle_state(), "\n";
		break;
	case 'start':
		start_service('pfb_dns_proxy');
		usleep(2500000);
		echo 'start_service: ', oracle_state(), "\n";
		break;
	case 'rc_packages':   // /etc/rc.packages PKG_NAME (DEINSTALL|POST-DEINSTALL), pinned master rc.packages
		// The hook requires config.inc, which pfSense's rc.packages has loaded already (core's own comment: loading it again would
		// invalidate the intermediate write): an empty file satisfies the require
		@mkdir('/tmp/oracle_inc');
		touch('/tmp/oracle_inc/config.inc');
		set_include_path('/tmp/oracle_inc' . PATH_SEPARATOR . get_include_path());
		$pkg = (string) ($probe_args[2] ?? '');
		$when = strtolower((string) ($probe_args[3] ?? ''));
		pkg_remove_prefix($pkg);
		delete_package_xml($pkg, $when);
		break;
	case 'state':
		echo oracle_state(), "\n";
		break;
	default:
		fwrite(STDERR, "unknown cmd\n");
		exit(2);
}
