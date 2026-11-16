<?php

declare(strict_types=1);

// Only pfSense boundaries are doubled; the maintenance dispatch and tick are shipped code.
$root = $argv[2];
$verb = $argv[1];
function safe_mkdir($path, $mode = 0755) {
	global $root;
	if (!str_starts_with($path, $root . '/')) {
		return FALSE;
	}
	return is_dir($path) || mkdir($path, $mode, TRUE);
}
require_once __DIR__ . '/../pfsense_doubles.php';
set_include_path(__DIR__ . '/../shims' . PATH_SEPARATOR . get_include_path());
$GLOBALS['g'] = ['vardb_path' => "$root/db", 'varlog_path' => "$root/log", 'tmp_path' => "$root/tmp", 'varrun_path' => "$root/tmp", 'pfblockerng_install' => FALSE, 'unbound_chroot_path' => '/var/unbound'];
$GLOBALS['pfb'] = [];
$GLOBALS['config'] = [];
config_set_path('installedpackages/pfblockerng/config/0', ['enable_cb' => ($argv[3] ?? 'on'), 'pfb_quiet_hours' => '', 'skipfeed' => '3']);
config_set_path('installedpackages/pfblockernglistsv4/config', [[
	'aliasname' => 'Maintenance', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay',
	'row' => [['header' => 'maintenance', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
]]);
config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
$GLOBALS['pfb_test_config_read_hook'] = static function () use ($root): void {
	$GLOBALS['pfb']['core_socket'] = "$root/no-core.sock";
	$GLOBALS['pfb']['core_revision_key'] = "$root/revision.key";
	$GLOBALS['pfb']['core_settings_failed'] = "$root/settings-failed";
	$GLOBALS['pfb']['pending_marker'] = "$root/pending";
	$GLOBALS['pfb']['folder_array'] = ["$root/db/pfblockerng", "$root/log/pfblockerng"];
	file_put_contents("$root/initialized", "config read\n", FILE_APPEND);
};
require_once dirname(__DIR__, 3) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
$warnings = [];
register_shutdown_function(static function () use ($root, &$warnings): void {
	file_put_contents("$root/notices.json", json_encode($GLOBALS['pfb_test_logger_calls'] ?? []));
	file_put_contents("$root/boundaries.json", json_encode([
		'services' => $GLOBALS['pfb_test_service_calls'] ?? [],
		'exec' => $GLOBALS['pfb_test_mwexec'] ?? [],
		'background' => $GLOBALS['pfb_test_mwexec_bg'] ?? [],
	]));
	file_put_contents("$root/warnings.json", json_encode($warnings, JSON_THROW_ON_ERROR));
	if ($warnings !== []) {
		exit(1);
	}
});
// A direct call is the manual tick contract; all other verbs enter the real CLI dispatcher.
$GLOBALS['argv'] = ['pfblockerng.inc', $verb === 'direct-tick' ? '' : $verb];
error_reporting(E_ALL & ~E_DEPRECATED);
set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$warnings): bool {
	if (($severity & E_WARNING) !== 0 && (error_reporting() & $severity) !== 0) {
		$warnings[] = ['severity' => $severity, 'message' => $message, 'file' => $file, 'line' => $line];
	}
	return FALSE;
});
if (is_file("$root/warning-canary")) {
	file_put_contents("$root/warning-canary-reached", "before fopen\n");
	if (file_get_contents("$root/warning-canary") === 'suppressed') {
		@fopen("$root/warning-canary-missing", 'rb');
	} else {
		fopen("$root/warning-canary-missing", 'rb');
	}
}
require dirname(__DIR__, 3) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
if ($verb === 'direct-tick') {
	pfb_global();
	pfblockerng_tick(ps_lines: []);
}
