<?php

declare(strict_types=1);

// Only pfSense's boundaries and the machine's pfctl and SQLite files are doubled; the verb dispatch and counter clearing are shipped code.
// $argv[1]: the sandbox root; <root>/case.json: {"enabled": bool, "widgets": {key: value}, "args": [string]}.
$root = $argv[1];
$case = json_decode((string) file_get_contents("$root/case.json"), TRUE, 512, JSON_THROW_ON_ERROR);
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
config_set_path('installedpackages/pfblockerng/config/0', ['enable_cb' => $case['enabled'] ? 'on' : '', 'skipfeed' => '3']);
config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
foreach ($case['widgets'] as $type => $value) {
	config_set_path("installedpackages/pfblockerngglobal/widget-{$type}", $value);
}
$GLOBALS['pfb_test_config_read_hook'] = static function () use ($root): void {
	$GLOBALS['pfb']['folder_array'] = ["$root/db/pfblockerng", "$root/log/pfblockerng"];
	$GLOBALS['pfb']['pfctl'] = "$root/pfctl";
	$GLOBALS['pfb']['dnsbl_resolver'] = "$root/resolver.sqlite";
	$GLOBALS['pfb']['dnsbl_info'] = "$root/dnsbl.sqlite";
	$GLOBALS['pfb']['errlog'] = "$root/error.log";
};
require_once dirname(__DIR__, 3) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
$warnings = [];
register_shutdown_function(static function () use ($root, &$warnings): void {
	file_put_contents("$root/warnings.json", json_encode($warnings, JSON_THROW_ON_ERROR));
	if ($warnings !== []) {
		exit(1);
	}
});
$GLOBALS['argv'] = array_merge(['pfblockerng.inc', 'core_counters'], $case['args']);
error_reporting(E_ALL & ~E_DEPRECATED);
set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$warnings): bool {
	if (($severity & E_WARNING) !== 0 && (error_reporting() & $severity) !== 0) {
		$warnings[] = ['severity' => $severity, 'message' => $message, 'file' => $file, 'line' => $line];
	}
	return FALSE;
});
require dirname(__DIR__, 3) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
