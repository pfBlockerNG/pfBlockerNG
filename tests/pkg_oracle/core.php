<?php
// The pinned pfSense core, as the functions pkg's DEINSTALL step runs, extracted by name from the REAL files
// ($CORE_DIR/<label>.<file>, fetched by build.sh at the commits in PINS and checked against their sha256) and eval'd as they are.
// Only what pfSense provides around them and the sandbox lacks is a stand-in, listed below; nothing here is a copy of a body.
//
// Load this BEFORE tests/php/bootstrap.php: the shared doubles are function_exists()-guarded, so these win.

const ORACLE_CORE_FUNCTIONS = [
	'service-utils.inc' => ['write_rcfile', 'start_service', 'stop_service', 'restart_service', 'is_service_running'],
	'pkg-utils.inc'     => ['delete_package_xml', 'get_package_id', 'get_package_internal_name', 'eval_once', 'pkg_remove_prefix'],
	'util.inc'          => ['isvalidpid'],
	'xmlparse.inc'      => ['listtags_pkg', 'startElement', 'endElement', 'cData', 'parse_xml_config_pkg', 'parse_xml_config_raw'],
];

/** The source text of one top-level function, from its `function` keyword to its closing brace. */
function oracle_function_source(string $file, string $name): string
{
	$tokens = token_get_all((string) file_get_contents($file));
	$count = count($tokens);
	for ($i = 0; $i < $count; $i++) {
		if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_FUNCTION) {
			continue;
		}
		$j = $i + 1;
		while ($j < $count && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
			$j++;
		}
		if (!is_array($tokens[$j]) || $tokens[$j][0] !== T_STRING || $tokens[$j][1] !== $name) {
			continue;
		}
		$source = '';
		$depth = 0;
		$opened = FALSE;
		for ($k = $i; $k < $count; $k++) {
			$text = is_array($tokens[$k]) ? $tokens[$k][1] : $tokens[$k];
			$source .= $text;
			if (is_array($tokens[$k]) && in_array($tokens[$k][0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], TRUE)) {
				$depth++;
			} elseif ($text === '{') {
				$depth++;
				$opened = TRUE;
			} elseif ($text === '}') {
				$depth--;
				if ($opened && $depth === 0) {
					return $source;
				}
			}
		}
	}
	throw new RuntimeException("function {$name} not found in {$file}");
}

$oracle_label = getenv('CORE_LABEL') ?: 'master';
$oracle_core_dir = getenv('CORE_DIR') ?: '/core';
foreach (ORACLE_CORE_FUNCTIONS as $oracle_file => $oracle_names) {
	foreach ($oracle_names as $oracle_name) {
		eval(oracle_function_source("{$oracle_core_dir}/{$oracle_label}.{$oracle_file}", $oracle_name));
	}
}

// Constants and helpers pfSense defines elsewhere (globals.inc, util.inc, ...), at their appliance values.
const RCFILEPREFIX = '/usr/local/etc/rc.d/';
const PFB_DNS_PROXY_RCFILE = '/usr/local/etc/rc.d/pfb_dns_proxy.sh';
const PFB_PACKAGE_XML = '/usr/local/pkg/pfblockerng.xml';
if (!defined('LOG_PREFIX_CONFIG')) {
	define('LOG_PREFIX_CONFIG', 'config');
}
if (!function_exists('gettext')) {
	function gettext($text) { return $text; }
}
function localize_text($text, ...$args) { return $args === [] ? $text : vsprintf($text, $args); }
function logger($level, $text, $prefix = '') { fwrite(STDERR, "logger: {$text}\n"); }
function update_status($text) { echo $text; }
function pkg_debug($text) {}
function g_get($key, $default = NULL) { return $GLOBALS['g'][$key] ?? ($key === 'pkg_prefix' ? 'pfSense-pkg-' : $default); }
function is_platform_booting() { return FALSE; }
function system_syslogd_start($sighup = FALSE) {}
function mwexec($command) { exec($command . ' 2>&1', $output, $rc); return $rc; }
function mwexec_bg($command, $clearsigmask = FALSE) { exec($command . ' >/dev/null 2>&1 &'); }
function is_process_running($process) { exec('pgrep -x ' . escapeshellarg((string) $process) . ' >/dev/null 2>&1', $output, $rc); return $rc === 0; }
// config.lib.inc (not pinned here): RELENG_2_7_2's delete_package_xml() makes sure a config path is an array before it edits it
function init_config_arr(array $keys) {
	$node = &$GLOBALS['config'];
	foreach ($keys as $key) {
		if (!isset($node[$key]) || !is_array($node[$key])) {
			$node[$key] = [];
		}
		$node = &$node[$key];
	}
}
function platform_booting() { return FALSE; }   // RELENG_2_7_2's name for is_platform_booting()
