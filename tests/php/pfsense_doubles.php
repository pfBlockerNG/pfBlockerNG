<?php
/*
 * pfsense_doubles.php — runtime doubles for the pfSense-provided functions that
 * pfblockerng.inc references but that don't exist off-appliance.
 *
 * The PHPStan stubs in stubs/pfsense/ only assert symbol existence (empty
 * bodies) — useless as behavioural doubles. Here we define the small set the
 * unit-tested code paths (and pfblockerng.inc's load-time top-level code)
 * actually invoke, with FAITHFUL behaviour where a tested function's result
 * depends on it:
 *
 *   - is_ipaddrv4 / is_ipaddrv6 / is_ipaddr — mirror pfSense util.inc exactly
 *     (ip2long round-trip for v4; filter_var for v6). pfb_filter (IP/IPV4) and
 *     pfb_dnsbl_abp_extract_ip depend on their precise accept/reject behaviour.
 *
 * Everything else is a minimal no-op/throwaway double: it exists only so the
 * symbol resolves. Functions reached only by code paths the seed suite does NOT
 * exercise (URL/HOSTNAME validation, host resolution) get a conservative stub.
 *
 * Each double is guarded by function_exists() so a future real include never
 * collides with it.
 */

if (!function_exists('is_ipaddrv4')) {
	// pfSense util.inc: a string whose ip2long round-trips back to itself.
	// Rejects '1.2.3', leading-zero octets, out-of-range, non-strings.
	function is_ipaddrv4($ipaddr) {
		if (!is_string($ipaddr) || empty($ipaddr)) {
			return false;
		}
		$ip_long = ip2long($ipaddr);
		$ip_reverse = long2ip($ip_long);
		return ($ipaddr === $ip_reverse);
	}
}

if (!function_exists('is_ipaddrv6')) {
	// pfSense util.inc: strip a zone id (%scope), then FILTER_VALIDATE_IP v6.
	function is_ipaddrv6($ipaddr) {
		if (!is_string($ipaddr) || empty($ipaddr)) {
			return false;
		}
		if (strstr($ipaddr, '%') !== false) {
			$parts = explode('%', $ipaddr);
			$ipaddr = $parts[0];
		}
		return (filter_var($ipaddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false);
	}
}

if (!function_exists('is_ipaddr')) {
	// pfSense util.inc: v4 OR v6.
	function is_ipaddr($ipaddr) {
		return (is_ipaddrv4($ipaddr) || is_ipaddrv6($ipaddr));
	}
}

if (!function_exists('is_hostname')) {
	// Reached only by PFB_FILTER_HOSTNAME, which the seed suite does not exercise.
	// Fail fast rather than guess pfSense's semantics (a guessed double could let a
	// future test pass against behaviour pfSense never had). Port the real
	// util.inc is_hostname() here when a HOSTNAME path is first tested.
	function is_hostname($hostname, $allow_wildcard = false) {
		throw new LogicException(__FUNCTION__ . '() double not implemented — port the real pfSense is_hostname() before testing this path');
	}
}

if (!function_exists('is_port')) {
	// pfSense util.inc: a single TCP/UDP port — a pure-digit string in 1..65535
	// (no ranges, no aliases). step3_submitphpaction() validates pfb_dnsport /
	// pfb_dnsport_ssl through this; WizardVipAutoTest supplies valid ports so the
	// port branch never masks the VIP-validation branch under test.
	function is_port($port) {
		if (!ctype_digit((string) $port)) {
			return false;
		}
		$port = (int) $port;
		return ($port >= 1 && $port <= 65535);
	}
}

if (!function_exists('system_get_uniqueid')) {
	// Called at pfblockerng.inc load time (cURL user-agent). Any stable string.
	function system_get_uniqueid() {
		return 'phpunit-0000000000000000';
	}
}

if (!function_exists('write_rcfile')) {
	// pfb_filter_service()/pfb_dnsbl_service() call this at load time. No-op:
	// we never assert rc.d generation in unit tests.
	function write_rcfile($rc) {
		return true;
	}
}

if (!function_exists('safe_mkdir')) {
	// pfSense util.inc: recursive mkdir if absent. Faithful — pfb_unbound_python_sources
	// uses it to (re)create the per-feed raw dir, which the manifest test relies on.
	function safe_mkdir($path, $mode = 0755) {
		if (!is_dir($path)) {
			return @mkdir($path, $mode, true);
		}
		return true;
	}
}

if (!function_exists('rmdir_recursive')) {
	// pfSense util.inc: delete a tree. Faithful — used to reset the raw dir.
	function rmdir_recursive($path) {
		if (!is_dir($path) || is_link($path)) {
			return @unlink($path);
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			rmdir_recursive("{$path}/{$entry}");
		}
		return @rmdir($path);
	}
}

if (!function_exists('unlink_if_exists')) {
	function unlink_if_exists($path) {
		if (is_file($path) || is_link($path)) {
			return @unlink($path);
		}
		return false;
	}
}

if (!function_exists('resolve_host_addresses')) {
	// Only reached by PFB_FILTER_URL, which the seed suite does not exercise. Fail
	// fast rather than return a guessed [] that could hide a missing real double.
	function resolve_host_addresses($host, $records = [], $dnscache = false) {
		throw new LogicException(__FUNCTION__ . '() double not implemented — add a real one before testing this path');
	}
}

if (!function_exists('is_ipaddr_configured')) {
	// Only reached by PFB_FILTER_URL, which the seed suite does not exercise. Fail
	// fast rather than return a guessed false that could hide a missing real double.
	function is_ipaddr_configured($ipaddr, $ignore_if = '', $check_localip = false, $check_subnets = false, $cidrprefix = '') {
		throw new LogicException(__FUNCTION__ . '() double not implemented — add a real one before testing this path');
	}
}

// --- config.lib.inc doubles (faithful path walkers over $GLOBALS['config']) ---
//
// pfb_manage_dnsbl_vip() (ADR-13 / PFBL-01) reads and writes config via the pfSense
// config path API. These mirror config.lib.inc's array_get_path/array_set_path
// semantics over a plain $GLOBALS['config'] array the tests seed, so the lifecycle
// code runs unmodified off-appliance. write_config() records each invocation in
// $GLOBALS['pfb_test_write_config_calls'] so tests can assert a path persisted
// config -- or, just as load-bearing, that an abort path did NOT.

if (!function_exists('config_get_path')) {
	// pfSense config.lib.inc: walk a '/'-separated path, $default when absent.
	function config_get_path(string $path, $default = null) {
		$node = $GLOBALS['config'] ?? [];
		foreach (explode('/', rtrim($path, '/')) as $key) {
			if (!is_array($node) || !array_key_exists($key, $node)) {
				return $default;
			}
			$node = $node[$key];
		}
		return $node;
	}
}

if (!function_exists('config_set_path')) {
	// pfSense config.lib.inc: set the value at a '/'-separated path (creating
	// intermediate arrays), returning the value set.
	function config_set_path(string $path, $value, $default = null) {
		$node = &$GLOBALS['config'];
		if (!is_array($node)) {
			$node = [];
		}
		foreach (explode('/', rtrim($path, '/')) as $key) {
			if (!is_array($node)) {
				return $default;
			}
			if (!array_key_exists($key, $node) || !is_array($node[$key])) {
				$node[$key] = [];
			}
			$node = &$node[$key];
		}
		$node = $value;
		return $value;
	}
}

if (!function_exists('config_path_enabled')) {
	// pfSense config.lib.inc: node exists, is an array and carries the enable key.
	function config_path_enabled(string $path, $enable_key = 'enable') {
		$node = config_get_path($path);
		return (is_array($node) && array_key_exists($enable_key, $node));
	}
}

if (!function_exists('write_config')) {
	// Persisting is out of scope off-appliance; record the call (so tests can
	// assert whether a code path wrote config) and report success like pfSense.
	function write_config($desc = 'Unknown', $backup = true, $write_config_only = false) {
		$GLOBALS['pfb_test_write_config_calls'][] = $desc;
		return true;
	}
}

if (!function_exists('get_configured_vip_ipv4')) {
	// pfSense util.inc (faithful-lite): resolve a '_vip<uniqid>' id against
	// virtualip/vip and return the entry's v4 address, null when unresolved.
	function get_configured_vip_ipv4($vipinterface = '') {
		if (!is_string($vipinterface) || !str_starts_with($vipinterface, '_vip')) {
			return null;
		}
		$uniqid = substr($vipinterface, strlen('_vip'));
		foreach (config_get_path('virtualip/vip', []) as $vip) {
			if (($vip['uniqid'] ?? '') === $uniqid && is_ipaddrv4($vip['subnet'] ?? '')) {
				return $vip['subnet'];
			}
		}
		return null;
	}
}

if (!function_exists('get_configured_vip_ipv6')) {
	// pfSense util.inc (faithful-lite): v6 counterpart of the above.
	function get_configured_vip_ipv6($vipinterface = '') {
		if (!is_string($vipinterface) || !str_starts_with($vipinterface, '_vip')) {
			return null;
		}
		$uniqid = substr($vipinterface, strlen('_vip'));
		foreach (config_get_path('virtualip/vip', []) as $vip) {
			if (($vip['uniqid'] ?? '') === $uniqid && is_ipaddrv6($vip['subnet'] ?? '')) {
				return $vip['subnet'];
			}
		}
		return null;
	}
}

// --- VIP doubles for pfb_validate_vips() (ADR-13) ---
//
// The v6-recommendation tests (DnsblV6RequiredTest) drive pfb_validate_vips() and the
// early "no VIP configured" branch with NO pfSense call. The few assertions that pass a
// non-empty VIP id continue past those early returns into the per-VIP checks; these
// conservative doubles make that continuation deterministic without coupling to real
// pfSense state. They are reached ONLY by tests that supply a '_vip_test_*' sentinel id.

if (!function_exists('get_configured_vip_interface')) {
	// pfSense util.inc: the friendly interface a VIP id lives on. The test sentinels are
	// not real VIPs, so report a non-'lo0' interface -> the validator's "VIP not on
	// interface" check fails for them. That is fine: those tests only assert the error is
	// NOT the v6-required message, never that validation passes.
	function get_configured_vip_interface($vipif) {
		// Constrain to the '_vip_test_*' sentinels the tests supply, so this
		// test-specific behaviour can't leak into unrelated tests sharing this file.
		if (is_string($vipif) && str_starts_with($vipif, '_vip_test_')) {
			return 'opt-double';
		}

		throw new LogicException(__FUNCTION__ . '() double not implemented for VIP id: ' . (string) $vipif);
	}
}

if (!function_exists('convert_friendly_interface_to_friendly_descr')) {
	// pfSense interfaces.inc: friendly name -> human description. Identity is enough for
	// the "VIP not on interface %s" message the doubled-interface path produces.
	function convert_friendly_interface_to_friendly_descr($interface) {
		return $interface;
	}
}
