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
	// Faithful-enough RFC-1123 hostname check (labels 1-63 of [a-z0-9-], not
	// starting/ending '-', total <= 255). The seed suite does not assert
	// PFB_FILTER_HOSTNAME edge cases; this only needs to be plausible.
	function is_hostname($hostname, $allow_wildcard = false) {
		if (!is_string($hostname) || $hostname === '' || strlen($hostname) > 255) {
			return false;
		}
		if ($allow_wildcard && strpos($hostname, '*') === 0) {
			$hostname = substr($hostname, 2);
		}
		foreach (explode('.', $hostname) as $label) {
			if (!preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i', $label)) {
				return false;
			}
		}
		return true;
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
	// Only reached by PFB_FILTER_URL, which the seed suite does not exercise.
	function resolve_host_addresses($host, $records = [], $dnscache = false) {
		return [];
	}
}

if (!function_exists('is_ipaddr_configured')) {
	// Only reached by PFB_FILTER_URL, which the seed suite does not exercise.
	function is_ipaddr_configured($ipaddr, $ignore_if = '', $check_localip = false, $check_subnets = false, $cidrprefix = '') {
		return false;
	}
}
