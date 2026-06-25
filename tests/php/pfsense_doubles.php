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
	// pfSense util.inc: returns 4 for an IPv4 address, 6 for an IPv6 address, FALSE
	// otherwise (verbatim upstream semantics — pfb_get_vips() switches on case 4/6,
	// so a bool double would mis-bucket every v6 VIP into v4 via loose TRUE==4).
	function is_ipaddr($ipaddr) {
		if (is_ipaddrv4($ipaddr)) {
			return 4;
		}
		if (is_ipaddrv6($ipaddr)) {
			return 6;
		}
		return FALSE;
	}
}

if (!function_exists('is_subnetv4')) {
	// pfSense util.inc: 'ipv4/bits' with a 0-32 prefix and a valid v4 network part.
	function is_subnetv4($subnet) {
		if (!is_string($subnet) || strpos($subnet, '/') === false) {
			return false;
		}
		list($ip, $bits) = explode('/', $subnet, 2);
		return (is_ipaddrv4($ip) && ctype_digit($bits) && (int) $bits >= 0 && (int) $bits <= 32);
	}
}

if (!function_exists('is_subnetv6')) {
	// pfSense util.inc: 'ipv6/bits' with a 0-128 prefix and a valid v6 network part.
	function is_subnetv6($subnet) {
		if (!is_string($subnet) || strpos($subnet, '/') === false) {
			return false;
		}
		list($ip, $bits) = explode('/', $subnet, 2);
		return (is_ipaddrv6($ip) && ctype_digit($bits) && (int) $bits >= 0 && (int) $bits <= 128);
	}
}

if (!function_exists('is_subnet')) {
	// pfSense util.inc: v4 OR v6 subnet.
	function is_subnet($subnet) {
		return (is_subnetv4($subnet) || is_subnetv6($subnet));
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
	// pfSense util.inc returns a list of ['type'=>'A'|'AAAA'|'CNAME','data'=>...]
	// records (or [] when a host does not resolve). FeedHostAllowedTest drives the
	// guard by seeding $GLOBALS['pfb_test_resolve_map'] (host => records | false).
	// A host absent from the map keeps the original fail-fast, so an unrelated path
	// reaching this double still surfaces as a missing double, not a silent [].
	function resolve_host_addresses($host, $records = [], $dnscache = false) {
		$map = $GLOBALS['pfb_test_resolve_map'] ?? null;
		if (is_array($map) && array_key_exists($host, $map)) {
			$result = $map[$host];
			return $result === false ? [] : $result;
		}
		throw new LogicException(__FUNCTION__ . '() double not implemented — add a real one before testing this path (host: ' . (string) $host . ')');
	}
}

if (!function_exists('is_ipaddr_configured')) {
	// pfSense interfaces.inc: TRUE when $ipaddr is an address configured on the box.
	// The feed-host self-exemption (pfb_ip_is_self) drives this — a test declares the
	// firewall's own addresses by seeding $GLOBALS['pfb_test_configured_ips'] (a list
	// of IP literals it returns TRUE for; absent/empty => no configured IPs).
	function is_ipaddr_configured($ipaddr, $ignore_if = '', $check_localip = false, $check_subnets = false, $cidrprefix = '') {
		$configured = $GLOBALS['pfb_test_configured_ips'] ?? [];
		return is_array($configured) && in_array($ipaddr, $configured, true);
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

if (!function_exists('config_del_path')) {
	// pfSense config.lib.inc: unset the node at a '/'-separated path.
	// A missing path is a no-op (matches pfSense behaviour).
	function config_del_path(string $path): void {
		$keys = explode('/', rtrim($path, '/'));
		$last = array_pop($keys);
		$node = &$GLOBALS['config'];
		foreach ($keys as $key) {
			if (!is_array($node) || !array_key_exists($key, $node)) {
				return;
			}
			$node = &$node[$key];
		}
		if (is_array($node)) {
			unset($node[$last]);
		}
	}
}

if (!function_exists('config_path_enabled')) {
	// pfSense config.lib.inc: node exists, is an array and carries the enable key.
	function config_path_enabled(string $path, $enable_key = 'enable') {
		$node = config_get_path($path);
		return (is_array($node) && array_key_exists($enable_key, $node));
	}
}

if (!function_exists('config_read_file')) {
	// pfSense config.lib.inc: reload config from disk. Off-appliance the config
	// lives in $GLOBALS['config'] (seeded per test) — no disk file exists, so
	// this is a deliberate no-op: pfb_global() calls it to pick up any in-flight
	// changes, but in tests the caller already seeded $GLOBALS['config'] before
	// calling pfb_global(). Returning [] matches the stub's declared return type.
	function config_read_file(bool $use_backup = false, bool $use_cache = true): array {
		return [];
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

if (!function_exists('pkg_version_compare')) {
	// pfSense pkg.inc / pkg-utils.inc: compare two package versions, returning the
	// FreeBSD pkg(8) symbol '<' | '=' | '>' for ($v1 <=> $v2). The real function shells
	// to `pkg version -t <v1> <v2>`; off-appliance we reproduce that ordering with PHP's
	// version_compare (which orders the pkg-style versions the decision core sees —
	// semver, the `_N` port revision the catalog uses for upgrade legs, and nightly's
	// dated `YYYYMMDD` versions). pfb_update_available() keys on the '<' result.
	function pkg_version_compare($v1, $v2) {
		$cmp = version_compare((string) $v1, (string) $v2);
		if ($cmp < 0) {
			return '<';
		}
		if ($cmp > 0) {
			return '>';
		}
		return '=';
	}
}

// --- ADR-19 Phase 3 doubles (cron software-update check) ---
//
// The orchestrator pfb_software_update_check() is unit-tested with the pkg IO injected
// via its $io override (so no real `pkg` shells off-appliance). These three pfSense
// functions it still reaches are doubled here, test-driveable via $GLOBALS:
//   * file_notice()        -> appended to $GLOBALS['pfb_test_file_notices'] so a test can
//                             assert a notice fired exactly when (and as often as) expected.
//   * is_subsystem_dirty() -> reads $GLOBALS['pfb_test_pkg_locked'] for the 'pkg' subsystem
//                             (default false) so the pkg-lock short-circuit can be exercised.
//   * get_dnsavailable()   -> reads $GLOBALS['pfb_test_dns_available'] (default true).

if (!function_exists('file_notice')) {
	function file_notice($id, $notice, $category = 'General', $url = '', $local_only = 0) {
		$GLOBALS['pfb_test_file_notices'][] = array(
			'id'         => $id,
			'notice'     => $notice,
			'category'   => $category,
			'url'        => $url,
			'local_only' => $local_only,
		);
	}
}

if (!function_exists('is_subsystem_dirty')) {
	function is_subsystem_dirty($subsystem = '') {
		if ($subsystem === 'pkg') {
			return (bool) ($GLOBALS['pfb_test_pkg_locked'] ?? false);
		}
		return false;
	}
}

if (!function_exists('get_dnsavailable')) {
	function get_dnsavailable($ipproto = 'inet') {
		return (bool) ($GLOBALS['pfb_test_dns_available'] ?? true);
	}
}

// --- pfb_collect_localip() doubles ---
//
// These support testing the local-IP collection logic off-appliance.
// Tests seed $GLOBALS['pfb_test_*'] maps; the doubles serve those values.

if (!function_exists('get_interfaces_with_gateway')) {
	// pfSense interfaces.inc: returns an array of friendly interface names that have
	// a gateway configured. Tests seed $GLOBALS['pfb_test_interfaces_with_gateway']
	// (a plain list of names, default []); absent the key → empty list.
	function get_interfaces_with_gateway() {
		return $GLOBALS['pfb_test_interfaces_with_gateway'] ?? [];
	}
}

if (!function_exists('get_interface_ip')) {
	// pfSense interfaces.inc: returns the runtime IPv4 address for a friendly interface
	// name, or null when unconfigured. Tests seed $GLOBALS['pfb_test_interface_ip']
	// (map of name => ipv4 string, default []); absent key → null (no address).
	function get_interface_ip($interface = 'wan', $gateways_status = false) {
		$map = $GLOBALS['pfb_test_interface_ip'] ?? [];
		return $map[$interface] ?? null;
	}
}

if (!function_exists('get_interface_ipv6')) {
	// pfSense interfaces.inc: returns the runtime IPv6 address for a friendly interface
	// name, or null when unconfigured. Tests seed $GLOBALS['pfb_test_configured_ipv6']
	// (map of name => ipv6 string, default []); absent key → null.
	function get_interface_ipv6($interface = 'wan', $flush = false, $linklocal_fallback = false, $gateways_status = false) {
		$map = $GLOBALS['pfb_test_configured_ipv6'] ?? [];
		return $map[$interface] ?? null;
	}
}

if (!function_exists('get_interface_subnetv6')) {
	// pfSense interfaces.inc: returns the runtime IPv6 prefix length (integer as string)
	// for a friendly interface name, or null when unconfigured. Tests seed
	// $GLOBALS['pfb_test_interface_subnetv6'] (map of name => bits string, default []).
	function get_interface_subnetv6($interface = 'wan') {
		$map = $GLOBALS['pfb_test_interface_subnetv6'] ?? [];
		return $map[$interface] ?? null;
	}
}

if (!function_exists('get_interface_subnet')) {
	// pfSense interfaces.inc: returns the runtime IPv4 prefix length (integer as string)
	// for a friendly interface name, or null when unconfigured. Tests seed
	// $GLOBALS['pfb_test_interface_subnet'] (map of name => bits string, default []).
	function get_interface_subnet($interface = 'wan') {
		$map = $GLOBALS['pfb_test_interface_subnet'] ?? [];
		return $map[$interface] ?? null;
	}
}

if (!function_exists('get_configured_ipv6_addresses')) {
	// pfSense interfaces.inc: returns a map of friendly-interface-name => runtime-IPv6-addr
	// for every interface that currently has an IPv6 address (incl. track6/dhcp6/SLAAC).
	// Tests seed $GLOBALS['pfb_test_configured_ipv6'] (same map the per-interface
	// get_interface_ipv6() reads from, so one seed covers both). Default → [].
	function get_configured_ipv6_addresses($linklocal_fallback = false) {
		return $GLOBALS['pfb_test_configured_ipv6'] ?? [];
	}
}

if (!function_exists('gen_subnetv6')) {
	// pfSense util.inc: given an IPv6 address and a prefix-length integer/string,
	// return the BARE network address (no prefix-length suffix). This matches the
	// real pfSense gen_subnetv6() behaviour — it returns just the masked address
	// (e.g. "2001:db8:1:2::"), NOT "addr/bits".  Callers that need CIDR notation
	// must append "/{$bits}" themselves (see pfb_collect_localip()).
	function gen_subnetv6($ipaddr, $bits) {
		$bits = (int) $bits;
		if ($bits < 0 || $bits > 128) {
			return '';
		}
		$packed = @inet_pton((string) $ipaddr);
		if ($packed === false) {
			return '';
		}
		// Build a 128-bit mask with $bits leading 1s.
		$mask   = str_repeat("\xff", (int) ($bits / 8));
		$remain = $bits % 8;
		if ($remain > 0) {
			$mask .= chr(0xff & (0xff << (8 - $remain)));
		}
		$mask = str_pad($mask, 16, "\x00");
		// AND each byte of the address with the mask.
		$net = '';
		for ($i = 0; $i < 16; $i++) {
			$net .= chr(ord($packed[$i]) & ord($mask[$i]));
		}
		// Return bare network address only — NO "/{$bits}" suffix (matches pfSense).
		return inet_ntop($net);
	}
}

if (!function_exists('subnetv4_expand')) {
	// pfSense util.inc: expand a CIDR subnet (e.g. '192.168.1.0/24') to a flat array
	// of all host IP strings in that range. Faithful but capped at 65536 hosts so an
	// accidental wide subnet can't OOM a test run.
	function subnetv4_expand($subnet) {
		if (strpos($subnet, '/') === false) {
			return [];
		}
		[$ip, $bits] = explode('/', $subnet, 2);
		$bits = (int) $bits;
		if ($bits < 0 || $bits > 32) {
			return [];
		}
		$base  = ip2long($ip);
		if ($base === false) {
			return [];
		}
		$count = 1 << (32 - $bits);
		// Mask to the network address.
		$mask  = $bits === 0 ? 0 : (~0 << (32 - $bits));
		$base  = $base & $mask;
		// Cap to avoid OOM in tests.
		$cap = min($count, 65536);
		$out = [];
		for ($i = 0; $i < $cap; $i++) {
			$out[] = long2ip($base + $i);
		}
		return $out;
	}
}

if (!function_exists('ip_in_subnet')) {
	// pfSense util.inc: TRUE when $addr falls within $subnet (supports both IPv4 and IPv6).
	// Faithful implementation using inet_pton for both families.
	function ip_in_subnet($addr, $subnet) {
		if (strpos($subnet, '/') === false) {
			return false;
		}
		[$net_addr, $bits] = explode('/', $subnet, 2);
		$bits = (int) $bits;

		$addr_packed = @inet_pton((string) $addr);
		$net_packed  = @inet_pton((string) $net_addr);
		if ($addr_packed === false || $net_packed === false) {
			return false;
		}
		$len = strlen($addr_packed);
		if ($len !== strlen($net_packed)) {
			// Different address families.
			return false;
		}
		// Compare $bits leading bits.
		$full_bytes = (int) ($bits / 8);
		$rem        = $bits % 8;
		for ($i = 0; $i < $full_bytes; $i++) {
			if (ord($addr_packed[$i]) !== ord($net_packed[$i])) {
				return false;
			}
		}
		if ($rem > 0 && $full_bytes < $len) {
			$mask = 0xff & (0xff << (8 - $rem));
			if ((ord($addr_packed[$full_bytes]) & $mask) !== (ord($net_packed[$full_bytes]) & $mask)) {
				return false;
			}
		}
		return true;
	}
}

// --- ADR-35 Phase 1 doubles — VIP lifecycle + NAT/service management ---
//
// SPECIALNET_VIPS: pfSense constant (value 12) from globals.inc. Defined here for
// the runtime double layer (the PHPStan stubs/pfsense/globals.php value is for static
// analysis only and is not loaded at runtime off-appliance).
if (!defined('SPECIALNET_VIPS')) {
	define('SPECIALNET_VIPS', 12);
}
//
//
// pfb_manage_dnsbl_vip() calls interface_vip_bring_down() on disable and
// interface_ipalias_configure() on enable (after VIP create).
// pfb_create_dnsbl() calls is_service_running(), restart_service(), stop_service(),
// and pfb_create_dnsbl_cert() which in turn calls cert_create().
// These are all pfSense runtime functions absent off-appliance; doubles here make
// the VIP/NAT oracle tests in DnsblMarkedVipTest runnable without a live box.

if (!function_exists('interface_vip_bring_down')) {
	// pfSense interfaces.inc: un-apply a VIP alias from the interface (live pf change).
	// Off-appliance: record the call for test inspection; no pf present.
	function interface_vip_bring_down($vip) {
		$GLOBALS['pfb_test_vip_bring_down_calls'][] = $vip;
		return TRUE;
	}
}

if (!function_exists('interface_ipalias_configure')) {
	// pfSense interfaces.inc: apply a VIP alias to the interface (live pf change).
	// Off-appliance: record the call for test inspection; no pf present.
	function interface_ipalias_configure($vip) {
		$GLOBALS['pfb_test_ipalias_configure_calls'][] = $vip;
		return TRUE;
	}
}

if (!function_exists('is_service_running')) {
	// pfSense service-utils.inc: TRUE when the named rc.d service is running.
	// Default TRUE so the 'if ($pfbupdate || !is_service_running())' block only
	// fires when $pfbupdate is TRUE (the NAT/config changed), matching real usage.
	// Tests can override via $GLOBALS['pfb_test_service_running'] (service => bool).
	function is_service_running($service, $ps = []) {
		$map = $GLOBALS['pfb_test_service_running'] ?? [];
		return (bool) ($map[$service] ?? TRUE);
	}
}

if (!function_exists('restart_service')) {
	// pfSense services.inc: restart a named rc.d service. No-op off-appliance.
	function restart_service($service) {
		return TRUE;
	}
}

if (!function_exists('stop_service')) {
	// pfSense services.inc: stop a named rc.d service. No-op off-appliance.
	function stop_service($service) {
		return TRUE;
	}
}

if (!function_exists('cert_create')) {
	// pfSense cert.inc: generate a self-signed certificate and populate $cert['prv'/'crt'].
	// Off-appliance: write empty base64-encoded blobs so the caller's file_put_contents
	// has valid (though empty) data. Returns TRUE (success) so the error-log branch is
	// not triggered, keeping the test clean.
	function cert_create(&$cert, $caref, $keylen, $lifetime, $dn, $type = 'self-signed', $digest = 'sha256', $curve = '', $pkcs_alg = '') {
		$cert['prv'] = base64_encode('');
		$cert['crt'] = base64_encode('');
		return TRUE;
	}
}

if (!function_exists('get_configured_vip_list')) {
	// pfSense interfaces.inc: map of VIP id ('_vip<uniqid>') => resolved IP address for
	// all configured VIPs. Used by pfb_get_vips() inside pfb_validate_vips().
	// Tests seed $GLOBALS['pfb_test_vip_list'] (map of id => addr); default empty map
	// → pfb_get_vips() returns no VIPs, which combined with a '_vip_test_*' id causes
	// pfb_validate_vips to return an 'invalid IPv4 VIP' error and force-disable DNSBL.
	// Tests that need DNSBL to stay enabled must seed a matching id => addr entry AND
	// use the 'opt-double' interface (matched by the get_configured_vip_interface double).
	function get_configured_vip_list($type = '') {
		return $GLOBALS['pfb_test_vip_list'] ?? [];
	}
}

if (!function_exists('get_specialnet')) {
	// pfSense interfaces.inc: returns an associative array of special network names/
	// addresses (VIPs, loopback, etc.) indexed by their IP/address. Used by pfb_get_vips()
	// to filter VIPs to only the ones in the SPECIALNET_VIPS set.
	// Tests seed $GLOBALS['pfb_test_specialnet'] (addr => label); default includes all
	// addresses from pfb_test_vip_list so pfb_get_vips() can match them.
	function get_specialnet($interface = '', $types = []) {
		// If a test has explicitly seeded this, use it.
		if (isset($GLOBALS['pfb_test_specialnet'])) {
			return $GLOBALS['pfb_test_specialnet'];
		}
		// Auto-derive from pfb_test_vip_list: every configured VIP addr counts as special.
		$map = [];
		foreach ($GLOBALS['pfb_test_vip_list'] ?? [] as $addr) {
			$map[$addr] = $addr;
		}
		return $map;
	}
}

if (!function_exists('where_is_ipaddr_configured')) {
	// pfSense interfaces.inc: returns a list of interface names where $addr is configured
	// (including subnet membership). Used by pfb_validate_vips() and pfb_pick_free_dnsbl_vip()
	// to detect VIP/subnet overlap.
	//
	// Seedable for picker tests: if $GLOBALS['pfb_test_configured_subnets'] is set to an
	// array of CIDR strings (e.g. ['10.0.0.0/8']), returns ['seeded'] (non-empty = "conflict")
	// when $ip falls inside any of them; otherwise returns [] (no conflict). When the global
	// is unset, always returns [] — preserving the off-appliance default so existing tests
	// are unaffected. Only IPv4 CIDRs are supported for seeding (the picker test is v4-only).
	function where_is_ipaddr_configured($ip, $ignore_if = '', $check_localip = FALSE, $check_subnets = FALSE, $cidrprefix = '') {
		$subnets = $GLOBALS['pfb_test_configured_subnets'] ?? null;
		if ($subnets === null) {
			return [];
		}
		$ip_long = ip2long($ip);
		if ($ip_long === FALSE) {
			// IPv6 address or unparseable — no subnet seed support; treat as free.
			return [];
		}
		foreach ($subnets as $cidr) {
			[$net, $bits] = explode('/', $cidr, 2) + [1 => '32'];
			$net_long = ip2long($net);
			if ($net_long === FALSE) {
				continue;
			}
			$mask = $bits === '32' ? 0xFFFFFFFF : ~((1 << (32 - (int) $bits)) - 1);
			// Cast to unsigned 32-bit via sprintf round-trip to avoid sign-bit issues.
			$mask      = (int) sprintf('%u', $mask & 0xFFFFFFFF);
			$net_long  = (int) sprintf('%u', $net_long & 0xFFFFFFFF);
			$ip_masked = (int) sprintf('%u', $ip_long & 0xFFFFFFFF);
			if (($ip_masked & $mask) === ($net_long & $mask)) {
				return ['seeded'];
			}
		}
		return [];
	}
}

if (!function_exists('is_validaliasname')) {
	// pfSense util.inc: alias names are alphanumeric + underscore, max 32 chars,
	// must not start with a digit.
	function is_validaliasname($name, $return_message = false, $object = 'alias') {
		if (!is_string($name) || $name === '') {
			return FALSE;
		}
		if (strlen($name) > 32) {
			return FALSE;
		}
		return (bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $name);
	}
}

if (!function_exists('get_configured_interface_with_descr')) {
	// pfSense interfaces.inc: returns a map of interface_name => friendly description.
	// Off-appliance, use pfb_test_interfaces if seeded; otherwise return an empty map.
	function get_configured_interface_with_descr($all = FALSE, $filter = FALSE) {
		return $GLOBALS['pfb_test_interfaces'] ?? [];
	}
}

// --- ADR-38 Phase 3 doubles ---

if (!function_exists('system_syslogd_start')) {
	// pfSense syslog.inc: (re)start syslogd, processing package <logging> elements
	// to add extra sockets and routing drop-ins.  Off-appliance this is a no-op:
	// we never assert syslogd restarts in the unit-test suite (that is the live-VM
	// smoke's job).  The call in pfblockerng_install.inc therefore resolves safely.
	function system_syslogd_start(bool $sighup = false): void {
		// No-op off-appliance.
	}
}

// --- pfb_tracker() doubles (#482) ---
//
// pfb_tracker() calls four pfSense interface helpers that have no off-appliance
// equivalent and were not previously exercised by the unit suite.  These minimal
// doubles make pfb_tracker() callable in tests; each is seedable via $GLOBALS so
// tests can control the char-sum and thus the natural tracker ID.

if (!function_exists('get_real_interface')) {
	// pfSense interfaces.inc: map friendly interface name to the real OS interface
	// (e.g. 'lan' -> 'em1').  Tests seed $GLOBALS['pfb_test_real_interface'] (map
	// of name => real-name); absent key returns the input unchanged (identity).
	function get_real_interface($interface = 'wan', $type = '') {
		$map = $GLOBALS['pfb_test_real_interface'] ?? [];
		return $map[$interface] ?? $interface;
	}
}

if (!function_exists('ip2long32')) {
	// pfSense util.inc: like ip2long() but returns an UNSIGNED 32-bit integer
	// (avoids sign issues on 64-bit PHP where ip2long returns a signed int for
	// addresses >= 128.0.0.0).  Faithful: cast the signed result to unsigned via
	// sprintf('%u').
	function ip2long32($ip) {
		$long = ip2long((string) $ip);
		if ($long === false) {
			return 0;
		}
		return (int) sprintf('%u', $long);
	}
}

if (!function_exists('find_interface_subnet')) {
	// pfSense interfaces.inc: returns the IPv4 prefix-length (as a string) for the
	// REAL interface name (i.e. after get_real_interface() has resolved it).
	// Tests seed $GLOBALS['pfb_test_find_interface_subnet'] (map of real-name =>
	// bits string, default []); absent key returns null.
	function find_interface_subnet($real_interface) {
		$map = $GLOBALS['pfb_test_find_interface_subnet'] ?? [];
		return $map[$real_interface] ?? null;
	}
}

if (!function_exists('find_interface_subnetv6')) {
	// pfSense interfaces.inc: IPv6 counterpart of find_interface_subnet.
	// Tests seed $GLOBALS['pfb_test_find_interface_subnetv6'] (map of real-name =>
	// bits string, default []); absent key returns null.
	function find_interface_subnetv6($real_interface) {
		$map = $GLOBALS['pfb_test_find_interface_subnetv6'] ?? [];
		return $map[$real_interface] ?? null;
	}
}
