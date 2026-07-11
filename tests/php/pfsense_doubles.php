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
 *   - is_ipaddrv4 / is_ipaddrv6 / is_ipaddr / is_linklocal — mirror pfSense
 *     util.inc CONTROL FLOW exactly: a bare ip2long() check for v4 (NO
 *     long2ip() round-trip); for v6 the "/" reject + link-local-only "%zone"
 *     strip + double-"::" reject, via filter_var() standing in for
 *     Net_IPv6::checkIPv6 (no PEAR off-appliance). pfb_filter (IP/IPV4) and
 *     pfb_dnsbl_abp_extract_ip depend on their precise accept/reject behaviour.
 *     NOTE on v4: PHP's ip2long() delegates to libc inet_pton(AF_INET), which
 *     accepts only the canonical dotted-quad — leading-zero octets like
 *     '192.000.002.005' are rejected on BOTH FreeBSD (the pfSense/CE target;
 *     inet_pton4's leading-zero guard) and glibc. Consequently the old
 *     round-trip was behaviourally equivalent for v4; dropping it is a
 *     control-flow-fidelity fix (mirror upstream verbatim), not a verdict
 *     flip. The v6 %zone fix IS a real verdict flip — see IpAddrDoublesTest.
 *
 * Everything else is a minimal no-op/throwaway double: it exists only so the
 * symbol resolves. Functions reached only by code paths the seed suite does NOT
 * exercise (URL/HOSTNAME validation, host resolution) get a conservative stub.
 *
 * Each double is guarded by function_exists() so a future real include never
 * collides with it.
 */

if (!function_exists('is_ipaddrv4')) {
	// pfSense util.inc verbatim: a bare ip2long() check, NO long2ip() round-trip.
	// Rejects '1.2.3' / out-of-range / leading-zero octets / non-strings —
	// ip2long() (libc inet_pton) accepts only the canonical dotted-quad, on
	// FreeBSD and glibc alike (see the file-header NOTE), so this double now
	// runs the exact same control flow as the real function.
	function is_ipaddrv4($ipaddr) {
		if (!is_string($ipaddr) || empty($ipaddr) || ip2long($ipaddr) === FALSE) {
			return false;
		}
		return true;
	}
}

if (!function_exists('is_linklocal')) {
	// pfSense util.inc: 4 for a 169.254.0.0/16 v4 address, 6 for a link-local v6
	// address, FALSE otherwise. Off-appliance there is no PEAR Net_IPv6, so the
	// v6 branch approximates NET_IPV6_LOCAL_LINK (fe80::/10, first hextet
	// fe80–febf) with a first-hextet pattern check on the address (checked
	// BEFORE any '%zone' is stripped, same as upstream — the zone is part of
	// the string Net_IPv6::getAddressType sees).
	function is_linklocal($ipaddr) {
		if (is_ipaddrv4($ipaddr)) {
			$ip4 = explode('.', $ipaddr);
			if ($ip4[0] === '169' && $ip4[1] === '254') {
				return 4;
			}
			return false;
		}
		if (is_string($ipaddr) && preg_match('/^fe[89ab][0-9a-f]:/i', $ipaddr) === 1) {
			return 6;
		}
		return false;
	}
}

if (!function_exists('is_ipaddrv6')) {
	// pfSense util.inc verbatim ordering: string/empty guard -> reject a "/mask"
	// suffix -> strip a "%zone" ONLY when the address is link-local (a non-link-
	// local zoned address like '2001:db8::1%em0' keeps its zone and fails to
	// validate) -> reject a double "::" (redmine #13069) -> validate. filter_var()
	// with FILTER_FLAG_IPV6 stands in for Net_IPv6::checkIPv6() (no PEAR off-appliance).
	function is_ipaddrv6($ipaddr) {
		if (!is_string($ipaddr) || empty($ipaddr)) {
			return false;
		}
		if (strstr($ipaddr, '/')) {
			return false;
		}
		if (strstr($ipaddr, '%') && is_linklocal($ipaddr)) {
			$tmpip = explode('%', $ipaddr);
			$ipaddr = $tmpip[0];
		}
		if (substr_count($ipaddr, '::') > 1) {
			return false;
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

if (!function_exists('is_domain')) {
	// pfSense util.inc verbatim (master, 2026-07): the domain-shape regex is_hostname() delegates to.
	function is_domain($domain, $allow_wildcard = false, $trailing_dot = true) {
		if (!is_string($domain)) {
			return false;
		}
		if (!$trailing_dot && ($domain[strlen($domain) - 1] == '.')) {
			return false;
		}
		if ($allow_wildcard) {
			$domain_regex = '/^(?:(?:[a-z_0-9\*]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$/i';
		} else {
			$domain_regex = '/^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$/i';
		}
		return (bool) preg_match($domain_regex, $domain);
	}
}

if (!function_exists('is_hostname')) {
	// pfSense util.inc verbatim (master, 2026-07): PFB_FILTER_HOSTNAME's validator.
	function is_hostname($hostname, $allow_wildcard = false) {
		if (!is_string($hostname)) {
			return false;
		}
		if (is_domain($hostname, $allow_wildcard)) {
			// A single trailing dot ("test.") is not a valid host in the root domain.
			if ((substr_count($hostname, '.') == 1) && ($hostname[strlen($hostname) - 1] == '.')) {
				return false;
			}
			return true;
		}
		return false;
	}
}

if (!function_exists('is_port')) {
	// pfSense util.inc verbatim (#723): digits 1..65535, OR a service name resolvable
	// via getservbyname() when \$validate_name (the default) — 'domain'/'http' are
	// valid ports to real pfSense, so the double must not model them as rejected.
	function is_port($port, $validate_name = true) {
		if (ctype_digit(strval($port)) && ((intval($port) >= 1) && (intval($port) <= 65535))) {
			return true;
		}
		if ($validate_name && (getservbyname($port, "tcp") || getservbyname($port, "udp") || getservbyname($port, "sctp"))) {
			return true;
		}
		return false;
	}
}

if (!function_exists('system_get_uniqueid')) {
	// Called at pfblockerng.inc load time (cURL user-agent). Any stable string.
	function system_get_uniqueid() {
		return 'phpunit-0000000000000000';
	}
}

if (!function_exists('write_rcfile')) {
	// pfb_filter_service()/pfb_dnsbl_service() call this at load time. Capture the rc
	// array (keyed by its 'file') so a test can assert the generated start/stop bodies
	// (e.g. the #662 daemon-fd-detach); behaviourally still a no-op on disk.
	function write_rcfile($rc) {
		if (isset($rc['file'])) {
			$GLOBALS['pfb_test_rcfiles'][$rc['file']] = $rc;
		}
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
	// Mirrors the real pfSense util.inc implementation: the argument is a glob
	// PATTERN, not a literal path — matches are unlinked, an empty match falls
	// back to a literal @unlink. Tests must model that re-glob behaviour.
	function unlink_if_exists($fn) {
		$to_do = glob($fn);
		if (is_array($to_do) && count($to_do) > 0) {
			$results = @array_map("unlink", $to_do);
			$result = !in_array(false, $results, true);
		} else {
			$result = @unlink($fn);
		}
		return $result;
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
	// not real VIPs, so report a non-'lo0' interface -> the validator's "VIP not found on
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
	// the "VIP not found on interface %s" message the doubled-interface path produces.
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
	function file_notice($id, $notice, $category = 'General', $url = '', $priority = 1, $local_only = false) {
		$GLOBALS['pfb_test_file_notices'][] = array(
			'id'         => $id,
			'notice'     => $notice,
			'category'   => $category,
			'url'        => $url,
			'priority'   => $priority,
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

if (!function_exists('isAllowedPage')) {
	// pfSense pfsense-utils.inc: TRUE when the current user may reach $page (honours the
	// admin uid-0 short-circuit + 'page-all' wildcard — see pfblockerng_software.php's
	// SECONDARY PRIVILEGE GATE comment, issue #485). Tests seed
	// $GLOBALS['pfb_test_allowed_pages'] (page => bool); an absent key defaults to TRUE so
	// every pre-existing test (none of which cares about this priv) is unaffected.
	function isAllowedPage($page) {
		$map = $GLOBALS['pfb_test_allowed_pages'] ?? [];
		return (bool) ($map[$page] ?? true);
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
		[$net_addr, $bits_raw] = explode('/', $subnet, 2);

		// ADR-53 review finding H3: real pfSense gates ip_in_subnet() on
		// is_subnetv4()/is_subnetv6(), whose shared is_subnet() (util.inc)
		// requires the mask to match `\d{1,3}` (digits only -- no sign, no
		// decimal point) and be <= 32 (v4) / <= 128 (v6). The previous version
		// of this double coerced the mask via a bare (int) cast with no range
		// check, so a malformed mask silently fell through as either an exact-
		// host match (an out-of-range mask like '/33') or "matches EVERY
		// address" (a non-numeric mask like '/abc', which (int) coerces to 0)
		// -- real pfSense rejects both outright (always FALSE). This matters
		// because pfb_ip_suppressed()/pfb_live_punch_plan() lean on this
		// double under PHPUnit; a lying double could hide a real suppression
		// over-match. Pinned by KillstatesSuppressionTest.php's
		// "OutOfRangeMask"/"NonNumericMask" vectors.
		if (!preg_match('/^\d{1,3}$/', $bits_raw)) {
			return false;
		}
		$bits = (int) $bits_raw;

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
		if ($bits > $len * 8) {
			// Out-of-range mask for this family (e.g. v4 '/33', v6 '/129').
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

if (!function_exists('is_alias')) {
	// pfSense util.inc: TRUE if a firewall alias with this name exists. Off-appliance,
	// resolve against the seeded $GLOBALS['pfb_test_aliases'] name list (empty by default).
	function is_alias($name) {
		return in_array((string) $name, $GLOBALS['pfb_test_aliases'] ?? [], TRUE);
	}
}

if (!function_exists('alias_get_type')) {
	// pfSense util.inc: return the 'type' of the named firewall alias, or '' when no
	// alias of that name exists. RESERVED SYSTEM TABLE NAMES TAKE PRECEDENCE over the
	// configuration (get_reserved_table_names(), matched case-insensitively) — the 8
	// static entries below are byte-identical across CE 2.8.0..master (globals.inc
	// $reserved_table_names, verified 2026-07-07; upstream can register more at runtime
	// via add_reserved_table()). Then config-based (reads aliases/alias via
	// config_get_path) — NOT the $aliastable cache that is_alias() uses.
	function alias_get_type($name) {
		$reserved = [
			'bogons'          => 'urltable',
			'bogonsv6'        => 'urltable',
			'sshguard'        => 'host',
			'snort2c'         => 'host',
			'virusprot'       => 'host',
			'vpn_networks'    => 'network',
			'negate_networks' => 'network',
			'tonatsubnets'    => 'network',
		];
		$lower = strtolower((string) $name);
		if (isset($reserved[$lower])) {
			return $reserved[$lower];
		}
		foreach (config_get_path('aliases/alias', []) as $a) {
			if (($a['name'] ?? '') === (string) $name) {
				return (string) ($a['type'] ?? '');
			}
		}
		return '';
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

// ADR-53 P8: pfb_v4_carve_single() (pfblockerng_extra.inc) calls the REAL
// pfSense long2ip32() to render the gap-range endpoints it feeds into
// ip_range_to_subnet_array() -- never redefined in production code.
// Off-appliance it doesn't exist, so it needs a faithful double.
//
// Upstream body verified BYTE-IDENTICAL at the same three dated refs already
// established for ip_range_to_subnet_array() above (src/etc/inc/util.inc;
// CLAUDE.md "Resolve pfSense-provided PHP functions from upstream"): CE 2.8.0
// (ed6c2eb84595aab998c3b3efaf16d226bd62c38d), CE 2.8.1
// (97f9eb5c819fd7f0c5f232d2581e5080be1cb18a), master tip
// (9363ac5b8651a1c7a333180425ce7719070f95f9). On 64-bit PHP (PHP_INT_SIZE ==
// 8, our test environment and the pfSense appliance target) the 32-bit-ARM
// branch never runs, so the double omits it and mirrors only the live path.
if (!function_exists('long2ip32')) {
	function long2ip32($ip) {
		return long2ip($ip & 0xFFFFFFFF);
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

if (!function_exists('isvalidpid')) {
	// pfSense util.inc: TRUE when the pidfile names a live process. Test double: liveness is
	// controlled per pidfile via $GLOBALS['pfb_test_valid_pids'] (map of pidfile => bool,
	// default []); an absent key reads as not running.
	function isvalidpid($pidfile) {
		return !empty($GLOBALS['pfb_test_valid_pids'][$pidfile]);
	}
}

// --- ADR-61 Phase 3 doubles: pfb_dnsbl_converged() + pfb_reload_unbound() restart path ---

if (!function_exists('is_process_running')) {
	// pfSense util.inc: TRUE when a process by that name has a live PID. Tests seed
	// $GLOBALS['pfb_test_process_running'][$process] with either a bool (constant
	// answer) or a callable(): bool (a per-call sequence, e.g. "running, then
	// stopped, then running again"). Default FALSE -- a dev/CI box never has a real
	// 'unbound' process, matching every call site's real off-appliance behaviour;
	// every test that needs it "up" sets the override explicitly.
	function is_process_running($process) {
		$v = $GLOBALS['pfb_test_process_running'][$process] ?? FALSE;
		return is_callable($v) ? (bool) $v() : (bool) $v;
	}
}

if (!function_exists('get_single_sysctl')) {
	// pfSense pfsense-utils.inc: read one sysctl OID as a string. pfb_unbound_py_swap_fits_ram()
	// reads 'hw.usermem' to project whether a zero-downtime swap fits in RAM. Tests seed
	// $GLOBALS['pfb_test_sysctl'][$oid]; default a generous 16 GiB so the swap-eligibility
	// gate passes unless a test deliberately RAM-starves it.
	function get_single_sysctl($oid) {
		return $GLOBALS['pfb_test_sysctl'][$oid] ?? (string) (16 * 1024 * 1024 * 1024);
	}
}

// --- pfb_remove_states() doubles (#702/#705) ---
//
// The kill-states validation walk (pfb_remove_states) reaches two util.inc
// helpers with no prior double: the RFC1918/CGN class check on the IPv4 branch
// and the DNS-server suppression source. Both are needed so the REAL function
// runs off-appliance (the pfctl boundary itself is the committed
// fixtures/fake_pfctl.sh stub).

if (!function_exists('is_private_ip')) {
	// pfSense util.inc: TRUE when the IPv4 address falls within a private range.
	// Faithful port of the upstream list-walk over ip_in_subnet().
	function is_private_ip($iptocheck) {
		foreach (['10.0.0.0/8', '100.64.0.0/10', '172.16.0.0/12', '192.168.0.0/16'] as $private) {
			if (ip_in_subnet($iptocheck, $private)) {
				return true;
			}
		}
		return false;
	}
}

if (!function_exists('get_dns_servers')) {
	// pfSense util.inc: the system's configured DNS servers. Test double: seedable
	// via $GLOBALS['pfb_test_dns_servers'] (default: none configured).
	function get_dns_servers() {
		return $GLOBALS['pfb_test_dns_servers'] ?? [];
	}
}

// --- ADR-53 P5 doubles: pure IPv6 CIDR set-subtraction engine ---
//
// pfb_cidr_subtract_v6()/pfb_suppress_file_v6() (pfblockerng_extra.inc) call the
// REAL pfSense ip_range_to_subnet_array() on-appliance -- it is never redefined
// in production code. Off-appliance it doesn't exist, so it needs a faithful
// double here.
//
// Upstream body verified BYTE-IDENTICAL at three dated refs on the public
// pfsense/pfsense mirror (src/etc/inc/util.inc; CLAUDE.md "Resolve pfSense-
// provided PHP functions from upstream"):
//   - CE 2.8.0 (min supported)  -- ed6c2eb84595aab998c3b3efaf16d226bd62c38d,
//     the youngest master commit at/before the 2025-05-28 release.
//   - CE 2.8.1 (latest released) -- 97f9eb5c819fd7f0c5f232d2581e5080be1cb18a,
//     the youngest master commit at/before the 2025-09-04 release.
//   - master tip -- 9363ac5b8651a1c7a333180425ce7719070f95f9 (2026-03-31).
// ip_range_to_subnet_array()'s body below is VENDORED VERBATIM from that
// source (its own doc comment kept intact). Its two callees --
// ip6_to_bin()/bin_to_compressed_ip6() -- use PEAR's Net_IPv6
// (Uncompress()/compress()) upstream, which doesn't exist off-appliance (the
// same "no PEAR off-appliance" constraint as is_ipaddrv6() above), so those two
// are faithful REIMPLEMENTATIONS using PHP's builtin inet_pton()/inet_ntop():
// packing/unpacking the same 128-bit value produces byte-identical
// binary-string / canonical-compressed output to the PEAR routines for any
// address inet_pton() itself accepts (RFC 5952 compression is exactly what
// inet_ntop() already implements).

if (!function_exists('ip6_to_bin')) {
	// FAITHFUL REIMPLEMENTATION (no PEAR off-appliance): pack the address with
	// inet_pton() and expand every byte to 8 bits, producing the same 128-char
	// '0'/'1' string upstream's Net_IPv6::Uncompress()+base_convert() loop does.
	function ip6_to_bin($ip) {
		// Mirror Net_IPv6::removeNetmaskSpec(): drop a trailing "/prefix" if present.
		$slash = strpos($ip, '/');
		if ($slash !== false) {
			$ip = substr($ip, 0, $slash);
		}
		$packed = @inet_pton($ip);
		if ($packed === false) {
			return '';
		}
		$bin = '';
		foreach (str_split($packed) as $byte) {
			$bin .= sprintf('%08b', ord($byte));
		}
		return $bin;
	}
}

if (!function_exists('bin_to_compressed_ip6')) {
	// FAITHFUL REIMPLEMENTATION (no PEAR off-appliance): pack the 128-bit binary
	// string back into 16 raw bytes and let inet_ntop() render the canonical
	// (RFC 5952) compressed form -- the same output Net_IPv6::compress() gives.
	function bin_to_compressed_ip6($bin) {
		$bin = str_pad($bin, 128, '0', STR_PAD_LEFT);
		$packed = '';
		foreach (str_split($bin, 8) as $byte_bin) {
			$packed .= chr(bindec($byte_bin));
		}
		return inet_ntop($packed);
	}
}

if (!function_exists('ip_range_to_subnet_array')) {
	/*
	 * Convert an IPv4 or IPv6 IP range to an array of subnets which can contain the range.
	 * Algorithm and embodying code PD'ed by Stilez - enjoy as you like :-)
	 *
	 * Documented on pfsense dev list 19-20 May 2013. Summary:
	 *
	 * The algorithm looks at patterns of 0's and 1's in the least significant bit(s), whether IPv4 or IPv6.
	 * These are all that needs checking to identify a _guaranteed_ correct, minimal and optimal subnet array.
	 *
	 * As a result, string/binary pattern matching of the binary IP is very efficient. It uses just 2 pattern-matching rules
	 * to chop off increasingly larger subnets at both ends that can't be part of larger subnets, until nothing's left.
	 *
	 * (a) If any range has EITHER low bit 1 (in startip) or 0 (in endip), that end-point is _always guaranteed_ to be optimally
	 * represented by its own 'single IP' CIDR; the remaining range then shrinks by one IP up or down, causing the new end-point's
	 * low bit to change from 1->0 (startip) or 0->1 (endip). Only one edge case needs checking: if a range contains exactly 2
	 * adjacent IPs of this format, then the two IPs themselves are required to span it, and we're done.
	 * Once this rule is applied, the remaining range is _guaranteed_ to end in 0's and 1's so rule (b) can now be used, and its
	 * low bits can now be ignored.
	 *
	 * (b) If any range has BOTH startip and endip ending in some number of 0's and 1's respectively, these low bits can
	 * *always* be ignored and "bit-shifted" for subnet spanning. So provided we remember the bits we've place-shifted, we can
	 * _always_ right-shift and chop off those bits, leaving a smaller range that has EITHER startip ending in 1 or endip ending
	 * in 0 (ie can now apply (a) again) or the entire range has vanished and we're done.
	 * We then loop to redo (a) again on the remaining (place shifted) range until after a few loops, the remaining (place shifted)
	 * range 'vanishes' by meeting the exit criteria of (a) or (b), and we're done.
	 *
	 * VENDORED VERBATIM from pfSense util.inc -- see the doubles-file-header
	 * attribution above for the three dated refs this was diffed byte-identical
	 * against.
	 */
	function ip_range_to_subnet_array($ip1, $ip2) {

		if (is_ipaddrv4($ip1) && is_ipaddrv4($ip2)) {
			$proto = 'ipv4';  // for clarity
			$bits = 32;
			$ip1bin = decbin(ip2long32($ip1));
			$ip2bin = decbin(ip2long32($ip2));
		} elseif (is_ipaddrv6($ip1) && is_ipaddrv6($ip2)) {
			$proto = 'ipv6';
			$bits = 128;
			$ip1bin = ip6_to_bin($ip1);
			$ip2bin = ip6_to_bin($ip2);
		} else {
			return array();
		}

		// it's *crucial* that binary strings are guaranteed the expected length;  do this for certainty even though for IPv6 it's redundant
		$ip1bin = str_pad($ip1bin, $bits, '0', STR_PAD_LEFT);
		$ip2bin = str_pad($ip2bin, $bits, '0', STR_PAD_LEFT);

		if ($ip1bin == $ip2bin) {
			return array($ip1 . '/' . $bits); // exit if ip1=ip2 (trivial case)
		}

		if ($ip1bin > $ip2bin) {
			list ($ip1bin, $ip2bin) = array($ip2bin, $ip1bin);  // swap if needed (ensures ip1 < ip2)
		}

		$rangesubnets = array();
		$netsize = 0;

		do {
			// at loop start, $ip1 is guaranteed strictly less than $ip2 (important for edge case trapping and preventing accidental binary wrapround)
			// which means the assignments $ip1 += 1 and $ip2 -= 1 will always be "binary-wrapround-safe"

			// step #1 if start ip (as shifted) ends in any '1's, then it must have a single cidr to itself (any cidr would include the '0' below it)

			if (substr($ip1bin, -1, 1) == '1') {
				// the start ip must be in a separate one-IP cidr range
				$new_subnet_ip = substr($ip1bin, $netsize, $bits - $netsize) . str_repeat('0', $netsize);
				$rangesubnets[$new_subnet_ip] = $bits - $netsize;
				$n = strrpos($ip1bin, '0');  //can't be all 1's
				$ip1bin = ($n == 0 ? '' : substr($ip1bin, 0, $n)) . '1' . str_repeat('0', $bits - $n - 1);  // BINARY VERSION OF $ip1 += 1
			}

			// step #2, if end ip (as shifted) ends in any zeros then that must have a cidr to itself (as cidr cant span the 1->0 gap)

			if (substr($ip2bin, -1, 1) == '0') {
				// the end ip must be in a separate one-IP cidr range
				$new_subnet_ip = substr($ip2bin, $netsize, $bits - $netsize) . str_repeat('0', $netsize);
				$rangesubnets[$new_subnet_ip] = $bits - $netsize;
				$n = strrpos($ip2bin, '1');  //can't be all 0's
				$ip2bin = ($n == 0 ? '' : substr($ip2bin, 0, $n)) . '0' . str_repeat('1', $bits - $n - 1);  // BINARY VERSION OF $ip2 -= 1
				// already checked for the edge case where end = start+1 and start ends in 0x1, above, so it's safe
			}

			// this is the only edge case arising from increment/decrement.
			// it happens if the range at start of loop is exactly 2 adjacent ips, that spanned the 1->0 gap. (we will have enumerated both by now)

			if ($ip2bin < $ip1bin) {
				continue;
			}

			// step #3 the start and end ip MUST now end in '0's and '1's respectively
			// so we have a non-trivial range AND the last N bits are no longer important for CIDR purposes.

			$shift = $bits - max(strrpos($ip1bin, '0'), strrpos($ip2bin, '1'));  // num of low bits which are '0' in ip1 and '1' in ip2
			$ip1bin = str_repeat('0', $shift) . substr($ip1bin, 0, $bits - $shift);
			$ip2bin = str_repeat('0', $shift) . substr($ip2bin, 0, $bits - $shift);
			$netsize += $shift;
			if ($ip1bin == $ip2bin) {
				// we're done.
				$new_subnet_ip = substr($ip1bin, $netsize, $bits - $netsize) . str_repeat('0', $netsize);
				$rangesubnets[$new_subnet_ip] = $bits - $netsize;
				continue;
			}

			// at this point there's still a remaining range, and either startip ends with '1', or endip ends with '0'. So repeat cycle.
		} while ($ip1bin < $ip2bin);

		// subnets are ordered by bit size. Re sort by IP ("naturally") and convert back to IPv4/IPv6

		ksort($rangesubnets, SORT_STRING);
		$out = array();

		foreach ($rangesubnets as $ip => $netmask) {
			if ($proto == 'ipv4') {
				$i = str_split($ip, 8);
				$out[] = implode('.', array(bindec($i[0]), bindec($i[1]), bindec($i[2]), bindec($i[3]))) . '/' . $netmask;
			} else {
				$out[] = bin_to_compressed_ip6($ip) . '/' . $netmask;
			}
		}

		return $out;
	}
}

if (!class_exists('Net_IPv6')) {
	// PEAR Net_IPv6 -- a pfSense on-appliance dependency (pulled in via util.inc's PEAR
	// includes), not installed off-appliance. pfblockerng.inc calls exactly ONE method,
	// isInNetmask($ip, "$network/$bits"), inside find_reported_header()'s (and, since
	// issue #809 Phase 3b, pfb_match_reported_cidr()'s) IPv6 CIDR-containment check —
	// this double stands in for that ONE call. FAITHFUL, not a shortcut: it delegates to
	// pfb_ip_in_cidr() (pfblockerng.inc), the package's own byte/bitmask packed-address
	// containment test, already covered by its own suite (FeedHostAllowedTest) -- so this
	// double carries no independent containment logic to get wrong. Guarded by
	// class_exists() so a real PEAR install (never present off-appliance) is never
	// shadowed.
	class Net_IPv6 {
		public static function isInNetmask($ip, $cidr) {
			return pfb_ip_in_cidr($ip, $cidr);
		}
	}
}

// --- services.inc cron doubles (issue #1204) ---
//
// pfblockerng_configure_tick_cron() (pfblockerng.inc) drives install_cron_job() to
// install/remove the scheduled tick and tear down legacy verb entries. Faithful to
// the real services.inc control flow: the FIRST cron/item whose command SUBSTRING-
// matches $command (strstr, not equality) is "the" entry; $active=true installs or
// overwrites it (appends when none matched); $active=false removes it. The removal
// reindexes (the real one leaves the hole) -- harmless: no caller indexes cron items,
// they only iterate. write_config() is not called; these tests assert cron state only.

if (!function_exists('configure_cron')) {
	// pfSense services.inc: rewrites /etc/crontab from config/cron/item. Nothing to
	// render off-appliance; tests assert state via config_get_path('cron/item').
	function configure_cron() {
	}
}

if (!function_exists('install_cron_job')) {
	function install_cron_job($command, $active = false, $minute = '0', $hour = '*', $mday = '*', $month = '*', $wday = '*', $who = 'root', $write_config = true) {
		$items = config_get_path('cron/item', []);
		$found = null;
		foreach ($items as $idx => $item) {
			if (strstr($item['command'] ?? '', $command)) {
				$found = $idx;
				break;
			}
		}

		if ($active) {
			$entry = compact('minute', 'hour', 'mday', 'month', 'wday', 'who', 'command');
			config_set_path('cron/item/' . ($found ?? count($items)), $entry);
		} elseif ($found !== null) {
			config_del_path("cron/item/{$found}");
			config_set_path('cron/item', array_values(config_get_path('cron/item', [])));
		}

		configure_cron();
	}
}
