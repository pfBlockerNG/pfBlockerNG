<?php

declare(strict_types=1);

/*
 * issue #4276: DNSBL is force-disabled with "IPv6 VIP not on interface Loopback" when the stored IPv6 VIP is the
 * literal 'none'. The DNSBL page and the wizard map 'none' to '' before they validate, but the wizard binds its
 * fields before its step action runs, so 'none' can reach config.xml, and pfb_global() hands the stored value
 * straight to pfb_validate_vips().
 *
 * Standalone runner: release/3.3 ships no PHPUnit, so it eval()s the PRODUCTION pfb_validate_vips() and the
 * pfb_global() DNSBL gate straight out of pfblockerng.inc, with pfSense platform doubles.
 *   A  pfb_validate_vips() matrix            B  pfb_global() keeps DNSBL on for a stored 'none'
 *
 * NOT covered: a live pfSense box (real VIP lookup, the wizard's field binding).
 */

$root = dirname(__DIR__, 2);
$inc = (string) file_get_contents($root . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
$failures = 0;

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

function same(mixed $expected, mixed $actual, string $message): void
{
	if ($expected !== $actual) {
		throw new RuntimeException($message . ': expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
	}
}

function row(string $name, callable $test): void
{
	global $failures;
	try {
		$test();
		echo "PASS {$name}\n";
	} catch (Throwable $error) {
		$failures++;
		echo "FAIL {$name}: {$error->getMessage()}\n";
	}
}

function function_source(string $source, string $name): string
{
	$start = strpos($source, "function {$name}(");
	check($start !== false, "missing function {$name}");
	$open = strpos($source, '{', $start);
	check($open !== false, "missing body of {$name}");
	$depth = 0;
	$length = strlen($source);
	for ($i = $open; $i < $length; $i++) {
		if ($source[$i] === '{') {
			$depth++;
		} elseif ($source[$i] === '}' && --$depth === 0) {
			return substr($source, $start, $i - $start + 1);
		}
	}
	throw new RuntimeException("unterminated {$name}");
}

function source_slice(string $source, string $startNeedle, string $endNeedle): string
{
	$start = strpos($source, $startNeedle);
	check($start !== false, "missing source marker {$startNeedle}");
	$end = strpos($source, $endNeedle, $start);
	check($end !== false, "missing source marker {$endNeedle}");
	return substr($source, $start, $end - $start);
}

// --- pfSense platform doubles: core VIPs by id, as config.xml <virtualip> would hold them -------------------

$GLOBALS['test_vips'] = [
	'_vip4lo' => ['if' => 'lo0', 'subnet' => '10.10.10.11', 'family' => 4],
	'_vip4lan' => ['if' => 'lan', 'subnet' => '192.168.10.11', 'family' => 4],
	'_vip6lo' => ['if' => 'lo0', 'subnet' => 'fd00::11', 'family' => 6],
	'_vip6lan' => ['if' => 'lan', 'subnet' => 'fd00:10::11', 'family' => 6],
];
$GLOBALS['test_log'] = [];

if (!function_exists('gettext')) {
	function gettext(string $s): string
	{
		return $s;
	}
}

function get_configured_vip_interface($vipid)
{
	return $GLOBALS['test_vips'][$vipid]['if'] ?? null;
}

function get_configured_vip_ipv4($vipid)
{
	$vip = $GLOBALS['test_vips'][$vipid] ?? null;
	return ($vip !== null && $vip['family'] === 4) ? $vip['subnet'] : null;
}

function get_configured_vip_ipv6($vipid)
{
	$vip = $GLOBALS['test_vips'][$vipid] ?? null;
	return ($vip !== null && $vip['family'] === 6) ? $vip['subnet'] : null;
}

function convert_friendly_interface_to_friendly_descr($interface)
{
	return ['lo0' => 'Loopback', 'lan' => 'LAN'][$interface] ?? $interface;
}

function where_is_ipaddr_configured($ipaddr, $ignore_if = '', $check_localip = false, $check_subnets = false, $cidrprefix = '')
{
	return [];
}

function pfb_get_vips(): array
{
	$vips = ['v4' => [], 'v6' => []];
	foreach ($GLOBALS['test_vips'] as $id => $vip) {
		$vips[$vip['family'] === 4 ? 'v4' : 'v6'][$id] = $vip['subnet'];
	}
	return $vips;
}

function pfb_logger($message, $type)
{
	$GLOBALS['test_log'][] = $message;
}

eval(function_source($inc, 'pfb_validate_vips'));

// --- A: pfb_validate_vips() matrix on the Loopback interface ---------------------------------------------------

$matrix = [
	'A1 valid IPv4 + IPv6 none'              => ['_vip4lo', 'none', [true, null]],
	'A2 valid IPv4 + IPv6 empty'             => ['_vip4lo', '', [true, null]],
	'A3 valid IPv4 + IPv6 null'              => ['_vip4lo', null, [true, null]],
	'A4 valid IPv4 + valid IPv6 (dual-stack)' => ['_vip4lo', '_vip6lo', [true, null]],
	'A5 valid IPv4 + IPv6 on another iface'  => ['_vip4lo', '_vip6lan', [false, 'IPv6 VIP not on interface Loopback']],
	'A6 IPv4 on another iface + IPv6 none'   => ['_vip4lan', 'none', [false, 'IPv4 VIP not on interface Loopback']],
	'A7 IPv4 none + valid IPv6 (IPv6-only)'  => ['none', '_vip6lo', [true, null]],
	'A8 IPv4 empty + valid IPv6 (IPv6-only)' => ['', '_vip6lo', [true, null]],
	'A9 IPv4 none + IPv6 none'               => ['none', 'none', [false, 'no VIP configured']],
	'A10 IPv4 empty + IPv6 empty'            => ['', '', [false, 'no VIP configured']],
	'A11 deleted IPv6 VIP id still rejected' => ['_vip4lo', '_vipgone', [false, 'IPv6 VIP not on interface Loopback']],
];

foreach ($matrix as $name => [$vip4, $vip6, $expected]) {
	row($name, static function () use ($vip4, $vip6, $expected): void {
		same($expected, pfb_validate_vips('lo0', $vip4, $vip6), 'pfb_validate_vips(lo0, ' . var_export($vip4, true) . ', ' . var_export($vip6, true) . ')');
	});
}

// --- B: the pfb_global() DNSBL gate, fed the reporter's stored config ------------------------------------------

$gate = source_slice($inc, "\tif (!empty(\$pfb['dnsbl'])) {\n\t\t\$vips_valid_result = pfb_validate_vips(", "\t\$pfb['dnsbl_port']");

row('B1 pfb_global keeps DNSBL on for stored pfb_dnsvip6 none', static function () use ($gate): void {
	$GLOBALS['test_log'] = [];
	$pfb = [
		'dnsbl' => 'on',
		'dnsbl_iface' => 'lo0',
		'dnsblconfig' => ['pfb_dnsbl' => 'on', 'pfb_dnsvip4' => '_vip4lo', 'pfb_dnsvip6' => 'none'],
	];
	eval($gate);
	same('on', $pfb['dnsbl'], 'DNSBL enabled state after the VIP gate');
	same([], $GLOBALS['test_log'], 'pfb_logger messages from the VIP gate');
});

row('B2 pfb_global still disables DNSBL for an IPv4 VIP on another interface', static function () use ($gate): void {
	$GLOBALS['test_log'] = [];
	$pfb = [
		'dnsbl' => 'on',
		'dnsbl_iface' => 'lo0',
		'dnsblconfig' => ['pfb_dnsbl' => 'on', 'pfb_dnsvip4' => '_vip4lan', 'pfb_dnsvip6' => 'none'],
	];
	eval($gate);
	same('', $pfb['dnsbl'], 'DNSBL enabled state after the VIP gate');
	same(["\nDNSBL disabled: IPv4 VIP not on interface Loopback"], $GLOBALS['test_log'], 'pfb_logger messages from the VIP gate');
});

row('B3 pfb_global still disables DNSBL for an IPv6 VIP on another interface', static function () use ($gate): void {
	$GLOBALS['test_log'] = [];
	$pfb = [
		'dnsbl' => 'on',
		'dnsbl_iface' => 'lo0',
		'dnsblconfig' => ['pfb_dnsbl' => 'on', 'pfb_dnsvip4' => '_vip4lo', 'pfb_dnsvip6' => '_vip6lan'],
	];
	eval($gate);
	same('', $pfb['dnsbl'], 'DNSBL enabled state after the VIP gate');
	same(["\nDNSBL disabled: IPv6 VIP not on interface Loopback"], $GLOBALS['test_log'], 'pfb_logger messages from the VIP gate');
});

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);
