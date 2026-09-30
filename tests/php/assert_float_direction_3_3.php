<?php

declare(strict_types=1);

/*
 * issue #3382 (release/3.3 backport of devel b46db588, eb16d776, acf7c29c, d7f95387).
 *
 * A floating rule matches on the interface a packet ENTERS, and a client's egress enters LAN
 * 'in', so every floating auto-rule is direction 'in' (Match always, Deny/Permit with Floating
 * Rules on; interface rules carry no direction key). Locally originated traffic never enters an
 * interface, so the opt-in 'Apply outbound rules to firewall traffic' setting (fw_self_outbound)
 * gives every outbound auto-rule a floating `out quick on <Inbound interfaces> from (self)` twin.
 *
 * Standalone runner (release/3.3 ships no PHPUnit): eval()s the PRODUCTION function and the
 * inline rule-assembly / IP-page-handler slices straight out of the shipped sources, with
 * behavioural doubles for the pfSense platform functions.
 *   A  direction matrix           B  twin shape and suppression
 *   C  assembly guard, per-inbound-interface twin placement, bucket reset, setting read, and the WHOLE
 *      assign-rules block over pass_order order_0..4 x Floating Rules on/off with user floating rules
 *   D  IP page (settings read through the Save handler): toggle validated before side effects,
 *      persisted, read back on the next load, re-render guard
 *
 * NOT covered: the checkbox itself (Form_Checkbox rendering, its checked state and help text) and a
 * live pfctl ruleset -- release/3.3 has no UI tier and no smoke seat.
 */

$root = dirname(__DIR__, 2);
$source = (string) file_get_contents($root . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
$ip_page = (string) file_get_contents($root . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php');
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

function source_slice(string $source, string $startNeedle, string $endNeedle, int $offset = 0): string
{
	$start = strpos($source, $startNeedle, $offset);
	check($start !== false, "missing source marker {$startNeedle}");
	$end = strpos($source, $endNeedle, $start);
	check($end !== false, "missing source marker {$endNeedle}");
	return substr($source, $start, $end - $start);
}

/** Run an extracted source slice against the given local variables; return every local afterwards. */
function run_slice(string $code, array $vars): array
{
	extract($vars, EXTR_SKIP);
	eval($code);
	unset($code, $vars);
	return get_defined_vars();
}

/** @return list<string> the PHP diagnostics raised while $body runs */
function diagnostics_of(callable $body): array
{
	$seen = [];
	set_error_handler(static function (int $errno, string $errstr) use (&$seen): bool {
		$seen[] = $errstr;
		return true;
	});
	try {
		$body();
	} finally {
		restore_error_handler();
	}
	return $seen;
}

// --- behavioural doubles -------------------------------------------------------------------

function pfb_tracker($alias, $int, $text)
{
	$GLOBALS['tracker_calls'][] = [$alias, $int, $text];
	return 1770000000 + count($GLOBALS['tracker_calls']);
}

const PFB_FILTER_ON_OFF = 21;
const PFB_FILTER_WORD = 6;

function pfb_filter($input, $type, $reference = 'Unknown', $default = '', $escape = false)
{
	if ($type === PFB_FILTER_ON_OFF) {
		return ($input === 'on' || $input === '') ? $input : '';
	}
	return $input;
}

function pfb_build_if_list($show_wan = false, $show_groups = false)
{
	return ['wan' => 'WAN', 'lan' => 'LAN', 'opt1' => 'OPT1'];
}

function is_ipaddrv4($ip)
{
	return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

function where_is_ipaddr_configured($ip, $x = '', $y = false, $z = false, $w = '')
{
	return [];
}

function mwexec_bg($command)
{
	$GLOBALS['ip_calls']['mwexec_bg'][] = $command;
}

function config_get_path($path, $default = null)
{
	if ($path === 'filter/rule') {
		return $GLOBALS['filter_rules'] ?? $default;
	}
	return $GLOBALS['config_store'][$path] ?? $default;
}

function config_set_path($path, $value)
{
	$GLOBALS['config_store'][$path] = $value;
	$GLOBALS['ip_calls']['config'][$path] = $value;
}

function config_read_file($cache = false, $force = false)
{
}

function write_config($message)
{
	$GLOBALS['ip_calls']['write'][] = $message;
}

function pfb_test_header($line)
{
	$GLOBALS['ip_calls']['header'][] = $line;
}

final class PfbTestExit extends Exception
{
}

// --- production under test -----------------------------------------------------------------

eval(function_source($source, 'pfb_firewall_rule'));

function production_base_rule(string $name): array
{
	global $source;
	check(preg_match('/^\$pfb\[\'' . $name . '\'\]\s*=\s*(array\([^;]*\));/m', $source, $m) === 1, "missing {$name}");
	return eval("return {$m[1]};");
}

const BUCKETS = [
	'deny_outbound', 'deny_inbound', 'permit_outbound', 'permit_inbound',
	'match_outbound', 'match_inbound', 'deny_self', 'permit_self', 'match_self',
];

/** Reset $pfb as sync_package_pfblockerng() leaves it for pfb_firewall_rule(). */
function fixture(string $float, string $fw_self = ''): void
{
	$reg = production_base_rule('base_rule_reg');
	$flt = production_base_rule('base_rule_float');
	$pfb = [
		'base_rule_reg'        => $reg,
		'base_rule_float'      => $flt,
		'base_rule'            => $float === 'on' ? $flt : $reg,
		'deny_action_inbound'  => 'block',
		'deny_action_outbound' => 'reject',
		'float'                => $float,
		'suffix'               => ' Auto Rule',
		'global_log'           => '',
		'fw_self'              => $fw_self,
	];
	$GLOBALS['pfb'] = $pfb;
}

function last_rule(string $bucket): array
{
	$rules = $GLOBALS['pfb'][$bucket] ?? [];
	check($rules !== [], "bucket {$bucket} is empty");
	return $rules[array_key_last($rules)];
}

/** Every bucket holds exactly the named number of rules (default none). */
function only_rules(array $counts): void
{
	foreach (BUCKETS as $bucket) {
		same($counts[$bucket] ?? 0, count($GLOBALS['pfb'][$bucket] ?? []), "rule count in {$bucket}");
	}
}

// --- A: direction matrix -------------------------------------------------------------------

foreach (['Deny' => 'deny', 'Permit' => 'permit', 'Match' => 'match'] as $family => $prefix) {
	foreach (['Inbound' => ['inbound'], 'Outbound' => ['outbound'], 'Both' => ['outbound', 'inbound']] as $role => $legs) {
		foreach (['on', ''] as $float) {
			$label = sprintf('A direction %s_%s float %s', $family, $role, $float === 'on' ? 'on' : 'off');
			row($label, static function () use ($family, $prefix, $role, $legs, $float): void {
				foreach (['default', 'WAN_DHCP'] as $gateway) {
					fixture($float);
					pfb_firewall_rule("{$family}_{$role}", 'pfB_A', '_v4', 'off', $gateway, $gateway);
					foreach ($legs as $leg) {
						$rule = last_rule("{$prefix}_{$leg}");
						if ($float === 'on' || $family === 'Match') {
							same('in', $rule['direction'] ?? null, "{$leg} rule direction (gateway {$gateway})");
						} else {
							check(!array_key_exists('direction', $rule), "{$leg} rule must carry no direction key with Floating Rules off (gateway {$gateway})");
						}
						if ($gateway === 'default') {
							check(!array_key_exists('gateway', $rule), "{$leg} rule: the default gateway leaves no gateway key");
						} else {
							same($gateway, $rule['gateway'] ?? null, "{$leg} rule keeps its custom gateway");
						}
					}
				}
			});
		}
	}
}

// --- B: firewall-traffic twins -------------------------------------------------------------

/** Outbound action => [twin bucket, twin type, client buckets the call fills]. */
const OUTBOUND_TWINS = [
	'Deny_Outbound'   => ['deny_self',   'reject', ['deny_outbound']],
	'Deny_Both'       => ['deny_self',   'reject', ['deny_outbound', 'deny_inbound']],
	'Permit_Outbound' => ['permit_self', 'pass',   ['permit_outbound']],
	'Permit_Both'     => ['permit_self', 'pass',   ['permit_outbound', 'permit_inbound']],
	'Match_Outbound'  => ['match_self',  'match',  ['match_outbound']],
	'Match_Both'      => ['match_self',  'match',  ['match_outbound', 'match_inbound']],
];

function twin_key_set(string $type, bool $logs): array
{
	$keys = ['floating', 'ipprotocol', 'type', 'descr', 'destination', 'protocol', 'created', 'direction', 'source'];
	if ($type !== 'match') {
		$keys[] = 'quick';
	}
	if ($logs) {
		$keys[] = 'log';
	}
	sort($keys);
	return $keys;
}

foreach (OUTBOUND_TWINS as $action => [$bucket, $type, $clients]) {
	foreach (['on', ''] as $float) {
		row(sprintf('B twin %s float %s', $action, $float === 'on' ? 'on' : 'off'), static function () use ($action, $bucket, $type, $clients, $float): void {
			fixture($float, 'on');
			// Every Advanced Outbound setting plus a custom gateway: all but the gateway reach the twin.
			pfb_firewall_rule($action, 'pfB_A', '_v4', 'off', 'default', 'GW_WAN_OUT', '', '', '', '', '', 'on', '', '443', 'tcp', '');

			only_rules(array_fill_keys(array_merge($clients, [$bucket]), 1));
			$twin = last_rule($bucket);

			$keys = array_keys($twin);
			sort($keys);
			same(twin_key_set($type, false), $keys, 'twin carries exactly the shared keys (no gateway, no stray client-rule keys)');
			same('yes', $twin['floating'], 'the twin is floating even with Floating Rules off');
			same('out', $twin['direction'], 'the twin matches traffic leaving the firewall');
			same($type, $twin['type'], "the twin has the client rule's disposition");
			if ($type === 'match') {
				check(!array_key_exists('quick', $twin), 'a match twin is not quick');
			} else {
				same('yes', $twin['quick'], 'a deny/permit twin is quick');
			}
			same(['network' => '(self)'], $twin['source'], 'the twin source is This Firewall (self)');
			same(['address' => 'pfB_A', 'port' => '443', 'not' => ''], $twin['destination'], 'destination alias, port and invert mirror the client rule');
			same('tcp', $twin['protocol'], 'protocol mirrors the client rule');
			same('inet', $twin['ipprotocol'], 'ipprotocol mirrors the client rule');
			same('pfB_A Auto Rule', $twin['descr'], 'the twin shares the client rule descr');
			same('Auto', $twin['created']['username'], 'created username');
			check(is_int($twin['created']['time']), 'created time is an int');
			same('GW_WAN_OUT', last_rule($clients[0])['gateway'], 'the client rule keeps its own gateway');
		});
	}
}

row('B twin follows vtype', static function (): void {
	fixture('', 'on');
	pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
	same('inet', last_rule('deny_self')['ipprotocol'], '_v4 twin');
	pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v6', 'off');
	same('inet6', last_rule('deny_self')['ipprotocol'], '_v6 twin');
});

row('B twin logs exactly when the client rule logs', static function (): void {
	fixture('', 'on');
	pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
	check(!array_key_exists('log', last_rule('deny_outbound')), 'before: client rule does not log');
	check(!array_key_exists('log', last_rule('deny_self')), 'before: twin does not log');

	pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'enabled');
	check(array_key_exists('log', last_rule('deny_outbound')), 'per-list logging: client rule logs');
	check(array_key_exists('log', last_rule('deny_self')), 'per-list logging carries to the twin');

	$GLOBALS['pfb']['global_log'] = 'on';
	pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
	check(array_key_exists('log', last_rule('deny_self')), 'global logging carries to the twin');
});

foreach (['Deny_Inbound' => 'deny_inbound', 'Permit_Inbound' => 'permit_inbound', 'Match_Inbound' => 'match_inbound'] as $action => $bucket) {
	row("B no twin for {$action}", static function () use ($action, $bucket): void {
		foreach (['on', ''] as $float) {
			fixture($float, 'on');
			pfb_firewall_rule($action, 'pfB_A', '_v4', 'off');
			only_rules([$bucket => 1]);
		}
	});
}

foreach (OUTBOUND_TWINS as $action => [$bucket, $type, $clients]) {
	row("B no twin for {$action} with the toggle off", static function () use ($action, $clients): void {
		fixture('', '');
		pfb_firewall_rule($action, 'pfB_A', '_v4', 'off');
		only_rules(array_fill_keys($clients, 1));
	});

	row("B no twin for {$action} with a Custom Source", static function () use ($action, $clients): void {
		fixture('', 'on');
		// A Custom Source scopes the client rule to specific hosts; a (self) twin would contradict it.
		pfb_firewall_rule($action, 'pfB_A', '_v4', 'off', 'default', 'default', '', '', '', '', '', '', '10.0.0.1');
		same(['address' => '10.0.0.1'], last_rule($clients[0])['source'], 'the client rule keeps its Custom Source');
		only_rules(array_fill_keys($clients, 1));
	});
}

// --- C: assembly guard, twin placement, bucket reset, setting read -------------------------

$guard_code = source_slice($source, "\$message = '';", 'if (empty($message)) {', (int) strpos($source, '$pfb_active_aliases = [];'));
$inbound_loop = source_slice($source, '// Define inbound interface rules', '// Define outbound interface rules');
$reset_code = source_slice($source, "unset(\$pfb['permit_inbound']", 'unset($cb_rules');
$assembly_code = source_slice($source, '$new_rules = $permit_rules = $match_rules', "// Remove 'created' tag (New vs old rules array comparison)");

function guard_message(array $pfb): string
{
	global $guard_code;
	return run_slice($guard_code, ['pfb' => $pfb])['message'];
}

foreach (['deny_self', 'permit_self', 'match_self'] as $bucket) {
	row("C {$bucket} without an Inbound interface stops the apply pass", static function () use ($bucket): void {
		$pfb = [$bucket => [['descr' => 'pfB_A']], 'inbound_interfaces' => [], 'outbound_interfaces' => ['lan']];
		$message = guard_message($pfb);
		check(str_contains($message, 'Inbound interface option not configured'), "expected the Inbound stop message, got '{$message}'");
		check(!str_contains($message, 'Outbound interface option not configured'), 'a twin bucket must not raise the Outbound message');

		$pfb['inbound_interfaces'] = ['lan'];
		same('', guard_message($pfb), 'with an Inbound interface the twin bucket does not stop the pass');
	});
}

row('C guard keeps its inbound/outbound behaviour without twins', static function (): void {
	same('', guard_message(['inbound_interfaces' => [], 'outbound_interfaces' => []]), 'no rules, no message');
	$message = guard_message(['deny_inbound' => [['descr' => 'x']], 'inbound_interfaces' => [], 'outbound_interfaces' => ['lan']]);
	check(str_contains($message, 'Inbound interface option not configured'), 'inbound rule without Inbound interface');
	$message = guard_message(['deny_outbound' => [['descr' => 'x']], 'inbound_interfaces' => ['lan'], 'outbound_interfaces' => []]);
	check(str_contains($message, 'Outbound interface option not configured'), 'outbound rule without Outbound interface');
});

/** @return array{0: list<array>, 1: list<string>} [new_rules, diagnostics] of the inbound-interface loop */
function assemble_inbound(array $inbound_interfaces, string $order = 'order_0'): array
{
	global $inbound_loop;
	$GLOBALS['tracker_calls'] = [];
	$pfb = $GLOBALS['pfb'];
	$pfb['order'] = $order;
	$pfb['inbound_interfaces'] = $inbound_interfaces;
	$pfb['inbound_floating'] = implode(',', $inbound_interfaces);
	$new_rules = [];
	$seen = diagnostics_of(static function () use ($inbound_loop, $pfb, &$new_rules): void {
		$new_rules = run_slice($inbound_loop, [
			'pfb' => $pfb, 'new_rules' => [], 'permit_rules' => [], 'fpermit_rules' => [], 'fmatch_rules' => [],
		])['new_rules'];
	});
	return [$new_rules, $seen];
}

function label(array $rule): string
{
	return implode(' ', [
		$rule['type'],
		$rule['direction'] ?? '-',
		$rule['interface'],
		isset($rule['source']['network']) ? '(self)' : 'client',
	]);
}

/** Every twin carries the tracker requested for its own descr, Inbound entry and role. */
function assert_twin_trackers(array $rules): void
{
	foreach ($rules as $rule) {
		if (!isset($rule['source']['network'])) {
			continue;
		}
		$role = ['pass' => 'permit_self', 'match' => 'match_self', 'reject' => 'deny_self'][$rule['type']];
		$call = [$rule['descr'], $rule['interface'], $role];
		$index = array_search($call, $GLOBALS['tracker_calls'], true);
		check($index !== false, 'tracker requested for ' . json_encode($call));
		same(1770000000 + $index + 1, $rule['tracker'], 'twin carries the tracker built for its own interface and role');
	}
}

function generate_all_both_actions(string $float, string $fw_self): void
{
	fixture($float, $fw_self);
	foreach (['Permit_Both', 'Match_Both', 'Deny_Both'] as $action) {
		pfb_firewall_rule($action, 'pfB_A', '_v4', 'off');
	}
}

row('C twins are emitted per Inbound interface after permit_inbound and after deny_inbound', static function (): void {
	generate_all_both_actions('', 'on');
	[$rules, $seen] = assemble_inbound(['lan', 'opt1']);
	same([], $seen, 'assembly raises no diagnostic');
	same([
		'pass - lan client',
		'pass out lan (self)',
		'match out lan (self)',
		'match in lan,opt1 client',
		'block - lan client',
		'reject out lan (self)',
		'pass - opt1 client',
		'pass out opt1 (self)',
		'match out opt1 (self)',
		'block - opt1 client',
		'reject out opt1 (self)',
	], array_map('label', $rules), 'rule sequence');

	assert_twin_trackers($rules);
});

row('C with Floating Rules on the single comma-joined Inbound entry carries one twin per role', static function (): void {
	generate_all_both_actions('on', 'on');
	[$rules] = assemble_inbound(['lan,opt1']);
	same([
		'pass in lan,opt1 client',
		'pass out lan,opt1 (self)',
		'match out lan,opt1 (self)',
		'match in lan,opt1 client',
		'block in lan,opt1 client',
		'reject out lan,opt1 (self)',
	], array_map('label', $rules), 'rule sequence');
});

row('C the toggle off assembles exactly the client rules and touches no twin bucket', static function (): void {
	generate_all_both_actions('', '');
	[$rules, $seen] = assemble_inbound(['lan', 'opt1']);
	same([], $seen, 'no diagnostic for absent twin buckets');
	same([
		'pass - lan client',
		'match in lan,opt1 client',
		'block - lan client',
		'pass - opt1 client',
		'block - opt1 client',
	], array_map('label', $rules), 'rule sequence');
});

row('C every rule bucket, twins included, is reset after assembly', static function () use ($reset_code): void {
	$pfb = array_fill_keys(BUCKETS, [['descr' => 'stale']]);
	$after = run_slice($reset_code, ['pfb' => $pfb])['pfb'];
	same([], array_keys($after), 'buckets left behind for the next pass');
});

row('C the toggle is read from ip/fw_self_outbound, absent reads off', static function () use ($source): void {
	check(preg_match('/^\s*(\$pfb\[\'fw_self\'\]\s*=[^\n]*;)/m', $source, $m) === 1, "missing \$pfb['fw_self'] read");
	$read = $m[1];
	$pfb = run_slice($read, ['pfb' => ['ipconfig' => ['fw_self_outbound' => 'on']]])['pfb'];
	same('on', $pfb['fw_self'], 'saved On');
	$pfb = run_slice($read, ['pfb' => ['ipconfig' => ['fw_self_outbound' => '']]])['pfb'];
	same('', $pfb['fw_self'], 'saved Off');
	$seen = diagnostics_of(static function () use ($read, &$pfb): void {
		$pfb = run_slice($read, ['pfb' => ['ipconfig' => ['enable_float' => 'on']]])['pfb'];
	});
	same('', $pfb['fw_self'], 'an install that never saved the setting reads off');
	same([], $seen, 'and raises no diagnostic');
});

// --- C (cont.): the WHOLE assign-rules block over pass_order x Floating Rules ---------------
// The inbound-interface loop cannot see the user's floating rules or the trailing emission blocks
// that order them, so twin placement per pass_order is pinned through the entire block.

/** Floating pass/match/block rules the user owns (spanning both Inbound interfaces), plus interface rules. */
function user_rules(): array
{
	$base = ['ipprotocol' => 'inet', 'source' => ['any' => ''], 'destination' => ['any' => '']];
	return [
		array_merge($base, ['type' => 'pass',  'floating' => 'yes', 'quick' => 'yes', 'interface' => 'lan,opt1', 'descr' => 'U_float_pass']),
		array_merge($base, ['type' => 'match', 'floating' => 'yes', 'interface' => 'lan,opt1', 'descr' => 'U_float_match']),
		array_merge($base, ['type' => 'block', 'floating' => 'yes', 'quick' => 'yes', 'interface' => 'lan,opt1', 'descr' => 'U_float_block']),
		array_merge($base, ['type' => 'pass', 'interface' => 'lan', 'descr' => 'U_lan_pass']),
		array_merge($base, ['type' => 'block', 'interface' => 'opt1', 'descr' => 'U_opt1_block']),
	];
}

/**
 * Tier of each floating-group class per Floating Rules setting and pass_order: devel's ORDER table
 * (pfb_build_autorule_list) in class form. A lower tier is evaluated first; one tier is unordered.
 * Tiers read as the IP page's labels: pfB pass/match | pfB block/reject | user pass/match | user block.
 * With Floating Rules off every user floating rule is one class, whatever its type.
 */
const FLOATING_TIERS = [
	'on' => [
		'order_0' => ['twin_pass' => 0, 'twin_match' => 0, 'twin_deny' => 1, 'user_pass' => 2, 'user_match' => 2, 'user_block' => 2],
		'order_1' => ['user_pass' => 0, 'user_match' => 0, 'twin_pass' => 1, 'twin_match' => 1, 'twin_deny' => 2, 'user_block' => 3],
		'order_2' => ['twin_pass' => 0, 'twin_match' => 0, 'user_pass' => 1, 'user_match' => 1, 'twin_deny' => 2, 'user_block' => 3],
		'order_3' => ['twin_pass' => 0, 'twin_match' => 0, 'twin_deny' => 1, 'user_pass' => 2, 'user_match' => 2, 'user_block' => 3],
		'order_4' => ['twin_pass' => 0, 'twin_match' => 0, 'twin_deny' => 1, 'user_block' => 2, 'user_pass' => 3, 'user_match' => 3],
	],
	'off' => [
		'order_0' => ['twin_pass' => 0, 'twin_match' => 0, 'twin_deny' => 1, 'user_pass' => 2, 'user_match' => 2, 'user_block' => 2],
		'order_1' => ['user_pass' => 0, 'user_match' => 0, 'user_block' => 0, 'twin_pass' => 1, 'twin_match' => 1, 'twin_deny' => 2],
		'order_2' => ['twin_pass' => 0, 'twin_match' => 0, 'user_pass' => 1, 'user_match' => 1, 'user_block' => 1, 'twin_deny' => 2],
		'order_3' => ['twin_pass' => 0, 'twin_match' => 0, 'twin_deny' => 1, 'user_pass' => 2, 'user_match' => 2, 'user_block' => 2],
		'order_4' => ['twin_pass' => 0, 'twin_match' => 0, 'twin_deny' => 1, 'user_pass' => 2, 'user_match' => 2, 'user_block' => 2],
	],
];

/**
 * Run the WHOLE assign-rules block on the buckets pfb_firewall_rule() generated for the three Both actions.
 *
 * @return array{0: list<array>, 1: list<string>} [new_rules, diagnostics]
 */
function assemble_all(string $order, string $float, string $fw_self): array
{
	global $assembly_code;
	generate_all_both_actions($float, $fw_self);
	$GLOBALS['tracker_calls'] = [];
	$GLOBALS['filter_rules'] = user_rules();
	$pfb = $GLOBALS['pfb'];
	$pfb['order'] = $order;
	$pfb['enable'] = '';
	$pfb['dnsbl'] = '';
	$pfb['inbound_interfaces'] = $float === 'on' ? ['lan,opt1'] : ['lan', 'opt1'];
	$pfb['outbound_interfaces'] = ['opt2'];
	$pfb['inbound_floating'] = 'lan,opt1';
	$pfb['outbound_floating'] = 'opt2';
	$new_rules = [];
	// The legacy block reads keys config.xml rules do not carry (source/address ...): those notices are
	// pre-existing, so callers assert only on what concerns the twins.
	$seen = diagnostics_of(static function () use ($assembly_code, $pfb, &$new_rules): void {
		$new_rules = run_slice($assembly_code, ['pfb' => $pfb, 'pfb_active_aliases' => []])['new_rules'];
	});
	return [$new_rules, $seen];
}

/**
 * Class and interface of every twin and user floating rule in emitted order; pfB client rules are not classified.
 *
 * @return list<array{0: string, 1: string}>
 */
function floating_classes(array $rules): array
{
	$classes = [];
	foreach ($rules as $rule) {
		if (($rule['floating'] ?? '') !== 'yes') {
			continue;
		}
		if (isset($rule['source']['network'])) {
			$classes[] = ['twin_' . match ($rule['type']) {
				'pass' => 'pass',
				'match' => 'match',
				default => 'deny',
			}, $rule['interface']];
		} elseif (str_starts_with($rule['descr'], 'U_')) {
			$classes[] = ['user_' . match ($rule['type']) {
				'pass' => 'pass',
				'match' => 'match',
				default => 'block',
			}, $rule['interface']];
		}
	}
	return $classes;
}

function class_counts(array $classes): array
{
	$counts = array_count_values(array_column($classes, 0));
	ksort($counts);
	return $counts;
}

foreach (['order_0', 'order_1', 'order_2', 'order_3', 'order_4'] as $order) {
	foreach (['on', ''] as $float) {
		$name = sprintf('C whole assembly %s float %s: twins exist per Inbound entry and sit in their pass_order tier', $order, $float === 'on' ? 'on' : 'off');
		row($name, static function () use ($order, $float): void {
			$tiers = FLOATING_TIERS[$float === 'on' ? 'on' : 'off'][$order];
			$users = ['user_block' => 1, 'user_match' => 1, 'user_pass' => 1];

			// Before: with the toggle off the block carries the user floating rules and no twin.
			[$rules] = assemble_all($order, $float, '');
			same($users, class_counts(floating_classes($rules)), 'toggle off: user floating rules only');

			[$rules, $seen] = assemble_all($order, $float, 'on');
			$entries = $float === 'on' ? ['lan,opt1'] : ['lan', 'opt1'];
			$expected = $users + ['twin_deny' => count($entries), 'twin_match' => count($entries), 'twin_pass' => count($entries)];
			ksort($expected);
			$classes = floating_classes($rules);
			same($expected, class_counts($classes), 'toggle on: one twin per Inbound entry and role, every user floating rule kept once');

			foreach (['pass', 'match', 'reject'] as $type) {
				$interfaces = array_column(array_filter($rules, static fn (array $r): bool => isset($r['source']['network']) && $r['type'] === $type), 'interface');
				sort($interfaces);
				same($entries, $interfaces, "interfaces of the {$type} twins");
			}

			// Every pair that can match the same packets keeps devel's order: a twin against any user
			// floating rule, and twins of one interface among themselves. Twins on different interfaces
			// never co-match, so the per-interface emission of 3.3 may interleave them.
			foreach ($classes as $i => [$first, $first_interface]) {
				foreach (array_slice($classes, $i + 1) as [$second, $second_interface]) {
					$twins = (int) str_starts_with($first, 'twin') + (int) str_starts_with($second, 'twin');
					if ($twins === 0 || ($twins === 2 && $first_interface !== $second_interface)) {
						continue;
					}
					if ($tiers[$second] < $tiers[$first]) {
						throw new RuntimeException(sprintf(
							'%s@%s is emitted before %s@%s, but %s evaluates %s first; emitted: %s',
							$first, $first_interface, $second, $second_interface, $order, $second,
							implode(', ', array_map(static fn (array $c): string => "{$c[0]}@{$c[1]}", $classes))
						));
					}
				}
			}

			assert_twin_trackers($rules);
			same([], array_values(array_filter($seen, static fn (string $m): bool => str_contains($m, '_self'))), 'no diagnostic about a twin bucket');
		});
	}
}

// --- D: IP page handler --------------------------------------------------------------------

/** The IP page from its settings read through the Save handler, with doubles for exit, header() and the ps listing. */
function ip_page_code(): string
{
	global $ip_page;
	$code = source_slice($ip_page, "\$pfb['iconfig'] = config_get_path(", '$pgtitle = ');
	foreach (['exit;' => 1, 'header(' => 2, "exec('/bin/ps -wx', \$result_cron);" => 1] as $needle => $expected) {
		same($expected, substr_count($code, $needle), "occurrences of {$needle} in the IP page slice");
	}
	return str_replace(
		['exit;', 'header(', "exec('/bin/ps -wx', \$result_cron);"],
		['throw new PfbTestExit();', 'pfb_test_header(', '$result_cron = array();'],
		$code
	);
}

/** A saved 3.3 IP configuration that pre-dates fw_self_outbound (the key is absent). */
function ip_seed_config(): void
{
	$GLOBALS['config_store'] = ['installedpackages/pfblockerngipsettings/config/0' => [
		'enable_dup' => '', 'enable_agg' => '', 'suppression' => 'on', 'enable_log' => '', 'ip_placeholder' => '127.1.7.7',
		'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'database_cc' => '',
		'maxmind_account' => '', 'maxmind_key' => '', 'inbound_interface' => 'lan', 'inbound_deny_action' => 'block',
		'outbound_interface' => 'opt1', 'outbound_deny_action' => 'reject', 'enable_float' => '', 'pass_order' => 'order_0',
		'autorule_suffix' => 'autorule', 'killstates' => '', 'v4suppression' => '',
	]];
}

/** Run the IP page against the $_POST the caller set. */
function ip_page_run(): array
{
	$ip_code = ip_page_code();
	$GLOBALS['ip_calls'] = ['mwexec_bg' => [], 'config' => [], 'header' => [], 'write' => []];
	$pconfig = [];
	$input_errors = [];
	$exited = false;
	$seen = diagnostics_of(static function () use ($ip_code, &$pconfig, &$input_errors, &$exited): void {
		try {
			$vars = run_slice($ip_code, ['pfb' => ['extraslog' => '/dev/null']]);
			$pconfig = $vars['pconfig'];
			$input_errors = $vars['input_errors'] ?? [];
		} catch (PfbTestExit) {
			$exited = true;
		}
	});
	return [
		'errors' => $input_errors, 'pconfig' => $pconfig, 'exited' => $exited,
		'diagnostics' => $seen, 'calls' => $GLOBALS['ip_calls'],
	];
}

/** GET the IP page: what a browser is shown from the stored configuration. */
function ip_load(): array
{
	$_POST = [];
	return ip_page_run();
}

/** Post an IP-settings Save; $omit lists POST keys a browser would not send, $fresh reseeds the stored configuration. */
function ip_save(array $post, array $omit = [], bool $fresh = true): array
{
	if ($fresh) {
		ip_seed_config();
	}
	$_POST = array_merge([
		'save' => 'Save', 'asn_reporting' => 'disabled', 'maxmind_locale' => 'fr', 'inbound_deny_action' => 'block',
		'outbound_deny_action' => 'reject', 'pass_order' => 'order_0', 'autorule_suffix' => 'autorule',
		'ip_placeholder' => '127.1.7.7', 'maxmind_account' => '', 'maxmind_key' => '', 'asn_token' => '',
		'v4suppression' => '', 'enable_dup' => '', 'enable_agg' => '', 'suppression' => '', 'enable_log' => '',
		'database_cc' => '', 'enable_float' => '', 'killstates' => '',
		'inbound_interface' => [], 'outbound_interface' => [],
	], $post);
	foreach ($omit as $key) {
		unset($_POST[$key]);
	}
	return ip_page_run();
}

const FW_SELF_ERROR = 'Apply outbound rules to firewall traffic requires at least one Inbound interface.';

row('D toggle on without a posted Inbound interface is rejected before any side effect', static function (): void {
	$result = ip_save(['fw_self_outbound' => 'on'], ['inbound_interface', 'outbound_interface']);
	check(in_array(FW_SELF_ERROR, (array) $result['errors'], true), 'expected the Inbound interface error, got ' . json_encode($result['errors']));
	same([], $result['calls']['mwexec_bg'], 'the rejected Save must not start the MaxMind conversion (locale en -> fr was requested)');
	same([], $result['calls']['config'], 'nothing is persisted');
	check(!$result['exited'], 'the handler does not redirect on a rejected Save');
	same([], $result['pconfig']['inbound_interface'], 'the re-render reads no Inbound selection the browser never posted');
	same([], $result['pconfig']['outbound_interface'], 'the re-render reads no Outbound selection the browser never posted');
	same([], $result['diagnostics'], 'the rejected Save raises no PHP diagnostic');
});

row('D toggle on with an empty or unknown Inbound selection is rejected', static function (): void {
	foreach ([[], ['bogus'], ['bogus', 'nope']] as $inbound) {
		$result = ip_save(['fw_self_outbound' => 'on', 'inbound_interface' => $inbound]);
		check(in_array(FW_SELF_ERROR, (array) $result['errors'], true), 'expected the error for ' . json_encode($inbound));
		same([], $result['calls']['config'], 'nothing persisted for ' . json_encode($inbound));
	}
});

row('D toggle on with a real Inbound interface is accepted and persisted, and Save proceeds', static function (): void {
	foreach ([['lan'], ['bogus', 'opt1']] as $inbound) {
		$result = ip_save(['fw_self_outbound' => 'on', 'inbound_interface' => $inbound]);
		same([], (array) $result['errors'], 'no input error for ' . json_encode($inbound));
		check($result['exited'], 'Save redirects after persisting');
		$saved = $result['calls']['config']['installedpackages/pfblockerngipsettings/config/0'] ?? null;
		check(is_array($saved), 'settings were written');
		same('on', $saved['fw_self_outbound'] ?? null, 'the toggle persists On');
		same(1, count($result['calls']['mwexec_bg']), 'an accepted Save still starts the requested MaxMind conversion');
	}
});

row('D toggle off needs no Inbound interface and persists off', static function (): void {
	$result = ip_save([], ['fw_self_outbound', 'inbound_interface']);
	same([], (array) $result['errors'], 'no input error');
	check($result['exited'], 'Save redirects after persisting');
	same('', $result['calls']['config']['installedpackages/pfblockerngipsettings/config/0']['fw_self_outbound'] ?? null, 'the toggle persists Off');
});

row('D the saved toggle reads back on the next page load', static function (): void {
	ip_seed_config();
	$page = ip_load();
	same('', $page['pconfig']['fw_self_outbound'], 'before: a saved 3.3 configuration without the key shows Off');
	same([], $page['diagnostics'], 'and loading it raises no PHP diagnostic');

	ip_save(['fw_self_outbound' => 'on', 'inbound_interface' => ['lan']], [], false);
	same('on', ip_load()['pconfig']['fw_self_outbound'], 'after saving On the page shows On');

	ip_save([], ['fw_self_outbound', 'inbound_interface'], false);
	same('', ip_load()['pconfig']['fw_self_outbound'], 'after unchecking and saving the page shows Off again');
});

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);
