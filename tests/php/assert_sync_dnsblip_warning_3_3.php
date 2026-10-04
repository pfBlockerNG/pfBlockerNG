<?php

declare(strict_types=1);

/*
 * issue #3442 (release/3.3 backport of #3441): the Sync page warns, and its help says, when pfSense HA
 * copies the pfB_DNSBLIP_v4 auto rules to a peer whose DNSBL settings are excluded from pfBlockerNG sync.
 *
 * Standalone runner: release/3.3 ships no PHPUnit and no UI tier, so it eval()s the PRODUCTION predicate
 * and the Sync/DNSBL page slices straight out of the shipped sources, with pfSense platform doubles.
 *   A  predicate matrix                  B  Sync page warning wiring, one stored input flipped per row
 *   C  help text built by the Sync and DNSBL page code
 *
 * NOT covered: live pfSense rendering (print_info_box markup, HA sync behaviour on a real peer).
 */

$root = dirname(__DIR__, 2);
$inc = (string) file_get_contents($root . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
$sync = (string) file_get_contents($root . '/src/usr/local/www/pfblockerng/pfblockerng_sync.php');
$dnsbl = (string) file_get_contents($root . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
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

function contains(string $needle, mixed $haystack, string $message): void
{
	if (!is_string($haystack) || !str_contains($haystack, $needle)) {
		throw new RuntimeException($message . ': expected to contain ' . var_export($needle, true) . ', got ' . var_export($haystack, true));
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

// --- behavioural doubles -------------------------------------------------------------------

if (!function_exists('gettext')) {
	function gettext(string $s): string
	{
		return $s;
	}
}

if (!function_exists('display_top_tabs')) {
	function display_top_tabs(...$args): void
	{
	}
}

if (!function_exists('print_info_box')) {
	function print_info_box($msg, $class = 'alert-warning', $btn = '')
	{
		$GLOBALS['info_boxes'][] = [$msg, $class];
	}
}

if (!function_exists('config_get_path')) {
	function config_get_path(string $path, mixed $default = null): mixed
	{
		$node = $GLOBALS['test_config'];
		foreach (explode('/', $path) as $segment) {
			if (!is_array($node) || !array_key_exists($segment, $node)) {
				return $default;
			}
			$node = $node[$segment];
		}
		return $node;
	}
}

/** Records every form element the page code builds, with its constructor args and help text. */
class Recording_Element
{
	public array $args;
	public mixed $help = NULL;

	public function __construct(...$args)
	{
		$this->args = $args;
		$GLOBALS['form_elements'][] = $this;
	}

	public function setHelp($help, ...$rest): static
	{
		$this->help = $help;
		return $this;
	}

	public function addInput($element)
	{
		return $element;
	}

	public function add($element)
	{
		return $element;
	}

	public function __call(string $name, array $arguments): static
	{
		return $this;
	}
}

class Form extends Recording_Element
{
}

class Form_Section extends Recording_Element
{
}

class Form_StaticText extends Recording_Element
{
}

class Form_Select extends Recording_Element
{
}

class Form_Input extends Recording_Element
{
}

class Form_Checkbox extends Recording_Element
{
}

function reset_state(array $config = []): void
{
	$GLOBALS['info_boxes'] = [];
	$GLOBALS['form_elements'] = [];
	$GLOBALS['test_config'] = $config;
}

// --- A: the production predicate -----------------------------------------------------------

$predicate_error = null;
try {
	eval(function_source($inc, 'pfblockerng_sync_dnsblip_mismatch'));
} catch (Throwable $error) {
	$predicate_error = $error->getMessage();
}

// (syncinterfaces, synconchanges, enable, dnsbl, dnsbl_ip_action, hasync_rules)
$base = ['on', 'auto', 'on', 'on', 'Deny_Both', 'on'];

/** The base arguments with the given positions replaced. */
function with_args(array $base, array $override): array
{
	foreach ($override as $position => $value) {
		$base[$position] = $value;
	}
	return $base;
}

$matrix = [
	['base: every condition holds, Deny_Both', $base, true],
	['sync target manual', with_args($base, [1 => 'manual']), true],
];
foreach (['Deny_Both', 'Deny_Inbound', 'Deny_Outbound', 'Permit_Both', 'Permit_Inbound', 'Permit_Outbound', 'Match_Both', 'Match_Inbound', 'Match_Outbound'] as $action) {
	$matrix[] = ["rule-generating action {$action}", with_args($base, [4 => $action]), true];
}
foreach ([
	'Alias_Deny' => 'Alias_Deny',
	'Alias_Permit' => 'Alias_Permit',
	'Alias_Match' => 'Alias_Match',
	'Alias_Native' => 'Alias_Native',
	'Disabled' => 'Disabled',
	'invalid Deny_Everything' => 'Deny_Everything',
	'foreign unbound' => 'unbound',
	'NULL' => null,
	'empty string' => '',
	'array' => ['Deny_Both'],
] as $label => $action) {
	$matrix[] = ["rule-less action {$label}", with_args($base, [4 => $action]), false];
}
$matrix[] = ['syncinterfaces empty string', with_args($base, [0 => '']), false];
$matrix[] = ['syncinterfaces NULL', with_args($base, [0 => null]), false];
$matrix[] = ["synconchanges 'disabled'", with_args($base, [1 => 'disabled']), false];
$matrix[] = ['synconchanges empty string', with_args($base, [1 => '']), false];
$matrix[] = ["synconchanges 'AUTO'", with_args($base, [1 => 'AUTO']), false];
$matrix[] = ["synconchanges ['auto']", with_args($base, [1 => ['auto']]), false];
$matrix[] = ['enable empty string', with_args($base, [2 => '']), false];
$matrix[] = ["enable 'ON'", with_args($base, [2 => 'ON']), false];
$matrix[] = ['dnsbl empty string', with_args($base, [3 => '']), false];
$matrix[] = ['hasync NULL', with_args($base, [5 => null]), false];
$matrix[] = ["hasync 'ON'", with_args($base, [5 => 'ON']), false];
$matrix[] = ['hasync TRUE', with_args($base, [5 => true]), false];

foreach ($matrix as [$label, $args, $expected]) {
	row("A {$label}", static function () use ($args, $expected, $predicate_error): void {
		check($predicate_error === null, (string) $predicate_error);
		same($expected, pfblockerng_sync_dnsblip_mismatch(...$args), 'pfblockerng_sync_dnsblip_mismatch(' . json_encode($args) . ')');
	});
}

// --- B: Sync page warning wiring -----------------------------------------------------------

function all_true_config(): array
{
	return [
		'installedpackages' => [
			'pfblockerngsync' => ['config' => [0 => ['syncinterfaces' => 'on', 'varsynconchanges' => 'auto', 'varsynctimeout' => '150']]],
			'pfblockerng' => ['config' => [0 => ['enable_cb' => 'on']]],
			'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => 'on', 'action' => 'Deny_Both']]],
		],
		'hasync' => ['synchronizerules' => 'on'],
	];
}

/** Run the Sync page code between its settings read and the form with the given stored config. */
function sync_page_info_boxes(array $config): array
{
	global $sync;
	reset_state($config);
	$code = source_slice($sync, "\$pfb['sconfig'] = config_get_path(", '// Select field options')
		. source_slice($sync, 'display_top_tabs($tab_array, true);', '$form = new Form(');
	// The runtime mirror is already off, as pfb_global() leaves it when the DNSBL VIPs are invalid.
	run_slice($code, ['pfb' => ['enable' => 'on', 'dnsbl' => '', 'dnsbl_ip' => 'Disabled'], 'tab_array' => []]);
	return $GLOBALS['info_boxes'];
}

function describe_boxes(array $boxes): string
{
	return json_encode($boxes, JSON_UNESCAPED_SLASHES) ?: '';
}

row('B1 every stored input on: one warning naming the peer, the alias and the remedy', static function (): void {
	$boxes = sync_page_info_boxes(all_true_config());
	same(1, count($boxes), 'info boxes shown (' . describe_boxes($boxes) . ')');
	same('warning', $boxes[0][1], 'info box class');
	foreach ([
		'DNSBL IP rules may be skipped on the High Availability peer',
		'pfB_DNSBLIP_v4',
		'Unresolvable alias',
		'Enable DNSBL with the same DNSBL IP settings on both nodes',
		'untick "Disable General/IP/DNSBL tab settings sync"',
	] as $needle) {
		contains($needle, $boxes[0][0], 'warning text');
	}
});

$flips = [
	'B2 hasync rule sync off (key absent)' => static function (array &$config): void {
		unset($config['hasync']);
	},
	'B3 syncinterfaces unticked' => static function (array &$config): void {
		$config['installedpackages']['pfblockerngsync']['config'][0]['syncinterfaces'] = '';
	},
	'B4 pfBlockerNG sync disabled' => static function (array &$config): void {
		$config['installedpackages']['pfblockerngsync']['config'][0]['varsynconchanges'] = 'disabled';
	},
	'B5 pfBlockerNG enable_cb off' => static function (array &$config): void {
		$config['installedpackages']['pfblockerng']['config'][0]['enable_cb'] = '';
	},
	'B6 DNSBL off' => static function (array &$config): void {
		$config['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_dnsbl'] = '';
	},
	'B7 DNSBL IP action Alias_Deny creates no rule' => static function (array &$config): void {
		$config['installedpackages']['pfblockerngdnsblsettings']['config'][0]['action'] = 'Alias_Deny';
	},
];
foreach ($flips as $name => $flip) {
	row("{$name}: no warning", static function () use ($flip): void {
		$before = sync_page_info_boxes(all_true_config());
		same(1, count($before), 'before-state: warnings with every stored input on (' . describe_boxes($before) . ')');

		$config = all_true_config();
		$flip($config);
		$after = sync_page_info_boxes($config);
		same(0, count($after), 'warnings after flipping one stored input (' . describe_boxes($after) . ')');
	});
}

// --- C: help text through the page code ----------------------------------------------------

row('C1 Sync tab checkbox help names the HA requirement and the alias', static function (): void {
	global $sync;
	reset_state();
	run_slice(
		source_slice($sync, "\$form = new Form('Save XMLRPC sync settings');", "\$section = new Form_Section('XMLRPC Replication Targets');"),
		[
			'pconfig' => ['varsynconchanges' => 'auto', 'varsynctimeout' => 150, 'syncinterfaces' => 'on'],
			'options_varsynconchanges' => ['disabled' => 'Do not sync this package configuration', 'auto' => 'Sync to configured system backup server', 'manual' => 'Sync to host(s) defined below'],
		],
	);
	$checkbox = null;
	foreach ($GLOBALS['form_elements'] as $element) {
		if ($element instanceof Form_Checkbox && ($element->args[0] ?? null) === 'syncinterfaces') {
			$checkbox = $element;
		}
	}
	check($checkbox !== null, "the page built no Form_Checkbox 'syncinterfaces'");
	contains("tab customizations will not be sync'd", $checkbox->help, 'before-state: the original help sentence survives');
	contains('enable DNSBL with the same DNSBL IP settings on both nodes', $checkbox->help, 'syncinterfaces help');
	contains('pfB_DNSBLIP_v4', $checkbox->help, 'syncinterfaces help');
});

row('C2 DNSBL tab DNSBL IPs note points at the Sync tab for HA pairs', static function (): void {
	global $dnsbl;
	reset_state();
	run_slice(source_slice($dnsbl, "\$section = new Form_Section('DNSBL IPs');", '$list_action_text = '), []);
	$note = null;
	foreach ($GLOBALS['form_elements'] as $element) {
		if ($element instanceof Form_StaticText) {
			$note = $element;
		}
	}
	check($note !== null, 'the DNSBL IPs section built no Form_StaticText');
	contains('configure DNSBL IP identically on both nodes', $note->args[1] ?? null, 'DNSBL IPs note');
	contains('Sync Tab', $note->args[1] ?? null, 'DNSBL IPs note');
});

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);
