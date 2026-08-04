<?php

declare(strict_types=1);

/**
 * Standalone settings-family bridge assertions for the release/3.3 source tree.
 * This runner deliberately avoids PHPUnit so release-branch CI can execute it directly.
 */

$GLOBALS['config'] = [];
$GLOBALS['pfb'] = [];
$GLOBALS['write_config_calls'] = [];

function config_get_path(string $path, mixed $default = null): mixed
{
	$value = $GLOBALS['config'];
	foreach (explode('/', trim($path, '/')) as $part) {
		if (!is_array($value) || !array_key_exists($part, $value)) {
			return $default;
		}
		$value = $value[$part];
	}
	return $value;
}

function config_set_path(string $path, mixed $value): void
{
	$parts = explode('/', trim($path, '/'));
	$cursor =& $GLOBALS['config'];
	foreach ($parts as $part) {
		if (!is_array($cursor)) {
			$cursor = [];
		}
		if (!array_key_exists($part, $cursor) || !is_array($cursor[$part])) {
			$cursor[$part] = [];
		}
		$cursor =& $cursor[$part];
	}
	$cursor = $value;
}

function write_config(string $message): void
{
	$GLOBALS['write_config_calls'][] = $message;
}

$extra = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
if (is_file($extra)) {
	require_once $extra;
}

$failures = 0;
$root = sys_get_temp_dir() . '/pfb_settings_family_3_3_' . bin2hex(random_bytes(5));
mkdir($root, 0700, true);
$GLOBALS['pfb']['dbdir'] = $root;

function row(string $name, callable $check): void
{
	global $failures;
	try {
		$check();
		echo "PASS {$name}\n";
	} catch (Throwable $error) {
		$failures++;
		echo "FAIL {$name}: {$error->getMessage()}\n";
	}
}

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

function same(mixed $expected, mixed $actual, string $message): void
{
	if ($expected !== $actual) {
		throw new RuntimeException($message);
	}
}

function reset_fixture(array $installed): void
{
	$GLOBALS['config'] = [
		'system' => ['hostname' => 'unchanged'],
		'installedpackages' => $installed,
	];
	$GLOBALS['write_config_calls'] = [];
	global $root;
	foreach (glob($root . '/*') ?: [] as $path) {
		is_dir($path) && !is_link($path) ? rmdir($path) : @unlink($path);
	}
	}

function slot(string $family): string
{
	global $root;
	return $root . '/settings-' . $family . '.xml';
}

function payload(string $family): array
{
	$xml = simplexml_load_file(slot($family), 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOBLANKS);
	check($xml !== false, 'slot XML parses');
	$decoded = base64_decode((string) $xml->payload, true);
	check($decoded !== false, 'slot payload decodes');
	$owned = @unserialize($decoded, ['allowed_classes' => false]);
	check(is_array($owned), 'slot payload is array');
	return $owned;
}

row('missing marker bootstraps 3.3', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['legacy' => 'yes']]]]);
	same('3.3', pfb_settings_family_current(), 'missing marker must be 3.3');
});

row('NULL marker bootstraps 3.3', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['settings_family' => null]]]]);
	same('3.3', pfb_settings_family_current(), 'NULL marker must be 3.3');
});

row('empty marker bootstraps 3.3', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['settings_family' => '']]]]);
	same('3.3', pfb_settings_family_current(), 'empty marker must be 3.3');
});

row('explicit 3.3, 4.0, and 4.1 markers accepted', static function (): void {
	foreach (['3.3', '4.0', '4.1'] as $family) {
		reset_fixture(['pfblockerng' => ['config' => ['0' => ['settings_family' => $family]]]]);
		same($family, pfb_settings_family_current(), 'explicit marker accepted');
	}
});

row('invalid marker type/value rejected', static function (): void {
	foreach ([['settings_family' => 3.3], ['settings_family' => '3.2'], ['settings_family' => '4.2']] as $marker) {
		reset_fixture(['pfblockerng' => ['config' => ['0' => $marker]]]);
		$thrown = false;
		try {
			pfb_settings_family_current();
		} catch (Throwable) {
			$thrown = true;
		}
		check($thrown, 'invalid marker must throw');
	}
});

row('marker write uses minimal PfbConfig boundary', static function (): void {
	reset_fixture([]);
	check(PfbConfig::read('gen/settings_family') === null, 'missing gateway read');
	PfbConfig::writeSystem('gen/settings_family', '3.3');
	same('3.3', config_get_path('installedpackages/pfblockerng/config/0/settings_family'), 'marker write');
	$thrown = false;
	try {
		PfbConfig::read('gen/unknown');
	} catch (Throwable) {
		$thrown = true;
	}
	check($thrown, 'unknown gateway key must throw');
});

row('source save captures exact owned sections only', static function (): void {
	$owned = [
		'pfblockerng' => ['config' => ['0' => ['credential' => 'secret-canary', 'empty' => [], 'nested' => ['order' => 'one']]]],
		'pfblockerngglobal' => ['unknown' => ['empty' => '', 'order' => 'two']],
	];
	reset_fixture($owned + ['otherpackage' => ['config' => ['untouched' => 'yes']]]);
	check(pfb_settings_family_save('4.1'), 'source save');
	same($owned, payload('4.1'), 'owned payload exact');
	check(!array_key_exists('otherpackage', payload('4.1')), 'foreign section excluded');
});

row('exact 3.3 target restore preserves foreign config', static function (): void {
	$owned = ['pfblockerng' => ['config' => ['0' => ['credential' => 'secret-canary', 'empty' => []]]]];
	reset_fixture($owned + ['otherpackage' => ['config' => ['untouched' => 'yes']]]);
	check(pfb_settings_family_save('3.3'), 'target save');
	$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'changed';
	$GLOBALS['config']['installedpackages']['otherpackage']['config']['untouched'] = 'changed';
	check(pfb_settings_family_replace('3.3'), 'target restore');
	same($owned['pfblockerng'], $GLOBALS['config']['installedpackages']['pfblockerng'], 'owned restore');
	same('changed', $GLOBALS['config']['installedpackages']['otherpackage']['config']['untouched'], 'foreign preserved');
	same('unchanged', $GLOBALS['config']['system']['hostname'], 'system preserved');
});

row('missing target slot is no-op', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['credential' => 'live']]]]);
	$before = $GLOBALS['config'];
	check(pfb_settings_family_replace('3.3'), 'missing target no-op');
	same($before, $GLOBALS['config'], 'missing target mutation');
});

row('corrupt XML and bad base64 fail before mutation', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['credential' => 'live']]]]);
	check(pfb_settings_family_save('3.3'), 'fixture save');
	file_put_contents(slot('3.3'), '<bad>');
	$before = $GLOBALS['config'];
	check(!pfb_settings_family_replace('3.3'), 'corrupt XML rejected');
	same($before, $GLOBALS['config'], 'corrupt XML mutation');
	file_put_contents(slot('3.3'), '<pfblockerng-settings><family>3.3</family><payload>not-base64!</payload></pfblockerng-settings>');
	chmod(slot('3.3'), 0600);
	check(!pfb_settings_family_replace('3.3'), 'bad base64 rejected');
	same($before, $GLOBALS['config'], 'bad base64 mutation');
});

row('object, cycle, wrong-family, and foreign payloads fail closed', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['credential' => 'live']]]]);
	$write = static function (string $family, array $owned): void {
		$xml = '<pfblockerng-settings><family>' . htmlspecialchars($family, ENT_XML1) . '</family><payload>'
			. base64_encode(serialize($owned)) . '</payload></pfblockerng-settings>';
		file_put_contents(slot('3.3'), $xml);
		chmod(slot('3.3'), 0600);
	};
	$object = ['pfblockerng' => ['object' => new stdClass()]];
	$write('3.3', $object);
	check(!pfb_settings_family_replace('3.3'), 'object rejected');
	$cycle = [];
	$cycle['self'] =& $cycle;
	$write('3.3', ['pfblockerng' => $cycle]);
	check(!pfb_settings_family_replace('3.3'), 'cycle rejected');
	$write('4.0', ['pfblockerng' => ['config' => []]]);
	check(!pfb_settings_family_replace('3.3'), 'wrong family rejected');
	$write('3.3', ['otherpackage' => ['config' => []]]);
	check(!pfb_settings_family_replace('3.3'), 'foreign section rejected');
});

row('unsafe root, owner, mode, type, and symlink predicates reject', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['live' => 'yes']]]]);
	$GLOBALS['pfb']['settings_family_expected_owner'] = (function_exists('posix_geteuid') ? posix_geteuid() : 0) + 1;
	check(!pfb_settings_family_save('3.3'), 'owner mismatch rejected');
	unset($GLOBALS['pfb']['settings_family_expected_owner']);
	chmod($GLOBALS['pfb']['dbdir'], 0777);
	check(!pfb_settings_family_save('3.3'), 'group-world root rejected');
	chmod($GLOBALS['pfb']['dbdir'], 0700);
	check(pfb_settings_family_save('3.3'), 'safe root save');
	chmod(slot('3.3'), 0644);
	check(!pfb_settings_family_save('3.3'), 'unsafe slot mode rejected');
	chmod(slot('3.3'), 0600);
	unlink(slot('3.3'));
	mkdir(slot('3.3'));
	check(!pfb_settings_family_replace('3.3'), 'directory slot rejected');
	rmdir(slot('3.3'));
	file_put_contents($GLOBALS['pfb']['dbdir'] . '/target', 'x');
	symlink($GLOBALS['pfb']['dbdir'] . '/target', slot('3.3'));
	check(!pfb_settings_family_replace('3.3'), 'symlink slot rejected');
	unlink(slot('3.3'));
});

row('no owned settings is no-op without inventing slot', static function (): void {
	reset_fixture(['otherpackage' => ['config' => ['untouched' => 'yes']]]);
	check(pfb_settings_family_save('3.3'), 'no owned save');
	check(!file_exists(slot('3.3')), 'no owned slot');
});

row('unknown fields, nesting, empty values, order, and credential survive', static function (): void {
	$owned = [
		'pfblockerng' => ['config' => ['0' => ['first' => 'one', 'empty' => '', 'credential' => 'secret-canary', 'nested' => ['second' => [], 'third' => ['deep' => null]]]]],
	];
	reset_fixture($owned);
	check(pfb_settings_family_save('3.3'), 'unknown save');
	$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0'] = ['changed' => true];
	check(pfb_settings_family_replace('3.3'), 'unknown restore');
	same($owned, $GLOBALS['config']['installedpackages'], 'unknown exact restore');
});

row('atomic overwrite leaves no temp residue', static function (): void {
	reset_fixture(['pfblockerng' => ['config' => ['0' => ['value' => 'one']]]]);
	check(pfb_settings_family_save('3.3'), 'first atomic save');
	$first = file_get_contents(slot('3.3'));
	$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['value'] = 'two';
	check(pfb_settings_family_save('3.3'), 'second atomic save');
	check($first !== file_get_contents(slot('3.3')), 'overwrite changed bytes');
	$temporary = array_filter(scandir($GLOBALS['pfb']['dbdir']) ?: [], static fn (string $entry): bool => str_starts_with($entry, '.settings-'));
	same([], array_values($temporary), 'temporary residue');
});

row('install helper order is save source, restore 3.3, existing installer, record 3.3', static function (): void {
	check(function_exists('pfb_install_settings_family_capture_restore'), 'capture helper exists');
	check(function_exists('pfb_install_settings_family_finalize'), 'finalize helper exists');
	$order = [];
	$source = pfb_install_settings_family_capture_restore(
		static function () use (&$order): string { $order[] = 'current'; return '4.1'; },
		static function (string $family) use (&$order): bool { $order[] = 'save:' . $family; return true; },
		static function (string $family) use (&$order): bool { $order[] = 'replace:' . $family; return true; }
	);
	pfb_install_settings_family_finalize(
		static function (string $family) use (&$order): bool { $order[] = 'record:' . $family; return true; }
	);
	same('4.1', $source, 'source returned');
	same(['current', 'save:4.1', 'replace:3.3', 'record:3.3'], $order, 'helper order');
});

row('installer call placement is structural', static function (): void {
	$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
	check($source !== '', 'installer source readable');
	$capture = strpos($source, '$pfb_installed_family = pfb_install_settings_family_capture_restore();');
	$refresh = strpos($source, 'pfb_global();', $capture === false ? 0 : $capture + 1);
	$finalize = strpos($source, 'pfb_install_settings_family_finalize();');
	$write = strrpos($source, "write_config('[pfBlockerNG] Save installation settings');");
	check($capture !== false && $refresh !== false && $finalize !== false && $write !== false, 'installer hooks present');
	check($capture < $refresh && $refresh < $finalize && $finalize < $write, 'installer hook order');
});

function remove_tree(string $path): void
{
	if (!is_dir($path)) {
		return;
	}
	foreach (scandir($path) ?: [] as $entry) {
		if ($entry === '.' || $entry === '..') {
			continue;
		}
		$child = $path . '/' . $entry;
		is_dir($child) && !is_link($child) ? remove_tree($child) : @unlink($child);
	}
	@rmdir($path);
}

remove_tree($root);
echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURES\n";
exit($failures === 0 ? 0 : 1);
