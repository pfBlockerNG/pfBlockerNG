<?php

declare(strict_types=1);

$GLOBALS['config'] = [];
$GLOBALS['config_disk'] = [];
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
	$cursor =& $GLOBALS['config'];
	foreach (explode('/', trim($path, '/')) as $part) {
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

function config_read_file(bool $unused_defaults = false, bool $unused_merge = false): bool
{
	$GLOBALS['config'] = $GLOBALS['config_disk'];
	return true;
}

function write_config(string $message): void
{
	$GLOBALS['write_config_calls'][] = $message;
	$GLOBALS['config_disk'] = $GLOBALS['config'];
}

function pfb_global(): void
{
	config_read_file(false, true);
	$GLOBALS['pfb']['config'] = config_get_path('installedpackages/pfblockerng/config/0', []);
}

$extra = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
require_once $extra;

$root = sys_get_temp_dir() . '/pfb_settings_family_replace_' . bin2hex(random_bytes(5));
mkdir($root, 0700, true);
$GLOBALS['pfb']['dbdir'] = $root;

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

try {
	$live = [
		'pfblockerng' => ['config' => ['0' => ['credential' => 'live-4.1', 'pfb_keep' => 'on']]],
		'otherpackage' => ['config' => ['untouched' => 'yes']],
	];
	$GLOBALS['config_disk'] = ['installedpackages' => $live];
	pfb_global();
	$legacy = ['pfblockerng' => ['config' => ['0' => ['credential' => 'legacy-3.3', 'pfb_keep' => 'off']]]];
	$document = new SimpleXMLElement('<pfblockerng-settings/>');
	$document->addChild('family', '3.3');
	$document->addChild('payload', base64_encode(serialize($legacy)));
	file_put_contents($root . '/settings-3.3.xml', $document->asXML());
	chmod($root . '/settings-3.3.xml', 0600);

	check(pfb_settings_family_replace('3.3'), 'replace succeeds');
	same('legacy-3.3', config_get_path('installedpackages/pfblockerng/config/0/credential'), 'pre-reload restore');
	same(['pfBlockerNG: restore settings family'], $GLOBALS['write_config_calls'], 'exact restore write message');
	pfb_global();
	same('legacy-3.3', config_get_path('installedpackages/pfblockerng/config/0/credential'), 'post-reload restore');
	same('legacy-3.3', $GLOBALS['pfb']['config']['credential'], 'pfb_global source reload');

	$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
	check(is_string($source) && str_contains($source, 'function pfb_global()'), 'real pfb_global source present');
	$start = strpos($source, 'function pfb_global()');
	check(strpos($source, 'config_read_file(false, true);', $start) !== false, 'real pfb_global reload retained');
	echo "PASS replace persistence and pfb_global reload\nALL PASS\n";
	$exit = 0;
} catch (Throwable $error) {
	echo "FAIL replace persistence: {$error->getMessage()}\n";
	$exit = 1;
}

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
exit($exit);
