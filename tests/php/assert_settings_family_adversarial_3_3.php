<?php

declare(strict_types=1);

$GLOBALS['config'] = [];
$GLOBALS['pfb'] = [];
$GLOBALS['write_config_calls'] = [];
$GLOBALS['dump_xml_config_calls'] = 0;
$GLOBALS['parse_xml_config_calls'] = 0;

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

function write_config(string $message): void
{
	$GLOBALS['write_config_calls'][] = $message;
}

function dump_xml_config(array $data, string $root): string
{
	$GLOBALS['dump_xml_config_calls']++;
	$document = new SimpleXMLElement('<' . $root . '/>');
	foreach ($data as $key => $value) {
		$document->addChild((string) $key, (string) $value);
	}
	return (string) $document->asXML();
}

function parse_xml_config(string $path, string $root): array|int
{
	$GLOBALS['parse_xml_config_calls']++;
	$document = @simplexml_load_file($path, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOBLANKS);
	if ($document === false || $document->getName() !== $root) {
		return -1;
	}
	return ['family' => (string) ($document->family ?? ''), 'payload' => (string) ($document->payload ?? '')];
}

$sourceRoot = getenv('PFB_SOURCE_ROOT');
$sourceRoot = is_string($sourceRoot) && $sourceRoot !== '' ? $sourceRoot : dirname(__DIR__, 2);
$extra = $sourceRoot . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
require_once $extra;

$root = sys_get_temp_dir() . '/pfb_settings_family_adversarial_' . bin2hex(random_bytes(5));
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

function reset_fixture(): void
{
	$GLOBALS['config'] = [
		'system' => ['hostname' => 'unchanged'],
		'installedpackages' => [
			'pfblockerng' => ['config' => ['0' => ['credential' => 'live']]],
			'otherpackage' => ['config' => ['untouched' => 'yes']],
		],
	];
	$GLOBALS['write_config_calls'] = [];
	$GLOBALS['dump_xml_config_calls'] = 0;
	$GLOBALS['parse_xml_config_calls'] = 0;
	global $root;
	foreach (glob($root . '/*') ?: [] as $path) {
		is_dir($path) && !is_link($path) ? rmdir($path) : @unlink($path);
	}
}

function write_slot(string $family, array $owned): void
{
	global $root;
	$document = new SimpleXMLElement('<pfblockerng-settings/>');
	$document->addChild('family', $family);
	$document->addChild('payload', base64_encode(serialize($owned)));
	file_put_contents($root . '/settings-3.3.xml', $document->asXML());
	chmod($root . '/settings-3.3.xml', 0600);
}

try {
	$hostile = [];
	$hostile['object'] = ['pfblockerng' => ['object' => new stdClass()]];
	$cycle = [];
	$cycle['self'] =& $cycle;
	$hostile['cycle'] = ['pfblockerng' => $cycle];
	$hostile['wrong family'] = ['family' => '4.0', 'owned' => ['pfblockerng' => ['config' => []]]];
	$hostile['foreign section'] = ['family' => '3.3', 'owned' => ['otherpackage' => ['config' => []]]];
	foreach ($hostile as $name => $fixture) {
		reset_fixture();
		$family = $fixture['family'] ?? '3.3';
		$owned = $fixture['owned'] ?? $fixture;
		write_slot($family, $owned);
		$before = $GLOBALS['config'];
		check(!pfb_settings_family_replace('3.3'), $name . ' must fail');
		same($before, $GLOBALS['config'], $name . ' mutated live config');
		same([], $GLOBALS['write_config_calls'], $name . ' wrote live config');
	}

	reset_fixture();
	check(pfb_settings_family_save('3.3'), 'native save');
	check($GLOBALS['dump_xml_config_calls'] > 0, 'native save must call dump_xml_config');
	$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'changed';
	check(pfb_settings_family_replace('3.3'), 'native restore');
	check($GLOBALS['parse_xml_config_calls'] > 0, 'native restore must call parse_xml_config');
	same('live', config_get_path('installedpackages/pfblockerng/config/0/credential'), 'native restore value');
	same(['pfBlockerNG: restore settings family'], $GLOBALS['write_config_calls'], 'native restore write');

	reset_fixture();
	check(pfb_settings_family_save('3.3'), 'corrupt fixture save');
	file_put_contents($root . '/settings-3.3.xml', '<broken>');
	chmod($root . '/settings-3.3.xml', 0600);
	$before = $GLOBALS['config'];
	$GLOBALS['write_config_calls'] = [];
	check(!pfb_settings_family_replace('3.3'), 'corrupt native slot must fail');
	same($before, $GLOBALS['config'], 'corrupt native slot mutated config');
	same([], $GLOBALS['write_config_calls'], 'corrupt native slot wrote config');

	$install = $sourceRoot . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
	$source = php_strip_whitespace($install);
	check($source !== '', 'installer source readable');
	$capture = strpos($source, '$pfb_installed_family = pfb_install_settings_family_capture_restore();');
	$workBegin = strpos($source, '$g[\'pfblockerng_install\'] = TRUE;');
	$workEnd = strrpos($source, 'update_status(" no changes required ... done.\\n");');
	$finalize = strpos($source, 'pfb_install_settings_family_finalize();');
	$finalWrite = strrpos($source, "write_config('[pfBlockerNG] Save installation settings');");
	check($capture !== false && $workBegin !== false && $workEnd !== false && $finalize !== false && $finalWrite !== false, 'installer order markers present');
	check($capture < $workBegin && $workBegin < $workEnd && $workEnd < $finalize && $finalize < $finalWrite, 'installer order must protect existing work');
	same(1, substr_count($source, 'pfb_install_settings_family_finalize();'), 'finalize count');
	echo "PASS hostile slots fail closed and installer order is protected\nALL PASS\n";
	$exit = 0;
} catch (Throwable $error) {
	echo "FAIL adversarial settings-family assertions: {$error->getMessage()}\n";
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
