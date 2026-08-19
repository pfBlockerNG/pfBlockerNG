<?php

declare(strict_types=1);

$GLOBALS['config'] = [];
$GLOBALS['pfb'] = [];
$GLOBALS['allowed'] = true;
define('PFB_REPO_GENERATE_HOOK', sys_get_temp_dir() . '/pfb-ca-hook-' . bin2hex(random_bytes(4)));
define('PFB_FILTER_ON_OFF', 1);
$timeout = trim((string) shell_exec('command -v timeout'));
define('PFB_PKG_TIMEOUT', escapeshellarg($timeout) . ' -s TERM -k 1 1');

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
		$cursor[$part] ??= [];
		$cursor =& $cursor[$part];
	}
	$cursor = $value;
}

function isAllowedPage(string $page): bool
{
	return $page === 'pkg_mgr_installed.php' && $GLOBALS['allowed'];
}

function is_subsystem_dirty(string $name): bool
{
	return false;
}

function pkg_version_compare(string $left, string $right): string
{
	$result = version_compare($left, $right);
	return $result < 0 ? '<' : ($result > 0 ? '>' : '=');
}

function pfb_filter(mixed $value, int $type, string $key): string
{
	return $value === 'on' ? 'on' : '';
}

$extra = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
$software = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_software.inc';
require_once $extra;
require_once $software;

$failures = 0;
function row(string $name, callable $check): void
{
	global $failures;
	try { $check(); echo "PASS {$name}\n"; }
	catch (Throwable $error) { $failures++; echo "FAIL {$name}: {$error->getMessage()}\n"; }
}
function check(bool $condition, string $message): void
{
	if (!$condition) { throw new RuntimeException($message); }
}
function same(mixed $expected, mixed $actual, string $message): void
{
	if ($expected !== $actual) { throw new RuntimeException($message); }
}

$root = sys_get_temp_dir() . '/pfb_pkg_ca_delegate_3_3_' . bin2hex(random_bytes(4));
mkdir($root, 0700, true);
$log = $root . '/calls.log';
$hook = PFB_REPO_GENERATE_HOOK;
file_put_contents($hook, "#!/bin/sh\nprintf '%s\\n' \"\$1\" >> " . escapeshellarg($log) . "\n[ \"\${PFB_HOOK_SLEEP:-0}\" = 1 ] && sleep 3\nexit \${PFB_HOOK_STATUS:-0}\n");
chmod($hook, 0700);

row('delegate validates actions and executes the installed hook', static function () use ($log): void {
	check(pfb_pkgconf_ca_command('ca-sync'), 'sync succeeds');
	check(pfb_pkgconf_ca_command('ca-revoke'), 'revoke succeeds');
	check(!pfb_pkgconf_ca_command('ca-state'), 'state is not an action');
	same(file_get_contents($log), "ca-sync\nca-revoke\n", 'hook calls');
	putenv('PFB_HOOK_STATUS=7');
	check(!pfb_pkgconf_ca_command('ca-sync'), 'hook failure propagates');
	putenv('PFB_HOOK_STATUS');
});

row('delegate bounds a hanging hook', static function (): void {
	putenv('PFB_HOOK_SLEEP=1');
	$started = microtime(true);
	check(!pfb_pkgconf_ca_command('ca-sync'), 'timeout status propagates');
	check(microtime(true) - $started < 2.5, 'hook timeout is bounded');
	putenv('PFB_HOOK_SLEEP');
});

@unlink($hook);
@unlink($log);
@rmdir($root);
echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURES\n";
exit($failures === 0 ? 0 : 1);
