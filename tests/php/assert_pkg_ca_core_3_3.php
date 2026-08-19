<?php

declare(strict_types=1);

$GLOBALS['config'] = [];
$GLOBALS['pfb'] = [];
$GLOBALS['allowed'] = true;
$GLOBALS['dirty'] = false;
$GLOBALS['notices'] = [];
define('PFB_FILTER_ON_OFF', 1);

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
	return $name === 'pkg' && $GLOBALS['dirty'];
}

function pkg_version_compare(string $left, string $right): string
{
	return version_compare($left, $right);
}

function pfb_filter(mixed $value, int $type, string $key): string
{
	return $value === 'on' ? 'on' : '';
}

function file_notice(mixed ...$args): void
{
	$GLOBALS['notices'][] = $args;
}

$extra = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
$software = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_software.inc';
require_once $extra;
require_once $software;

$failures = 0;
$root = sys_get_temp_dir() . '/pfb_pkg_ca_3_3_' . bin2hex(random_bytes(5));
mkdir($root . '/certs', 0700, true);
putenv("PFB_UPGRADE_LOCK={$root}/upgrade.lock");
$hash = $root . '/certs/hash.0';
file_put_contents($hash, 'x');
$GLOBALS['pfb']['dbdir'] = $root;
$bundle = $root . '/bundle.pem';
file_put_contents($bundle, "CA\n");
$pkgconf = $root . '/pkg.conf';
$base = "PKG_ENV {\n\tSSL_CA_CERT_FILE=/tmp/bundle.pem\n\tOTHER=value\n}\nTAIL\n";

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
		throw new RuntimeException($message . ' expected=' . var_export($expected, true) . ' actual=' . var_export($actual, true));
	}
}

row('config gateway registers consent and preserves settings family', static function (): void {
	$GLOBALS['config'] = [];
	same(null, PfbConfig::read('gen/pfb_pkg_ca_consent'), 'absent consent');
	PfbConfig::writeSystem('gen/pfb_pkg_ca_consent', 'on');
	same('on', PfbConfig::read('gen/pfb_pkg_ca_consent'), 'stored consent');
	check(pfb_pkg_ca_consent_enabled(), 'consent accessor');
	PfbConfig::writeSystem('gen/pfb_pkg_ca_consent', '');
	check(!pfb_pkg_ca_consent_enabled(), 'off accessor');
	PfbConfig::writeSystem('gen/settings_family', '3.3');
	same('3.3', PfbConfig::read('gen/settings_family'), 'family seam');
	foreach ([['gen/pfb_pkg_ca_consent', 'yes'], ['gen/pfb_pkg_ca_consent', null], ['gen/unknown', 'on']] as $bad) {
		$thrown = false;
		try {
			PfbConfig::writeSystem($bad[0], $bad[1]);
		} catch (Throwable) {
			$thrown = true;
		}
		check($thrown, 'bad gateway input rejected');
	}
});

row('web write requires software privilege and canonical token', static function (): void {
	$GLOBALS['config'] = [];
	$GLOBALS['allowed'] = false;
	$thrown = false;
	try { PfbConfig::write('gen/pfb_pkg_ca_consent', 'on'); } catch (Throwable) { $thrown = true; }
	check($thrown, 'privilege denied');
	$GLOBALS['allowed'] = true;
	PfbConfig::write('gen/pfb_pkg_ca_consent', 'on');
	same('on', PfbConfig::read('gen/pfb_pkg_ca_consent'), 'privileged write');
	$GLOBALS['allowed'] = true;
});

row('CA environment prefix validates each half and shell quotes', static function (): void {
	$dir = $GLOBALS['pfb']['dbdir'] . "/ca dir's";
	mkdir($dir, 0700, true);
	$file = $GLOBALS['pfb']['dbdir'] . "/ca file's.pem";
	file_put_contents($file, 'x');
	same("SSL_CA_CERT_PATH='" . str_replace("'", "'\\''", $dir) . "' SSL_CA_CERT_FILE='" . str_replace("'", "'\\''", $file) . "' ", pfb_pkg_ca_env_prefix($dir, $file), 'quoted prefix');
	same("SSL_CA_CERT_FILE='" . str_replace("'", "'\\''", $file) . "' ", pfb_pkg_ca_env_prefix('', $file), 'empty path keeps bundle');
	file_put_contents($file, '');
	same("SSL_CA_CERT_PATH='" . str_replace("'", "'\\''", $dir) . "' ", pfb_pkg_ca_env_prefix($dir, $file), 'empty bundle omitted');
});

row('parser add/remove is exact and byte preserving', static function () use (&$base): void {
	$patched = pfb_pkgconf_ca_add($base, '/etc/ssl/certs');
	check($patched !== '' && str_contains($patched, "\tSSL_CA_CERT_PATH=/etc/ssl/certs\n}"), 'add line');
	same($base, pfb_pkgconf_ca_remove($patched, '/etc/ssl/certs'), 'round trip');
	check(!pfb_pkgconf_ca_needed("PKG_ENV {\n\tSSL_CA_CERT_FILE=relative\n}\n"), 'unsafe file path');
	check(!pfb_pkgconf_ca_needed("PKG_ENV {\n\tSSL_CA_CERT_FILE=/tmp/a\n\tSSL_CA_CERT_FILE=/tmp/b\n}\n"), 'duplicate file key');
	check(!pfb_pkgconf_ca_needed("PKG_ENV {\n\tSSL_CA_CERT_FILE=/tmp/a\n\tSSL_CA_CERT_PATH=/tmp/foreign\n}\n"), 'foreign path');
	check(!pfb_pkgconf_ca_needed("PKG_ENV {\n\tX={\n}\n\tSSL_CA_CERT_FILE=/tmp/a\n}\n"), 'nested block');
});

row('state and sync enforce Plus filesystem guards', static function () use (&$pkgconf, &$base, &$bundle): void {
	file_put_contents($pkgconf, str_replace('/tmp/bundle.pem', $bundle, $base));
	same('needed', pfb_pkgconf_ca_state($pkgconf, true, $GLOBALS['pfb']['dbdir'] . '/certs'), 'needed state');
	$GLOBALS['dirty'] = false;
	check(pfb_pkgconf_ca_sync(true, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs'), 'sync add');
	same('patched', pfb_pkgconf_ca_state($pkgconf, true, $GLOBALS['pfb']['dbdir'] . '/certs'), 'patched state');
	check(pfb_pkgconf_ca_sync(false, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs'), 'sync remove');
	same('needed', pfb_pkgconf_ca_state($pkgconf, true, $GLOBALS['pfb']['dbdir'] . '/certs'), 'removed state');
	$GLOBALS['dirty'] = true;
	check(!pfb_pkgconf_ca_sync(true, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs'), 'dirty refused');
	$GLOBALS['dirty'] = false;
	@unlink($GLOBALS['pfb']['dbdir'] . '/certs/hash.0');
	file_put_contents($pkgconf, "PKG_ENV {\n\tSSL_CA_CERT_FILE={$bundle}\n}\n");
	check(!pfb_pkgconf_ca_sync(true, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs'), 'empty cert dir refused');
	file_put_contents($GLOBALS['pfb']['dbdir'] . '/certs/hash.0', 'x');
	check(pfb_pkgconf_ca_sync(true, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs'), 'populated cert dir');
});

row('save apply and tick are best effort', static function () use (&$pkgconf, &$base, &$bundle): void {
	$GLOBALS['config'] = [];
	PfbConfig::writeSystem('gen/pfb_pkg_ca_consent', 'on');
	same('on', pfb_pkgconf_ca_save([]), 'hidden section does not revoke');
	same('', pfb_pkgconf_ca_save(['pfb_pkg_ca_consent_shown' => '1']), 'unchecked token');
	file_put_contents($pkgconf, str_replace('/tmp/bundle.pem', $bundle, $base));
	PfbConfig::writeSystem('gen/pfb_pkg_ca_consent', 'on');
	check(pfb_pkgconf_ca_apply('on', false, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs', true), 'apply');
	$GLOBALS['notices'] = [];
	pfb_pkgconf_ca_tick(false, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs', true);
	check(count($GLOBALS['notices']) === 0, 'provenance denial is silent');
	file_put_contents($pkgconf, str_replace('/tmp/bundle.pem', $bundle, $base));
	@unlink($GLOBALS['pfb']['dbdir'] . '/certs/hash.0');
	pfb_pkgconf_ca_tick(true, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs', true);
	check(count($GLOBALS['notices']) === 1, 'notice');
	pfb_pkgconf_ca_tick(true, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs', true);
	check(count($GLOBALS['notices']) === 1, 'notice dedupe');
});

row('both networked pkg commands carry the CA prefix before timeout', static function () use (&$software): void {
	$source = file_get_contents($software);
	check(is_string($source), 'software source readable');
	check(substr_count($source, 'exec("{$ca}{$tmo}{$bin}') === 2, 'both networked calls prefixed');
	check(strpos($source, 'exec("{$tmo}{$bin} update') === false, 'no unprefixed update call');
	check(strpos($source, 'exec("{$tmo}{$bin} rquery') === false, 'no unprefixed rquery call');
});

function remove_tree(string $path): void
{
	if (!is_dir($path)) { return; }
	foreach (scandir($path) ?: [] as $entry) {
		if ($entry === '.' || $entry === '..') { continue; }
		$child = $path . '/' . $entry;
		is_dir($child) && !is_link($child) ? remove_tree($child) : @unlink($child);
	}
	@rmdir($path);
}

remove_tree($root);
echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURES\n";
exit($failures === 0 ? 0 : 1);
