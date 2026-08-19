<?php

declare(strict_types=1);

$GLOBALS['config'] = [];
$GLOBALS['pfb'] = [];
$GLOBALS['dirty'] = false;

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
		$cursor[$part] ??= [];
		$cursor =& $cursor[$part];
	}
	$cursor = $value;
}

function isAllowedPage(string $page): bool
{
	return $page === 'pkg_mgr_installed.php';
}

function is_subsystem_dirty(string $name): bool
{
	return $name === 'pkg' && $GLOBALS['dirty'];
}

function pkg_version_compare(string $left, string $right): string
{
	$result = version_compare($left, $right);
	return $result < 0 ? '<' : ($result > 0 ? '>' : '=');
}

$extra = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
$software = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_software.inc';
require_once $extra;
require_once $software;

$failures = 0;
$root = sys_get_temp_dir() . '/pfb_pkg_ca_hardening_3_3_' . bin2hex(random_bytes(5));
mkdir($root . '/certs', 0700, true);
$GLOBALS['pfb']['dbdir'] = $root;
file_put_contents($root . '/certs/hash.0', 'x');
$bundle = $root . '/bundle.pem';
file_put_contents($bundle, "CA\n");
$pkgconf = $root . '/pkg.conf';
$base = "PKG_ENV {\n\tSSL_CA_CERT_FILE={$bundle}\n}\n";
file_put_contents($pkgconf, $base);
$lockfile = $root . '/upgrade.lock';

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

row('forced refresh and newest catalog version stay pinned', static function () use ($software): void {
	check(pfb_pkg_newest_version(['1.9.9', '1.10.0', '1.2.0', [], '']) === '1.10.0', 'newest version selection');
	$source = file_get_contents($software);
	check(is_string($source), 'software source readable');
	check(str_contains($source, 'exec("{$ca}{$tmo}{$bin} update -f -r {$repo}'), 'forced prefixed update');
	check(str_contains($source, 'return ($ret === 0 && $out !== []) ? pfb_pkg_newest_version($out) :'), 'newest result wiring');
});

row('CA prefix refuses symlinks and invalid bundles', static function () use ($root, $bundle): void {
	$path_link = $root . '/certs-link';
	$bundle_link = $root . '/bundle-link.pem';
	symlink($root . '/certs', $path_link);
	symlink($bundle, $bundle_link);
	check(!str_contains(pfb_pkg_ca_env_prefix($path_link, $bundle), 'SSL_CA_CERT_PATH'), 'symlink path omitted');
	check(!str_contains(pfb_pkg_ca_env_prefix($root . '/certs', $bundle_link), 'SSL_CA_CERT_FILE'), 'symlink bundle omitted');
	check(!str_contains(pfb_pkg_ca_env_prefix($root . '/certs', $root . '/certs'), 'SSL_CA_CERT_FILE'), 'directory bundle omitted');
	file_put_contents($bundle, '');
	check(!str_contains(pfb_pkg_ca_env_prefix($root . '/certs', $bundle), 'SSL_CA_CERT_FILE'), 'empty bundle omitted');
	file_put_contents($bundle, "CA\n");
	@unlink($path_link);
	@unlink($bundle_link);
});

row('parser refuses CRLF and preserves no-final-newline bytes', static function () use ($base): void {
	$crlf = str_replace("\n", "\r\n", $base);
	check(!pfb_pkgconf_ca_needed($crlf), 'CRLF shape refused rather than guessed');
	$no_final = rtrim($base, "\n");
	$patched = pfb_pkgconf_ca_add($no_final, '/etc/ssl/certs');
	check($patched !== '', 'no-final-newline shape patched');
	check(pfb_pkgconf_ca_remove($patched, '/etc/ssl/certs') === $no_final, 'no-final-newline round trip');
	check(!pfb_pkgconf_ca_needed("# SSL_CA_CERT_PATH=/tmp/fake\n{$base}"), 'comment token refuses patch');
});

row('atomic writer refuses stale content and lock contention', static function () use ($pkgconf, $base, $lockfile): void {
	check(!pfb_pkgconf_write_atomic($pkgconf, "new\n", "stale\n", $lockfile), 'stale expected bytes refused');
	check(file_get_contents($pkgconf) === $base, 'stale refusal preserves file');
	$lock = fopen($lockfile, 'c');
	check(is_resource($lock) && flock($lock, LOCK_EX | LOCK_NB), 'fixture lock acquired');
	try {
		check(!pfb_pkgconf_ca_sync(true, $pkgconf, $GLOBALS['pfb']['dbdir'] . '/certs', $lockfile), 'contended upgrade lock refused');
		check(file_get_contents($pkgconf) === $base, 'lock refusal preserves file');
	} finally {
		flock($lock, LOCK_UN);
		fclose($lock);
	}
});

row('pkg.conf symlink is never followed or replaced', static function () use ($root, $pkgconf): void {
	$link = $root . '/pkg-link.conf';
	symlink($pkgconf, $link);
	check(pfb_pkgconf_ca_state($link, true) === '', 'symlink state unsupported');
	check(!pfb_pkgconf_ca_sync(true, $link, $root . '/certs'), 'symlink sync refused');
	check(is_link($link), 'symlink survives');
	@unlink($link);
});

row('foreign and duplicate CA paths never report owned success', static function () use ($pkgconf, $base): void {
	$foreign = str_replace("}\n", "\tSSL_CA_CERT_PATH=/tmp/foreign\n}\n", $base);
	file_put_contents($pkgconf, $foreign);
	check(pfb_pkgconf_ca_state($pkgconf, true) === '', 'foreign path state unsupported');
	check(!pfb_pkgconf_ca_sync(true, $pkgconf, '/etc/ssl/certs'), 'foreign path sync refused');
	check(!pfb_pkgconf_ca_apply('on', false, $pkgconf, '/etc/ssl/certs', true), 'foreign path apply refused');
	check(file_get_contents($pkgconf) === $foreign, 'foreign path bytes preserved');

	$duplicate = str_replace(
		"}\n",
		"\tSSL_CA_CERT_PATH=/etc/ssl/certs\n\tSSL_CA_CERT_PATH=/etc/ssl/certs\n}\n",
		$base
	);
	file_put_contents($pkgconf, $duplicate);
	check(pfb_pkgconf_ca_state($pkgconf, true) === '', 'duplicate path state unsupported');
	check(!pfb_pkgconf_ca_sync(true, $pkgconf, '/etc/ssl/certs'), 'duplicate path sync refused');
	check(!pfb_pkgconf_ca_apply('on', false, $pkgconf, '/etc/ssl/certs', true), 'duplicate path apply refused');
	check(file_get_contents($pkgconf) === $duplicate, 'duplicate path bytes preserved');
});

row('notice signature detects same-metadata content rewrites', static function () use ($root): void {
	$file = $root . '/signature.conf';
	file_put_contents($file, 'AAAA');
	touch($file, 1000000000);
	$first = pfb_pkgconf_ca_notice_signature($file);
	file_put_contents($file, 'BBBB');
	touch($file, 1000000000);
	$second = pfb_pkgconf_ca_notice_signature($file);
	check($first !== $second, 'same inode, mtime, and size still changes signature');
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
