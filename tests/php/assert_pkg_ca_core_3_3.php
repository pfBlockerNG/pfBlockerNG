<?php

declare(strict_types=1);

$GLOBALS['config'] = [];
$GLOBALS['pfb'] = [];
$GLOBALS['allowed'] = true;
define('PFB_FILTER_ON_OFF', 1);
define('PFB_REPO_GENERATE_HOOK', sys_get_temp_dir() . '/pfb-ca-core-' . bin2hex(random_bytes(4)));
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
$hook_log = PFB_REPO_GENERATE_HOOK . '.log';
file_put_contents(
	PFB_REPO_GENERATE_HOOK,
	"#!/bin/sh\nprintf '%s\\n' \"\$1\" >> " . escapeshellarg($hook_log) . "\nexit \${PFB_HOOK_STATUS:-0}\n"
);
chmod(PFB_REPO_GENERATE_HOOK, 0700);

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

row('save persists only the rendered consent token', static function (): void {
	$GLOBALS['config'] = [];
	PfbConfig::writeSystem('gen/pfb_pkg_ca_consent', 'on');
	same('on', pfb_pkgconf_ca_save([]), 'hidden section does not revoke');
	same('', pfb_pkgconf_ca_save(['pfb_pkg_ca_consent_shown' => '1']), 'unchecked token');
});

row('apply maps consent transitions to the hook', static function () use (&$hook_log): void {
	check(pfb_pkgconf_ca_apply('on', false), 'consent on syncs');
	check(pfb_pkgconf_ca_apply('', true), 'on to off revokes');
	check(pfb_pkgconf_ca_apply('', false), 'off to off is a no-op');
	same("ca-sync\nca-revoke\n", file_get_contents($hook_log), 'transition calls');
	putenv('PFB_HOOK_STATUS=1');
	check(!pfb_pkgconf_ca_apply('on', false), 'hook failure propagates');
	putenv('PFB_HOOK_STATUS');
});

row('pkg wrapper syncs before running and fails closed', static function () use (&$hook_log): void {
	file_put_contents($hook_log, '');
	$out = [];
	$ret = -1;
	pfb_pkg_exec('/usr/bin/printf ok', $out, $ret);
	same(0, $ret, 'command status');
	same(['ok'], $out, 'command output');
	same("ca-sync\n", file_get_contents($hook_log), 'pre-command sync');
	putenv('PFB_HOOK_STATUS=1');
	pfb_pkg_exec('/usr/bin/printf should-not-run', $out, $ret);
	same(-1, $ret, 'blocked status');
	same([], $out, 'blocked output');
	putenv('PFB_HOOK_STATUS');
});

row('both pkg commands delegate to the hook immediately before execution', static function () use (&$software): void {
	$source = file_get_contents($software);
	check(is_string($source), 'software source readable');
	$wrapper_start = strpos($source, 'function pfb_pkg_exec');
	$wrapper_end = strpos($source, 'function pfb_pkg_installed_name', $wrapper_start);
	check($wrapper_start !== false && $wrapper_end !== false, 'pkg wrapper slice');
	$wrapper = substr($source, $wrapper_start, $wrapper_end - $wrapper_start);
	// issue #2630: the login-generation branch returns early with a plain exec;
	// the OLD-generation exec (the last one in the wrapper) must still sit behind
	// the ca-sync gate.
	$login_pos = strpos($wrapper, 'pfb_pkgconf_ca_hook_is_login()');
	$sync_pos = strpos($wrapper, "pfb_pkgconf_ca_command('ca-sync')");
	$exec_pos = strrpos($wrapper, 'exec($command');
	check($login_pos !== false, 'login-generation early return present');
	check($sync_pos !== false && $exec_pos !== false && $sync_pos < $exec_pos, 'old-generation exec stays behind the ca-sync gate');
	$start = strpos($source, 'function pfb_pkg_latest');
	$end = strpos($source, 'function pfb_pkgconf_ca_save', $start);
	check($start !== false && $end !== false, 'latest slice');
	$latest = substr($source, $start, $end - $start);
	check(substr_count($latest, 'pfb_pkg_exec("{$tmo}{$bin}') === 2, 'both latest calls use wrapper');
	check(substr_count($source, 'pfb_pkg_exec(') === 6, 'all five pkg calls use the wrapper');
	check(!str_contains($latest, 'SSL_CA_CERT_PATH='), 'no PHP environment decoration');
});

// -- login-generation semantics (issue #2630): under the installer's new hook the
// consent defaults ON (absent key = on; a present empty token = explicit opt-out).
row('login generation: consent defaults on, present-empty opts out', static function (): void {
	file_put_contents(PFB_REPO_GENERATE_HOOK, "#!/bin/sh\n# verbs: login-ca-sync login-ca-revoke\nexit 0\n");
	chmod(PFB_REPO_GENERATE_HOOK, 0700);
	config_set_path('installedpackages/pfblockerng/config/0', []);
	check(pfb_pkg_ca_consent_enabled(), 'absent key reads as consented under the login hook');
	config_set_path('installedpackages/pfblockerng/config/0/pfb_pkg_ca_consent', '');
	check(!pfb_pkg_ca_consent_enabled(), 'present empty token is the explicit opt-out');
	config_set_path('installedpackages/pfblockerng/config/0/pfb_pkg_ca_consent', 'on');
	check(pfb_pkg_ca_consent_enabled(), 'explicit on stays on');
});

row('old generation: consent stays opt-in', static function (): void {
	file_put_contents(PFB_REPO_GENERATE_HOOK, "#!/bin/sh\nexit 0\n");
	chmod(PFB_REPO_GENERATE_HOOK, 0700);
	config_set_path('installedpackages/pfblockerng/config/0', []);
	check(!pfb_pkg_ca_consent_enabled(), 'absent key stays off under the old hook');
});

@unlink(PFB_REPO_GENERATE_HOOK);
@unlink($hook_log);

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURES\n";
exit($failures === 0 ? 0 : 1);
