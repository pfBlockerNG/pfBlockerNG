<?php
/*
 * PHPUnit bootstrap for the pfBlockerNG PHP unit suite.
 *
 * Strategy (see tests/php/README.md): load the REAL production include
 * src/usr/local/pkg/pfblockerng/pfblockerng.inc unmodified, so the tests
 * exercise shipped code rather than copies. pfblockerng.inc opens with
 * require_once() of eight pfSense core includes and runs a little top-level
 * code; we make that resolvable off-appliance without touching production:
 *
 *   1. Prepend tests/php/shims/ to include_path — empty files named after the
 *      eight required pfSense includes satisfy require_once() as no-ops.
 *   2. Provide behavioural doubles (pfsense_doubles.php) for the pfSense
 *      runtime functions the load-time code and the tested functions call.
 *   3. Seed $g / $pfb so load-time $pfb[...] path assignments point at a
 *      writable temp sandbox (pfb_logger uses @file_put_contents — harmless).
 *   4. Clear $argv so the bottom-of-file daemon dispatch (if (isset($argv[1])))
 *      stays dormant under PHPUnit.
 *
 * The two top-level service installers (pfb_filter_service/pfb_dnsbl_service)
 * only build an rc array and call write_rcfile(), which we double to a no-op.
 */

require_once __DIR__ . '/pfsense_doubles.php';

// 1. Shims for the eight pfSense includes required at the top of pfblockerng.inc.
set_include_path(__DIR__ . '/shims' . PATH_SEPARATOR . get_include_path());

// 3. Writable per-invocation sandbox for any load-time/log file writes.
$pfb_test_owner_pid = getmypid();
$pfb_test_tmp = sys_get_temp_dir() . '/pfb_php_unit_' . $pfb_test_owner_pid . '_' . bin2hex(random_bytes(8));
if (!mkdir($pfb_test_tmp, 0777, TRUE)) {
	throw new RuntimeException("PHPUnit sandbox creation failed: {$pfb_test_tmp}");
}
register_shutdown_function(static function () use ($pfb_test_tmp, $pfb_test_owner_pid): void {
	// pcntl_fork() inherits shutdown callbacks; only the process that created this tree owns it.
	if (getmypid() === $pfb_test_owner_pid) {
		rmdir_recursive($pfb_test_tmp);
	}
});
unset($pfb_test_owner_pid);
foreach (['db', 'log', 'tmp'] as $pfb_test_subdir) {
	$pfb_test_path = "{$pfb_test_tmp}/{$pfb_test_subdir}";
	if (!mkdir($pfb_test_path, 0777, TRUE)) {
		throw new RuntimeException("PHPUnit sandbox directory creation failed: {$pfb_test_path}");
	}
}
unset($pfb_test_path, $pfb_test_subdir);

$GLOBALS['g'] = [
	'vardb_path'  => "{$pfb_test_tmp}/db",
	'varlog_path' => "{$pfb_test_tmp}/log",
	'tmp_path'    => "{$pfb_test_tmp}/tmp",
	'pfblockerng_install' => false,
];
$GLOBALS['pfb'] = [];

// 4. Keep the daemon dispatch dormant. Save/replace argv (PHPUnit has already
//    parsed its own arguments by now, so this is safe).
$GLOBALS['argv'] = ['pfblockerng.inc'];
$GLOBALS['argc'] = 1;

// 4b. Keep the resolver start dormant too, the sibling of step 4: no unit test may
//     start Unbound (issue #2613) or pay either appliance wait. The executable double
//     exits 127 because an absent binary returns exactly that off-appliance, which keeps
//     the caller's retval != 0 retry branch exercised without a shell compound escaping
//     the timeout wrapper. Guarded: a re-load stays silent.
$GLOBALS['pfb_test_unbound_start_log'] = "{$pfb_test_tmp}/unbound_start.log";
$pfb_test_unbound_start_cmd = "{$pfb_test_tmp}/unbound-start-double";
file_put_contents($pfb_test_unbound_start_cmd, <<<'SH'
	#!/bin/sh
	printf '%s\n' 'unit-test double: Unbound start suppressed' | tee -a "$1"
	exit 127
	SH);
chmod($pfb_test_unbound_start_cmd, 0755);
if (!defined('PFB_UNBOUND_START_CMD')) {
	define('PFB_UNBOUND_START_CMD', escapeshellarg($pfb_test_unbound_start_cmd) . ' '
		. escapeshellarg($GLOBALS['pfb_test_unbound_start_log']));
}
if (!defined('PFB_UNBOUND_STOP_WAIT')) {
	define('PFB_UNBOUND_STOP_WAIT', 2);
}
if (!defined('PFB_UNBOUND_KILL_WAIT')) {
	define('PFB_UNBOUND_KILL_WAIT', 1);
}
if (!defined('PFB_UNBOUND_START_WAIT')) {
	define('PFB_UNBOUND_START_WAIT', 2);
}
unset($pfb_test_unbound_start_cmd);

// 4c. Replace the mount-executing include even on hosts with pfBlockerNG installed.
$GLOBALS['pfb_test_unbound_include_log'] = "{$pfb_test_tmp}/unbound_include.log";
$pfb_test_unbound_include_file = "{$pfb_test_tmp}/pfb-unbound-include-double.inc";
file_put_contents($pfb_test_unbound_include_file, '<?php file_put_contents('
	. var_export($GLOBALS['pfb_test_unbound_include_log'], TRUE) . ", \"included\\n\", FILE_APPEND);\n");
if (!defined('PFB_UNBOUND_INCLUDE_FILE')) {
	define('PFB_UNBOUND_INCLUDE_FILE', $pfb_test_unbound_include_file);
}
unset($pfb_test_unbound_include_file);

// 4d. Record package commands and preserve the missing-package failure result.
$GLOBALS['pfb_test_pkg_bin_log'] = "{$pfb_test_tmp}/pkg_bin.log";
$pfb_test_pkg_bin = "{$pfb_test_tmp}/pkg-bin-double";
file_put_contents($pfb_test_pkg_bin, "#!/bin/sh\n"
	. 'printf \'%s\n\' "$*" >> ' . escapeshellarg($GLOBALS['pfb_test_pkg_bin_log']) . "\n"
	. "exit 1\n");
chmod($pfb_test_pkg_bin, 0755);
if (!defined('PFB_PKG_BIN')) {
	define('PFB_PKG_BIN', $pfb_test_pkg_bin);
}
unset($pfb_test_pkg_bin);

// 4e. Override both the initial prefix and the source pfb_global() uses to rebuild it.
$GLOBALS['pfb_test_chroot_cmd_log'] = "{$pfb_test_tmp}/chroot_cmd.log";
$pfb_test_chroot_cmd = "{$pfb_test_tmp}/chroot-cmd-double";
file_put_contents($pfb_test_chroot_cmd, "#!/bin/sh\n"
	. 'printf \'%s\n\' "$*" >> ' . escapeshellarg($GLOBALS['pfb_test_chroot_cmd_log']) . "\n"
	. "exit 0\n");
chmod($pfb_test_chroot_cmd, 0755);
if (!defined('PFB_UNBOUND_CONTROL_BIN')) {
	define('PFB_UNBOUND_CONTROL_BIN', $pfb_test_chroot_cmd);
}
$GLOBALS['pfb']['chroot_cmd'] = $pfb_test_chroot_cmd;
unset($pfb_test_chroot_cmd);

// 2 + load. Define the production functions by including the real source.
// pfblockerng.inc is legacy code that emits some load-time E_DEPRECATED/E_WARNING
// notices (e.g. an optional-before-required parameter, a switch `continue`) that
// are pre-existing and unrelated to the tests. Silence them around the include
// only, then restore full reporting so test execution stays strict.
$pfb_prev_er = error_reporting();
error_reporting($pfb_prev_er & ~E_DEPRECATED & ~E_WARNING);
require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
error_reporting($pfb_prev_er);
$pfb_test_timeout_out = [];
$pfb_test_timeout_rc = 0;
exec('command -v timeout 2>/dev/null', $pfb_test_timeout_out, $pfb_test_timeout_rc);
$pfb_test_timeout = trim((string) ($pfb_test_timeout_out[0] ?? ''));
if ($pfb_test_timeout_rc !== 0 || !is_executable($pfb_test_timeout)) {
	throw new RuntimeException('PHPUnit requires a real timeout(1) on PATH for bounded process tests.');
}
$GLOBALS['pfb']['timeout'] = $pfb_test_timeout;
unset($pfb_test_timeout_out, $pfb_test_timeout_rc, $pfb_test_timeout);
/**
 * Issue #3195: resolve the host's bsdtar binary.
 *
 * FreeBSD and macOS ship bsdtar at /usr/bin/tar.
 * Linux development seats provide bsdtar via libarchive-tools.
 * If bsdtar cannot be resolved on the host, crash fast with RuntimeException.
 *
 * @param ?callable(string): string $lookup
 * @param ?callable(string): bool   $executable_check
 */
function pfb_resolve_archiver(?string $os_family = NULL, ?callable $lookup = NULL, ?callable $executable_check = NULL): string
{
	$family = $os_family ?? PHP_OS_FAMILY;
	$is_exec = $executable_check ?? 'is_executable';
	if ($family === 'BSD' || $family === 'Darwin') {
		$tar = '/usr/bin/tar';
	} else {
		$finder = $lookup ?? static function (string $cmd): string {
			return trim((string) shell_exec('command -v ' . escapeshellarg($cmd) . ' 2>/dev/null'));
		};
		$tar = $finder('bsdtar');
	}
	if ($tar === '' || !call_user_func($is_exec, $tar)) {
		throw new RuntimeException("bsdtar binary missing on host ({$family})");
	}
	return $tar;
}

function pfb_test_tar(): string
{
	return $GLOBALS['pfb']['tar'] ?? '/usr/bin/tar';
}

function pfb_test_preflight_path(string $root, string $path, string $label): string
{
	$root = rtrim($root, DIRECTORY_SEPARATOR) ?: DIRECTORY_SEPARATOR;
	$path = rtrim($path, DIRECTORY_SEPARATOR) ?: DIRECTORY_SEPARATOR;
	$prefix = $root === DIRECTORY_SEPARATOR ? $root : $root . DIRECTORY_SEPARATOR;
	if ($path !== $root && !str_starts_with($path, $prefix)) {
		throw new RuntimeException("refusing {$label} outside trusted temporary root {$root}");
	}
	$canonical = realpath($root);
	if ($canonical === FALSE) {
		throw new RuntimeException("could not inspect trusted temporary root {$root}");
	}
	foreach (explode(DIRECTORY_SEPARATOR, ltrim(substr($path, strlen($root)), DIRECTORY_SEPARATOR)) as $component) {
		if ($component === '' || $component === '.') {
			continue;
		}
		if ($component === '..') {
			throw new RuntimeException("refusing {$label} outside trusted temporary root {$root}");
		}
		$canonical .= DIRECTORY_SEPARATOR . $component;
		if (is_link($canonical)) {
			throw new RuntimeException("refusing {$label} symlink {$canonical}");
		}
	}
	return $canonical;
}

function pfb_test_as_unprivileged(callable $callback, array $owned_paths = []): mixed
{
	if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
		return $callback();
	}
	$uid = 65534;
	$tmp_path = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
	$tmp_prefix_end = strpos($tmp_path, DIRECTORY_SEPARATOR, 1);
	$tmp_prefix = $tmp_prefix_end === FALSE ? $tmp_path : substr($tmp_path, 0, $tmp_prefix_end);
	$tmp = pfb_test_preflight_path($tmp_prefix, $tmp_path, 'nested TMPDIR');
	$owners = [];
	$modes = [];
	$tmp_owner = NULL;

	foreach ($owned_paths as $path) {
		$canonical_path = pfb_test_preflight_path($tmp_path, $path, 'owned-path');
		if (!file_exists($path)) {
			throw new RuntimeException("could not prepare {$path} for an unprivileged fixture");
		}
		for ($directory = dirname($canonical_path); $canonical_path !== $tmp && $directory !== $tmp;
		    $directory = dirname($directory)) {
			$mode = fileperms($directory);
			if ($mode === FALSE) {
				throw new RuntimeException("could not inspect owned-path ancestor {$directory}");
			}
			if (($mode & 0001) === 0) {
				$modes[$directory] = $mode & 07777;
			}
		}
		$paths = [$path];
		if (is_dir($path)) {
			foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path,
				FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $entry) {
				$owned_path = $entry->getPathname();
				if ($entry->isLink()) {
					throw new RuntimeException("refusing owned-path symlink {$owned_path}");
				}
				$paths[] = $owned_path;
			}
		}
		foreach ($paths as $owned_path) {
			$owner = fileowner($owned_path);
			if ($owner === FALSE) {
				throw new RuntimeException("could not inspect {$owned_path} for an unprivileged fixture");
			}
			$owners[$owned_path] = $owner;
		}
	}

	for ($directory = $tmp; ; $directory = dirname($directory)) {
		$mode = fileperms($directory);
		if ($mode === FALSE) {
			throw new RuntimeException("could not inspect nested TMPDIR ancestor {$directory}");
		}
		if (($mode & 0001) === 0) {
			$modes[$directory] = $mode & 07777;
		}
		if ($directory === dirname($directory)) {
			break;
		}
	}
	if (isset($modes[$tmp])) {
		$tmp_owner = fileowner($tmp);
		if ($tmp_owner === FALSE) {
			throw new RuntimeException("could not inspect nested TMPDIR {$tmp} ownership");
		}
	}

	$restore = static function () use (&$owners, &$modes, $tmp, $tmp_path, &$tmp_owner): void {
		$restore_error = NULL;
		foreach (array_reverse($owners, TRUE) as $path => $owner) {
			try {
				pfb_test_preflight_path($tmp_path, $path, 'replacement');
			} catch (RuntimeException $error) {
				$restore_error ??= $error->getMessage() . ' during ownership restore';
				continue;
			}
			if (file_exists($path) && !chown($path, $owner)) {
				$restore_error ??= "could not restore {$path} ownership";
			}
		}
		if ($tmp_owner !== NULL && (!file_exists($tmp) || is_link($tmp) || !chown($tmp, $tmp_owner))) {
			$restore_error ??= "could not safely restore nested TMPDIR {$tmp} ownership";
		}
		foreach (array_reverse($modes, TRUE) as $directory => $mode) {
			if (!file_exists($directory) || is_link($directory) || !chmod($directory, $mode)) {
				$restore_error ??= "could not safely restore nested TMPDIR ancestor {$directory} mode";
			}
		}
		if ($restore_error !== NULL) {
			throw new RuntimeException($restore_error);
		}
	};

	$sockets = FALSE;
	try {
		foreach ($modes as $directory => $mode) {
			if ($directory !== $tmp && !chmod($directory, $mode | 0001)) {
				throw new RuntimeException("could not make nested TMPDIR ancestor {$directory} traversable");
			}
		}
		if ($tmp_owner !== NULL && !chown($tmp, $uid)) {
			throw new RuntimeException("could not make nested TMPDIR {$tmp} traversable by an unprivileged fixture");
		}
		foreach ($owners as $owned_path => $_owner) {
			if (!chown($owned_path, $uid)) {
				throw new RuntimeException("could not prepare {$owned_path} for an unprivileged fixture");
			}
		}
		$sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
		$pid = $sockets === FALSE ? -1 : pcntl_fork();
		if ($pid === -1) {
			throw new RuntimeException('could not fork an unprivileged permission-denial fixture');
		}
	} catch (Throwable $error) {
		if (is_array($sockets)) {
			fclose($sockets[0]);
			fclose($sockets[1]);
		}
		$restore();
		throw $error;
	}

	if ($pid === 0) {
		fclose($sockets[0]);
		try {
			if (!posix_setgid($uid) || !posix_setuid($uid)) {
				throw new RuntimeException('could not drop privileges in permission-denial fixture');
			}
			$payload = ['ok' => TRUE, 'value' => $callback()];
		} catch (Throwable $error) {
			$payload = ['ok' => FALSE, 'error' => get_class($error) . ': ' . $error->getMessage()];
		}
		fwrite($sockets[1], base64_encode(serialize($payload)) . "\n");
		fclose($sockets[1]);
		exit($payload['ok'] ? 0 : 1);
	}

	fclose($sockets[1]);
	$waited = FALSE;
	try {
		$encoded = fgets($sockets[0]);
		fclose($sockets[0]);
		pcntl_waitpid($pid, $status);
		$waited = TRUE;
		$payload = is_string($encoded)
			? unserialize(base64_decode(trim($encoded)), ['allowed_classes' => FALSE])
			: NULL;
		if (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0 || !is_array($payload)
			|| ($payload['ok'] ?? FALSE) !== TRUE) {
			throw new RuntimeException('unprivileged fixture failed: '
				. ($payload['error'] ?? 'child exited unexpectedly'));
		}
		return $payload['value'];
	} finally {
		if (is_resource($sockets[0])) {
			fclose($sockets[0]);
		}
		if (!$waited) {
			pcntl_waitpid($pid, $status);
		}
		$restore();
	}
}

$GLOBALS['pfb']['tar'] = pfb_resolve_archiver();

// Snapshot the SHIPPED $pfb['mime_types'] allow-list exactly as the just-loaded
// production source defines it, before any test mutates/unsets $GLOBALS['pfb']
// (several sibling tests overwrite it in setUp/tearDown). This immutable copy
// lets allow-list oracles assert against the REAL shipped list, not a hand-mirror.
$GLOBALS['pfb_shipped_mime_types'] = $GLOBALS['pfb']['mime_types'] ?? [];

// 5. Load the setup-wizard controller's FUNCTIONS so the unit suite can invoke
//    them on shipped code (WizardVipAutoTest -> step3_submitphpaction). The wizard
//    .inc cannot be require()d as-is here: it opens with four require_once()s —
//    three relative (config.inc/util.inc/services.inc, satisfiable by the shims)
//    plus one HOST-ABSOLUTE require of /usr/local/pkg/pfblockerng/pfblockerng.inc
//    (NOT resolvable via include_path, and a duplicate of the real include already
//    loaded above) — and then runs top-level wiring (pfb_global(), interface-list
//    build) that needs runtime pfSense state we deliberately do not stand up.
//    So we read the source, strip its require_once() lines, and eval only from the
//    first function definition onward: the function bodies are the shipped code
//    under test, defined verbatim; no production file is modified. Guarded so a
//    real include path (on-appliance) never double-defines.
// 6. Load the ADR-28 adapter helpers so tests can exercise them against the
//    real bootstrap environment (enums + adapter fns; inlined into pfblockerng_extra.inc,
//    ADR-28 P4).  On-appliance pfblockerng.inc loads extra.inc via a host-absolute
//    file_exists() check that is not satisfied off-appliance, so we load it explicitly
//    here by its repo-relative path.
require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
if (!function_exists('step3_submitphpaction')) {
	$pfb_wizard_src = file_get_contents(
		dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc'
	);
	if ($pfb_wizard_src === false) {
		throw new RuntimeException('test bootstrap: failed to read pfblockerng_wizard.inc for the wizard-function load');
	}
	// Drop the top-of-file require_once() statements (shims/real include already
	// satisfy them); keep everything else byte-for-byte.
	$pfb_wizard_src = preg_replace('/^\s*require_once\(.*\);\s*$/m', '', $pfb_wizard_src);
	// Eval only the function definitions (from the first `function ` keyword),
	// skipping the top-level wiring that would call into unprovisioned runtime.
	$pfb_fn_pos = strpos($pfb_wizard_src, 'function ');
	if ($pfb_fn_pos !== false) {
		eval("\n" . substr($pfb_wizard_src, $pfb_fn_pos));
	}
	unset($pfb_wizard_src, $pfb_fn_pos);
}

// 7. Parity snapshot of the package's loaded function surface (#1122 phase 0),
//    taken here so it reflects exactly what the umbrella + extra load defines,
//    before any test can add or shadow symbols (order-independent by
//    construction). The defining file selects package functions only — it
//    excludes the doubles, vendor code, and the wizard eval above — but the
//    snapshot records no file-of-origin, so relocating a function between
//    package files (the #1122 split) leaves it byte-identical.
//    Coupling caveat: extra.inc's function_exists()-guarded CE-compat shims
//    (localize_text, logger) are in the inventory only while
//    pfsense_doubles.php defines no double for them — adding such a double
//    later flips the parity test red with zero production change.
$pfb_pkg_dir = realpath(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng') . DIRECTORY_SEPARATOR;
$pfb_inventory = [];
foreach (get_defined_functions()['user'] as $pfb_fn_name) {
	$pfb_fn_ref = new ReflectionFunction($pfb_fn_name);
	$pfb_fn_file = $pfb_fn_ref->getFileName();
	if ($pfb_fn_file === false
	    || strncmp((string) realpath($pfb_fn_file), $pfb_pkg_dir, strlen($pfb_pkg_dir)) !== 0) {
		continue;
	}
	$pfb_fn_params = [];
	foreach ($pfb_fn_ref->getParameters() as $pfb_fn_param) {
		$pfb_fn_params[] = [
			'name'     => $pfb_fn_param->getName(),
			'byRef'    => $pfb_fn_param->isPassedByReference(),
			'variadic' => $pfb_fn_param->isVariadic(),
			'type'     => $pfb_fn_param->hasType() ? (string) $pfb_fn_param->getType() : null,
			'default'  => $pfb_fn_param->isDefaultValueAvailable()
				? var_export($pfb_fn_param->getDefaultValue(), true)
				: null,
		];
	}
	$pfb_inventory[$pfb_fn_ref->getName()] = [
		'returnsRef'  => $pfb_fn_ref->returnsReference(),
		'returnType'  => $pfb_fn_ref->hasReturnType() ? (string) $pfb_fn_ref->getReturnType() : null,
		'params'      => $pfb_fn_params,
	];
}
ksort($pfb_inventory, SORT_STRING);
$GLOBALS['pfb_function_inventory'] = $pfb_inventory;
unset($pfb_pkg_dir, $pfb_inventory, $pfb_fn_name, $pfb_fn_ref, $pfb_fn_file, $pfb_fn_params, $pfb_fn_param);
