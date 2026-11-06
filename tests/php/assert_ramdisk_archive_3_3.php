<?php

declare(strict_types=1);

// Runs the production pfb_aliastables(), pfb_filter_service(), pfb_dnsbl_service() and the CLI
// dispatcher from pfblockerng.inc, extracted verbatim into a generated harness. Host collaborators
// are fixtures: config state (JSON file), config writes, logger, rc.d writer, read_xml_tag.sh,
// timeout, ps/kill/pgrep/killall/logger. Inside the evaluated copy of pfb_aliastables only,
// /usr/bin/tar becomes a wrapper that may remove one input first, and /var/unbound/ becomes a
// fixture directory. Nothing writes /usr/local, /var/unbound or /usr/bin.

const SELECTED = [
	'aliasdir/pfB_Block_v4.txt',
	'aliasdir/pfB_Block_v6.txt',
	'aliasdir/pfB_sp ace\'q"$m.txt',
	'dnsbl/dnsbl_file.conf',
	'var_unbound/pfb_unbound.conf',
	'var_unbound/pfb_py_block.py',
];

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
	global $passes, $failures;
	$GLOBALS['pfb'] = $GLOBALS['pfbDefault'];
	try {
		$test();
		$passes++;
		echo "PASS {$name}\n";
	} catch (Throwable $error) {
		$failures++;
		echo "FAIL {$name}: {$error->getMessage()}\n";
	}
}

function function_source(string $source, string $signature): string
{
	$start = strpos($source, $signature);
	check($start !== false, "missing {$signature}");
	$end = strpos($source, "\n}\n", $start);
	check($end !== false, "unterminated {$signature}");
	return substr($source, $start, $end + 2 - $start);
}

function text_between(string $source, string $startNeedle, string $endNeedle): string
{
	$start = strpos($source, $startNeedle);
	check($start !== false, "missing {$startNeedle}");
	$end = strpos($source, $endNeedle, $start);
	check($end !== false, "missing {$endNeedle}");
	return substr($source, $start, $end - $start);
}

function build_harness(string $source, string $root, array $pfb): string
{
	$aliasTables = strtr(function_source($source, 'function pfb_aliastables($mode) {'), [
		'/usr/bin/tar -jcvf' => "{$root}/bin/tar -jcvf",
		'/var/unbound/' => "{$root}/var_unbound/",
	]);
	$stubs = <<<'STUBS'
		function config_read_file($clear = false, $reload = false): void {}
		function pfb_global(): void {}
		function pfb_test_state(): array
		{
			$raw = @file_get_contents((string) getenv('PFB_TEST_STATE'));
			return $raw === false ? [] : (json_decode($raw, true) ?? []);
		}
		function config_get_path(string $path, $default = null)
		{
			$node = pfb_test_state();
			foreach (explode('/', $path) as $part) {
				if (!is_array($node) || !array_key_exists($part, $node)) {
					return $default;
				}
				$node = $node[$part];
			}
			return $node;
		}
		function config_path_enabled(string $path, string $key): bool
		{
			$node = config_get_path($path, []);
			return is_array($node) && array_key_exists($key, $node);
		}
		function config_set_path(string $path, $value): void
		{
			$state = pfb_test_state();
			$node = &$state;
			foreach (explode('/', $path) as $part) {
				if (!isset($node[$part]) || !is_array($node[$part])) {
					$node[$part] = [];
				}
				$node = &$node[$part];
			}
			$node = $value;
			file_put_contents((string) getenv('PFB_TEST_STATE'), json_encode($state));
		}
		function write_config($message = ''): void
		{
			file_put_contents((string) getenv('PFB_TEST_WRITES'), $message . "\n", FILE_APPEND);
		}
		function pfb_logger($log, $logtype = 0): void
		{
			file_put_contents((string) getenv('PFB_TEST_LOGFILE'), $log, FILE_APPEND);
		}
		function unlink_if_exists($path): void
		{
			if (is_string($path) && $path !== '' && file_exists($path)) {
				@unlink($path);
			}
		}
		function write_rcfile(array $rc): void
		{
			$GLOBALS['pfb_test_rc'] = $rc;
		}
		define('LOG_PREFIX_PKG_PFBLOCKERNG', 'pfBlockerNG');
		STUBS;
	return "<?php\n"
		. '$pfb = ' . var_export($pfb, true) . ";\n"
		. $stubs . "\n"
		. $aliasTables . "\n"
		. function_source($source, 'function pfb_filter_service() {') . "\n"
		. function_source($source, 'function pfb_dnsbl_service() {') . "\n"
		. text_between($source, '// Commandline arguments for daemons', '// Function to convert string to lowercase');
}

function write_fixtures(string $root): void
{
	$fixtures = [
		'tar' => <<<'SH'
			#!/bin/sh
			printf 'tar %s\n' "$*" >> "$PFB_TEST_EVENTS"
			if [ -n "${PFB_TEST_TAR_REMOVE:-}" ]; then rm -f -- "$PFB_TEST_TAR_REMOVE"; fi
			exec /usr/bin/tar "$@"
			SH,
		'timeout' => <<<'SH'
			#!/bin/sh
			printf 'timeout %s\n' "$*" >> "$PFB_TEST_EVENTS"
			if [ "${PFB_TEST_TIMEOUT_EXPIRE:-0}" = 1 ]; then exit 124; fi
			shift 5
			exec "$@"
			SH,
		'read_xml_tag.sh' => <<<'SH'
			#!/bin/sh
			case "$2" in
				system/use_mfs_tmpvar)
					if [ "${PFB_TEST_RAMDISK:-0}" = 1 ]; then printf 'true\n'; fi
					;;
			esac
			SH,
		'ps' => <<<'SH'
			#!/bin/sh
			printf '%s\n' "${PFB_TEST_PS:-}"
			SH,
		'kill' => <<<'SH'
			#!/bin/sh
			printf 'kill %s\n' "$*" >> "$PFB_TEST_EVENTS"
			SH,
		'killall' => <<<'SH'
			#!/bin/sh
			printf 'killall %s\n' "$*" >> "$PFB_TEST_EVENTS"
			SH,
		'pgrep' => "#!/bin/sh\nexit 1\n",
		'logger' => "#!/bin/sh\nexit 0\n",
	];
	foreach ($fixtures as $name => $script) {
		file_put_contents("{$root}/bin/{$name}", $script . "\n");
		chmod("{$root}/bin/{$name}", 0700);
	}
}

function archive(): string
{
	return (string) $GLOBALS['pfb']['aliasarchive'];
}

function state_text(): string
{
	return (string) @file_get_contents((string) getenv('PFB_TEST_STATE'));
}

function file_lines(string $variable): array
{
	return array_values(array_filter(@file((string) getenv($variable), FILE_IGNORE_NEW_LINES) ?: [], 'strlen'));
}

function events_matching(string $prefix): array
{
	return array_values(array_filter(file_lines('PFB_TEST_EVENTS'), static fn(string $line): bool => str_starts_with($line, $prefix)));
}

function writes(): array
{
	return file_lines('PFB_TEST_WRITES');
}

function logtext(): string
{
	return (string) @file_get_contents((string) getenv('PFB_TEST_LOGFILE'));
}

function clear_observations(): void
{
	foreach (['PFB_TEST_WRITES', 'PFB_TEST_LOGFILE', 'PFB_TEST_EVENTS'] as $variable) {
		file_put_contents((string) getenv($variable), '');
	}
}

function reset_state(bool $ramdisk, bool $hooks): void
{
	$state = [];
	if ($ramdisk) {
		$state['system']['use_mfs_tmpvar'] = '';
	}
	if ($hooks) {
		$state['system']['earlyshellcmd'] = ['/usr/local/pkg/pfblockerng/pfblockerng.sh aliastables'];
		$state['installedpackages']['shellcmdsettings']['config'] = [[
			'cmd' => '/usr/local/pkg/pfblockerng/pfblockerng.sh aliastables',
			'cmdtype' => 'earlyshellcmd',
			'description' => 'pfBlockerNG earlyshellcmd. DO NOT EDIT/DELETE!',
		]];
	}
	file_put_contents((string) getenv('PFB_TEST_STATE'), json_encode($state));
	putenv('PFB_TEST_RAMDISK=' . ($ramdisk ? '1' : '0'));
	putenv('PFB_TEST_TAR_REMOVE=');
	putenv('PFB_TEST_TIMEOUT_EXPIRE=0');
	putenv('PFB_TEST_PS=');
	clear_observations();
}

function hooks_registered(): bool
{
	$earlyshellcmd = json_encode(config_get_path('system/earlyshellcmd')) ?: '';
	$shellcmd = json_encode(config_get_path('installedpackages/shellcmdsettings/config')) ?: '';
	return str_contains($earlyshellcmd, 'pfblockerng.sh aliastables')
		&& str_contains($shellcmd, 'pfblockerng.sh aliastables');
}

function write_distractors(string $root): void
{
	file_put_contents("{$root}/aliasdir/notes.txt", "not selected\n");
	file_put_contents("{$root}/var_unbound/other.conf", "not selected\n");
}

function write_sources(string $root): void
{
	file_put_contents("{$root}/aliasdir/pfB_Block_v4.txt", "10.0.0.1\n10.0.0.2\n");
	file_put_contents("{$root}/aliasdir/pfB_Block_v6.txt", "2001:db8::1\n");
	file_put_contents("{$root}/aliasdir/pfB_sp ace'q\"\$m.txt", "quoted name\n");
	file_put_contents("{$root}/dnsbl/dnsbl_file.conf", "local-zone: \"example.test\" static\n\x00\xff");
	file_put_contents("{$root}/var_unbound/pfb_unbound.conf", "server:\n");
	file_put_contents("{$root}/var_unbound/pfb_py_block.py", "print('ok')\n");
	write_distractors($root);
}

function reset_tree(string $root, bool $sources): void
{
	foreach (['etc', 'aliasdir', 'dnsbl', 'var_unbound'] as $dir) {
		exec('rm -rf ' . escapeshellarg("{$root}/{$dir}"));
		mkdir("{$root}/{$dir}", 0700);
	}
	clearstatcache(true);
	if ($sources) {
		write_sources($root);
	} else {
		write_distractors($root);
	}
}

function selected_sources(string $root): array
{
	$sources = [];
	foreach (SELECTED as $relative) {
		$sources[$relative] = (string) file_get_contents("{$root}/{$relative}");
	}
	return $sources;
}

function assert_archive_holds(string $archive, string $root, array $expected): void
{
	check(is_file($archive), 'archive is missing');
	same('BZh', (string) file_get_contents($archive, false, null, 0, 3), 'archive is not bzip2');
	exec('tar -jtf ' . escapeshellarg($archive) . ' 2>&1', $listing, $status);
	same(0, $status, 'archive listing failed');
	same(count($expected), count(array_filter($listing, 'strlen')), 'archive member count');
	$extract = "{$root}/extract";
	exec('rm -rf ' . escapeshellarg($extract));
	clearstatcache(true);
	mkdir($extract, 0700);
	exec('tar -jxf ' . escapeshellarg($archive) . ' -C ' . escapeshellarg($extract) . ' 2>&1', $out, $status);
	same(0, $status, 'archive extraction failed');
	foreach ($expected as $relative => $bytes) {
		same($bytes, @file_get_contents("{$extract}{$root}/{$relative}"), "member {$relative}");
	}
	exec('rm -rf ' . escapeshellarg($extract));
}

function snapshot_archive(string $archive): array
{
	exec('stat -c ' . escapeshellarg('%i %y') . ' ' . escapeshellarg($archive) . ' 2>&1', $stat, $status);
	same(0, $status, 'archive stat failed: ' . implode(' ', $stat));
	return [$stat[0], md5_file($archive)];
}

function run_cli(string $root, string $mode): array
{
	exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("{$root}/harness.php") . ' ' . escapeshellarg($mode) . ' 2>&1', $out, $status);
	return [$status, implode("\n", $out)];
}

function stop_map(string $root): array
{
	return [
		'/usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc' => PHP_BINARY . " -f {$root}/harness.php",
		'/usr/local/sbin/read_xml_tag.sh' => "{$root}/bin/read_xml_tag.sh",
		'/usr/bin/timeout' => "{$root}/bin/timeout",
		'/usr/bin/logger' => "{$root}/bin/logger",
		'/usr/bin/killall' => "{$root}/bin/killall",
		'/bin/pgrep' => "{$root}/bin/pgrep",
		'/bin/kill' => "{$root}/bin/kill",
		'/bin/ps' => "{$root}/bin/ps",
	];
}

function run_stop(string $surface, string $root): array
{
	$GLOBALS['pfb_test_rc'] = null;
	($surface === 'filter' ? 'pfb_filter_service' : 'pfb_dnsbl_service')();
	$body = $GLOBALS['pfb_test_rc']['stop'] ?? null;
	check(is_string($body) && $body !== '', "{$surface} stop body was not generated");
	$file = "{$root}/stop_{$surface}.sh";
	file_put_contents($file, strtr($body, stop_map($root)));
	exec('dash -n ' . escapeshellarg($file) . ' 2>&1', $syntax, $syntaxStatus);
	same(0, $syntaxStatus, "{$surface} stop body syntax: " . implode("\n", $syntax));
	exec('dash ' . escapeshellarg($file) . ' 2>&1', $out, $status);
	return [$status, implode("\n", $out)];
}

$passes = 0;
$failures = 0;
$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
$root = sys_get_temp_dir() . '/pfb_ramdisk_3_3_' . bin2hex(random_bytes(5));
foreach (['bin', 'etc', 'state', 'aliasdir', 'dnsbl', 'var_unbound'] as $dir) {
	mkdir("{$root}/{$dir}", 0700, true);
}
putenv("PFB_TEST_STATE={$root}/state/config.json");
putenv("PFB_TEST_WRITES={$root}/state/config-writes.log");
putenv("PFB_TEST_LOGFILE={$root}/state/pfb.log");
putenv("PFB_TEST_EVENTS={$root}/state/events.log");
write_fixtures($root);
file_put_contents("{$root}/harness.php", build_harness($source, $root, [
	'aliasdir' => "{$root}/aliasdir",
	'aliasarchive' => "{$root}/etc/aliastables.tar.bz2",
	'dnsbl_file' => "{$root}/dnsbl/dnsbl_file",
]));

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
	if (!(error_reporting() & $severity)) {
		return false;
	}
	throw new ErrorException($message, 0, $severity, $file, $line);
});
require "{$root}/harness.php";
$GLOBALS['pfbDefault'] = $GLOBALS['pfb'];

// Ramdisk archive: conf/save create a missing archive; update always refreshes; OFF cleans up.
row('conf: missing archive is created as real bz2 with exact selected bytes and boot hooks registered', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, false);
	$selected = selected_sources($root);
	pfb_aliastables('conf');
	assert_archive_holds(archive(), $root, $selected);
	check(hooks_registered(), 'conf did not register boot hooks');
});

row('conf: present archive keeps bytes, inode and mtime and runs no tar after sources change', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, true);
	pfb_aliastables('update');
	$before = snapshot_archive(archive());
	clear_observations();
	file_put_contents("{$root}/aliasdir/pfB_Block_v4.txt", "10.9.9.9\n");
	pfb_aliastables('conf');
	same($before, snapshot_archive(archive()), 'conf rewrote the present archive');
	same([], events_matching('tar '), 'conf invoked tar');
});

row('save: present archive keeps bytes and inode, config untouched, no tar', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, true);
	pfb_aliastables('update');
	$before = snapshot_archive(archive());
	$stateBefore = state_text();
	clear_observations();
	file_put_contents("{$root}/aliasdir/pfB_Block_v4.txt", "10.9.9.9\n");
	pfb_aliastables('save');
	same($before, snapshot_archive(archive()), 'save rewrote the present archive');
	same($stateBefore, state_text(), 'save changed config');
	same([], writes(), 'save wrote config');
	same([], events_matching('tar '), 'save invoked tar');
});

row('save: missing archive is created as real bz2 with zero config mutation even when hooks are absent', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, false);
	$selected = selected_sources($root);
	$stateBefore = state_text();
	pfb_aliastables('save');
	assert_archive_holds(archive(), $root, $selected);
	same($stateBefore, state_text(), 'save changed config');
	same([], writes(), 'save wrote config');
	check(!hooks_registered(), 'save registered boot hooks');
});

row('CLI aliastables_save: real save path creates the bz2 and writes no config', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, false);
	$selected = selected_sources($root);
	$stateBefore = state_text();
	[$status, $output] = run_cli($root, 'aliastables_save');
	same(0, $status, "CLI exit status: {$output}");
	assert_archive_holds(archive(), $root, $selected);
	same($stateBefore, state_text(), 'CLI save changed config');
	same([], writes(), 'CLI save wrote config');
});

row('OFF + stale hooks: save and CLI keep the archive and never write config; write double records a conf write', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, true);
	pfb_aliastables('update');
	$archive = snapshot_archive(archive());
	reset_state(false, true);
	$stateBefore = state_text();
	pfb_aliastables('save');
	check(is_file(archive()), 'in-process save removed the archive while OFF');
	same($archive, snapshot_archive(archive()), 'in-process save changed the archive');
	same($stateBefore, state_text(), 'in-process save changed config');
	same([], writes(), 'in-process save wrote config');
	[$status, $output] = run_cli($root, 'aliastables_save');
	same(0, $status, "CLI exit status: {$output}");
	same($archive, snapshot_archive(archive()), 'CLI save changed the archive');
	same($stateBefore, state_text(), 'CLI save changed config');
	same([], writes(), 'CLI save wrote config');
	pfb_aliastables('conf');
	check(writes() !== [], 'config write double did not record a conf write');
});

row('OFF: conf and update keep non-RAM cleanup (archive deleted, hooks removed)', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, true);
	pfb_aliastables('update');
	check(is_file(archive()), 'archive was not built while ON');
	reset_state(false, true);
	pfb_aliastables('conf');
	check(!file_exists(archive()), 'OFF conf kept the archive');
	check(!hooks_registered(), 'OFF conf kept boot hooks');
	reset_state(true, true);
	pfb_aliastables('update');
	reset_state(false, true);
	pfb_aliastables('update');
	check(!file_exists(archive()), 'OFF update kept the archive');
	check(!hooks_registered(), 'OFF update kept boot hooks');
});

row('ON + no selected sources: save and conf leave no archive and no temp file; conf still registers hooks', static function () use ($root): void {
	reset_tree($root, false);
	reset_state(true, false);
	$stateBefore = state_text();
	pfb_aliastables('save');
	check(!file_exists(archive()), 'save created an archive from an empty selection');
	same([], glob("{$root}/etc/*"), 'save left a file in etc');
	same($stateBefore, state_text(), 'save changed config');
	pfb_aliastables('conf');
	check(!file_exists(archive()), 'conf created an archive from an empty selection');
	same([], glob("{$root}/etc/*"), 'conf left a file in etc');
	check(hooks_registered(), 'conf did not register hooks for an empty selection');
});

row('ON + present archive + update: changed selected bytes replace the archive', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, false);
	pfb_aliastables('update');
	file_put_contents("{$root}/aliasdir/pfB_Block_v4.txt", "10.9.9.9\n");
	pfb_aliastables('update');
	assert_archive_holds(archive(), $root, selected_sources($root));
});

row('destination parent absent: no parent created, no archive, no success claim (conf, save, update)', static function () use ($root): void {
	foreach (['conf', 'save', 'update'] as $mode) {
		reset_tree($root, true);
		reset_state(true, false);
		$GLOBALS['pfb']['aliasarchive'] = "{$root}/absent/aliastables.tar.bz2";
		pfb_aliastables($mode);
		check(!is_dir("{$root}/absent"), "{$mode} created the missing parent");
		check(!file_exists("{$root}/absent/aliastables.tar.bz2"), "{$mode} created an archive in a missing parent");
		check(!str_contains(logtext(), 'Archiving selected pfBlockerNG files'), "{$mode} logged success for a missing parent");
	}
});

row('destination parent is a regular file: file untouched, no archive, no success claim (conf, save, update)', static function () use ($root): void {
	foreach (['conf', 'save', 'update'] as $mode) {
		reset_tree($root, true);
		reset_state(true, false);
		file_put_contents("{$root}/notdir", 'keep');
		$GLOBALS['pfb']['aliasarchive'] = "{$root}/notdir/aliastables.tar.bz2";
		pfb_aliastables($mode);
		same('keep', file_get_contents("{$root}/notdir"), "{$mode} changed the non-directory parent");
		check(!file_exists("{$root}/notdir/aliastables.tar.bz2"), "{$mode} created an archive under a file");
		check(!str_contains(logtext(), 'Archiving selected pfBlockerNG files'), "{$mode} logged success for a file parent");
	}
});

row('publication failure: non-empty directory at the destination stays intact, no temp left, no success claim', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, false);
	mkdir(archive(), 0700);
	file_put_contents(archive() . '/keep', 'keep');
	pfb_aliastables('update');
	check(is_dir(archive()) && file_get_contents(archive() . '/keep') === 'keep', 'destination directory was altered');
	same([archive()], glob("{$root}/etc/*"), 'temporary file left behind');
	check(!str_contains(logtext(), 'Archiving selected pfBlockerNG files'), 'failed publication logged success');
});

row('failed build (tar input disappears): previous archive byte-identical, temp removed, no success claim', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, false);
	pfb_aliastables('update');
	$before = snapshot_archive(archive());
	clear_observations();
	putenv("PFB_TEST_TAR_REMOVE={$root}/aliasdir/pfB_Block_v4.txt");
	pfb_aliastables('update');
	check(count(events_matching('tar ')) === 1, 'tar was not invoked by the failed build');
	same($before, snapshot_archive(archive()), 'failed build changed the previous archive');
	same([archive()], glob("{$root}/etc/*"), 'temporary file left behind');
	check(!str_contains(logtext(), 'Archiving selected pfBlockerNG files'), 'failed build logged success');
});

row('failed build (tar input disappears) with no prior archive: archive stays missing, temp removed', static function () use ($root): void {
	reset_tree($root, true);
	reset_state(true, false);
	putenv("PFB_TEST_TAR_REMOVE={$root}/aliasdir/pfB_Block_v4.txt");
	pfb_aliastables('conf');
	check(count(events_matching('tar ')) === 1, 'conf did not attempt the build');
	check(!file_exists(archive()), 'failed build created an archive');
	same([], glob("{$root}/etc/*"), 'temporary file left behind');
	check(!str_contains(logtext(), 'Archiving selected pfBlockerNG files'), 'failed build logged success');
});

// Generated rc stop surfaces, executed under dash with fixtures for every privileged path.
foreach (['filter', 'dnsbl'] as $surface) {
	row("{$surface} stop: ON + missing archive is built through the real save CLI with zero config writes", static function () use ($root, $surface): void {
		reset_tree($root, true);
		reset_state(true, false);
		$selected = selected_sources($root);
		$stateBefore = state_text();
		[$status, $output] = run_stop($surface, $root);
		same(0, $status, "stop exit status: {$output}");
		assert_archive_holds(archive(), $root, $selected);
		check(count(events_matching('timeout -s TERM -k 5 60 ')) === 1, 'bounded save was not invoked exactly once');
		same($stateBefore, state_text(), 'stop changed config');
		same([], writes(), 'stop wrote config');
	});

	row("{$surface} stop: ON + present archive is not rewritten and no save runs", static function () use ($root, $surface): void {
		reset_tree($root, true);
		reset_state(true, false);
		pfb_aliastables('update');
		$before = snapshot_archive(archive());
		clear_observations();
		[$status, $output] = run_stop($surface, $root);
		same(0, $status, "stop exit status: {$output}");
		same($before, snapshot_archive(archive()), 'stop rewrote the present archive');
		same([], events_matching('timeout '), 'stop invoked the save');
		same([], events_matching('tar '), 'stop invoked tar');
	});

	row("{$surface} stop: OFF writes nothing (no archive, no save, no config)", static function () use ($root, $surface): void {
		reset_tree($root, true);
		reset_state(false, false);
		$stateBefore = state_text();
		[$status, $output] = run_stop($surface, $root);
		same(0, $status, "stop exit status: {$output}");
		check(!file_exists(archive()), 'OFF stop created an archive');
		same([], events_matching('timeout '), 'OFF stop invoked the save');
		same($stateBefore, state_text(), 'OFF stop changed config');
		same([], writes(), 'OFF stop wrote config');
	});
}

foreach ([['filter', '4242 php -f pfblockerng.inc filterlog', 'kill -9 4242'], ['dnsbl', '4343 php -f pfblockerng.inc queries', 'kill -9 4343']] as [$surface, $psLine, $kill]) {
	row("{$surface} stop: timed-out save still completes the stop and daemon-stop continues", static function () use ($root, $surface, $psLine, $kill): void {
		reset_tree($root, true);
		reset_state(true, false);
		putenv('PFB_TEST_TIMEOUT_EXPIRE=1');
		putenv("PFB_TEST_PS={$psLine}");
		[$status, $output] = run_stop($surface, $root);
		same(0, $status, "stop exit status: {$output}");
		check(count(events_matching('timeout -s TERM -k 5 60 ')) === 1, 'bounded save command was not invoked');
		check(in_array($kill, file_lines('PFB_TEST_EVENTS'), true), "daemon-stop continuation did not run: {$kill}");
		check(!file_exists(archive()), 'expired save left an archive');
	});
}

exec('rm -rf ' . escapeshellarg($root));
echo "RESULT: {$passes} passed, {$failures} failed\n";
echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);
