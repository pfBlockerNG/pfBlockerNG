<?php

declare(strict_types=1);

/**
 * Child process for DnsProxyActivationRollbackTest's race cases (issue #3572): one of two recoveries of the same box, each
 * a real process, so the locks are the kernel's flock(2) and not a double. argv: role (owner | contender | fd | leaf), state
 * directory, the ordinal of the DNS config unlock the owner is held after (0 = never), the rc script the proxy is named by,
 * and for fd and leaf the nonce that names the run.
 *
 * The state directory is the parent's: memory.json (the config this process starts from: for the contender, the copy it
 * read BEFORE the owner ran), disk.json (config.xml as it is on disk: every fresh read takes it, every write_config()
 * rewrites it, so the owner's writes reach the contender only through it), pfb.ser (the runtime $pfb, $g and the interface
 * doubles), unbound-start (the Unbound restart command), and the proxy's pidfile and marker, which both processes read.
 * $g['tmp_path'] is the state directory too: it is where pfSense's try_lock() and the rollback's operation lock keep their
 * lock files, so both reach the same inode.
 * Each effect is appended to events.log as `<role> <kind> [detail]` in the order it happens: write (write_config), svc (a
 * proxy service call), rc_stop (the rc script's stop), unbound_start (an Unbound restart), lock / blocked / unlock (the
 * locks), done (the recovery returned). On stdout, one line each: `BLOCKED <lock>` when an attempt finds a lock held,
 * `WAITING <lock>` when the recovery then enters its positive wait for it (it goes on only after a line on stdin),
 * `PAUSED <n> <json>` when the owner stops after its n-th DNS config unlock, or the fd role at the notice that reports its
 * rollback finished (`PAUSED notice`), reporting the toggle and snapshot config.xml holds (it then waits for a line on
 * stdin), and `DONE <json>` when the recovery returns.
 *
 * The locks are the kernel's. try_lock() makes one non-blocking flock(LOCK_EX | LOCK_NB) attempt; a timeout of 0 returns NULL
 * at once when the name is held, and a positive budget announces BLOCKED and WAITING, then blocks in flock(LOCK_EX) once
 * resumed. The rollback's operation lock no longer comes from try_lock(): the rehosted roll_back() and pfb_flock_bounded()
 * call flock() through race_flock(), which returns the kernel's answer untouched and only observes it. The positive wait is
 * the production helper's own: the first attempt that finds the lock held makes it sleep on the virtual clock, and the
 * clock's sleep hook announces WAITING and holds the retry until the parent resumes it. There is no poll loop. This fixture
 * tests mutual exclusion only: a timeout's FALSE is covered by PfbFlockBoundedTest, not here.
 *
 * The fd role is the owner with the rollback held at its completion notice, its Unbound start command leaving a daemon
 * behind: the leaf role (see race_leaf()).
 */

$race = ['role' => (string) $argv[1], 'dir' => (string) $argv[2], 'pause' => (int) $argv[3], 'nonce' => (string) ($argv[5] ?? ''),
	'unlocks' => 0, 'names' => [], 'blocked' => NULL];
$raceRcfile = (string) $argv[4];
$repo = dirname(__DIR__, 3);

if ($race['role'] === 'leaf') {
	race_leaf($race);
}

const RACE_TOGGLE = 'installedpackages/pfblockerngdns/config/0/pfb_dns';
const RACE_SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';

// Defined before the bootstrap, which defines only what is still undefined: the rc script and the start command are the
// state directory's, and the operation lock's budget is the production's 30 s (the readiness wait is set on the clock below).
define('PFB_DNS_PROXY_RCFILE', $raceRcfile);
define('PFB_DNS_PROXY_START_WAIT', 30);
define('PFB_UNBOUND_START_CMD', escapeshellarg($race['dir'] . '/unbound-start') . ' ' . escapeshellarg($race['role']) . ' '
	. escapeshellarg($race['dir'] . '/events.log')
	. ($race['role'] === 'fd' ? ' ' . implode(' ', array_map('escapeshellarg', [PHP_BINARY, __FILE__, $race['dir'], $race['nonce']])) : ''));

require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/support/PfbFlockClockFixture.php';

function race_event(string $detail): void
{
	file_put_contents($GLOBALS['race']['dir'] . '/events.log', $GLOBALS['race']['role'] . " {$detail}\n", FILE_APPEND);
}

function race_say(string $line): void
{
	fwrite(STDOUT, $line . "\n");
	fflush(STDOUT);
}

function race_disk(): array
{
	return json_decode((string) file_get_contents($GLOBALS['race']['dir'] . '/disk.json'), TRUE, 512, JSON_THROW_ON_ERROR);
}

function race_persist(): void
{
	file_put_contents($GLOBALS['race']['dir'] . '/disk.json', json_encode($GLOBALS['config'], JSON_THROW_ON_ERROR));
}

function race_at(array $config, string $path): mixed
{
	foreach (explode('/', $path) as $key) {
		if (!is_array($config) || !array_key_exists($key, $config)) {
			return NULL;
		}
		$config = $config[$key];
	}
	return $config;
}

function race_proxy_valid(): void
{
	$GLOBALS['pfb_test_valid_pids'][$GLOBALS['pfb']['dns_proxy_pidfile']] = TRUE;
	$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_PIDFILE] = TRUE;
	race_backend_serves();
}

/**
 * The Unbound backend the gateway forwards to answers in this process: its pidfile names a live process and the process owns the
 * upstream's sockets, and the gateway's command line names that upstream. A process has no other process's sockstat or ps table.
 */
function race_backend_serves(): void
{
	$pidfile = $GLOBALS['g']['varrun_path'] . '/unbound.pid';
	file_put_contents($pidfile, "5151\n");
	$GLOBALS['pfb_test_valid_pids'][$pidfile] = TRUE;
	file_put_contents($GLOBALS['pfb_test_sockstat_output'],
		"unbound unbound 5151 3 tcp4 127.0.0.1:5353 *:*\nunbound unbound 5151 4 udp4 127.0.0.1:5353 *:*\n");
	file_put_contents($GLOBALS['pfb_test_ps_output'], '4242 ' . PFB_DNS_PROXY_DIR
		. "/bin/freebsd-amd64/pfb-dns --listen 127.0.0.1 --port 53 --upstream 127.0.0.1:5353\n");
}

/** The proxy comes up alive and never publishes its marker: the state the activation leaves a proxy that never serves in. */
function race_proxy_up(): void
{
	file_put_contents($GLOBALS['pfb']['dns_proxy_pidfile'], "4242\n");
	@unlink($GLOBALS['pfb']['dns_proxy_ready']);
	race_proxy_valid();
}

function race_proxy_down(): void
{
	@unlink($GLOBALS['pfb']['dns_proxy_pidfile']);
	@unlink($GLOBALS['pfb']['dns_proxy_ready']);
	unset($GLOBALS['pfb_test_valid_pids'][$GLOBALS['pfb']['dns_proxy_pidfile']], $GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_PIDFILE]);
}

/**
 * pfSense's try_lock() on the kernel's flock(2), one file per name under $g['tmp_path']. Mutual exclusion only: a timeout of
 * 0 returns NULL at once when the name is held; a positive budget announces BLOCKED and WAITING and blocks until the holder
 * releases.
 */
function try_lock($lock, $timeout = 5)
{
	$handle = fopen($GLOBALS['g']['tmp_path'] . "/{$lock}.lock", 'c');
	if (flock($handle, LOCK_EX | LOCK_NB)) {
		return race_locked($handle, $lock);
	}
	if ($timeout <= 0) {
		fclose($handle);
		return NULL;
	}
	race_event("blocked {$lock}");
	race_say("BLOCKED {$lock}");
	race_wait($lock);
	flock($handle, LOCK_EX);
	return race_locked($handle, $lock);
}

/** The recovery is in its positive wait for $lock: say so, and go on only when the parent resumes it. */
function race_wait(string $lock): void
{
	race_say("WAITING {$lock}");
	if (fgets(STDIN) === FALSE) {
		exit(3);
	}
}

/**
 * flock() as the rehosted bodies call it, observed and otherwise untouched: the kernel's answer and its would-block flag are
 * returned as they are, so a body that never acquires still fails, and a zero budget still times out. A would-block on an
 * acquire is announced BLOCKED and remembered, for the clock's sleep hook to turn into WAITING when the helper does wait.
 */
function race_flock($stream, int $operation, &$would_block = NULL): bool
{
	$GLOBALS['race']['blocked'] = NULL;
	$acquiring = ($operation & ~LOCK_NB) !== LOCK_UN;
	$lock = basename((string) (stream_get_meta_data($stream)['uri'] ?? ''), '.lock');
	$got = flock($stream, $operation, $would_block);
	if ($got && $acquiring) {
		race_locked($stream, $lock);
	} elseif (!$got && $acquiring && $would_block === 1) {
		race_event("blocked {$lock}");
		race_say("BLOCKED {$lock}");
		$GLOBALS['race']['blocked'] = $lock;
	}
	return $got;
}

/**
 * The leaf role: the daemon an Unbound start leaves behind. It leaves the start's process group, as a real daemon does, never
 * opens the operation lock, and talks to the parent over its own unix socket, so it shares none of the owner's pipes and does
 * not depend on the owner living. Whatever it holds of the lock files, it inherited. It reports `READY <nonce> <pid> <ppid>
 * <pgid> <sid> <json: the .lock files it holds open, where /proc says>`, answers `PING <nonce>` with `PONG <nonce> <pid>`,
 * and exits on `EXIT <nonce>`, on the socket's EOF, or after 30 s without a word: a bound on an orphan, never a verdict.
 */
function race_leaf(array $race): never
{
	posix_setsid();
	$control = @stream_socket_client('unix://' . $race['dir'] . '/leaf.sock', $errno, $error, 10);
	if ($control === FALSE) {
		exit(2);
	}
	$holds = [];
	foreach (glob('/proc/self/fd/*') ?: [] as $fd) {
		$target = @readlink($fd);
		if ($target !== FALSE && str_ends_with($target, '.lock')) {
			$holds[] = basename($target);
		}
	}
	fwrite($control, sprintf("READY %s %d %d %d %d %s\n", $race['nonce'], getmypid(), posix_getppid(), posix_getpgid(0), posix_getsid(0),
		json_encode($holds, JSON_THROW_ON_ERROR)));
	// The start command waits for this EOF: from here the daemon is out of the start's process group and known to the parent
	fclose(STDOUT);
	while (TRUE) {
		$read = [$control];
		$write = [];
		$except = [];
		if (stream_select($read, $write, $except, 30) !== 1) {
			exit(4);
		}
		$line = fgets($control);
		if ($line === FALSE) {
			exit(0);
		}
		$words = explode(' ', trim($line));
		if (($words[1] ?? '') !== $race['nonce']) {
			continue;
		}
		if ($words[0] === 'EXIT') {
			exit(0);
		}
		if ($words[0] === 'PING') {
			fwrite($control, "PONG {$race['nonce']} " . getmypid() . "\n");
		}
	}
}

function race_locked($handle, string $lock)
{
	$GLOBALS['race']['names'][(int) $handle] = $lock;
	race_event("lock {$lock}");
	return $handle;
}

/** pfSense's unlock(): releases the handle, and holds the owner after its configured DNS config unlock until it is released. */
function unlock($lock = 0)
{
	if (!is_resource($lock)) {
		return;
	}
	$name = $GLOBALS['race']['names'][(int) $lock] ?? '?';
	unset($GLOBALS['race']['names'][(int) $lock]);
	race_event("unlock {$name}");
	flock($lock, LOCK_UN);
	fclose($lock);
	if ($name !== 'pfb_dns_config') {
		return;
	}
	$GLOBALS['race']['unlocks']++;
	if ($GLOBALS['race']['unlocks'] !== $GLOBALS['race']['pause']) {
		return;
	}
	race_pause((string) $GLOBALS['race']['unlocks']);
}

/** Reports the toggle and snapshot config.xml holds, then holds this process until the parent writes a line on its stdin. */
function race_pause(string $at): void
{
	$disk = race_disk();
	race_say('PAUSED ' . $at . ' ' . json_encode([
		'toggle' => race_at($disk, RACE_TOGGLE),
		'saved' => race_at($disk, RACE_SAVED),
	], JSON_THROW_ON_ERROR));
	if (fgets(STDIN) === FALSE) {
		exit(3);
	}
}

/**
 * The shared double's notice, and in the fd role a stop at the one that reports the rollback finished: the operation lock is
 * still taken there, and the Unbound the rollback started has already been launched.
 */
function file_notice($id, $notice, $category = 'General', $url = '', $priority = 1, $local_only = false)
{
	$GLOBALS['pfb_test_file_notices'][] = array(
		'id'         => $id,
		'notice'     => $notice,
		'category'   => $category,
		'url'        => $url,
		'priority'   => $priority,
		'local_only' => $local_only,
	);
	if ($GLOBALS['race']['role'] === 'fd' && $id === 'pfBlockerNG DNS Proxy') {
		race_pause('notice');
	}
}

$state = unserialize((string) file_get_contents($race['dir'] . '/pfb.ser'));
$GLOBALS['pfb'] = $state['pfb'];
$GLOBALS['g'] = $state['g'];
// The lock files of pfSense's try_lock() and of the rollback's operation lock are one directory: $g['tmp_path'] is the state directory's
$GLOBALS['g']['tmp_path'] = $race['dir'];
foreach ($state['doubles'] as $name => $value) {
	$GLOBALS[$name] = $value;
}
$GLOBALS['config'] = json_decode((string) file_get_contents($race['dir'] . '/memory.json'), TRUE, 512, JSON_THROW_ON_ERROR);
$GLOBALS['pfb_test_config_read_calls'] = [];
if (is_file($GLOBALS['pfb']['dns_proxy_pidfile'])) {
	race_proxy_valid();
}

// config.xml is the file: a write lands on it, and a fresh read takes it (the trait's convention, over a shared file)
$GLOBALS['pfb_test_write_config_hook'] = static function (string $description): void {
	race_event("write {$description}");
	race_persist();
};
$GLOBALS['pfb_test_config_read_hook'] = static function (): void {
	if (end($GLOBALS['pfb_test_config_read_calls']) === [FALSE, FALSE]) {
		$GLOBALS['config'] = race_disk();
	}
};
$GLOBALS['pfb_test_service_hook'] = static function (string $fn, string $service): void {
	if ($service !== 'pfb_dns_proxy') {
		return;
	}
	race_event("svc {$fn}");
	if ($fn === 'stop_service') {
		race_proxy_down();
	} else {
		race_proxy_up();
	}
};
$GLOBALS['pfb_test_mwexec_hook'] = static function (string $command): int {
	if ($command === PFB_DNS_PROXY_RCFILE . ' stop') {
		race_event('rc_stop');
		race_proxy_down();
	}
	return 0;
};

// The recovery as the readiness confirmation runs it, with the rollback it calls and the bounded lock helper the rollback takes its
// operation lock with, all on the clock: the readiness wait and the operation lock's wait are the production 30 s, virtual, so
// the lock's positive wait is reached and observed (race_flock() and the sleep hook) without a real wait.
$clock = new PfbFlockClockFixture();
$namespace = $clock->loadChain(
	['pfb_dns_proxy_confirm_ready', 'pfb_dns_proxy_await_ready', 'pfb_dns_proxy_roll_back', 'pfb_flock_bounded'],
	['PFB_DNS_PROXY_START_WAIT' => PFB_DNS_PROXY_START_WAIT]
);
eval(sprintf(<<<'PHP'
	namespace %s;

	function flock($stream, int $operation, &$would_block = NULL): bool
	{
		return \race_flock($stream, $operation, $would_block);
	}
	PHP, $namespace));
$clock->setOnSleep(static function (): void {
	$lock = $GLOBALS['race']['blocked'];
	if ($lock !== NULL) {
		$GLOBALS['race']['blocked'] = NULL;
		race_wait($lock);
	}
});
$confirmed = ($namespace . '\\pfb_dns_proxy_confirm_ready')();
race_event('done');
race_say('DONE ' . json_encode(['confirmed' => $confirmed], JSON_THROW_ON_ERROR));
