<?php

declare(strict_types=1);

/**
 * Child process for DnsProxyActivationRollbackTest's race cases (issue #3572): one of two recoveries of the same box, each
 * a real process, so the locks are the kernel's flock(2) and not a double. argv: role (owner | contender), state
 * directory, the ordinal of the DNS config unlock the owner is held after (0 = never), the rc script the proxy is named by.
 *
 * The state directory is the parent's: memory.json (the config this process starts from: for the contender, the copy it
 * read BEFORE the owner ran), disk.json (config.xml as it is on disk: every fresh read takes it, every write_config()
 * rewrites it, so the owner's writes reach the contender only through it), pfb.ser (the runtime $pfb, $g and the interface
 * doubles), unbound-start (the Unbound restart command), and the proxy's pidfile and marker, which both processes read.
 * Each effect is appended to events.log as `<role> <kind> [detail]` in the order it happens: write (write_config), svc (a
 * proxy service call), rc_stop (the rc script's stop), unbound_start (an Unbound restart), lock / blocked / unlock (the
 * locks), done (the recovery returned). On stdout, one line each: `BLOCKED <lock>` when an attempt finds a lock held,
 * `PAUSED <n> <json>` when the owner stops after its n-th DNS config unlock, reporting the toggle and snapshot config.xml
 * holds (it then waits for a line on stdin), and `DONE <json>` when the recovery returns.
 *
 * The locks are real: try_lock() takes flock(LOCK_EX | LOCK_NB) on a file per name, tried first and then polled until its
 * timeout (a timeout of 0 gives up at once). The production code is the shipped .inc over the shared doubles.
 */

$race = ['role' => (string) $argv[1], 'dir' => (string) $argv[2], 'pause' => (int) $argv[3], 'unlocks' => 0, 'names' => []];
$raceRcfile = (string) $argv[4];
$repo = dirname(__DIR__, 3);

const RACE_TOGGLE = 'installedpackages/pfblockerngdns/config/0/pfb_dns';
const RACE_SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';

// Defined before the bootstrap, which defines only what is still undefined: the rc script and the start command are the
// state directory's, and the operation lock's budget is the production's 30 s (the readiness wait is set on the clock below).
define('PFB_DNS_PROXY_RCFILE', $raceRcfile);
define('PFB_DNS_PROXY_START_WAIT', 30);
define('PFB_UNBOUND_START_CMD', escapeshellarg($race['dir'] . '/unbound-start') . ' ' . escapeshellarg($race['role']) . ' '
	. escapeshellarg($race['dir'] . '/events.log'));

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

/** pfSense's try_lock(), on the kernel's flock(2) per name: the handle on success, NULL when the name stays held for $timeout. */
function try_lock($lock, $timeout = 5)
{
	$handle = fopen($GLOBALS['race']['dir'] . "/{$lock}.lock", 'c');
	$deadline = microtime(TRUE) + $timeout;
	$announced = FALSE;
	while (TRUE) {
		if (flock($handle, LOCK_EX | LOCK_NB)) {
			$GLOBALS['race']['names'][(int) $handle] = $lock;
			race_event("lock {$lock}");
			return $handle;
		}
		if (!$announced) {
			$announced = TRUE;
			race_event("blocked {$lock}");
			race_say("BLOCKED {$lock}");
		}
		if (microtime(TRUE) >= $deadline) {
			fclose($handle);
			return NULL;
		}
		usleep(20000);
	}
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
	$disk = race_disk();
	race_say('PAUSED ' . $GLOBALS['race']['unlocks'] . ' ' . json_encode([
		'toggle' => race_at($disk, RACE_TOGGLE),
		'saved' => race_at($disk, RACE_SAVED),
	], JSON_THROW_ON_ERROR));
	if (fgets(STDIN) === FALSE) {
		exit(3);
	}
}

$state = unserialize((string) file_get_contents($race['dir'] . '/pfb.ser'));
$GLOBALS['pfb'] = $state['pfb'];
$GLOBALS['g'] = $state['g'];
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

// The recovery as the readiness confirmation runs it: the readiness wait is 0 on the clock, the operation lock's budget is
// the production 30 s (it is taken by the global roll_back(), which this namespace does not load).
$clock = new PfbFlockClockFixture();
$namespace = $clock->loadChain(['pfb_dns_proxy_confirm_ready', 'pfb_dns_proxy_await_ready'], ['PFB_DNS_PROXY_START_WAIT' => 0]);
$confirmed = ($namespace . '\\pfb_dns_proxy_confirm_ready')();
race_event('done');
race_say('DONE ' . json_encode(['confirmed' => $confirmed], JSON_THROW_ON_ERROR));
