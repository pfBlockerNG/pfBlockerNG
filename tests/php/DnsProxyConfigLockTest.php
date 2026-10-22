<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNSBL settings page and pfb_dns_proxy_resolver() both read-modify-write config.xml: the page
 * replaces the whole pfblockerngdnsblsettings section, the Resolver move writes its snapshot marker into that same
 * section and moves the unbound keys. Each works on the copy of config.xml it read when its process started, and
 * pfSense's write_config() writes that copy back whole, so the later writer erases whatever the earlier one wrote.
 *
 * Both therefore take ONE named, bounded pfSense lock (try_lock(): it gives up after a hard cap, never waits for
 * ever) and read config.xml afresh once they hold it, then write and release. Intent pinned here:
 *   - the lock is taken before the fresh read and held through write_config(), and released on every way out;
 *   - what the move snapshots and rewrites comes from the fresh read, not from the copy read at process start;
 *   - a lock that stays taken, or a fresh read that fails, abandons the move or restore (nothing written, snapshot kept,
 *     operator told) for the next apply to retry, and a restore abandoned that way never stopped the proxy: the
 *     proxy is stopped (up to 7 s) only once the lock is held and config.xml was read afresh, so the Resolver that
 *     stayed moved keeps being served;
 *   - a restore abandoned because the proxy outlived its stop restarts it, after the lock is released, so the
 *     moved Resolver is served again;
 *   - a restore reads config.xml afresh under the lock BEFORE it decides there is nothing to put back: this process's copy can
 *     predate a takeover another apply just made, and a restore that trusts it leaves the Resolver moved with the proxy it needs
 *     about to be removed; the copy that read left behind is what the caller's ownership checks then see.
 *
 * The lock and the config re-read are the pfsense_doubles.php doubles: try_lock() records every attempt and models
 * a lock that is not reentrant, config_read_file() runs a hook standing in for what another process wrote.
 */
#[CoversFunction('pfb_dns_proxy_resolver')]
#[CoversFunction('pfb_dns_config_lock')]
#[CoversFunction('pfb_dns_config_refresh')]
final class DnsProxyConfigLockTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const LOCK = 'pfb_dns_config';
	private const DOUBLE_GLOBALS = ['pfb_test_lock_events', 'pfb_test_lock_held', 'pfb_test_try_lock_fail', 'pfb_test_config_read_hook',
		'pfb_test_config_read_fails', 'pfb_test_config_read_calls', 'pfb_test_config_read_lock_held', 'pfb_test_write_config_hook', 'pfb_test_write_config_result',
		'pfb_test_write_config_calls', 'pfb_test_file_notices', 'pfb_test_service_calls', 'pfb_test_service_hook', 'pfb_test_valid_pids', 'pfb_test_rcfiles', 'pfb_test_rcfile_writes',
		'pfb_test_mwexec', 'pfb_test_mwexec_hook'];

	private string $tmp;
	private bool $hadPfb = FALSE;
	private bool $hadConfig = FALSE;
	private array $originalPfb = [];
	private array $originalConfig = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		foreach (self::DOUBLE_GLOBALS as $name) {
			unset($GLOBALS[$name]);
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_proxy_lock_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'logdir' => $this->tmp,
			'log'    => "{$this->tmp}/pfb.log",
			'errlog' => "{$this->tmp}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$this->setUpUpstreamFixture();
		$keys = array_fill_keys(PFB_DNS_PROXY_RESOLVER_KEYS, ['present' => FALSE, 'value' => NULL]);
		PfbConfig::writeSystem('dns/pfb_dns_saved', base64_encode((string) json_encode($keys)));
		pfb_dns_proxy_service();
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$this->tearDownUpstreamFixture();
		$this->clearProxyFiles();
		foreach (self::DOUBLE_GLOBALS as $name) {
			unset($GLOBALS[$name]);
		}
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->tmp);
	}

	/** The Resolver as the user has it: DoT on, two LAN interfaces, own options. */
	private function seedResolver(array $override = []): array
	{
		$unbound = $override + [
			'enable'           => '',
			'sslcertref'       => 'cert123',
			'tlsport'          => '853',
			'port'             => '53',
			'active_interface' => 'lan,opt1',
			'enablessl'        => '',
			'custom_options'   => base64_encode("do-ip6: no\nprefetch: yes"),
		];
		$GLOBALS['config']['unbound'] = $unbound;
		return $unbound;
	}

	/** Moves the Resolver (ON) with the lock doubles recording from a clean slate; returns the moved config. */
	private function moveThenResetDoubles(): array
	{
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE), 'test bootstrap: the move happens');
		foreach (['pfb_test_lock_events', 'pfb_test_config_read_calls', 'pfb_test_config_read_lock_held', 'pfb_test_write_config_calls', 'pfb_test_file_notices'] as $name) {
			unset($GLOBALS[$name]);
		}
		return $GLOBALS['config'];
	}

	/** @return list<array<int,mixed>> */
	private function lockEvents(): array
	{
		return $GLOBALS['pfb_test_lock_events'] ?? [];
	}

	private function lockHeld(): bool
	{
		return !empty($GLOBALS['pfb_test_lock_held']);
	}

	private function writes(): int
	{
		return count($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	// -----------------------------------------------------------------------
	// L1 -- the lock, the fresh read and the write, in that order
	// -----------------------------------------------------------------------

	public function testTheMoveTakesOneNamedBoundedLockThenReadsFreshThenWritesThenReleases(): void
	{
		// Given an unmoved Resolver, and hooks that see whether the lock is held at the fresh read and at the write
		$this->seedResolver();
		$order = [];
		$GLOBALS['pfb_test_config_read_hook'] = function () use (&$order): void {
			$order[] = 'read:' . ($this->lockHeld() ? 'held' : 'free');
		};
		$GLOBALS['pfb_test_write_config_hook'] = function () use (&$order): void {
			$order[] = 'write:' . ($this->lockHeld() ? 'held' : 'free');
		};

		// When the proxy is turned on
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		// Then config.xml was read afresh and written while the lock was held, and the lock was released after
		$this->assertSame(['read:held', 'write:held'], $order);
		$events = $this->lockEvents();
		$this->assertCount(2, $events, 'one acquire, one release');
		$this->assertSame('try_lock', $events[0][0]);
		$this->assertSame(self::LOCK, $events[0][1]);
		$this->assertGreaterThan(0, $events[0][2], 'the wait is bounded: try_lock() gives up after this many seconds');
		$this->assertLessThanOrEqual(30, $events[0][2], 'and short enough for a web request');
		$this->assertSame(['unlock'], $events[1]);
		$this->assertFalse($this->lockHeld(), 'the lock is released');
	}

	public function testTheMoveSnapshotsAndRewritesWhatTheFreshReadFoundNotWhatThisProcessReadAtStart(): void
	{
		// Given this process read the Resolver before the admin saved new Custom Options on the Resolver page
		$stale = $this->seedResolver();
		$fresh = $stale;
		$fresh['custom_options'] = base64_encode("do-ip6: no\nprefetch: yes\ncache-min-ttl: 60");
		$GLOBALS['pfb_test_config_read_hook'] = static function () use ($fresh): void {
			$GLOBALS['config']['unbound'] = $fresh;
		};
		$this->assertNotSame($fresh['custom_options'], config_get_path('unbound/custom_options'), 'before: this process holds the stale copy');

		// When the proxy is turned on
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		// Then the snapshot and the rewritten Custom Options are built on the admin's saved text
		$saved = pfb_dns_proxy_saved();
		$this->assertIsArray($saved);
		$this->assertSame($fresh['custom_options'], $saved['custom_options']['value'], 'the snapshot restores what the admin saved');
		$this->assertStringContainsString('cache-min-ttl: 60', (string) base64_decode((string) config_get_path('unbound/custom_options')),
			'the moved Custom Options keep the admin\'s newer lines');
	}

	public function testTheRestoreTakesTheLockAndReadsFreshBeforeItStopsTheProxyThenWritesUnderTheLock(): void
	{
		// Given a moved Resolver, and hooks that see whether the lock is held at the fresh read, the stop and the write
		$this->moveThenResetDoubles();
		$seen = [];
		$GLOBALS['pfb_test_config_read_hook'] = function () use (&$seen): void {
			$seen[] = 'read:' . ($this->lockHeld() ? 'held' : 'free');
		};
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen): void {
			$seen[] = "{$fn}:{$service}:" . ($this->lockHeld() ? 'held' : 'free');
		};
		$GLOBALS['pfb_test_mwexec_hook'] = function (string $command) use (&$seen): int {
			$seen[] = str_replace(PFB_DNS_PROXY_RCFILE, 'rc', $command) . ':' . ($this->lockHeld() ? 'held' : 'free');
			return 0;
		};
		$GLOBALS['pfb_test_write_config_hook'] = function () use (&$seen): void {
			$seen[] = 'write:' . ($this->lockHeld() ? 'held' : 'free');
		};

		// When the proxy is turned off
		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));

		// Then the proxy was stopped (once, and never restarted) only after the lock was held and config.xml read
		// afresh, the restore was written under the lock, and the lock is released
		$this->assertSame(['read:held', 'rc stop:held', 'write:held'], $seen);
		$this->assertSame([['try_lock', self::LOCK, $this->lockEvents()[0][2]], ['unlock']], $this->lockEvents());
		$this->assertSame([TRUE], $GLOBALS['pfb_test_config_read_lock_held'], 'config.xml is read afresh once, under the lock');
		$this->assertNull(pfb_dns_proxy_saved());
	}

	public function testARestoreThatHoldsTheLockStopsTheLiveProxyItOwns(): void
	{
		// Given a moved Resolver and the live proxy that serves it
		$this->moveThenResetDoubles();
		$this->seedLiveProxyThatAStopClears();
		$this->assertProxyStillServes('before');

		// When the restore runs with the lock free
		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));

		// Then the stop cleared that proxy's pids and marker: the proxies the tests below read back are ones a stop does clear
		$this->assertProxyWasStopped('after the restore');
	}

	/** @return array<string,array{string}> the pidfile that still names a live process after the stop */
	public static function survivors(): array
	{
		return [
			'the proxy itself'    => [PFB_DNS_PROXY_PIDFILE],
			'only its supervisor' => [PFB_DNS_PROXY_DAEMON_PIDFILE],
		];
	}

	#[DataProvider('survivors')]
	public function testARestoreAbandonedForAProxyThatOutlivedItsStopRestartsItOnceTheLockIsReleased(string $pidfile): void
	{
		// Given a moved Resolver and a proxy that survives its stop, and a hook that sees whether the lock is held at
		// each service call
		$this->moveThenResetDoubles();
		$GLOBALS['pfb_test_valid_pids'] = [$pidfile => TRUE];
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen): void {
			$seen[] = "{$fn}:{$service}:" . ($this->lockHeld() ? 'held' : 'free');
		};
		$GLOBALS['pfb_test_mwexec_hook'] = function (string $command) use (&$seen): int {
			$seen[] = str_replace(PFB_DNS_PROXY_RCFILE, 'rc', $command) . ':' . ($this->lockHeld() ? 'held' : 'free');
			return 0;
		};

		// When the proxy is turned off
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the Resolver stays moved with its snapshot, and the proxy that serves it is started again AFTER the lock was
		// released: its start (up to 10 s on the start lock, 7 s to stop a survivor) must not lengthen the hold
		$this->assertFalse($changed);
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the restore is retried by the next apply');
		$this->assertSame(0, $this->writes());
		$this->assertSame(['rc stop:held', 'rc start:free'], $seen);
		$this->assertFalse($this->lockHeld());
	}

	public function testTheSettingsPagesLockWaitOutlastsTheProxyStopThatRunsUnderTheLock(): void
	{
		// Given the proxy's rc script, whose stop gives up after a fixed number of one-second ticks
		pfb_dns_proxy_service();
		$stop = (string) ($GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh']['stop'] ?? '');
		$this->assertSame(1, preg_match('~(\d+)\)\s*/usr/bin/logger[^\n]*still running after KILL~', $stop, $giveUp),
			'test bootstrap: the stop script names the tick it gives up at');

		// Then a settings save that arrives as the restore starts its stop still takes the lock inside its own bounded wait:
		// the stop's give-up ticks, plus a second for the restore's own fresh read and write
		$this->assertGreaterThan((int) $giveUp[1] + 1, PFB_DNS_CONFIG_LOCK_WAIT,
			'the lock wait must outlast the stop that now runs under the lock');
	}

	// -----------------------------------------------------------------------
	// L2 -- the lock stays taken
	// -----------------------------------------------------------------------

	/** @return array<string,array{bool}> whether the call moves (ON) or restores (OFF) */
	public static function directions(): array
	{
		return ['moving the Resolver' => [TRUE], 'restoring the Resolver' => [FALSE]];
	}

	#[DataProvider('directions')]
	public function testALockThatStaysTakenAbandonsTheCallWithoutWritingAndTellsTheOperator(bool $on): void
	{
		// Given another save holds the lock, over the Resolver in the state this direction starts from
		if ($on) {
			$this->seedResolver();
		} else {
			$this->moveThenResetDoubles();
		}
		$this->seedLiveProxyThatAStopClears();
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When the call is made
		$changed = pfb_dns_proxy_resolver($on);

		// Then nothing was read afresh or written, config.xml and the snapshot are as they were ...
		$this->assertFalse($changed);
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_config_read_calls'] ?? [], 'no config reload without the lock');
		$this->assertSame(0, $this->writes());
		$this->assertProxyStillServes('the proxy keeps serving the Resolver that stayed moved');
		if (!$on) {
			$this->assertNotNull(pfb_dns_proxy_saved(), 'the restore keeps the snapshot for the next apply');
		}

		// ... exactly one bounded attempt was made, nothing is held, and the operator-visible notice says what to do
		$this->assertCount(1, $this->lockEvents());
		$this->assertFalse($this->lockHeld());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('DNS proxy', $notice['notice']);
		$this->assertStringContainsString('locked', $notice['notice']);
		$this->assertStringContainsString('next apply', $notice['notice']);
		$this->assertSame(2, $notice['priority']);
		$this->assertStringContainsString('DNS proxy', (string) @file_get_contents($GLOBALS['pfb']['errlog']));
	}

	// -----------------------------------------------------------------------
	// L3 -- released on every way out; a restore with nothing to put back takes the lock too, to learn that
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function exits(): array
	{
		return [
			'a move'                                    => ['move'],
			'a move that finds the Resolver already moved' => ['idempotent'],
			'a move refused for Listen Port 5353'       => ['refused port'],
			'a move refused for an own 5353 interface'  => ['refused bind'],
			'a move refused for our block with no snapshot' => ['refused block'],
			'a restore'                                 => ['restore'],
			'a restore abandoned for a live proxy'      => ['abandoned'],
			'a restore of our block with no snapshot'   => ['no snapshot'],
		];
	}

	#[DataProvider('exits')]
	public function testTheLockIsReleasedOnEveryWayOut(string $exit): void
	{
		// Given the Resolver in the state this exit starts from
		switch ($exit) {
			case 'move':
				$this->seedResolver();
				break;
			case 'idempotent':
				$this->moveThenResetDoubles();
				break;
			case 'refused port':
				$this->seedResolver(['port' => '5353']);
				break;
			case 'refused bind':
				$this->seedResolver(['custom_options' => base64_encode("interface: 127.0.0.1@5353")]);
				break;
			case 'refused block':
				$this->moveThenResetDoubles();
				config_del_path(self::SAVED);
				break;
			case 'restore':
				$this->moveThenResetDoubles();
				break;
			case 'abandoned':
				$this->moveThenResetDoubles();
				$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => TRUE];
				break;
			case 'no snapshot':
				$this->moveThenResetDoubles();
				config_del_path(self::SAVED);
				break;
		}

		// When the call for its direction is made
		pfb_dns_proxy_resolver(in_array($exit, ['move', 'idempotent', 'refused port', 'refused bind', 'refused block'], TRUE));

		// Then the call ran under the lock (an abandoned restore too: its stop now runs under it), every acquire has its
		// release, and nothing is held
		$acquires = count(array_filter($this->lockEvents(), static fn (array $e): bool => $e[0] === 'try_lock'));
		$releases = count(array_filter($this->lockEvents(), static fn (array $e): bool => $e[0] === 'unlock'));
		$this->assertGreaterThan(0, $acquires, 'the call took the lock');
		$this->assertSame($acquires, $releases, 'one release per acquire');
		$this->assertFalse($this->lockHeld());
	}

	public function testARestoreOverAnUntouchedResolverStillTakesTheLockAndReadsFreshButStopsAndWritesNothing(): void
	{
		// Given a Resolver that looks untouched in this process's copy and in config.xml alike: every apply with the toggle off asks for the restore
		$this->seedResolver();
		$this->configXmlOnDisk();
		$this->seedLiveProxyThatAStopClears();

		// When it is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the lock was taken for the decision, config.xml was read afresh under it, and nothing was stopped or written
		$this->assertFalse($changed);
		$this->assertSame(['try_lock', 'unlock'], array_column($this->lockEvents(), 0), 'one bounded attempt, then its release');
		$this->assertSame([TRUE], $GLOBALS['pfb_test_config_read_lock_held'] ?? [], 'config.xml is read afresh once, under the lock');
		$this->assertSame(0, $this->writes());
		$this->assertProxyStillServes('there is nothing to put back');
		$this->assertFalse($this->lockHeld());
	}

	public function testARestoreFromACopyThatPredatesTheTakeoverPutsBackTheResolverTheFreshReadFinds(): void
	{
		// Given another apply moved the Resolver (config.xml holds the move and its snapshot) and this process still holds the
		// copy it read before: the user's Resolver, no snapshot
		$this->moveThenResetDoubles();
		$this->configXmlOnDisk();
		$GLOBALS['config'] = [];
		$this->seedResolver();
		unset($GLOBALS['pfb_test_service_calls']);
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen): void {
			$seen[] = "{$fn}:{$service}:" . ($this->lockHeld() ? 'held' : 'free');
		};
		$GLOBALS['pfb_test_mwexec_hook'] = function (string $command) use (&$seen): int {
			$seen[] = str_replace(PFB_DNS_PROXY_RCFILE, 'rc', $command) . ':' . ($this->lockHeld() ? 'held' : 'free');
			return 0;
		};
		$this->assertNull(pfb_dns_proxy_saved(), 'before: this process\'s copy shows nothing moved');
		$this->assertSame('lo0', $this->onDisk('unbound/active_interface'), 'before: config.xml holds the moved Resolver');
		$this->assertNotSame('', $this->onDisk(self::SAVED), 'before: and its snapshot');

		// When the proxy is turned off
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore ran from the fresh read: the proxy was stopped under the lock and config.xml has the user's Resolver back
		$this->assertTrue($changed, 'the restore the stale copy hid was made');
		$this->assertSame(['rc stop:held'], $seen);
		$this->assertSame('lan,opt1', $this->onDisk('unbound/active_interface'), 'config.xml has the user\'s interfaces again');
		$this->assertSame('', $this->onDisk(self::SAVED), 'and the snapshot is cleared');
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertFalse($this->lockHeld());
	}

	// -----------------------------------------------------------------------
	// L4 -- the shared lock helper
	// -----------------------------------------------------------------------

	public function testTheLockHelperReturnsTheHandleAfterAFreshReadAndNullWithoutReadingWhenTheLockIsTaken(): void
	{
		// When the lock is free
		$key = pfb_dns_config_lock();

		// Then it returns the handle with config.xml read afresh under it
		$this->assertIsResource($key);
		$this->assertTrue($this->lockHeld());
		$this->assertSame([TRUE], $GLOBALS['pfb_test_config_read_lock_held']);
		unlock($key);

		// When another process holds it
		unset($GLOBALS['pfb_test_config_read_calls'], $GLOBALS['pfb_test_config_read_lock_held']);
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$taken = pfb_dns_config_lock();

		// Then it returns NULL and reloads nothing: this process's copy is not replaced by a read made without the lock
		$this->assertNull($taken);
		$this->assertSame([], $GLOBALS['pfb_test_config_read_calls'] ?? []);
	}

	public function testTheLockHelperLetsGoAndReturnsNullWhenTheFreshReadFails(): void
	{
		// Given config.xml cannot be parsed afresh: this process would be left holding its stale copy
		$GLOBALS['pfb_test_config_read_fails'] = TRUE;

		// When the lock is asked for while it is free
		$key = pfb_dns_config_lock();

		// Then the caller gets NULL, as for a lock that stayed taken, and the lock it did take was released
		$this->assertNull($key);
		$this->assertSame(['try_lock', 'unlock'], array_column($this->lockEvents(), 0), 'one bounded attempt, then its release');
		$this->assertFalse($this->lockHeld());
	}

	public function testTheRefreshReadsConfigXmlAfreshUnderTheLockAndLetsGoSoTheCopyShowsWhatAnotherApplyMoved(): void
	{
		// Given this process holds a copy that predates a takeover config.xml holds
		$this->moveThenResetDoubles();
		$this->configXmlOnDisk();
		$GLOBALS['config'] = [];
		$this->seedResolver();
		$this->assertFalse(pfb_dns_proxy_owns_resolver(), 'before: the copy says the Resolver is not ours');

		// When the copy is refreshed
		$fresh = pfb_dns_config_refresh();

		// Then it is config.xml as of the lock, the lock is released, and the Resolver is ours
		$this->assertTrue($fresh);
		$this->assertSame([TRUE], $GLOBALS['pfb_test_config_read_lock_held'], 'config.xml is read afresh once, under the lock');
		$this->assertSame(['try_lock', 'unlock'], array_column($this->lockEvents(), 0));
		$this->assertFalse($this->lockHeld());
		$this->assertTrue(pfb_dns_proxy_owns_resolver(), 'after: the copy shows the move');
	}

	/** @return array<string,array{string}> the global that makes the fresh read impossible */
	public static function noFreshRead(): array
	{
		return ['the lock stays taken' => ['pfb_test_try_lock_fail'], 'config.xml cannot be parsed' => ['pfb_test_config_read_fails']];
	}

	#[DataProvider('noFreshRead')]
	public function testTheRefreshSaysSoWhenThereIsNoFreshReadAndLeavesTheCopyAlone(string $double): void
	{
		// Given a copy that holds a Resolver the user has, and no way to read config.xml afresh
		$this->seedResolver();
		$before = $GLOBALS['config'];
		$GLOBALS[$double] = TRUE;

		// When the copy is refreshed
		$fresh = pfb_dns_config_refresh();

		// Then the caller is told the copy says nothing about config.xml, and nothing is held
		$this->assertFalse($fresh);
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertFalse($this->lockHeld());
	}

	#[DataProvider('directions')]
	public function testAFreshReadThatFailsAbandonsTheCallWithoutWritingAndTellsTheOperator(bool $on): void
	{
		// Given config.xml cannot be parsed afresh, over the Resolver in the state this direction starts from
		if ($on) {
			$this->seedResolver();
		} else {
			$this->moveThenResetDoubles();
		}
		$this->seedLiveProxyThatAStopClears();
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_config_read_fails'] = TRUE;

		// When the call is made
		$changed = pfb_dns_proxy_resolver($on);

		// Then the stale copy was not written back, the snapshot stays for the next apply, nothing is held ...
		$this->assertFalse($changed);
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame(0, $this->writes());
		$this->assertProxyStillServes('the proxy keeps serving the Resolver that stayed moved');
		if (!$on) {
			$this->assertNotNull(pfb_dns_proxy_saved(), 'the restore keeps the snapshot for the next apply');
		}
		$this->assertFalse($this->lockHeld());

		// ... and the operator-visible notice says it will be retried
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertStringContainsString('next apply', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}
}
