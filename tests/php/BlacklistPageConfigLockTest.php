<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3980 -- the DNSBL Category page (pfblockerng_blacklist.php) writes the pfblockerngblacklist section of config.xml, and
 * write_config() writes the whole copy of config.xml the request read when it started. pfBlockerNG Core's settings adapter writes
 * the same section, and the groups beside it, under the DNS config lock (pfb_core_settings_backend()), so a page save landing around
 * an adapter write put the adapter's change back.
 *
 * Both of the page's writes, the Save button and the Enable/Language auto-submit, take that lock (pfb_dns_config_lock()), apply their
 * change to the config.xml the lock reloads, write under it, release it, and only then tell Core and mark the Update pending, and only
 * after a write that was made:
 *   - what the adapter wrote in between (another section's group, the category schedule an auto-submit does not post) survives, and the
 *     posted change is applied;
 *   - a lock that stays taken, or a failed fresh read, writes nothing and says so (an input error, no redirect);
 *   - a write pfSense refuses (FALSE) or fails (-1) is an input error too: no redirect, nothing pending, Core is not told;
 *   - a save the validation refuses, or a write that throws, still releases the lock.
 *
 * Each case runs the page's real code in a child process (support/GroupsPageWorker.php), because the page ends with exit().
 */
final class BlacklistPageConfigLockTest extends TestCase
{
	private const DNSBL = 'pfblockerngdnsbl';
	private const LOCK = ['try_lock', 'pfb_dns_config', 10];
	private const WRITE = '[ pfBlockerNG ] save DNSBL Category settings';

	private string $dir;
	/** @var ?array{0: resource, 1: array<int, resource>, 2: string} */
	private ?array $standIn = NULL;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_blacklist_lock_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		if ($this->standIn !== NULL) {
			[$process, $pipes] = $this->standIn;
			proc_terminate($process);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		rmdir_recursive($this->dir);
	}

	/**
	 * @param array<string, mixed> $case the worker's case
	 * @return array<string, mixed> the worker's result
	 */
	private function worker(string $scenario, array $case = []): array
	{
		$result = "{$this->dir}/result.json";
		@unlink($result);
		$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/GroupsPageWorker.php', 'blacklist', $scenario, $result, json_encode($case, JSON_THROW_ON_ERROR)], 60.0);
		$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}{$process['stdout']}");
		return json_decode((string) file_get_contents($result), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, mixed> the DNSBL Category section of a config.xml */
	private static function blacklist(array $config): array
	{
		return $config['installedpackages']['pfblockerngblacklist'] ?? [];
	}

	/** @return list<string> the names of the events (lock, read, write) in order */
	private static function eventNames(array $result): array
	{
		return array_map(static fn (array $event): string => $event[0], $result['events']);
	}

	/** @return list<string> the DNSBL groups' names */
	private static function names(array $config): array
	{
		return array_map(static fn (mixed $group): string => $group['aliasname'] ?? '(empty)', $config['installedpackages'][self::DNSBL]['config'] ?? []);
	}

	/** A refused save: nothing is marked pending, Core is told nothing, and the page comes back with its one error instead of redirecting. */
	private function assertRefused(array $result, string $reason): void
	{
		$this->assertFalse($result['pendingMarked'], 'no Update is pending');
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertSame($result['before'], $result['disk'], 'nothing is saved');
		$this->assertCount(1, $result['inputErrors'], 'the form comes back with one error');
		$this->assertStringContainsString($reason, $result['inputErrors'][0]);
		$this->assertTrue($result['returned'], 'the form is rendered again, not redirected as saved');
		$this->assertFalse($result['lockHeld'], 'released');
	}

	// ----- the Save button -----

	public function testASaveTakesTheLockWritesOnceAndTellsCoreAfterTheUnlock(): void
	{
		// Given a stored schedule of Never and a Core that answers
		$socket = $this->core();

		$result = $this->worker('plain', ['core' => ['socket' => $socket], 'timeline' => "{$this->dir}/timeline"]);

		$this->assertSame('Never', self::blacklist($result['before'])['blacklist_freq'], 'before-state: the stored schedule is Never');
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::WRITE], $result['writes'], 'one write');
		$this->assertSame(['try_lock', 'read', 'write', 'unlock', 'SettingsChanged'], $this->timeline(), 'lock, fresh read under it, one write, release, then Core is told once');
		$this->assertSame(self::LOCK, $result['events'][0], 'the lock the settings adapter takes');
		$this->assertSame('EveryDay', self::blacklist($result['disk'])['blacklist_freq'], 'the posted schedule is saved');
		$this->assertTrue($result['pendingMarked'], 'the Update is pending');
		$this->assertFalse($result['returned'], 'redirected as saved');
		$this->assertNull($result['settingsFailed']);
		$this->assertFalse($result['lockHeld'], 'released');
	}

	public function testASaveAppliesItsPostedFieldsToTheFreshConfigAndKeepsWhatCoreWroteSince(): void
	{
		// Given a save that read Alpha at Never and no Charlie, and Core patching Alpha and appending Charlie since
		$result = $this->worker('interleave');
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before']), 'before-state: the request did not have Charlie');
		$this->assertSame(['Alpha', 'Bravo', 'Charlie'], self::names($result['diskBefore']), 'before-state: on disk Core had appended Charlie');

		// Then every posted field is saved ...
		$saved = self::blacklist($result['disk']);
		$this->assertSame('Enable', $saved['blacklist_enable']);
		$this->assertSame('DE', $saved['blacklist_lang']);
		$this->assertSame('ut1', $saved['blacklist_selected']);
		$this->assertSame('EveryDay', $saved['blacklist_freq']);
		$this->assertSame(['adult', 'ads'], array_column($saved['item'], 'selected'), 'one entry per provider, with its posted categories');
		// ... and nothing Core wrote since was put back
		$alpha = $result['disk']['installedpackages'][self::DNSBL]['config'][0];
		$this->assertSame('06hours', $alpha['cron'], "Core's patch of the group's schedule is kept");
		$this->assertSame('patched by Core', $alpha['description'], "Core's patch of the group's description is kept");
		$this->assertContains('Charlie', self::names($result['disk']), 'the group Core appended is kept');
		$this->assertSame([self::WRITE], $result['writes'], 'one write');
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
		$this->assertFalse($result['lockHeld']);
	}

	public function testASaveIsRefusedWhileAnotherSaveHoldsTheConfigLock(): void
	{
		$result = $this->worker('lock_taken');

		$this->assertSame([], $result['writes'], 'nothing is written');
		$this->assertRefused($result, 'another save of the pfSense configuration is in progress');
		$this->assertSame([self::LOCK], $result['events'], 'only the bounded attempt: no read, no write');
	}

	public function testASaveWhoseFreshReadFailsIsRefusedAndReleasesTheLock(): void
	{
		$result = $this->worker('read_fails');

		$this->assertSame([], $result['writes'], 'nothing is written');
		$this->assertRefused($result, 'another save of the pfSense configuration is in progress');
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result), 'locked, the read failed, released, never written');
	}

	/** @return array<string, array{string}> the worker's scenario: pfSense's write_config() answers FALSE (refused) or -1 (not written) */
	public static function refusedWrites(): array
	{
		return ['the write is refused' => ['write_refused'], 'config.xml could not be written' => ['write_failed']];
	}

	#[DataProvider('refusedWrites')]
	public function testASaveWhoseWriteFailsSaysSoAndTellsCoreNothing(string $scenario): void
	{
		$result = $this->worker($scenario);

		$this->assertRefused($result, 'the configuration could not be written');
		$this->assertSame([self::WRITE], $result['writes'], 'the page tried to write');
		$this->assertSame(['try_lock', 'read', 'write', 'read', 'unlock'], self::eventNames($result), 'config.xml is read again under the lock, then released');
	}

	public function testASaveTheValidationRefusesWritesNothingAndReleasesTheLock(): void
	{
		$result = $this->worker('plain', ['post' => ['blacklist_ut1' => ['not-a-category']]]);

		$this->assertSame([], $result['writes'], 'nothing is written');
		$this->assertRefused($result, '[ not-a-category ] is not a valid Selection!');
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result), 'locked from a fresh read, refused, released, never written');
	}

	public function testASaveWhoseWriteThrowsStillReleasesTheConfigLock(): void
	{
		$result = $this->worker('write_throws');

		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result), 'the lock is released after the throwing write');
		$this->assertFalse($result['lockHeld']);
	}

	// ----- the Enable/Language auto-submit -----

	public function testAnAutoSubmitWritesUnderTheLockAndTellsCoreAfterTheUnlock(): void
	{
		$socket = $this->core();

		$result = $this->worker('plain', ['arm' => 'auto', 'core' => ['socket' => $socket], 'timeline' => "{$this->dir}/timeline"]);

		$this->assertSame('Disable', self::blacklist($result['before'])['blacklist_enable'], 'before-state: the category updates are off');
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::WRITE], $result['writes']);
		$this->assertSame(['try_lock', 'read', 'write', 'unlock', 'SettingsChanged'], $this->timeline());
		$saved = self::blacklist($result['disk']);
		$this->assertSame('Enable', $saved['blacklist_enable'], 'the posted select is saved');
		$this->assertSame(['Never', 'EN'], [$saved['blacklist_freq'], $saved['blacklist_lang']], 'the fields it did not post are as they were');
		$this->assertTrue($result['pendingMarked']);
		$this->assertFalse($result['returned'], 'redirected as saved');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAnAutoSubmitKeepsTheScheduleCoreChangedSince(): void
	{
		// Given Core having set the category schedule to Weekly after this request read it at Never
		$result = $this->worker('interleave', ['arm' => 'auto']);
		$this->assertSame('Never', self::blacklist($result['before'])['blacklist_freq'], 'before-state: the request read Never');
		$this->assertSame('Weekly', self::blacklist($result['diskBefore'])['blacklist_freq'], 'before-state: on disk Core had set Weekly');

		// Then the toggle is saved on top of it, not over it
		$saved = self::blacklist($result['disk']);
		$this->assertSame('Enable', $saved['blacklist_enable']);
		$this->assertSame('Weekly', $saved['blacklist_freq'], "Core's schedule is kept");
		$this->assertContains('Charlie', self::names($result['disk']), 'so is the group Core appended');
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
	}

	public function testAnAutoSubmitIsRefusedWhileAnotherSaveHoldsTheConfigLock(): void
	{
		$result = $this->worker('lock_taken', ['arm' => 'auto']);

		$this->assertSame([], $result['writes'], 'nothing is written');
		$this->assertRefused($result, 'another save of the pfSense configuration is in progress');
		$this->assertSame([self::LOCK], $result['events'], 'only the bounded attempt: no read, no write');
	}

	public function testARequestThatPostsNoneOfThePagesFieldsTakesNoLockAndWritesNothing(): void
	{
		$result = $this->worker('plain', ['arm' => 'auto', 'post' => ['blacklist_enable' => NULL, 'unrelated' => 'x']]);

		$this->assertSame([], $result['events'], 'no lock, no read');
		$this->assertSame([], $result['writes']);
		$this->assertSame([], $result['inputErrors']);
		$this->assertTrue($result['returned']);
		$this->assertFalse($result['pendingMarked']);
	}

	// ----- Core's notice -----

	/** Start a Core stand-in on a socket that records into the timeline file; returns the socket. */
	private function core(): string
	{
		$socket = "{$this->dir}/api.sock";
		$script = ['SettingsChanged' => [200, ['initialized' => TRUE, 'revision' => 4, 'projections' => []]]];
		$this->standIn = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreSettingsStandIn.php', $socket, "{$this->dir}/timeline", json_encode($script, JSON_THROW_ON_ERROR)]);
		$deadline = hrtime(TRUE) + 10_000_000_000;
		for ($out = ''; !str_contains($out, 'ready'); usleep(1000)) {
			$out .= (string) stream_get_contents($this->standIn[1][1]);
			if (hrtime(TRUE) > $deadline) {
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
		}
		return $socket;
	}

	/** @return list<string> the lock/write events of the page and the requests Core got, as they happened */
	private function timeline(): array
	{
		$lines = @file("{$this->dir}/timeline", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		return array_map(static fn (string $line): string => ($entry = json_decode($line, TRUE, 512, JSON_THROW_ON_ERROR))['event'] ?? $entry['method'], $lines);
	}
}
