<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3945 -- the Groups pages (pfblockerng_category_edit.php: the group save; pfblockerng_category.php: the delete, the
 * field/order update and the empty-row cleanup) write the groups' sections of config.xml, and write_config() writes the whole copy
 * of config.xml the request read when it started. pfBlockerNG Core's settings adapter writes the same sections under the DNS config
 * lock (pfb_core_settings_backend()), so a page write landing around an adapter write put the adapter's change back.
 *
 * Every write of the two pages takes that lock (pfb_dns_config_lock()), applies its change to the config.xml the lock reloads, writes
 * under it, releases it, and only then tells Core, and only after a write that was made:
 *   - what the adapter wrote in between (another group patched, a new group appended) survives, and the posted change is applied;
 *   - a lock that stays taken, or a failed fresh read, writes nothing and says so (an input error, the delete's message, the update's
 *     AJAX error array): no side effect of the action (the sync-status ledger) happens either;
 *   - a group the request addresses that is gone from the fresh config is never written back as a half-built or resurrected group.
 *
 * Each case runs the pages' real code in a child process (support/GroupsPageWorker.php), because the pages end with exit().
 */
final class GroupsPageConfigLockTest extends TestCase
{
	private const DNSBL = 'pfblockerngdnsbl';
	private const LOCK = ['try_lock', 'pfb_dns_config', 10];

	private string $dir;
	/** @var ?array{0: resource, 1: array<int, resource>, 2: string} */
	private ?array $standIn = NULL;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_groups_lock_' . bin2hex(random_bytes(6));
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
	private function worker(string $page, string $scenario, array $case = []): array
	{
		$result = "{$this->dir}/result.json";
		@unlink($result);
		$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/GroupsPageWorker.php', $page, $scenario, $result, json_encode($case, JSON_THROW_ON_ERROR)], 60.0);
		$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}{$process['stdout']}");
		return json_decode((string) file_get_contents($result), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return list<mixed> the groups of one section of a config.xml */
	private static function groupList(array $config, string $conf = self::DNSBL): array
	{
		return $config['installedpackages'][$conf]['config'] ?? [];
	}

	/** @return list<string> the groups' names, '(empty)' for an empty entry */
	private static function names(array $config, string $conf = self::DNSBL): array
	{
		return array_map(static fn (mixed $group): string => $group['aliasname'] ?? '(empty)', self::groupList($config, $conf));
	}

	/** @return array<string, mixed> the group named $name */
	private static function group(array $config, string $name, string $conf = self::DNSBL): array
	{
		foreach (self::groupList($config, $conf) as $group) {
			if (($group['aliasname'] ?? NULL) === $name) {
				return $group;
			}
		}
		return [];
	}

	/** @return list<string> the names of the events (lock, read, write) in order */
	private static function eventNames(array $result): array
	{
		return array_map(static fn (array $event): string => $event[0], $result['events']);
	}

	private function assertCoreAlpha(array $disk, string $conf = self::DNSBL): void
	{
		$alpha = self::group($disk, 'Alpha', $conf);
		$this->assertSame('06hours', $alpha['cron'] ?? NULL, "Core's patch of the other group's schedule is kept");
		$this->assertSame('patched by Core', $alpha['description'] ?? NULL, "Core's patch of the other group's description is kept");
		$this->assertContains('Charlie', self::names($disk, $conf), 'the group Core appended is kept');
	}

	// ----- the group editor's save -----

	/** @return array<string, array{string, string, string}> the group type, its section, its name in the save message */
	public static function editorTypes(): array
	{
		return ['DNSBL' => ['dnsbl', 'pfblockerngdnsbl', 'DNSBL'], 'IPv4' => ['ipv4', 'pfblockernglistsv4', 'IPv4']];
	}

	#[DataProvider('editorTypes')]
	public function testAGroupSaveAppliesItsPostedFieldsToTheFreshConfigAndKeepsWhatCoreWroteSince(string $type, string $conf, string $label): void
	{
		// Given a save that read config.xml with Alpha at Never and no Charlie, and Core patching Alpha and appending Charlie since
		$result = $this->worker('edit', 'interleave', ['type' => $type]);
		$this->assertSame('Never', self::group($result['before'], 'Alpha', $conf)['cron'], 'before-state: the request read Alpha at Never');
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before'], $conf), 'before-state: the request did not have Charlie');
		$this->assertSame('06hours', self::group($result['diskBefore'], 'Alpha', $conf)['cron'], 'before-state: on disk Core had patched Alpha');

		// Then the edited group is saved as posted ...
		$bravo = self::group($result['disk'], 'Bravo', $conf);
		$this->assertSame('edited on the page', $bravo['description'] ?? NULL, 'the posted description is saved');
		$this->assertSame('Weekly', $bravo['cron'] ?? NULL, 'so is the posted schedule');
		$this->assertSame('https://example.invalid/bravo-edited.txt', $bravo['row'][0]['url'] ?? NULL, 'and the posted feed row');
		// ... and nothing Core wrote since was put back
		$this->assertCoreAlpha($result['disk'], $conf);
		$this->assertSame(["pfBlockerNG: Saved [ Type:{$label}, Name:Bravo ] configuration"], $result['writes'], 'one write');
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result), 'lock, fresh read under it, one write, then release');
		$this->assertSame(self::LOCK, $result['events'][0], 'the lock the settings adapter takes');
		$this->assertFalse($result['lockHeld'], 'released');
	}

	public function testAGroupSaveIsRefusedWhileAnotherSaveHoldsTheConfigLock(): void
	{
		$result = $this->worker('edit', 'lock_taken');

		$this->assertCount(1, $result['inputErrors'], 'the form comes back with one error');
		$this->assertStringContainsString('another save of the pfSense configuration is in progress', $result['inputErrors'][0]);
		$this->assertTrue($result['returned'], 'the form is rendered again, not redirected as saved');
		$this->assertSame([self::LOCK], $result['events'], 'only the bounded attempt: no read, no write');
		$this->assertSame([], $result['writes']);
		$this->assertSame($result['before'], $result['disk'], 'nothing is saved');
		$this->assertFalse($result['pendingMarked'], 'no Update is pending');
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAGroupSaveWhoseFreshReadFailsIsRefusedAndReleasesTheLock(): void
	{
		$result = $this->worker('edit', 'read_fails');

		$this->assertCount(1, $result['inputErrors']);
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result), 'locked, the read failed, released, never written');
		$this->assertSame([], $result['writes']);
		$this->assertTrue($result['returned']);
		$this->assertFalse($result['lockHeld']);
	}

	public function testAGroupRemovedSinceTheFormWasLoadedIsNotSavedBackAsANewGroup(): void
	{
		// Given Bravo, the group being edited, deleted on disk since the request read config.xml
		$result = $this->worker('edit', 'row_deleted');
		$this->assertContains('Bravo', self::names($result['before']), 'before-state: the request read Bravo');
		$this->assertNotContains('Bravo', self::names($result['diskBefore']), 'before-state: Bravo is gone from disk');

		// Then the save is refused: the group is not written back
		$this->assertCount(1, $result['inputErrors']);
		$this->assertStringContainsString('changed by another save', $result['inputErrors'][0]);
		$this->assertSame([], $result['writes']);
		$this->assertSame(['Alpha'], self::names($result['disk']), 'the list is as the other save left it');
		$this->assertFalse($result['lockHeld'], 'the lock is released on the refusal');
	}

	/** @return array<string, array{string}> the worker's scenario: pfSense's write_config() answers FALSE (refused) or -1 (not written) */
	public static function refusedWrites(): array
	{
		return ['the write is refused' => ['write_refused'], 'config.xml could not be written' => ['write_failed']];
	}

	#[DataProvider('refusedWrites')]
	public function testAGroupSaveWhoseWriteFailsSaysSoAndTellsCoreNothing(string $scenario): void
	{
		$result = $this->worker('edit', $scenario);

		$this->assertCount(1, $result['inputErrors']);
		$this->assertStringContainsString('could not be written', $result['inputErrors'][0]);
		$this->assertTrue($result['returned'], 'the form is rendered again with what was posted');
		$this->assertSame($result['before'], $result['disk'], 'nothing is saved');
		$this->assertFalse($result['pendingMarked']);
		$this->assertNull($result['settingsFailed'], 'config.xml did not change: Core is not told');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAGroupSaveWhoseWriteThrowsStillReleasesTheConfigLock(): void
	{
		$result = $this->worker('edit', 'write_throws');

		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result), 'the lock is released after the throwing write');
		$this->assertFalse($result['lockHeld']);
	}

	public function testACoreNoticeFollowsTheUnlockOfAGroupSave(): void
	{
		$socket = $this->core();

		$result = $this->worker('edit', 'interleave', ['core' => ['socket' => $socket], 'timeline' => "{$this->dir}/timeline"]);

		$this->assertSame(['try_lock', 'read', 'write', 'unlock', 'SettingsChanged'], $this->timeline(), 'Core is told after the lock is let go, not while a slow Core would hold it');
		$this->assertNull($result['settingsFailed']);
	}

	// ----- the group list: delete -----

	public function testADeleteRemovesTheGroupFromTheFreshConfigAndKeepsWhatCoreWroteSince(): void
	{
		// Given a delete of Bravo that read Alpha at Never, with Core patching Alpha and appending Charlie since, and Bravo's ledger entry open
		$result = $this->worker('list', 'interleave', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1'], 'ledger' => TRUE]);
		$this->assertSame('Never', self::group($result['before'], 'Alpha')['cron'], 'before-state: the request read Alpha at Never');
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledgerBefore'], 'before-state: the ledger entry is open');

		// Then Bravo is gone and Core's changes stay
		$this->assertNotContains('Bravo', self::names($result['disk']), 'the group is removed');
		$this->assertCoreAlpha($result['disk']);
		$this->assertSame(['Alpha', 'Charlie'], self::names($result['disk']), 'nothing else moved');
		$this->assertSame('Removed [ Type: DNSBL Groups, Name: Bravo ]', $result['savemsg']);
		$this->assertSame([], $result['ledger'], "the removed group's ledger entry is closed");
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
		$this->assertFalse($result['lockHeld']);
	}

	public function testADeleteIsRefusedWhileAnotherSaveHoldsTheConfigLockAndChangesNothing(): void
	{
		$result = $this->worker('list', 'lock_taken', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1'], 'ledger' => TRUE]);

		$this->assertSame(['Alpha', 'Bravo'], self::names($result['disk']), 'the group is still there');
		$this->assertSame($result['before'], $result['disk']);
		$this->assertStringContainsString('another save of the pfSense configuration is in progress', (string) $result['savemsg']);
		$this->assertStringContainsString('Could not delete', (string) $result['savemsg']);
		$this->assertSame([], $result['writes']);
		$this->assertSame([self::LOCK], $result['events'], 'only the bounded attempt');
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledger'], "the group stays, so its ledger entry stays open");
		$this->assertFalse($result['pendingMarked']);
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertFalse($result['lockHeld']);
	}

	public function testADeleteOfAGroupAnotherSaveAlreadyRemovedWritesNothing(): void
	{
		// Given Bravo already deleted on disk (with Alpha patched) since the request read config.xml
		$result = $this->worker('list', 'row_deleted', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1'], 'ledger' => TRUE]);
		$this->assertContains('Bravo', self::names($result['before']), 'before-state: the request read Bravo');

		// Then it is not found: nothing is written back, nothing is resurrected, and the lock is released
		$this->assertStringContainsString('not found', (string) $result['savemsg']);
		$this->assertSame([], $result['writes']);
		$this->assertSame(['Alpha'], self::names($result['disk']));
		$this->assertSame('06hours', self::group($result['disk'], 'Alpha')['cron'], "Core's patch is kept");
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledger'], 'no side effect for a delete that did not happen');
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result));
		$this->assertFalse($result['lockHeld']);
	}

	#[DataProvider('refusedWrites')]
	public function testADeleteWhoseWriteFailsSaysSoAndTellsCoreNothing(string $scenario): void
	{
		$result = $this->worker('list', $scenario, ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1']]);

		$this->assertStringContainsString('could not be written', (string) $result['savemsg']);
		$this->assertSame($result['before'], $result['disk']);
		$this->assertNull($result['settingsFailed'], 'config.xml did not change: Core is not told');
		$this->assertFalse($result['pendingMarked']);
		$this->assertFalse($result['lockHeld']);
	}

	public function testACoreNoticeFollowsTheUnlockOfADelete(): void
	{
		$socket = $this->core();

		$this->worker('list', 'interleave', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1'], 'core' => ['socket' => $socket], 'timeline' => "{$this->dir}/timeline"]);

		$this->assertSame(['try_lock', 'read', 'write', 'unlock', 'SettingsChanged'], $this->timeline());
	}

	// ----- the group list: field and order update (the AJAX save) -----

	public function testAFieldUpdateIsAppliedToTheFreshConfigAndKeepsWhatCoreWroteSince(): void
	{
		$result = $this->worker('list', 'interleave', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '1', 'postdata' => 'action-1=Disabled&cron-1=Weekly']]);
		$this->assertSame('unbound', self::group($result['before'], 'Bravo')['action'], 'before-state: Bravo is enabled');

		$bravo = self::group($result['disk'], 'Bravo');
		$this->assertSame('Disabled', $bravo['action'], 'the posted action is saved');
		$this->assertSame('Weekly', $bravo['cron'], 'so is the posted schedule');
		$this->assertCoreAlpha($result['disk']);
		$this->assertSame(['pfBlockerNG: Saved page order format/settings for [ DNSBL Groups ]'], $result['writes']);
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
		$this->assertFalse($result['lockHeld']);
	}

	public function testAReorderIsAppliedToTheFreshConfigAndKeepsTheGroupCoreAppendedSince(): void
	{
		$result = $this->worker('list', 'interleave', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'ids' => 'ids[0]=r1&ids[1]=r0']]);
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before']), 'before-state: the order as the page read it');

		$this->assertSame(['Bravo', 'Alpha', 'Charlie'], self::names($result['disk']), 'the posted order, then the group the page did not know');
		$this->assertCoreAlpha($result['disk']);
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
	}

	public function testAGeoipFieldUpdateReadsTheContinentsFromTheFreshConfig(): void
	{
		// Given Africa (row 1) updated while Core patched Europe's schedule since the request read config.xml
		$result = $this->worker('list', 'interleave', ['type' => 'geoip', 'post' => ['act' => 'update', 'type' => 'geoip', 'rowid' => '1', 'postdata' => 'action-1=Deny_Inbound']]);
		$this->assertSame('Never', $result['before']['installedpackages']['pfblockerngeurope']['config'][0]['cron'], 'before-state: the request read Europe at Never');

		$this->assertSame('Deny_Inbound', $result['disk']['installedpackages']['pfblockerngafrica']['config'][0]['action'], 'the posted action is saved');
		$this->assertSame('Weekly', $result['disk']['installedpackages']['pfblockerngeurope']['config'][0]['cron'], "Core's patch of another continent is kept");
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
	}

	/** @return array<string, array{array<string, string>}> */
	public static function updates(): array
	{
		return [
			'a field change' => [['postdata' => 'action-1=Disabled']],
			'a reorder' => [['ids' => 'ids[0]=r1&ids[1]=r0']],
		];
	}

	/** @param array<string, string> $post */
	#[DataProvider('updates')]
	public function testAnUpdateIsRefusedWhileAnotherSaveHoldsTheConfigLock(array $post): void
	{
		$result = $this->worker('list', 'lock_taken', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '1'] + $post]);

		$errors = json_decode($result['output'], TRUE);
		$this->assertIsArray($errors, "the AJAX error channel is a JSON array: {$result['output']}");
		$this->assertStringContainsString('another save of the pfSense configuration is in progress', (string) ($errors[0] ?? ''));
		$this->assertSame([], $result['writes']);
		$this->assertSame($result['before'], $result['disk']);
		$this->assertSame([self::LOCK], $result['events'], 'only the bounded attempt');
		$this->assertFalse($result['pendingMarked']);
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertFalse($result['lockHeld']);
	}

	/** @param array<string, string> $post */
	#[DataProvider('updates')]
	public function testAnUpdateOfAGroupAnotherSaveRemovedWritesNothingAndKeepsItRemoved(array $post): void
	{
		// Given Bravo, the group the update addresses, deleted on disk since the request read config.xml
		$result = $this->worker('list', 'row_deleted', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '1'] + $post]);
		$this->assertContains('Bravo', self::names($result['before']), 'before-state: the request read Bravo');

		// Then the update reports an error and writes nothing: no half-built group appears
		$errors = json_decode($result['output'], TRUE);
		$this->assertIsArray($errors, "the AJAX error channel is a JSON array: {$result['output']}");
		$this->assertNotSame([], $errors);
		$this->assertSame([], $result['writes']);
		$this->assertSame(['Alpha'], self::names($result['disk']));
		$this->assertFalse($result['lockHeld']);
	}

	#[DataProvider('refusedWrites')]
	public function testAnUpdateWhoseWriteFailsSaysSoAndTellsCoreNothing(string $scenario): void
	{
		$result = $this->worker('list', $scenario, ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '1', 'postdata' => 'action-1=Disabled']]);

		$errors = json_decode($result['output'], TRUE);
		$this->assertIsArray($errors, "the AJAX error channel is a JSON array: {$result['output']}");
		$this->assertStringContainsString('could not be written', (string) ($errors[0] ?? ''));
		$this->assertNull($result['settingsFailed'], 'config.xml did not change: Core is not told');
		$this->assertFalse($result['pendingMarked']);
		$this->assertFalse($result['lockHeld']);
	}

	// ----- the group list: the empty-row cleanup -----

	public function testTheEmptyRowCleanupDoesNotPutBackWhatCoreWroteSince(): void
	{
		// Given a page view that read an empty <config></config> first row, and Core patching Alpha and appending Charlie since
		$result = $this->worker('list', 'interleave', ['get' => ['type' => 'dnsbl'], 'emptyFirstRow' => TRUE]);
		$this->assertSame(['(empty)', 'Alpha', 'Bravo'], self::names($result['before']), 'before-state: the request read the empty first row');
		$this->assertSame(['(empty)', 'Alpha', 'Bravo', 'Charlie'], self::names($result['diskBefore']), 'before-state: on disk the row is there and Core appended Charlie');

		// Then the empty row is removed and Core's changes stay
		$this->assertSame(['Alpha', 'Bravo', 'Charlie'], self::names($result['disk']));
		$this->assertCoreAlpha($result['disk']);
		$this->assertSame(['pfBlockerNG: Removed empty rowdata'], $result['writes']);
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
		$this->assertTrue($result['returned'], 'the page goes on to render');
		$this->assertFalse($result['lockHeld']);
	}

	public function testTheEmptyRowCleanupWritesNothingWhenAnotherSaveAlreadyRemovedTheRow(): void
	{
		$result = $this->worker('list', 'cleaned_elsewhere', ['get' => ['type' => 'dnsbl'], 'emptyFirstRow' => TRUE]);
		$this->assertSame(['(empty)', 'Alpha', 'Bravo'], self::names($result['before']), 'before-state: the request read the empty first row');

		$this->assertSame([], $result['writes'], 'judged again under the lock: nothing left to remove');
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['disk']), "the other save's list stands");
		$this->assertSame('06hours', self::group($result['disk'], 'Alpha')['cron']);
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result));
		$this->assertNull($result['settingsFailed'], 'nothing written: Core is not told');
		$this->assertFalse($result['lockHeld']);
	}

	public function testTheEmptyRowCleanupWritesNothingWhileAnotherSaveHoldsTheConfigLock(): void
	{
		$result = $this->worker('list', 'lock_taken', ['get' => ['type' => 'dnsbl'], 'emptyFirstRow' => TRUE]);

		$this->assertSame([], $result['writes']);
		$this->assertSame($result['before'], $result['disk']);
		$this->assertSame([self::LOCK], $result['events'], 'only the bounded attempt');
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertTrue($result['returned'], 'the page still renders');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAGroupListViewWithNothingToCleanTakesNoLockAndWritesNothing(): void
	{
		$result = $this->worker('list', 'plain', ['get' => ['type' => 'dnsbl']]);

		$this->assertSame([], $result['events'], 'a plain view never takes the config lock');
		$this->assertSame([], $result['writes']);
		$this->assertTrue($result['returned']);
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
