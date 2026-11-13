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
 *   - a group the request addresses that is gone from the fresh config is never written back as a half-built or resurrected group;
 *   - the row at the posted index must still be the group the request meant: the editor compares it with the row its request loaded,
 *     the delete with the group name the list page posts. Another group at that index (the first group was deleted since) is never
 *     overwritten or deleted;
 *   - the list's bulk update posts, with every row it changes or reorders, the name of the group the page showed there (aliasname-N, a
 *     GeoIP row's continent); a row posted without its name, or under a name that is not the group at that index now, refuses the
 *     whole update on the AJAX error channel and nothing is written;
 *   - the sync-status ledger of a removed or renamed group is closed only after the write was made.
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

	public function testAGroupSaveNeverOverwritesAnotherGroupThatNowHoldsTheRowIndex(): void
	{
		// Given Alpha, the group the form edits at row 0, deleted by another save since the request read it: Bravo is row 0 now
		$result = $this->worker('edit', 'first_deleted', ['rowid' => 0, 'post' => ['aliasname' => 'Alpha'], 'ledger' => ['Alpha', 'Bravo']]);
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before']), 'before-state: the request read Alpha at row 0');
		$this->assertSame(['Bravo'], self::names($result['diskBefore']), 'before-state: on disk row 0 is Bravo');

		// Then the save is refused: Bravo is not overwritten, renamed or closed
		$this->assertCount(1, $result['inputErrors']);
		$this->assertStringContainsString('changed by another save', $result['inputErrors'][0]);
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['writes']);
		$this->assertSame($result['diskBefore'], $result['disk'], 'config.xml is as the other save left it');
		$this->assertSame(['DNSBL_Alpha/download', 'DNSBL_Bravo/download'], $result['ledger'], 'no ledger entry is closed');
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result));
		$this->assertFalse($result['lockHeld']);
	}

	public function testANewGroupIsNotSavedOverAGroupCoreAddedAtItsRowIndexSince(): void
	{
		// Given a new group for row 2, which the request found free, and Core appending Charlie at row 2 since
		$result = $this->worker('edit', 'interleave', ['rowid' => 2, 'post' => ['aliasname' => 'Delta']]);
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before']), 'before-state: row 2 was free');
		$this->assertSame(['Alpha', 'Bravo', 'Charlie'], self::names($result['diskBefore']), 'before-state: on disk Core took row 2');

		// Then the save is refused and Charlie stays
		$this->assertCount(1, $result['inputErrors']);
		$this->assertStringContainsString('changed by another save', $result['inputErrors'][0]);
		$this->assertSame([], $result['writes']);
		$this->assertSame(['Alpha', 'Bravo', 'Charlie'], self::names($result['disk']));
		$this->assertFalse($result['lockHeld']);
	}

	public function testARenameClosesTheOldNamesLedgerEntryOnceTheWriteIsMade(): void
	{
		$result = $this->worker('edit', 'plain', ['post' => ['aliasname' => 'BravoRenamed'], 'ledger' => TRUE]);
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledgerBefore'], 'before-state: the old name has an open entry');

		$this->assertSame(['Alpha', 'BravoRenamed'], self::names($result['disk']), 'the group is renamed');
		$this->assertSame([], $result['ledger'], "the old name's entry is closed");
	}

	#[DataProvider('refusedWrites')]
	public function testARenameWhoseWriteFailsKeepsTheOldNamesLedgerEntryOpen(string $scenario): void
	{
		$result = $this->worker('edit', $scenario, ['post' => ['aliasname' => 'BravoRenamed'], 'ledger' => TRUE]);
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledgerBefore'], 'before-state: the old name has an open entry');

		$this->assertSame(['Alpha', 'Bravo'], self::names($result['disk']), 'the group is not renamed');
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledger'], 'it keeps its name, so its entry stays open');
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
		$result = $this->worker('list', 'interleave', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1', 'aliasname' => 'Bravo'], 'ledger' => TRUE]);
		$this->assertSame('Never', self::group($result['before'], 'Alpha')['cron'], 'before-state: the request read Alpha at Never');
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledgerBefore'], 'before-state: the ledger entry is open');

		// Then Bravo is gone and Core's changes stay
		$this->assertNotContains('Bravo', self::names($result['disk']), 'the group is removed');
		$this->assertCoreAlpha($result['disk']);
		$this->assertSame(['Alpha', 'Charlie'], self::names($result['disk']), 'nothing else moved');
		$this->assertSame('Removed [ Type: DNSBL Groups, Name: Bravo ]', $result['savemsg']);
		$this->assertSame([], $result['ledger'], "the removed group's ledger entry is closed");
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
		$this->assertTrue($result['pendingMarked'], 'the removal applies at the next Update');
		$this->assertFalse($result['lockHeld']);
	}

	public function testADeleteIsRefusedWhileAnotherSaveHoldsTheConfigLockAndChangesNothing(): void
	{
		$result = $this->worker('list', 'lock_taken', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1', 'aliasname' => 'Bravo'], 'ledger' => TRUE]);

		$this->assertSame(['Alpha', 'Bravo'], self::names($result['disk']), 'the group is still there');
		$this->assertSame($result['before'], $result['disk']);
		$this->assertSame('The group was not deleted: another save of the pfSense configuration is in progress. Try again in a moment.', $result['savemsg'], 'a delete says it did not happen, and that retrying is for the delete');
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
		$result = $this->worker('list', 'row_deleted', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1', 'aliasname' => 'Bravo'], 'ledger' => TRUE]);
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
		$result = $this->worker('list', $scenario, ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1', 'aliasname' => 'Bravo'], 'ledger' => TRUE]);
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledgerBefore'], 'before-state: the ledger entry is open');

		$this->assertStringContainsString('The group was not deleted', (string) $result['savemsg']);
		$this->assertStringContainsString('could not be written', (string) $result['savemsg']);
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledger'], 'the group stays, so its ledger entry stays open');
		$this->assertSame($result['before'], $result['disk']);
		$this->assertNull($result['settingsFailed'], 'config.xml did not change: Core is not told');
		$this->assertFalse($result['pendingMarked']);
		$this->assertFalse($result['lockHeld']);
	}

	public function testADeleteNeverRemovesAnotherGroupThatNowHoldsTheRowIndex(): void
	{
		// Given Alpha, the group the page showed at row 0, deleted by another save: Bravo is row 0 now
		$result = $this->worker('list', 'first_deleted', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '0', 'aliasname' => 'Alpha'], 'ledger' => ['Alpha', 'Bravo']]);
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before']), 'before-state: the request read Alpha at row 0');
		$this->assertSame(['Bravo'], self::names($result['diskBefore']), 'before-state: on disk row 0 is Bravo');

		// Then nothing is deleted, written or closed
		$this->assertSame('The group was not deleted: it was changed by another save. Reload the page and try again.', $result['savemsg']);
		$this->assertSame([], $result['writes']);
		$this->assertSame(['Bravo'], self::names($result['disk']), 'Bravo is still there');
		$this->assertSame(['DNSBL_Alpha/download', 'DNSBL_Bravo/download'], $result['ledger'], 'no ledger entry is closed');
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result));
		$this->assertFalse($result['pendingMarked']);
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertFalse($result['lockHeld']);
	}

	/** @return array<string, array{array<string, string|list<string>>}> what the list page's delete posts, apart from the action */
	public static function deletesOfTheWrongGroup(): array
	{
		return [
			'the name of another group' => [['rowid' => '1', 'aliasname' => 'Alpha']],
			'no name at all' => [['rowid' => '1']],
			'an empty name' => [['rowid' => '1', 'aliasname' => '']],
			'a name that is no word' => [['rowid' => '1', 'aliasname' => 'Bravo; drop']],
			'an array for the name' => [['rowid' => '1', 'aliasname' => ['Bravo']]],
		];
	}

	/** @param array<string, string|list<string>> $post */
	#[DataProvider('deletesOfTheWrongGroup')]
	public function testADeleteThatDoesNotNameTheGroupAtTheRowIsRefused(array $post): void
	{
		$result = $this->worker('list', 'plain', ['post' => ['act' => 'del', 'type' => 'dnsbl'] + $post, 'ledger' => TRUE]);

		$this->assertSame('The group was not deleted: it was changed by another save. Reload the page and try again.', $result['savemsg']);
		$this->assertSame([], $result['writes']);
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['disk']), 'both groups are still there');
		$this->assertSame(['DNSBL_Bravo/download'], $result['ledger']);
		$this->assertFalse($result['lockHeld']);
	}

	public function testAnEmptyRowCleanupAndADeleteInOneRequestWriteTwiceUnderOneLock(): void
	{
		// Given a delete of Bravo that finds an empty <config></config> row first
		$result = $this->worker('list', 'plain', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1', 'aliasname' => 'Bravo'], 'emptyFirstRow' => TRUE]);
		$this->assertSame(['(empty)', 'Alpha', 'Bravo'], self::names($result['before']), 'before-state: the request read the empty first row');

		// Then the cleanup and the delete both write inside the lock the request took once
		$this->assertSame(['try_lock', 'read', 'write', 'write', 'unlock'], self::eventNames($result), 'one lock around both writes');
		$this->assertSame(['pfBlockerNG: Removed empty rowdata', 'pfBlockerNG: Removed [ DNSBL Groups | Bravo ]'], $result['writes']);
		$this->assertSame(['Alpha'], self::names($result['disk']));
		$this->assertFalse($result['lockHeld']);
	}

	public function testACoreNoticeFollowsTheUnlockOfADelete(): void
	{
		$socket = $this->core();

		$this->worker('list', 'interleave', ['post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1', 'aliasname' => 'Bravo'], 'core' => ['socket' => $socket], 'timeline' => "{$this->dir}/timeline"]);

		$this->assertSame(['try_lock', 'read', 'write', 'unlock', 'SettingsChanged'], $this->timeline());
	}

	// ----- the group list: field and order update (the AJAX save) -----

	public function testAFieldUpdateIsAppliedToTheFreshConfigAndKeepsWhatCoreWroteSince(): void
	{
		$result = $this->worker('list', 'interleave', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '1', 'postdata' => 'aliasname-1=Bravo&action-1=Disabled&cron-1=Weekly']]);
		$this->assertSame('unbound', self::group($result['before'], 'Bravo')['action'], 'before-state: Bravo is enabled');

		$bravo = self::group($result['disk'], 'Bravo');
		$this->assertSame('Disabled', $bravo['action'], 'the posted action is saved');
		$this->assertSame('Weekly', $bravo['cron'], 'so is the posted schedule');
		$this->assertCoreAlpha($result['disk']);
		$this->assertSame(['pfBlockerNG: Saved page order format/settings for [ DNSBL Groups ]'], $result['writes']);
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
		$this->assertTrue($result['pendingMarked'], 'the change applies at the next Update');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAReorderIsAppliedToTheFreshConfigAndKeepsTheGroupCoreAppendedSince(): void
	{
		$result = $this->worker('list', 'interleave', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'ids' => 'ids[0]=r1&ids[1]=r0', 'postdata' => 'aliasname-0=Alpha&aliasname-1=Bravo']]);
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before']), 'before-state: the order as the page read it');

		$this->assertSame(['Bravo', 'Alpha', 'Charlie'], self::names($result['disk']), 'the posted order, then the group the page did not know');
		$this->assertCoreAlpha($result['disk']);
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
		$this->assertTrue($result['pendingMarked'], 'the new order applies at the next Update');
	}

	public function testAGeoipFieldUpdateReadsTheContinentsFromTheFreshConfig(): void
	{
		// Given Africa (row 1) updated while Core patched Europe's schedule since the request read config.xml
		$result = $this->worker('list', 'interleave', ['type' => 'geoip', 'post' => ['act' => 'update', 'type' => 'geoip', 'rowid' => '1', 'postdata' => 'aliasname-1=Africa&action-1=Deny_Inbound']]);
		$this->assertSame('Never', $result['before']['installedpackages']['pfblockerngeurope']['config'][0]['cron'], 'before-state: the request read Europe at Never');

		$this->assertSame('Deny_Inbound', $result['disk']['installedpackages']['pfblockerngafrica']['config'][0]['action'], 'the posted action is saved');
		$this->assertSame('Weekly', $result['disk']['installedpackages']['pfblockerngeurope']['config'][0]['cron'], "Core's patch of another continent is kept");
		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], self::eventNames($result));
	}

	/** @return array<string, array{array<string, string>}> */
	public static function updates(): array
	{
		return [
			'a field change' => [['postdata' => 'aliasname-1=Bravo&action-1=Disabled']],
			'a reorder' => [['ids' => 'ids[0]=r1&ids[1]=r0', 'postdata' => 'aliasname-0=Alpha&aliasname-1=Bravo']],
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
		$this->assertStringContainsString('changed by another save', (string) ($errors[0] ?? ''), 'it says the group is not there any more');
		$this->assertSame([], $result['writes']);
		$this->assertSame(['Alpha'], self::names($result['disk']));
		$this->assertFalse($result['lockHeld']);
	}

	/** @return list<string> what the AJAX error channel printed */
	private function ajaxErrors(array $result): array
	{
		$errors = json_decode($result['output'], TRUE);
		$this->assertIsArray($errors, "the AJAX error channel is a JSON array: {$result['output']}");
		return array_map('strval', $errors);
	}

	/** @return array<string, array{array<string, string>}> an update that posts no group name for the rows it changes or reorders */
	public static function unnamedUpdates(): array
	{
		return [
			'a field change' => [['postdata' => 'action-1=Disabled']],
			'a cron change' => [['postdata' => 'cron-1=Weekly']],
			'a reorder' => [['ids' => 'ids[0]=r1&ids[1]=r0']],
			'a reorder whose postdata names only one row' => [['ids' => 'ids[0]=r1&ids[1]=r0', 'postdata' => 'aliasname-1=Bravo']],
		];
	}

	/** @param array<string, string> $post */
	#[DataProvider('unnamedUpdates')]
	public function testAnUpdateThatPostsNoGroupNameForARowItChangesIsRefused(array $post): void
	{
		$result = $this->worker('list', 'plain', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '0'] + $post]);

		$errors = $this->ajaxErrors($result);
		$this->assertStringContainsString('without its group name', $errors[0] ?? '');
		$this->assertSame([], $result['writes']);
		$this->assertSame($result['before'], $result['disk'], 'nothing is saved');
		$this->assertFalse($result['pendingMarked']);
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAnUpdateOfRowZeroNeverChangesTheGroupThatTookItsPlaceWhenTheFirstGroupWasDeleted(): void
	{
		// Given Alpha, row 0 when the page was shown, deleted by another save during the locked refresh: Bravo is row 0 now
		$result = $this->worker('list', 'first_deleted', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '0', 'postdata' => 'action-0=Disabled']]);
		$this->assertSame(['Alpha', 'Bravo'], self::names($result['before']), 'before-state: the request read Alpha at row 0');
		$this->assertSame(['Bravo'], self::names($result['diskBefore']), 'before-state: on disk row 0 is Bravo');
		$this->assertSame('unbound', self::group($result['diskBefore'], 'Bravo')['action'], 'before-state: Bravo is enabled');

		// Then the update is refused and Bravo is still enabled
		$this->assertNotSame([], $this->ajaxErrors($result));
		$this->assertSame([], $result['writes']);
		$this->assertSame('unbound', self::group($result['disk'], 'Bravo')['action'], 'Bravo is not disabled by a change meant for Alpha');
		$this->assertSame($result['diskBefore'], $result['disk']);
		$this->assertFalse($result['lockHeld']);
	}

	/** @return array<string, array{array<string, string>}> updates that name the groups the page showed: Alpha at row 0, Bravo at row 1 */
	public static function namedUpdates(): array
	{
		return [
			'a field change of row 0' => [['postdata' => 'aliasname-0=Alpha&action-0=Disabled']],
			'a field change of both rows' => [['postdata' => 'aliasname-0=Alpha&aliasname-1=Bravo&action-0=Disabled&action-1=Disabled']],
			'a reorder' => [['ids' => 'ids[0]=r1&ids[1]=r0', 'postdata' => 'aliasname-0=Alpha&aliasname-1=Bravo']],
		];
	}

	/** @param array<string, string> $post */
	#[DataProvider('namedUpdates')]
	public function testAnUpdateNamingAGroupAnotherSaveDeletedIsRefusedAndChangesNothing(array $post): void
	{
		// Given Alpha deleted on disk since the page was shown: Bravo is row 0 now, and there is no row 1
		$result = $this->worker('list', 'first_deleted', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '0'] + $post]);
		$this->assertSame(['Bravo'], self::names($result['diskBefore']), 'before-state: on disk row 0 is Bravo');

		$errors = $this->ajaxErrors($result);
		$this->assertStringContainsString('changed by another save', $errors[0] ?? '', 'the AJAX error channel says the page is out of date');
		$this->assertSame([], $result['writes']);
		$this->assertSame($result['diskBefore'], $result['disk'], 'nothing is saved: Bravo keeps its action and its place');
		$this->assertFalse($result['pendingMarked']);
		$this->assertNull($result['settingsFailed'], 'Core is not told');
		$this->assertSame(['try_lock', 'read', 'unlock'], self::eventNames($result));
		$this->assertFalse($result['lockHeld']);
	}

	/** @return array<string, array{array<string, string>, string}> the update, and what the AJAX error channel says */
	public static function misnamedUpdates(): array
	{
		return [
			'a field change under the other group\'s name' => [['postdata' => 'aliasname-0=Bravo&aliasname-1=Alpha&action-1=Disabled'], 'changed by another save'],
			'a reorder under swapped names' => [['ids' => 'ids[0]=r1&ids[1]=r0', 'postdata' => 'aliasname-0=Bravo&aliasname-1=Alpha'], 'changed by another save'],
			'a name that is not a string' => [['postdata' => 'aliasname-1[]=Bravo&action-1=Disabled'], 'without its group name'],
		];
	}

	/** @param array<string, string> $post */
	#[DataProvider('misnamedUpdates')]
	public function testAnUpdateWhoseNamesAreNotTheGroupsAtTheirRowsIsRefused(array $post, string $says): void
	{
		$result = $this->worker('list', 'plain', ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '0'] + $post]);

		$this->assertStringContainsString($says, $this->ajaxErrors($result)[0] ?? '');
		$this->assertSame([], $result['writes']);
		$this->assertSame($result['before'], $result['disk'], 'nothing is saved');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAGeoipUpdateNamingAnotherContinentThanTheRowIsRefused(): void
	{
		// Given Africa at row 1, posted under Europe's name
		$result = $this->worker('list', 'plain', ['type' => 'geoip', 'post' => ['act' => 'update', 'type' => 'geoip', 'rowid' => '1', 'postdata' => 'aliasname-1=Europe&action-1=Deny_Inbound']]);

		$errors = $this->ajaxErrors($result);
		$this->assertStringContainsString('changed by another save', $errors[0] ?? '');
		$this->assertSame([], $result['writes']);
		$this->assertSame('Disabled', $result['disk']['installedpackages']['pfblockerngafrica']['config'][0]['action'], 'Africa keeps its action');
		$this->assertFalse($result['lockHeld']);
	}

	public function testAGeoipUpdateWithoutTheContinentNameIsRefused(): void
	{
		$result = $this->worker('list', 'plain', ['type' => 'geoip', 'post' => ['act' => 'update', 'type' => 'geoip', 'rowid' => '1', 'postdata' => 'action-1=Deny_Inbound']]);

		$this->assertStringContainsString('without its group name', $this->ajaxErrors($result)[0] ?? '');
		$this->assertSame([], $result['writes']);
		$this->assertSame($result['before'], $result['disk']);
	}

	public function testAnUpdateLeavesTheStoredNameOfAGroupWithMarkupCharactersAsItIs(): void
	{
		// Given a group stored under a name with quote and markup characters (an imported or restored name), named as it is stored
		$name = 'Br"a<v>&o';
		$result = $this->worker('list', 'plain', ['bravoName' => $name, 'post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '1', 'postdata' => 'aliasname-1=' . rawurlencode($name) . '&action-1=Disabled']]);
		$this->assertSame($name, $result['before']['installedpackages']['pfblockerngdnsbl']['config'][1]['aliasname'], 'before-state: the name is stored as it is');

		// Then the action is saved, and the name is not rewritten as the HTML-escaped text the update filters its values to
		$this->assertSame('', $result['output'], 'no error is printed');
		$this->assertSame('Disabled', $result['disk']['installedpackages']['pfblockerngdnsbl']['config'][1]['action']);
		$this->assertSame($name, $result['disk']['installedpackages']['pfblockerngdnsbl']['config'][1]['aliasname'], 'the name is the group\'s identity: it stays byte for byte');
	}

	#[DataProvider('refusedWrites')]
	public function testAnUpdateWhoseWriteFailsSaysSoAndTellsCoreNothing(string $scenario): void
	{
		$result = $this->worker('list', $scenario, ['post' => ['act' => 'update', 'type' => 'dnsbl', 'rowid' => '1', 'postdata' => 'aliasname-1=Bravo&action-1=Disabled']]);

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
