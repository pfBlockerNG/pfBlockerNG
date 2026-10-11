<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 -- the Sync page's "Disable General/IP/DNSBL tab settings sync" checkbox
 * (`sync/syncinterfaces`) becomes the registered select `sync/syncscope`
 * (`policy` | `all` | `lists`), and a saved opt-out migrates exactly once, without a
 * behaviour change (docs/specs/xmlrpc-per-field-sync.md, "Scopes and migration").
 *
 * The mapping reads the old key with its toggle semantics: a case variant of 'on' is the
 * checked box (`lists`); every other stored value, junk and non-scalars included, and an
 * absent key is the unchecked box (`all`). A node with no saved sync section has sync
 * disabled and takes the registry default `policy` from the registry pass instead.
 */
#[CoversFunction('pfb_sync_scope_migrate')]
#[CoversFunction('pfb_migration_registry')]
#[CoversFunction('pfb_run_migrations')]
#[CoversFunction('pfb_registry_pass')]
final class SyncScopeMigrationTest extends TestCase
{
	private const SYNC_SECTION = 'installedpackages/pfblockerngsync/config/0';
	private const MIGRATION_ID = 'issue3452-sync-scope-migrate';

	protected function setUp(): void
	{
		$GLOBALS['config']                      = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices']       = [];
	}

	/**
	 * A saved sync section as a pre-#3452 node left it; $extra adds or overrides keys.
	 *
	 * @param  array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private static function savedSection(array $extra): array
	{
		return $extra + [
			'varsynconchanges' => 'manual',
			'varsynctimeout'   => '150',
			'row'              => [
				0 => [
					'varsyncprotocol'     => 'https',
					'varsyncipaddress'    => '192.0.2.10',
					'varsyncport'         => '443',
					'varsyncdestinenable' => 'on',
				],
			],
		];
	}

	/**
	 * @param  array<string,mixed> $section
	 * @return array<string,mixed> the section with its keys in a fixed order
	 */
	private static function sorted(array $section): array
	{
		ksort($section);
		return $section;
	}

	/** @return list<string> the write_config() messages this migration produced (others flush too) */
	private static function scopeFlushes(): array
	{
		return array_values(array_filter(
			$GLOBALS['pfb_test_write_config_calls'],
			static fn (string $message): bool => str_contains($message, 'issue #3452')
		));
	}

	// --- registry -----------------------------------------------------------

	public function testSyncScopeIsRegisteredAsAPlainLocalStringDefaultingToPolicy(): void
	{
		$registry = pfb_cfg_registry();

		$this->assertArrayHasKey('sync/syncscope', $registry);
		$entry = $registry['sync/syncscope'];
		$this->assertSame('policy', $entry['default'], 'a fresh install and a never-saved Sync page sync policy');
		$this->assertNull($entry['read_adapter'], 'plain string: the three tokens are stored verbatim');
		$this->assertNull($entry['write_adapter'], 'plain string: the three tokens are stored verbatim');
		$this->assertSame('local', $entry['sync'], 'the Sync section is never sent');
		$this->assertArrayNotHasKey('grandfather', $entry, 'the toggle read is case-insensitive; a raw-token map cannot express it');
		$this->assertArrayHasKey('no_grandfather', $entry);
		$this->assertStringContainsString('issue3452', $entry['no_grandfather'], 'the reason must cite the migration that runs first');
	}

	public function testSyncInterfacesIsNoLongerRegistered(): void
	{
		$this->assertArrayNotHasKey('sync/syncinterfaces', pfb_cfg_registry());

		$this->expectException(InvalidArgumentException::class);
		PfbConfig::read('sync/syncinterfaces');
	}

	public function testGatewayReadsTheStoredScopeAndTheDefaultWhenAbsent(): void
	{
		$this->assertSame('policy', PfbConfig::read('sync/syncscope'), 'absent reads the registered default');

		foreach (['policy', 'all', 'lists'] as $token) {
			config_set_path(self::SYNC_SECTION . '/syncscope', $token);
			$this->assertSame($token, PfbConfig::read('sync/syncscope'), "stored {$token} reads back verbatim");
		}
	}

	// --- pure migration -----------------------------------------------------

	/** @return iterable<string,array{0:mixed,1:string}> */
	public static function storedCheckboxProvider(): iterable
	{
		yield "'on' is the checked box"             => ['on', 'lists'];
		yield "'ON' is the checked box (case)"      => ['ON', 'lists'];
		yield "'On' is the checked box (case)"      => ['On', 'lists'];
		yield "'' is the unchecked box"             => ['', 'all'];
		yield "'off' is the unchecked box"          => ['off', 'all'];
		yield "'OFF' is the unchecked box"          => ['OFF', 'all'];
		yield "'yes' is junk, not On"               => ['yes', 'all'];
		yield "'1' is junk, not On"                 => ['1', 'all'];
		yield 'a non-scalar array is not On'        => [['on'], 'all'];
	}

	#[DataProvider('storedCheckboxProvider')]
	public function testStoredCheckboxMapsToScopeAndTheOldKeyIsRemoved(mixed $stored, string $scope): void
	{
		$cfg      = self::savedSection(['syncinterfaces' => $stored]);
		$expected = self::savedSection(['syncscope' => $scope]);

		$migrated = pfb_sync_scope_migrate($cfg);

		$this->assertNotNull($migrated, 'a saved section without syncscope must migrate');
		$this->assertArrayNotHasKey('syncinterfaces', $migrated);
		$this->assertSame(self::sorted($expected), self::sorted($migrated), 'every other key must survive byte for byte');
	}

	public function testAbsentCheckboxMapsToAll(): void
	{
		$cfg = self::savedSection([]);
		$this->assertArrayNotHasKey('syncinterfaces', $cfg, 'before: the legacy key is absent');

		$migrated = pfb_sync_scope_migrate($cfg);

		$this->assertSame(self::sorted(self::savedSection(['syncscope' => 'all'])), self::sorted($migrated ?? []));
	}

	public function testNoSavedSyncSectionIsLeftToTheRegistryDefault(): void
	{
		$this->assertNull(pfb_sync_scope_migrate([]));
	}

	/** @return iterable<string,array{0:mixed}> */
	public static function existingScopeProvider(): iterable
	{
		foreach (['policy', 'all', 'lists', 'bogus', ''] as $stored) {
			yield "existing syncscope {$stored}" => [$stored];
		}
	}

	#[DataProvider('existingScopeProvider')]
	public function testAnExistingScopeIsNeverRewritten(mixed $stored): void
	{
		$cfg = self::savedSection(['syncscope' => $stored, 'syncinterfaces' => 'on']);

		$this->assertNull(pfb_sync_scope_migrate($cfg), 'an operator or earlier run already decided the scope');
	}

	public function testSecondRunOnTheFirstRunsOutputIsANoOp(): void
	{
		$first = pfb_sync_scope_migrate(self::savedSection(['syncinterfaces' => 'on']));
		$this->assertNotNull($first, 'before: the first run migrates');

		$this->assertNull(pfb_sync_scope_migrate($first));
	}

	// --- registry wiring ----------------------------------------------------

	public function testMigrationIsRegisteredAgainstTheSyncSection(): void
	{
		$entries = array_values(array_filter(
			pfb_migration_registry(),
			static fn (array $entry): bool => $entry['id'] === self::MIGRATION_ID
		));

		$this->assertCount(1, $entries);
		$this->assertSame(PFB_SECTIONS['sync'], $entries[0]['section']);
		$this->assertSame('pfb_sync_scope_migrate', $entries[0]['apply']);
		$this->assertSame('4.0.0', $entries[0]['since']);
	}

	public function testRunMigrationsPersistsTheScopeOnceAndDropsTheOldKey(): void
	{
		config_set_path(self::SYNC_SECTION, self::savedSection(['syncinterfaces' => 'On']));

		pfb_run_migrations();

		$stored = config_get_path(self::SYNC_SECTION);
		$this->assertSame('lists', $stored['syncscope'] ?? NULL);
		$this->assertArrayNotHasKey('syncinterfaces', $stored);
		$this->assertSame(self::savedSection([])['row'], $stored['row'], 'the target rows are untouched');
		$this->assertSame('manual', $stored['varsynconchanges']);
		$this->assertCount(1, self::scopeFlushes(), 'one flush for the one migration that had work');

		pfb_run_migrations();

		$this->assertSame($stored, config_get_path(self::SYNC_SECTION), 'a second run changes nothing');
		$this->assertCount(1, self::scopeFlushes(), 'a second run flushes nothing');
	}

	public function testRunMigrationsLeavesAnAbsentSyncSectionAbsent(): void
	{
		pfb_run_migrations();

		$this->assertNull(config_get_path(self::SYNC_SECTION, NULL));
		$this->assertSame([], self::scopeFlushes());
	}

	// --- installer sequence: modes, migrations, registry pass ----------------

	/**
	 * Runs the installer's order over the live test config and returns the sync section
	 * after the registry pass, as the installer would persist it.
	 *
	 * @return array<string,mixed>
	 */
	private function runInstallerSequence(): array
	{
		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$modes = pfb_registry_section_modes($sections);

		pfb_run_migrations();

		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$result = pfb_registry_pass($sections, NULL, $modes);

		return $result[self::SYNC_SECTION] ?? $sections[self::SYNC_SECTION];
	}

	public function testFreshInstallSeedsPolicy(): void
	{
		$sync = $this->runInstallerSequence();

		$this->assertSame('policy', $sync['syncscope'] ?? NULL);
		$this->assertArrayNotHasKey('syncinterfaces', $sync);
	}

	public function testFreshEmptySectionSeedsPolicyThroughTheRegistryPass(): void
	{
		$result = pfb_registry_pass([self::SYNC_SECTION => []]);

		$this->assertSame('policy', $result[self::SYNC_SECTION]['syncscope'] ?? NULL);
		$this->assertArrayNotHasKey('syncinterfaces', $result[self::SYNC_SECTION]);
	}

	#[DataProvider('storedCheckboxProvider')]
	public function testUpgradeKeepsTheMigratedScopeThroughTheRegistryPass(mixed $stored, string $scope): void
	{
		config_set_path(self::SYNC_SECTION, self::savedSection(['syncinterfaces' => $stored]));

		$sync = $this->runInstallerSequence();

		$this->assertSame($scope, $sync['syncscope'] ?? NULL, 'the registry default must not overwrite the migrated scope');
		$this->assertArrayNotHasKey('syncinterfaces', $sync);
	}

	public function testUpgradeOfASavedSectionWithoutTheOldKeyKeepsAllSettingsSyncing(): void
	{
		config_set_path(self::SYNC_SECTION, self::savedSection([]));

		$sync = $this->runInstallerSequence();

		$this->assertSame('all', $sync['syncscope'] ?? NULL, 'an unchecked or never-set box synced every section; the registry default must not narrow it');
	}
}
