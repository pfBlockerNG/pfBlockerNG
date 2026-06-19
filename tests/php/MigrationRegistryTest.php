<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 2 — Migration registry + driver.
 *
 * Scenario: pfb_run_migrations() consolidates four independent upgrade migrations
 * (ADR-02 python-mode, PFBL-03 control-legacy seed, ADR-22 lenient, issue #281 pfb_keep)
 * into one ordered, idempotent, registry-driven driver.
 *
 * Contract (§2.4 ADR-29):
 *   - ORDERING: migrations fire in the documented order; a later migration sees the
 *     section state left by an earlier one in the same run.
 *   - IDEMPOTENCY / RUN-ONCE: a second pfb_run_migrations() call on an already-migrated
 *     config is a no-op (no write_config() calls).
 *   - BEHAVIOUR-PRESERVATION: the driver reproduces the same keys + values that the four
 *     hand-wired install.inc blocks produced on every install state (fresh, legacy-missing-key,
 *     already-migrated).
 *   - pfb_migration_registry() returns exactly four entries in the correct order.
 */
#[CoversFunction('pfb_run_migrations')]
#[CoversFunction('pfb_migration_registry')]
#[CoversFunction('pfb_dnsbl_python_migrate')]
final class MigrationRegistryTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Constants matching the production section paths (avoid magic strings).
	// -----------------------------------------------------------------------

	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const GEN_SECTION   = 'installedpackages/pfblockerng/config/0';

	// -----------------------------------------------------------------------
	// Fixture helpers
	// -----------------------------------------------------------------------

	protected function setUp(): void
	{
		$GLOBALS['config']                    = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	private function seedDnsbl(array $data): void
	{
		config_set_path(self::DNSBL_SECTION, $data);
	}

	private function seedGen(array $data): void
	{
		config_set_path(self::GEN_SECTION, $data);
	}

	private function getDnsbl(): array
	{
		return config_get_path(self::DNSBL_SECTION, []);
	}

	private function getGen(): array
	{
		return config_get_path(self::GEN_SECTION, []);
	}

	private function writeConfigCalls(): array
	{
		return $GLOBALS['pfb_test_write_config_calls'] ?? [];
	}

	// -----------------------------------------------------------------------
	// A — Registry shape
	// -----------------------------------------------------------------------

	/**
	 * Registry returns exactly four entries in the correct declared order.
	 */
	public function testRegistryHasFourEntriesInOrder(): void
	{
		$registry = pfb_migration_registry();

		$this->assertCount(4, $registry);

		// Order must match the original install.inc sequence.
		$this->assertSame('adr02-dnsbl-python-mode',    $registry[0]['id']);
		$this->assertSame('pfbl03-control-legacy-seed', $registry[1]['id']);
		$this->assertSame('adr22-dnsbl-lenient',        $registry[2]['id']);
		$this->assertSame('issue281-pfb-keep-seed',     $registry[3]['id']);
	}

	/**
	 * Every entry carries the required fields.
	 */
	public function testRegistryEntriesHaveRequiredFields(): void
	{
		foreach (pfb_migration_registry() as $entry) {
			$this->assertArrayHasKey('id',      $entry);
			$this->assertArrayHasKey('section', $entry);
			$this->assertArrayHasKey('apply',   $entry);
			$this->assertArrayHasKey('message', $entry);
			$this->assertArrayHasKey('since',   $entry);
			$this->assertIsCallable($entry['apply'], "apply for {$entry['id']} must be callable");
		}
	}

	/**
	 * DNSBL migrations target the DNSBL section; pfb_keep targets the general section.
	 */
	public function testRegistryEntriesSectionsAreCorrect(): void
	{
		$registry = pfb_migration_registry();
		$this->assertSame(self::DNSBL_SECTION, $registry[0]['section']);
		$this->assertSame(self::DNSBL_SECTION, $registry[1]['section']);
		$this->assertSame(self::DNSBL_SECTION, $registry[2]['section']);
		$this->assertSame(self::GEN_SECTION,   $registry[3]['section']);
	}

	// -----------------------------------------------------------------------
	// B — pfb_dnsbl_python_migrate() unit tests (the new helper extracted
	//     from the ADR-02 inline block).
	// -----------------------------------------------------------------------

	/**
	 * Scenario: fresh install (empty section) — nothing to migrate.
	 *   Given no prior DNSBL config, the migration returns NULL (no write).
	 */
	public function testPythonMigrateSkipsFreshInstall(): void
	{
		// Before: no config section.
		$this->assertNull(pfb_dnsbl_python_migrate([]));
		$this->assertNull(pfb_dnsbl_python_migrate(null));
	}

	/**
	 * Scenario: existing install with legacy mode — keys are set to python-only.
	 *   Given a populated DNSBL section with old dnsbl_mode value.
	 *   When the migration runs.
	 *   Then dnsbl_mode = 'dnsbl_python' and pfb_py_block = 'on'.
	 */
	public function testPythonMigrateSetsTargetValues(): void
	{
		$dconfig = ['pfb_dnsbl' => 'on', 'dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_block' => ''];
		// Before: dnsbl_mode is not python-only.
		$this->assertNotSame('dnsbl_python', $dconfig['dnsbl_mode']);

		$out = pfb_dnsbl_python_migrate($dconfig);

		// After: both keys are forced to target values.
		$this->assertIsArray($out);
		$this->assertSame('dnsbl_python', $out['dnsbl_mode']);
		$this->assertSame('on', $out['pfb_py_block']);
		// Other keys are preserved.
		$this->assertSame('on', $out['pfb_dnsbl']);
	}

	/**
	 * Scenario: already migrated — idempotent, returns NULL.
	 *   Given a section where both keys already carry the target values.
	 *   Then the migration returns NULL (run-once).
	 */
	public function testPythonMigrateIsIdempotentWhenAlreadyMigrated(): void
	{
		$dconfig = ['pfb_dnsbl' => 'on', 'dnsbl_mode' => 'dnsbl_python', 'pfb_py_block' => 'on'];
		// Before: already migrated.
		$this->assertSame('dnsbl_python', $dconfig['dnsbl_mode']);
		$this->assertSame('on', $dconfig['pfb_py_block']);

		$out = pfb_dnsbl_python_migrate($dconfig);

		// After: nothing changes (NULL = no write).
		$this->assertNull($out);
	}

	/**
	 * Scenario: only one of the two keys needs updating — still migrates.
	 */
	public function testPythonMigrateWhenOnlyOnekeyNeedsUpdate(): void
	{
		// dnsbl_mode already correct but pfb_py_block is not.
		$out1 = pfb_dnsbl_python_migrate(['pfb_dnsbl' => 'on', 'dnsbl_mode' => 'dnsbl_python', 'pfb_py_block' => '']);
		$this->assertIsArray($out1);
		$this->assertSame('dnsbl_python', $out1['dnsbl_mode']);
		$this->assertSame('on', $out1['pfb_py_block']);

		// pfb_py_block correct but dnsbl_mode is not.
		$out2 = pfb_dnsbl_python_migrate(['pfb_dnsbl' => 'on', 'dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_block' => 'on']);
		$this->assertIsArray($out2);
		$this->assertSame('dnsbl_python', $out2['dnsbl_mode']);
		$this->assertSame('on', $out2['pfb_py_block']);
	}

	// -----------------------------------------------------------------------
	// C — Driver: fresh install (both sections absent)
	// -----------------------------------------------------------------------

	/**
	 * Scenario: fresh install — no sections exist.
	 *   Given no config at all.
	 *   When pfb_run_migrations() runs.
	 *   Then no write_config() is called and no config paths are created.
	 */
	public function testDriverFreshInstallIsNoOp(): void
	{
		// Before: config is empty.
		$this->assertSame([], config_get_path(self::DNSBL_SECTION, []));
		$this->assertSame([], config_get_path(self::GEN_SECTION, []));

		pfb_run_migrations();

		// After: still no sections and no writes (all migrations return NULL for empty input).
		$this->assertSame([], config_get_path(self::DNSBL_SECTION, []));
		$this->assertSame([], config_get_path(self::GEN_SECTION, []));
		$this->assertSame([], $this->writeConfigCalls());
	}

	// -----------------------------------------------------------------------
	// D — Driver: existing install missing each key (the migration case)
	// -----------------------------------------------------------------------

	/**
	 * Scenario: existing DNSBL config with legacy mode keys.
	 *   Given a populated DNSBL section with old dnsbl_mode.
	 *   When the driver runs.
	 *   Then ADR-02 fires, producing the python-only keys.
	 *   And the write_config message matches the original install.inc message exactly.
	 */
	public function testDriverMigratesDnsblModeOnExistingInstall(): void
	{
		$this->seedDnsbl(['pfb_dnsbl' => 'on', 'dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_block' => '']);
		// Before: legacy mode.
		$this->assertSame('dnsbl_unbound', $this->getDnsbl()['dnsbl_mode']);

		pfb_run_migrations();

		// After: python-only mode forced.
		$dnsbl = $this->getDnsbl();
		$this->assertSame('dnsbl_python', $dnsbl['dnsbl_mode']);
		$this->assertSame('on', $dnsbl['pfb_py_block']);
		// The exact write_config message from the original block.
		$this->assertContains(
			'pfBlockerNG: migrated DNSBL to Python-only mode',
			$this->writeConfigCalls()
		);
	}

	/**
	 * Scenario: existing DNSBL config with DNSBL control enabled but not yet seeded.
	 *   Given pfb_control = 'on' and no seed marker.
	 *   When the driver runs.
	 *   Then PFBL-03 fires: legacy toggle seeded ON, marker set.
	 */
	public function testDriverSeedsControlLegacyOnExistingInstallWithControlOn(): void
	{
		$this->seedDnsbl([
			'pfb_dnsbl'  => 'on',
			'dnsbl_mode' => 'dnsbl_python',
			'pfb_py_block' => 'on',
			'pfb_control'  => 'on',
		]);
		// Before: no seed marker.
		$this->assertArrayNotHasKey('pfb_control_legacy_seeded', $this->getDnsbl());

		pfb_run_migrations();

		$dnsbl = $this->getDnsbl();
		$this->assertSame('on', $dnsbl['pfb_control_legacy']);
		$this->assertSame('on', $dnsbl['pfb_control_legacy_seeded']);
		$this->assertContains(
			'pfBlockerNG: seeded legacy DNSBL control toggle (PFBL-03)',
			$this->writeConfigCalls()
		);
	}

	/**
	 * Scenario: existing DNSBL config missing the lenient key.
	 *   Given a populated section without pfb_dnsbl_lenient.
	 *   When the driver runs (with ADR-02 and PFBL-03 already migrated).
	 *   Then ADR-22 fires: lenient set to 'on'.
	 */
	public function testDriverMigratesLenientOnExistingInstall(): void
	{
		// Pre-seed the DNSBL section in an already-ADR02+PFBL03 state to isolate ADR-22.
		$this->seedDnsbl([
			'pfb_dnsbl'              => 'on',
			'dnsbl_mode'             => 'dnsbl_python',
			'pfb_py_block'           => 'on',
			'pfb_control_legacy_seeded' => 'on',
		]);
		$this->assertArrayNotHasKey('pfb_dnsbl_lenient', $this->getDnsbl());

		pfb_run_migrations();

		$dnsbl = $this->getDnsbl();
		$this->assertSame('on', $dnsbl['pfb_dnsbl_lenient']);
		$this->assertContains(
			'pfBlockerNG: preserve permissive DNSBL parsing for existing install (ADR-22 migration)',
			$this->writeConfigCalls()
		);
	}

	/**
	 * Scenario: existing General config missing pfb_keep.
	 *   Given a populated General section without pfb_keep.
	 *   When the driver runs.
	 *   Then issue-#281 fires: pfb_keep seeded to 'on'.
	 */
	public function testDriverSeedsPfbKeepOnExistingInstall(): void
	{
		$this->seedGen(['enable_cb' => 'on', 'pfb_interval' => '1']);
		$this->assertArrayNotHasKey('pfb_keep', $this->getGen());

		pfb_run_migrations();

		$gen = $this->getGen();
		$this->assertSame('on', $gen['pfb_keep']);
		$this->assertContains(
			'pfBlockerNG: preserve settings across upgrade (seed Keep flag, issue #281)',
			$this->writeConfigCalls()
		);
	}

	// -----------------------------------------------------------------------
	// E — Driver: already migrated (idempotency / run-once)
	// -----------------------------------------------------------------------

	/**
	 * Scenario: a second run on an already-fully-migrated config is a complete no-op.
	 *
	 * Given both sections carry all expected post-migration values.
	 * When pfb_run_migrations() is called a second time.
	 * Then no write_config() is called.
	 */
	public function testDriverIsNoOpOnAlreadyMigratedConfig(): void
	{
		// Seed both sections in their fully-migrated state.
		$this->seedDnsbl([
			'pfb_dnsbl'                 => 'on',
			'dnsbl_mode'                => 'dnsbl_python',
			'pfb_py_block'              => 'on',
			'pfb_control_legacy_seeded' => 'on',
			'pfb_dnsbl_lenient'         => 'on',
		]);
		$this->seedGen(['enable_cb' => 'on', 'pfb_keep' => 'on']);

		// First run should be a no-op since all keys already carry migrated values.
		pfb_run_migrations();
		$this->assertSame([], $this->writeConfigCalls(), 'First run on migrated config must be a no-op');

		// Second run is also a no-op.
		pfb_run_migrations();
		$this->assertSame([], $this->writeConfigCalls(), 'Second run on migrated config must still be a no-op');
	}

	/**
	 * Scenario: feeding the output of a first full run back through a second run
	 * is idempotent — no additional writes, same final state.
	 *
	 * This simulates a box that has been through one upgrade and then receives
	 * another (e.g. a point release). The two runs must produce identical config.
	 */
	public function testDriverSecondRunAfterFullMigrationIsIdentical(): void
	{
		// Start from a legacy state that needs all four migrations.
		$this->seedDnsbl([
			'pfb_dnsbl'  => 'on',
			'dnsbl_mode' => 'dnsbl_unbound',
			'pfb_py_block' => '',
			'pfb_control'  => 'on',
		]);
		$this->seedGen(['enable_cb' => 'on', 'pfb_interval' => '1']);

		// First run: all four migrations fire.
		pfb_run_migrations();
		$dnsbl_after_first = $this->getDnsbl();
		$gen_after_first   = $this->getGen();
		$writes_first      = $this->writeConfigCalls();
		$this->assertGreaterThan(0, count($writes_first), 'First run must produce writes');

		// Reset write tracker only; config stays as the first run left it.
		$GLOBALS['pfb_test_write_config_calls'] = [];

		// Second run: all apply() callables see the already-migrated values → NULL → no write.
		pfb_run_migrations();
		$this->assertSame([], $this->writeConfigCalls(), 'Second run must not write again');
		$this->assertSame($dnsbl_after_first, $this->getDnsbl(), 'DNSBL section must be unchanged on second run');
		$this->assertSame($gen_after_first,   $this->getGen(),   'General section must be unchanged on second run');
	}

	// -----------------------------------------------------------------------
	// F — Ordering: later migrations see the state from earlier ones
	// -----------------------------------------------------------------------

	/**
	 * Scenario: ADR-02 and PFBL-03 interact — PFBL-03 must see the section as
	 * ADR-02 left it (same section, in-order within one run).
	 *
	 * Given a populated DNSBL section with pfb_control='on' and legacy mode.
	 * When the driver runs.
	 * Then ADR-02 fires first (forcing python mode), THEN PFBL-03 sees the
	 * updated section and seeds the legacy control toggle.
	 * Both write_config messages appear, in order.
	 */
	public function testOrderingAdr02BeforePfbl03WithinOneRun(): void
	{
		$this->seedDnsbl([
			'pfb_dnsbl'    => 'on',
			'dnsbl_mode'   => 'dnsbl_unbound',
			'pfb_py_block' => '',
			'pfb_control'  => 'on',
		]);

		pfb_run_migrations();

		$dnsbl   = $this->getDnsbl();
		$writes  = $this->writeConfigCalls();

		// ADR-02 result present.
		$this->assertSame('dnsbl_python', $dnsbl['dnsbl_mode']);
		$this->assertSame('on', $dnsbl['pfb_py_block']);
		// PFBL-03 result present.
		$this->assertSame('on', $dnsbl['pfb_control_legacy']);
		$this->assertSame('on', $dnsbl['pfb_control_legacy_seeded']);

		// ADR-02 message precedes PFBL-03 message in the write log.
		$adr02_pos   = array_search('pfBlockerNG: migrated DNSBL to Python-only mode', $writes, TRUE);
		$pfbl03_pos  = array_search('pfBlockerNG: seeded legacy DNSBL control toggle (PFBL-03)', $writes, TRUE);
		$this->assertNotFalse($adr02_pos,  'ADR-02 write_config must be called');
		$this->assertNotFalse($pfbl03_pos, 'PFBL-03 write_config must be called');
		$this->assertLessThan($pfbl03_pos, $adr02_pos, 'ADR-02 must fire before PFBL-03');
	}

	/**
	 * Scenario: DNSBL migrations fire before the General section migration.
	 *   All three DNSBL migration messages appear before the General #281 message.
	 */
	public function testOrderingDnsblMigrationsBeforeGeneralMigration(): void
	{
		$this->seedDnsbl([
			'pfb_dnsbl'  => 'on',
			'dnsbl_mode' => 'dnsbl_unbound',
			'pfb_py_block' => '',
			'pfb_control'  => 'on',
		]);
		$this->seedGen(['enable_cb' => 'on']);

		pfb_run_migrations();

		$writes = $this->writeConfigCalls();

		$keep_pos   = array_search(
			'pfBlockerNG: preserve settings across upgrade (seed Keep flag, issue #281)',
			$writes,
			TRUE
		);
		$this->assertNotFalse($keep_pos, 'issue #281 write_config must appear');

		// Every DNSBL write must come before the General write.
		foreach ($writes as $pos => $msg) {
			if ($pos === $keep_pos) {
				continue;
			}
			$this->assertLessThan($keep_pos, $pos, "DNSBL write '{$msg}' must precede General write");
		}
	}

	// -----------------------------------------------------------------------
	// G — write_config messages match original install.inc messages exactly
	// -----------------------------------------------------------------------

	/**
	 * Each write_config message must exactly match the string used in the original
	 * hand-wired install.inc block (byte-identical — history, log searches, and
	 * any external tooling that parses these messages must not break).
	 */
	public function testWriteConfigMessagesMatchOriginalInstallIncMessages(): void
	{
		// Trigger all four migrations.
		$this->seedDnsbl([
			'pfb_dnsbl'  => 'on',
			'dnsbl_mode' => 'dnsbl_unbound',
			'pfb_py_block' => '',
			'pfb_control'  => 'on',
		]);
		$this->seedGen(['enable_cb' => 'on']);

		pfb_run_migrations();

		$writes = $this->writeConfigCalls();

		$this->assertContains('pfBlockerNG: migrated DNSBL to Python-only mode', $writes);
		$this->assertContains('pfBlockerNG: seeded legacy DNSBL control toggle (PFBL-03)', $writes);
		$this->assertContains(
			'pfBlockerNG: preserve permissive DNSBL parsing for existing install (ADR-22 migration)',
			$writes
		);
		$this->assertContains(
			'pfBlockerNG: preserve settings across upgrade (seed Keep flag, issue #281)',
			$writes
		);
	}
}
