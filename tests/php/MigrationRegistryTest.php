<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 2 — Migration registry + driver.
 *
 * Scenario: pfb_run_migrations() consolidates the independent upgrade migrations
 * (ADR-02 python-mode, PFBL-03 control-legacy seed) into one ordered, idempotent,
 * registry-driven driver, alongside issue #1898's per-row key rename.
 *
 * issue #1921 (S2): the four grandfather/preservation migrations that used to live in
 * this registry (#1887's two '' preservations, ADR-22's lenient seed, issue #281's
 * pfb_keep seed) are folded into pfb_registry_pass() (pfblockerng.inc) -- the one
 * registry-driven pass the installer runs AFTER this driver. Coverage for that
 * behaviour now lives in RegistryPassTest, not here.
 *
 * issue #1907 (S3): pfb_python_gated_toggles_migrate() joins the registry, positioned
 * immediately before adr02-dnsbl-python-mode -- it disables a stored 'on' for
 * pfb_py_reply/pfb_hsts that was inert under pre-upgrade Unbound mode (both were
 * python-gated in 3.2), reading dnsbl_mode as evidence BEFORE ADR-02 overwrites it.
 *
 * Contract (§2.4 ADR-29):
 *   - ORDERING: migrations fire in the documented order; a later migration sees the
 *     section state left by an earlier one in the same run.
 *   - IDEMPOTENCY / RUN-ONCE: a second pfb_run_migrations() call on an already-migrated
 *     config is a no-op (no write_config() calls).
 *   - RAW WRITE-BACK (issue #1921): every write this driver performs must persist
 *     RAW (adapter-free, PfbConfig::writeSectionRawSystem()) -- a migration transforms
 *     raw storage, and canonicalising a bystander would mutate a key outside the
 *     migration's declared work and hide the exact input from pfb_registry_pass().
 *   - pfb_migration_registry() returns exactly the declared entries in the correct order,
 *     each declaring exactly one of the single-'section' / multi-'sections' target forms.
 */
#[CoversFunction('pfb_run_migrations')]
#[CoversFunction('pfb_migration_registry')]
#[CoversFunction('pfb_dnsbl_python_migrate')]
#[CoversFunction('pfb_python_gated_toggles_migrate')]
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
		$GLOBALS['pfb_test_file_notices']       = [];
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
	 * Registry returns exactly five entries in the correct declared order (issue #1921
	 * S2: the other four migrations folded into pfb_registry_pass(); issue #1907 adds
	 * the bespoke python-gated-toggles migration, positioned immediately before ADR-02
	 * -- it must run while dnsbl_mode still evidences pre-upgrade Unbound mode, which
	 * ADR-02 overwrites).
	 */
	public function testRegistryHasFiveEntriesInOrder(): void
	{
		$registry = pfb_migration_registry();

		$this->assertCount(5, $registry);

		// issue #1898's per-row key rename runs first -- the scalar-section half now
		// lives as registry 'old_name' slots consumed by pfb_registry_pass(), which
		// runs AFTER this whole driver.
		$this->assertSame('issue1898-legacy-key-rename', $registry[0]['id']);
		// issue #1907: must run BEFORE ADR-02 -- it reads dnsbl_mode as evidence of a
		// pre-upgrade Unbound install, and ADR-02 immediately overwrites that same key.
		$this->assertSame('issue1907-python-gated-toggles', $registry[1]['id']);
		// Then the original install.inc sequence for what remains, order unchanged.
		$this->assertSame('adr02-dnsbl-python-mode',    $registry[2]['id']);
		$this->assertSame('pfbl03-control-legacy-seed', $registry[3]['id']);
		$this->assertSame('issue2308-quarter-hour-schedule', $registry[4]['id']);
	}

	/**
	 * Every entry carries the required fields, and declares EXACTLY ONE of the two
	 * target forms — a single 'section', or issue #1898's 'sections' list. Carrying
	 * both, or neither, would leave pfb_run_migrations() guessing which branch owns
	 * the entry.
	 */
	public function testRegistryEntriesHaveRequiredFields(): void
	{
		foreach (pfb_migration_registry() as $entry) {
			$this->assertArrayHasKey('id',      $entry);
			$this->assertArrayHasKey('apply',   $entry);
			$this->assertArrayHasKey('message', $entry);
			$this->assertArrayHasKey('since',   $entry);
			$this->assertIsCallable($entry['apply'], "apply for {$entry['id']} must be callable");

			$this->assertSame(
				1,
				(int) isset($entry['section']) + (int) isset($entry['sections']),
				"{$entry['id']} must declare exactly one of 'section' / 'sections'"
			);
			if (isset($entry['sections'])) {
				$this->assertNotEmpty($entry['sections'], "{$entry['id']}: 'sections' must not be empty");
			}
		}
	}

	/**
	 * The issue #1898 rename spans the DNSBL settings section plus the dynamic per-feed
	 * row section; ADR-02 and PFBL-03 both target the DNSBL section.
	 */
	public function testRegistryEntriesSectionsAreCorrect(): void
	{
		$registry = pfb_migration_registry();
		$this->assertSame(
			[self::DNSBL_SECTION, 'installedpackages/pfblockerngdnsbl/config'],
			$registry[0]['sections']
		);
		$this->assertSame(self::DNSBL_SECTION, $registry[1]['section']);
		$this->assertSame(self::DNSBL_SECTION, $registry[2]['section']);
		$this->assertSame(self::DNSBL_SECTION, $registry[3]['section']);
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
	// B2 — pfb_python_gated_toggles_migrate() unit tests (issue #1907): both
	//      pfb_py_reply and pfb_hsts were python-gated in 3.2
	//      ($mode == 'enabled' && dnsbl_mode == 'dnsbl_python'), so a stored 'on' under
	//      Unbound mode was inert -- disable it before ADR-02 forces python mode and
	//      would otherwise activate it. dnsbl_mode is unregistered, so its PRESENCE
	//      (not its value) is the only reliable pre-upgrade-Unbound-mode evidence: a
	//      fresh-4.0 install's registry-seeded section never carries it.
	// -----------------------------------------------------------------------

	public function testPythonGatedTogglesMigrateSkipsEmptyOrNonArray(): void
	{
		$this->assertNull(pfb_python_gated_toggles_migrate([]));
		$this->assertNull(pfb_python_gated_toggles_migrate(null));
	}

	/**
	 * Row (ii): dnsbl_mode ABSENT -- must stay a no-op even though pfb_py_reply is
	 * stored 'on', because a fresh-4.0-seeded section has NO dnsbl_mode key at all (the
	 * registry pass seeds only registered keys, and dnsbl_mode is unregistered). The
	 * regression this pins: loosening the guard to
	 * `($dconfig['dnsbl_mode'] ?? '') !== 'dnsbl_python'` would fire here and wrongly
	 * disable a fresh install's seeded default-on toggle.
	 */
	public function testPythonGatedTogglesMigrateNoOpWhenDnsblModeAbsent(): void
	{
		$out = pfb_python_gated_toggles_migrate(['pfb_dnsbl' => 'on', 'pfb_py_reply' => 'on']);
		$this->assertNull($out);
	}

	/** Row (iii): dnsbl_mode already 'dnsbl_python' -- no-op (ADR-02 already ran, or a new install that later wrote it). */
	public function testPythonGatedTogglesMigrateNoOpWhenAlreadyPythonMode(): void
	{
		$out = pfb_python_gated_toggles_migrate([
			'pfb_dnsbl' => 'on', 'dnsbl_mode' => 'dnsbl_python', 'pfb_py_reply' => 'on', 'pfb_hsts' => 'on',
		]);
		$this->assertNull($out);
	}

	/** Row (iv): dnsbl_mode present, non-python -- but both toggles absent/''/'off' -- no-op. */
	public function testPythonGatedTogglesMigrateNoOpWhenTogglesNotOn(): void
	{
		$absent = pfb_python_gated_toggles_migrate(['dnsbl_mode' => 'dnsbl_unbound']);
		$this->assertNull($absent);

		$empty = pfb_python_gated_toggles_migrate(['dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_reply' => '', 'pfb_hsts' => '']);
		$this->assertNull($empty);

		$off = pfb_python_gated_toggles_migrate(['dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_reply' => 'off', 'pfb_hsts' => 'off']);
		$this->assertNull($off);
	}

	/** Row (i): dnsbl_mode present, non-python, both toggles stored 'on' -- both flip to 'off'. */
	public function testPythonGatedTogglesMigrateDisablesBothWhenModeIsPreUpgradeUnbound(): void
	{
		$dconfig = ['pfb_dnsbl' => 'on', 'dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_reply' => 'on', 'pfb_hsts' => 'on'];

		$out = pfb_python_gated_toggles_migrate($dconfig);

		$this->assertIsArray($out);
		$this->assertSame('off', $out['pfb_py_reply']);
		$this->assertSame('off', $out['pfb_hsts']);
		// Other keys preserved; this migration never touches dnsbl_mode itself.
		$this->assertSame('on', $out['pfb_dnsbl']);
		$this->assertSame('dnsbl_unbound', $out['dnsbl_mode']);
	}

	/** Only one of the two toggles is 'on' -- still fires, flips only that one. */
	public function testPythonGatedTogglesMigrateFlipsOnlyTheOnToggle(): void
	{
		$out1 = pfb_python_gated_toggles_migrate(['dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_reply' => 'on', 'pfb_hsts' => 'off']);
		$this->assertIsArray($out1);
		$this->assertSame('off', $out1['pfb_py_reply']);
		$this->assertSame('off', $out1['pfb_hsts']);

		$out2 = pfb_python_gated_toggles_migrate(['dnsbl_mode' => 'dnsbl_unbound', 'pfb_py_reply' => 'off', 'pfb_hsts' => 'on']);
		$this->assertIsArray($out2);
		$this->assertSame('off', $out2['pfb_py_reply']);
		$this->assertSame('off', $out2['pfb_hsts']);
	}

	// -----------------------------------------------------------------------
	// C — Driver: fresh install (both sections absent)
	// -----------------------------------------------------------------------

	/**
	 * Scenario: fresh install — no sections exist.
	 *   Given no config at all.
	 *   When pfb_run_migrations() runs.
	 *   Then the canonical General schedule is seeded in one write.
	 */
	public function testDriverFreshInstallSeedsCanonicalSchedule(): void
	{
		// Before: config is empty.
		$this->assertSame([], config_get_path(self::DNSBL_SECTION, []));
		$this->assertSame([], config_get_path(self::GEN_SECTION, []));

		pfb_run_migrations();

		// After: schedule migration creates the canonical General schema in one write.
		$this->assertSame([], config_get_path(self::DNSBL_SECTION, []));
		$this->assertSame('on', config_get_path(self::GEN_SECTION . '/pfb_scheduled_feed_updates'));
		$this->assertSame('7', config_get_path(self::GEN_SECTION . '/pfb_schedule_weekday'));
		$this->assertSame('3', config_get_path(self::GEN_SECTION . '/skipfeed'));
		$this->assertCount(1, $this->writeConfigCalls());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'fresh schedule seeding is not malformed legacy state');
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
	 * issue #1921 (S2) raw-driver regression: pfb_run_migrations()'s write paths must
	 * persist RAW (adapter-free), so a still-raw legacy value on a BYSTANDER key
	 * survives to the registry pass (a later step) for grandfathering -- canonicalising
	 * it here, ahead of that pass, would destroy the value the pass needs to see.
	 *
	 * Fixture: a section where ADR-02 (dnsbl_mode/pfb_py_block) fires AND top1m_source
	 * holds the raw pre-#872 legacy token 'alexa' (an ADR-02-unrelated bystander key,
	 * carried along by the section-level write-back). Asserts the persisted blob still
	 * holds 'alexa' -- NOT the adapter-canonicalised 'tranco' -- after the migration
	 * driver runs. A section-level write that canonicalises adapter-bearing keys (like
	 * today's PfbConfig::writeSectionSystem()) fails this; only a RAW section write
	 * (PfbConfig::writeSectionRawSystem()) preserves the bystander byte.
	 */
	public function testAdr02FiresButRawWriteBackPreservesBystanderLegacyTop1mSource(): void
	{
		$this->seedDnsbl([
			'pfb_dnsbl'    => 'on',
			'dnsbl_mode'   => 'dnsbl_unbound', // ADR-02 must fire on this key
			'pfb_py_block' => '',
			'top1m_source' => 'alexa',          // bystander: still the raw legacy token
		]);

		pfb_run_migrations();

		$dnsbl = $this->getDnsbl();
		// ADR-02 fired (the driver actually ran and rewrote this section).
		$this->assertSame('dnsbl_python', $dnsbl['dnsbl_mode']);
		$this->assertSame('on', $dnsbl['pfb_py_block']);
		// The bystander legacy token must survive RAW: this migration does not own it.
		// An ordinary adapter-backed write may canonicalise it later (issue #1921).
		$this->assertSame('alexa', $dnsbl['top1m_source'],
			'pfb_run_migrations() write-back must persist unrelated bystander values byte-identical'
		);
	}

	/**
	 * Row (i) driver half (mirrors testAdr02FiresButRawWriteBackPreservesBystanderLegacyTop1mSource
	 * above): issue #1907's write-back through pfb_run_migrations() must also persist RAW --
	 * a bystander legacy top1m_source token must survive untouched alongside the disabled
	 * toggles.
	 */
	public function testDriverPythonGatedTogglesFiresWithRawWriteBackPreservingBystander(): void
	{
		$this->seedDnsbl([
			'pfb_dnsbl'    => 'on',
			'dnsbl_mode'   => 'dnsbl_unbound',
			'pfb_py_reply' => 'on',
			'pfb_hsts'     => 'on',
			'top1m_source' => 'alexa', // bystander: still the raw legacy token
		]);

		pfb_run_migrations();

		$dnsbl = $this->getDnsbl();
		$this->assertSame('off', $dnsbl['pfb_py_reply'], 'issue #1907 migration must disable pfb_py_reply');
		$this->assertSame('off', $dnsbl['pfb_hsts'], 'issue #1907 migration must disable pfb_hsts');
		$this->assertSame('alexa', $dnsbl['top1m_source'],
			'the bystander legacy token must survive RAW write-back');
		$this->assertContains(
			'pfBlockerNG: disable python-gated DNSBL toggles inert under pre-upgrade Unbound mode (issue #1907)',
			$this->writeConfigCalls()
		);
	}

	/**
	 * Row (vi): full driver run -- issue #1907 must fire and consume the pre-upgrade
	 * dnsbl_mode evidence BEFORE ADR-02 overwrites it. If ordered the other way, ADR-02
	 * would already have forced dnsbl_mode to 'dnsbl_python' and issue #1907's guard
	 * would see "already python" and never fire -- the disable would silently vanish.
	 */
	public function testDriverIssue1907FiresBeforeAdr02DestroysTheModeEvidence(): void
	{
		$this->seedDnsbl([
			'pfb_dnsbl'    => 'on',
			'dnsbl_mode'   => 'dnsbl_unbound',
			'pfb_py_block' => '',
			'pfb_py_reply' => 'on',
			'pfb_hsts'     => 'on',
		]);

		pfb_run_migrations();

		$dnsbl = $this->getDnsbl();
		$this->assertSame('off', $dnsbl['pfb_py_reply'],
			'issue #1907 must have fired while dnsbl_mode still evidenced pre-upgrade Unbound mode');
		$this->assertSame('dnsbl_python', $dnsbl['dnsbl_mode'], 'ADR-02 still forces python-only mode afterward');

		$writes         = $this->writeConfigCalls();
		$issue1907_pos  = array_search(
			'pfBlockerNG: disable python-gated DNSBL toggles inert under pre-upgrade Unbound mode (issue #1907)',
			$writes,
			TRUE
		);
		$adr02_pos = array_search('pfBlockerNG: migrated DNSBL to Python-only mode', $writes, TRUE);
		$this->assertNotFalse($issue1907_pos, 'issue #1907 write_config must be called');
		$this->assertNotFalse($adr02_pos, 'ADR-02 write_config must be called');
		$this->assertLessThan($adr02_pos, $issue1907_pos,
			'issue #1907 must fire before ADR-02 destroys the dnsbl_mode evidence');
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

	// issue #1921 (S2): the ADR-22 lenient-seed and issue-#281 pfb_keep-seed driver
	// tests that used to live here moved to RegistryPassTest (rows 4 and 7) -- that
	// behaviour is now pfb_registry_pass()'s, not pfb_run_migrations()'s.

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
		$this->seedGen([
			'enable_cb' => 'on', 'pfb_keep' => 'on', 'skipfeed' => '0',
			'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0',
		]);

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
		// Start from a legacy state that needs both remaining scalar migrations.
		$this->seedDnsbl([
			'pfb_dnsbl'  => 'on',
			'dnsbl_mode' => 'dnsbl_unbound',
			'pfb_py_block' => '',
			'pfb_control'  => 'on',
		]);
		$this->seedGen(['enable_cb' => 'on', 'pfb_interval' => '1']);

		// First run: ADR-02 and PFBL-03 fire.
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

	// issue #1921 (S2): testOrderingDnsblMigrationsBeforeGeneralMigration used to pin
	// DNSBL-section migrations firing before the General-section issue-#281 seed. That
	// seed folded into pfb_registry_pass(); every entry left in pfb_migration_registry()
	// now targets the DNSBL section exclusively, so there is no cross-section ordering
	// left for this driver to guarantee (within-DNSBL ordering is
	// testOrderingAdr02BeforePfbl03WithinOneRun above).

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
		// Trigger both remaining scalar migrations (ADR-02, PFBL-03).
		$this->seedDnsbl([
			'pfb_dnsbl'  => 'on',
			'dnsbl_mode' => 'dnsbl_unbound',
			'pfb_py_block' => '',
			'pfb_control'  => 'on',
		]);

		pfb_run_migrations();

		$writes = $this->writeConfigCalls();

		$this->assertContains('pfBlockerNG: migrated DNSBL to Python-only mode', $writes);
		$this->assertContains('pfBlockerNG: seeded legacy DNSBL control toggle (PFBL-03)', $writes);
	}
}
