<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1898 — retire the compatibility-only stored config-key names.
 *
 * Three landed decisions deliberately froze a stored `config.xml` key while the
 * runtime/UI vocabulary moved on, purely so 4.x could share config.xml with the
 * 3.2.x family: the dead-Alexa TOP1M cluster (#872/#877), and ADR-66 §2.1/§2.2's
 * TLD Allow and TLD Wildcard families. The owner retired that goal; downgrade
 * safety now comes from the settings-family snapshots, so current code stores the
 * current vocabulary and one atomic, idempotent post-install migration carries an
 * existing installation forward.
 *
 * What this pins:
 *   - the mapping is exactly the 14 audited rows, no style renames;
 *   - each preflight disposition (absent/absent, present/absent, absent/present,
 *     both-equal, both-different) behaves as specified;
 *   - a conflicting row fails CLOSED — the WHOLE config is left unchanged, across
 *     every section, and an actionable notice fires that never echoes a value;
 *   - the migration is pure before commit, atomic across both affected sections,
 *     persisted by ONE write_config(), and a second run mutates nothing;
 *   - the seeding pass materialises every registered scalar exactly once, never
 *     overwriting a value an earlier grandfather/migration already decided; and
 *   - it skips the handful of keys whose ABSENCE is load-bearing today, so the
 *     pass cannot change behaviour on its way to making storage explicit.
 */
#[CoversFunction('pfb_legacy_key_rename_migrate')]
#[CoversFunction('pfb_registered_scalars_seed')]
#[CoversFunction('pfb_run_migrations')]
final class LegacyKeyRenameMigrationTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const ROWS_SECTION  = 'installedpackages/pfblockerngdnsbl/config';
	private const GEN_SECTION   = 'installedpackages/pfblockerng/config/0';
	private const SS_SECTION    = 'installedpackages/pfblockerngsafesearch';
	private const IP_SECTION    = 'installedpackages/pfblockerngipsettings/config/0';
	private const REP_SECTION   = 'installedpackages/pfblockerngreputation/config/0';

	/** The audited mapping, restated here so the test is the independent oracle. */
	private const EXPECTED_DNSBL_RENAMES = [
		'alexa_enable'     => 'top1m_enable',
		'alexa_type'       => 'top1m_source',
		'alexa_count'      => 'top1m_count',
		'alexa_inclusion'  => 'top1m_inclusion',
		'pfb_pytld'        => 'tld_allow',
		'pfb_pytld_sort'   => 'tld_allow_sort',
		'pfb_pytlds_gtld'  => 'tld_allow_gtld',
		'pfb_pytlds_cctld' => 'tld_allow_cctld',
		'pfb_pytlds_itld'  => 'tld_allow_itld',
		'pfb_pytlds_bgtld' => 'tld_allow_bgtld',
		'pfb_tld'          => 'tld_wildcard',
		'tldblacklist'     => 'tld_wildcard_blacklist',
		'tldexclusion'     => 'tld_wildcard_exclusion',
	];

	private const EXPECTED_ROW_RENAMES = ['filter_alexa' => 'filter_top1m'];

	protected function setUp(): void
	{
		$GLOBALS['config']                      = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices']       = [];
	}

	// -----------------------------------------------------------------------
	// Fixtures
	// -----------------------------------------------------------------------

	/**
	 * A DNSBL-settings section as a genuine pre-#1898 install holds it: every old
	 * key present, spanning the value shapes the migration must carry unchanged --
	 * empty, '0', an on/off token, an ordinary word, a CSV multi-select, and a
	 * base64-encoded textarea blob.
	 */
	private function legacyDnsblSection(): array
	{
		return [
			'pfb_dnsbl'        => 'on',
			'alexa_enable'     => 'on',
			'alexa_type'       => 'cisco',
			'alexa_count'      => '5000',
			'alexa_inclusion'  => 'com,net,org',
			'pfb_pytld'        => 'on',
			'pfb_pytld_sort'   => '',
			'pfb_pytlds_gtld'  => 'arpa,example,com,net',
			'pfb_pytlds_cctld' => 'ca,uk',
			'pfb_pytlds_itld'  => '',
			'pfb_pytlds_bgtld' => '0',
			'pfb_tld'          => 'on',
			'tldblacklist'     => base64_encode("zip\nmov\n"),
			'tldexclusion'     => base64_encode("good.example.com\n"),
		];
	}

	/** Two DNSBL feed rows, the dynamic per-row section the row rename targets. */
	private function legacyRowsSection(): array
	{
		return [
			['aliasname' => 'ADs',    'filter_alexa' => 'on',  'state' => 'Enabled'],
			['aliasname' => 'Malware', 'filter_alexa' => '',    'state' => 'Enabled'],
		];
	}

	private function seed(string $section, array $data): void
	{
		config_set_path($section, $data);
	}

	private function get(string $section): array
	{
		$raw = config_get_path($section, []);
		return is_array($raw) ? $raw : [];
	}

	private function noticeText(): string
	{
		$out = '';
		foreach ($GLOBALS['pfb_test_file_notices'] ?? [] as $notice) {
			$out .= (string) ($notice['notice'] ?? '') . "\n";
		}
		return $out;
	}

	/** Run the rename migration over the two sections it owns, as the driver does. */
	private function applyRename(): ?array
	{
		return pfb_legacy_key_rename_migrate([
			self::DNSBL_SECTION => $this->get(self::DNSBL_SECTION),
			self::ROWS_SECTION  => $this->get(self::ROWS_SECTION),
		]);
	}

	// -----------------------------------------------------------------------
	// A — the mapping is exactly the audited rows
	// -----------------------------------------------------------------------

	/**
	 * The map declares exactly the two affected sections and exactly the 14 audited
	 * pairs. A 15th row would be a style rename the ticket forbids; a missing row
	 * would leave a retired name in production storage.
	 */
	public function testRenameMapIsExactlyTheAuditedRows(): void
	{
		$by_section = [];
		foreach (PFB_LEGACY_KEY_RENAMES as $spec) {
			$by_section[$spec['section']] = $spec;
		}

		$this->assertSame(
			[self::DNSBL_SECTION, self::ROWS_SECTION],
			array_keys($by_section),
			'rename map must cover the DNSBL settings section and the per-row feed section, in that order'
		);
		$this->assertSame(self::EXPECTED_DNSBL_RENAMES, $by_section[self::DNSBL_SECTION]['keys']);
		$this->assertSame(self::EXPECTED_ROW_RENAMES, $by_section[self::ROWS_SECTION]['keys']);
		$this->assertFalse($by_section[self::DNSBL_SECTION]['rows'], 'DNSBL settings is a scalar section');
		$this->assertTrue($by_section[self::ROWS_SECTION]['rows'], 'the feed section is a list of per-feed rows');
	}

	/**
	 * After the rename no retired name is registered any more, and every renamed
	 * target that WAS registered stays registered under the same section — the
	 * "no dual-read, no fallback compatibility path" constraint, checked against
	 * the live registry rather than a hand-kept list.
	 */
	public function testRegistryCarriesOnlyTheNewNames(): void
	{
		$registry = pfb_cfg_registry();

		foreach (self::EXPECTED_DNSBL_RENAMES as $old => $new) {
			$this->assertArrayNotHasKey(
				'dnsbl/' . $old,
				$registry,
				"retired key '{$old}' must no longer be registered (it would keep a compatibility path alive)"
			);
		}

		// The eight rows that were registered before the rename stay registered, under
		// the same 'dnsbl' alias (issue #1931: PFB_SECTIONS['dnsbl'] is that real path).
		$this->assertSame(self::DNSBL_SECTION, PFB_SECTIONS['dnsbl']);
		foreach (['top1m_enable', 'top1m_source', 'top1m_count', 'top1m_inclusion',
			'tld_allow', 'tld_wildcard', 'tld_wildcard_blacklist', 'tld_wildcard_exclusion'] as $new) {
			$this->assertArrayHasKey('dnsbl/' . $new, $registry, "renamed key '{$new}' must stay registered");
		}
	}

	// -----------------------------------------------------------------------
	// B — the five preflight dispositions
	// -----------------------------------------------------------------------

	/** old absent, new absent: nothing to do anywhere. */
	public function testPreflightBothAbsentIsANoOp(): void
	{
		$this->seed(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);

		$this->assertNull($this->applyRename(), 'a section with no retired key must not be rewritten');
	}

	/** old present, new absent: the value moves, byte-identically. */
	public function testPreflightOldOnlyMovesTheValueByteIdentically(): void
	{
		$blob = base64_encode("zip\nmov\n");
		$this->seed(self::DNSBL_SECTION, ['tldblacklist' => $blob]);

		$result = $this->applyRename();

		$this->assertIsArray($result);
		$this->assertSame($blob, $result[self::DNSBL_SECTION]['tld_wildcard_blacklist']);
		$this->assertArrayNotHasKey('tldblacklist', $result[self::DNSBL_SECTION]);
	}

	/** old absent, new present: already migrated — no second pass, no rewrite. */
	public function testPreflightNewOnlyIsAlreadyMigrated(): void
	{
		$this->seed(self::DNSBL_SECTION, ['tld_wildcard' => 'on', 'top1m_count' => '5000']);

		$this->assertNull($this->applyRename(), 'an already-migrated section must not be rewritten');
	}

	/** both present, same value: converge on the new key, drop the old one. */
	public function testPreflightBothPresentAndEqualConvergesOnTheNewKey(): void
	{
		$this->seed(self::DNSBL_SECTION, ['pfb_tld' => 'on', 'tld_wildcard' => 'on']);

		$result = $this->applyRename();

		$this->assertIsArray($result);
		$this->assertSame('on', $result[self::DNSBL_SECTION]['tld_wildcard']);
		$this->assertArrayNotHasKey('pfb_tld', $result[self::DNSBL_SECTION]);
	}

	/**
	 * both present, different values: fail CLOSED. No guess, no partial write --
	 * and the notice names the keys so an operator can act, without echoing either
	 * value (these fields carry base64 list blobs and multi-selects).
	 */
	public function testPreflightConflictFailsClosedWithASecretSafeNotice(): void
	{
		$this->seed(self::DNSBL_SECTION, [
			'pfb_tld'      => 'on',
			'tld_wildcard' => 'off',
			'alexa_count'  => '5000',
		]);

		$this->assertNull($this->applyRename(), 'a conflicting row must abandon the whole migration');

		$text = $this->noticeText();
		$this->assertStringContainsString('pfb_tld', $text, 'notice must name the retired key');
		$this->assertStringContainsString('tld_wildcard', $text, 'notice must name the current key');
		$this->assertStringNotContainsString("'on'", $text, 'notice must not echo stored values');
		$this->assertStringNotContainsString("'off'", $text, 'notice must not echo stored values');
	}

	/**
	 * All-or-nothing across BOTH sections: one conflicting row in the DNSBL
	 * settings section must leave the untouched per-row section unmigrated too --
	 * a half-migrated config is the data-loss shape this ticket exists to avoid.
	 */
	public function testConflictLeavesEveryOtherRowAndSectionUnmigrated(): void
	{
		$legacy = $this->legacyDnsblSection();
		$legacy['tld_wildcard'] = 'off';       // conflicts with the legacy pfb_tld = 'on'
		$this->seed(self::DNSBL_SECTION, $legacy);
		$this->seed(self::ROWS_SECTION, $this->legacyRowsSection());

		$this->assertNull($this->applyRename());

		pfb_run_migrations();

		$this->assertSame('cisco', $this->get(self::DNSBL_SECTION)['alexa_type'] ?? NULL,
			'a non-conflicting sibling key must NOT be migrated when another row conflicts');
		$this->assertSame('on', $this->get(self::ROWS_SECTION)[0]['filter_alexa'] ?? NULL,
			'the per-row section must be left alone when the scalar section conflicts');
	}

	// -----------------------------------------------------------------------
	// C — the driver: atomic, one write, idempotent
	// -----------------------------------------------------------------------

	/**
	 * Scenario: a genuine pre-#1898 install upgrades.
	 *
	 * Given a DNSBL settings section holding every retired key across the full
	 *   range of stored value shapes, plus two feed rows carrying the retired
	 *   per-row key,
	 * When the post-install migration driver runs once,
	 * Then config.xml holds only the current names, every value survives
	 *   byte-identically, and exactly one write_config() records the rename.
	 */
	public function testDriverMigratesEveryRowAndPersistsOnce(): void
	{
		$legacy = $this->legacyDnsblSection();
		$this->seed(self::DNSBL_SECTION, $legacy);
		$this->seed(self::ROWS_SECTION, $this->legacyRowsSection());

		// BEFORE: the retired names are what is stored.
		$this->assertArrayHasKey('alexa_type', $this->get(self::DNSBL_SECTION));
		$this->assertArrayHasKey('filter_alexa', $this->get(self::ROWS_SECTION)[0]);

		pfb_run_migrations();

		$dnsbl = $this->get(self::DNSBL_SECTION);
		foreach (self::EXPECTED_DNSBL_RENAMES as $old => $new) {
			$this->assertArrayNotHasKey($old, $dnsbl, "retired key '{$old}' still stored after migration");
			$this->assertArrayHasKey($new, $dnsbl, "current key '{$new}' missing after migration");
			// alexa_type is the one adapter-bearing row: its write-back canonicalises
			// through PfbTop1mSource, which is the documented behaviour-equivalent move.
			if ($old !== 'alexa_type') {
				$this->assertSame($legacy[$old], $dnsbl[$new], "value of '{$old}' not carried byte-identically to '{$new}'");
			}
		}
		$this->assertSame('cisco', $dnsbl['top1m_source'], 'a canonical TOP1M token must survive the adapter round-trip');

		$rows = $this->get(self::ROWS_SECTION);
		$this->assertSame('on', $rows[0]['filter_top1m']);
		$this->assertSame('', $rows[1]['filter_top1m']);
		$this->assertArrayNotHasKey('filter_alexa', $rows[0]);
		$this->assertArrayNotHasKey('filter_alexa', $rows[1]);
		$this->assertSame('ADs', $rows[0]['aliasname'], 'unrelated per-row keys must pass through untouched');

		$rename_writes = array_filter(
			$GLOBALS['pfb_test_write_config_calls'],
			static fn (string $msg): bool => str_contains($msg, '1898')
		);
		$this->assertCount(1, $rename_writes, 'the rename must persist with exactly one write_config() event');
	}

	/**
	 * Idempotence: a second driver run over the migrated result mutates nothing and
	 * records no further rename write.
	 */
	public function testSecondRunIsAByteIdenticalNoOp(): void
	{
		$this->seed(self::DNSBL_SECTION, $this->legacyDnsblSection());
		$this->seed(self::ROWS_SECTION, $this->legacyRowsSection());
		pfb_run_migrations();

		$dnsbl_after_first = $this->get(self::DNSBL_SECTION);
		$rows_after_first  = $this->get(self::ROWS_SECTION);
		$GLOBALS['pfb_test_write_config_calls'] = [];

		pfb_run_migrations();

		$this->assertSame($dnsbl_after_first, $this->get(self::DNSBL_SECTION));
		$this->assertSame($rows_after_first, $this->get(self::ROWS_SECTION));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'],
			'a re-run on an already-migrated config must not call write_config() at all');
	}

	/**
	 * A legacy TOP1M token riding the rename still coalesces to its canonical
	 * successor: the value migration is behaviour-preserving, not byte-preserving,
	 * exactly where the registered adapter says so (#872 'alexa' -> 'tranco').
	 */
	public function testLegacyTop1mTokenCoalescesThroughTheRenamedKeysAdapter(): void
	{
		$this->seed(self::DNSBL_SECTION, ['alexa_type' => 'alexa', 'alexa_enable' => 'on']);

		pfb_run_migrations();

		$this->assertSame('tranco', $this->get(self::DNSBL_SECTION)['top1m_source']);
	}

	/**
	 * The rename runs AFTER the two issue #1887 '' preservations (whose intent an
	 * adapter-riding write-back would destroy) and before the remaining entries.
	 */
	public function testRenameIsOrderedAfterTheEmptyStringPreservations(): void
	{
		$ids = array_column(pfb_migration_registry(), 'id');

		$this->assertSame('issue1887-toggle-empty-preserve-gen', $ids[0]);
		$this->assertSame('issue1887-toggle-empty-preserve-dnsbl', $ids[1]);
		$this->assertSame('issue1898-legacy-key-rename', $ids[2]);
	}

	/**
	 * A fresh install has no retired key anywhere, so the migration is inert and
	 * creates only current names.
	 */
	public function testFreshInstallIsUntouchedByTheRename(): void
	{
		pfb_run_migrations();

		$this->assertSame([], $this->get(self::ROWS_SECTION));
		foreach (array_keys(self::EXPECTED_DNSBL_RENAMES) as $old) {
			$this->assertArrayNotHasKey($old, $this->get(self::DNSBL_SECTION));
		}
	}

	// -----------------------------------------------------------------------
	// D — the seeding pass
	// -----------------------------------------------------------------------

	/**
	 * Every registered scalar absent from its section is materialised at its
	 * registered default, so "absent" stops being a third semantic state.
	 */
	public function testSeedMaterialisesAbsentRegisteredScalarsAtTheirDefault(): void
	{
		$changed = pfb_registered_scalars_seed([]);

		$this->assertSame('on', $changed[self::GEN_SECTION]['pfb_keep'] ?? NULL);
		$this->assertSame('1', $changed[self::GEN_SECTION]['pfb_interval'] ?? NULL);
		$this->assertSame('tranco', $changed[self::DNSBL_SECTION]['top1m_source'] ?? NULL);
		$this->assertSame('Disable', $changed[self::SS_SECTION]['safesearch_enable'] ?? NULL);
		$this->assertSame('', $changed[self::IP_SECTION]['v6suppression'] ?? NULL);
		$this->assertSame('', $changed[self::REP_SECTION]['enable_rep'] ?? NULL);
	}

	/**
	 * The seed skips every registered key whose LITERAL ABSENCE some consumer still
	 * reads as a distinct state. Materialising those would change behaviour on the
	 * way to making storage explicit, which is the opposite of this ticket's point:
	 *
	 *   - `v4suppression` — pfblockerng_install.inc's ADR-53 pfBlockerNGSuppress
	 *     alias conversion is gated on "never migrated" (absent) versus "present but
	 *     empty", a distinction its own comment calls out;
	 *   - `pfb_cache`, `pfb_py_reply`, `pfb_hsts` — pfblockerng_dnsbl.php renders
	 *     these CHECKED when the key is absent (`isset(...) ? ... : 'on'`) while the
	 *     registry default is '', so seeding '' would silently flip the first-open
	 *     rendering, and therefore what a first save stores (issue #1907).
	 */
	public function testSeedSkipsKeysWhoseAbsenceIsLoadBearing(): void
	{
		$changed = pfb_registered_scalars_seed([]);

		$this->assertArrayNotHasKey('v4suppression', $changed[self::IP_SECTION] ?? [],
			'v4suppression absence gates the ADR-53 install migration');
		foreach (['pfb_cache', 'pfb_py_reply', 'pfb_hsts'] as $key) {
			$this->assertArrayNotHasKey($key, $changed[self::DNSBL_SECTION] ?? [],
				"seeding '{$key}' would flip the DNSBL page's absent-default rendering (issue #1907)");
		}
	}

	/**
	 * The seed never overwrites a decision an earlier grandfather or migration
	 * already made -- including an explicit 'off' whose registered default is 'on',
	 * which is precisely the value a naive re-seed would destroy.
	 */
	public function testSeedNeverOverwritesAnExistingValue(): void
	{
		$changed = pfb_registered_scalars_seed([
			self::GEN_SECTION => [
				'pfb_feed_internal_filter' => 'off',   // the #1770 grandfather's pin
				'pfb_alias_delta_mode'     => 'replace', // the ADR-40 grandfather's pin
				'pfb_keep'                 => 'off',   // a 3.2 operator's deliberate opt-out
			],
		]);

		$this->assertSame('off', $changed[self::GEN_SECTION]['pfb_feed_internal_filter']);
		$this->assertSame('replace', $changed[self::GEN_SECTION]['pfb_alias_delta_mode']);
		$this->assertSame('off', $changed[self::GEN_SECTION]['pfb_keep']);
	}

	/**
	 * settings_family is the installer's own schema marker, not an operator
	 * setting: seeding it would write the legacy '3.2' default over the family the
	 * installer is about to record (issues #1770/#1771/#1775 keep it out of every
	 * "is this operator configuration?" decision for the same reason).
	 */
	public function testSeedNeverMaterialisesTheInstallerSchemaMarker(): void
	{
		$changed = pfb_registered_scalars_seed([]);

		$this->assertArrayNotHasKey('settings_family', $changed[self::GEN_SECTION] ?? []);
	}

	/**
	 * A fail-closed conflict must stay RECOVERABLE, so the seed must not materialise a
	 * current name's default while its retired name is still stored.
	 *
	 * The rename is all-or-nothing: one conflicting pair leaves every OTHER retired key
	 * present-and-unmigrated. Seeding those current names would give each of them a
	 * both-present-and-different pair of its own on the next install, turning a
	 * single-key recovery into an N-key one and destroying the old-present/new-absent
	 * path that migrates them cleanly the moment the operator resolves the one real
	 * conflict.
	 */
	public function testSeedDoesNotManufactureConflictsOutOfAnUnmigratedSection(): void
	{
		$legacy = $this->legacyDnsblSection();
		$legacy['tld_wildcard'] = 'off';        // the single real conflict (legacy pfb_tld = 'on')
		$this->seed(self::DNSBL_SECTION, $legacy);

		pfb_run_migrations();
		// Before: the migration failed closed, so every retired name is still stored.
		$this->assertArrayHasKey('alexa_type', $this->get(self::DNSBL_SECTION));

		$changed = pfb_registered_scalars_seed([self::DNSBL_SECTION => $this->get(self::DNSBL_SECTION)]);

		foreach (['top1m_enable', 'top1m_source', 'top1m_count', 'top1m_inclusion',
			'tld_allow', 'tld_wildcard_blacklist', 'tld_wildcard_exclusion'] as $new_key) {
			$this->assertArrayNotHasKey(
				$new_key,
				$changed[self::DNSBL_SECTION] ?? [],
				"seeding '{$new_key}' while its retired name is still stored manufactures a second conflict"
			);
		}
		// ...while a registered key with no retired predecessor still seeds normally, so
		// the guard is scoped to the rename map rather than disabling the whole section.
		$this->assertSame('reject', $changed[self::DNSBL_SECTION]['dnsbl_dot_block_action'] ?? NULL);
	}

	/** A second pass over the seeded result changes nothing. */
	public function testSeedIsIdempotent(): void
	{
		$first = pfb_registered_scalars_seed([]);

		$this->assertSame([], pfb_registered_scalars_seed($first),
			'a re-seed over an already-seeded config must report no section as changed');
	}

	/**
	 * The seed must run AFTER the rename migration and AFTER both install-default
	 * grandfathers -- they live at the END of pfblockerng_install.inc, so a seed
	 * placed in the migration registry would materialise the registry default first
	 * and permanently disarm them. Source-order assertion, the house pattern for
	 * install.inc ordering (PfbSettingsFamilyPostInstallCaptureTest).
	 */
	public function testSeedRunsAfterMigrationsAndBothInstallDefaultGrandfathers(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$this->assertIsString($source);

		$migrations   = strpos($source, 'pfb_run_migrations();');
		$feed_default = strpos($source, 'pfb_feed_filter_install_default($pfb_gcfg)');
		$delta_default = strpos($source, 'pfb_alias_delta_mode_install_default($pfb_gcfg)');
		$seed         = strpos($source, 'pfb_registered_scalars_seed(');
		$final_write  = strpos($source, "write_config('[pfBlockerNG] Save installation settings')");

		$this->assertNotFalse($migrations);
		$this->assertNotFalse($feed_default);
		$this->assertNotFalse($delta_default);
		$this->assertNotFalse($seed, 'pfblockerng_install.inc must call the seeding pass');
		$this->assertNotFalse($final_write);

		$this->assertGreaterThan($migrations, $seed, 'seed must follow the migration driver');
		$this->assertGreaterThan($feed_default, $seed, 'seed must follow the feed-filter grandfather');
		$this->assertGreaterThan($delta_default, $seed, 'seed must follow the alias-delta-mode grandfather');
		$this->assertLessThan($final_write, $seed, 'seed must ride the installer trailing write_config()');
	}
}
