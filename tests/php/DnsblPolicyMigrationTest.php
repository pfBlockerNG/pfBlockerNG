<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Upgrade legacy DNSBL policy and VIP groups atomically, preserving explicit
 * mechanisms, bystanders, and choices made after the one-time conversion.
 */
#[CoversFunction('pfb_dnsbl_policy_migrate')]
#[CoversFunction('pfb_dnsbl_policy_is_fresh_install')]
#[CoversFunction('pfb_dnsbl_policy_upgrade')]
final class DnsblPolicyMigrationTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const GROUPS_SECTION = 'installedpackages/pfblockerngdnsbl/config';

	/** The seven concrete DNSBL blocking/logging mechanisms (issue #3288 Constraints: unchanged). */
	private const CONCRETE_MECHANISMS = [
		'enabled', 'disabled_log', 'disabled', 'nxdomain_log', 'nxdomain', 'nodata_log', 'nodata',
	];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		unset($GLOBALS['pfb_test_write_config_hook']);
	}

	// -----------------------------------------------------------------------
	// A — pfb_dnsbl_policy_is_fresh_install(): the cross-section freshness predicate
	// -----------------------------------------------------------------------

	public function testFreshRequiresBothDnsblSectionAndGroupsEmpty(): void
	{
		$this->assertTrue(pfb_dnsbl_policy_is_fresh_install([], []));
	}

	/** Existing groups are operator data even if DNSBL settings have never been saved. */
	public function testNotFreshWhenSettingsSectionEmptyButGroupsPresent(): void
	{
		$groups = [0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled']];

		$this->assertFalse(pfb_dnsbl_policy_is_fresh_install([], $groups));
	}

	public function testNotFreshWhenSettingsSectionHasDataButGroupsEmpty(): void
	{
		$this->assertFalse(pfb_dnsbl_policy_is_fresh_install(['pfb_dnsbl' => 'on'], []));
	}

	public function testNotFreshWhenBothSectionsHaveData(): void
	{
		$this->assertFalse(pfb_dnsbl_policy_is_fresh_install(
			['pfb_dnsbl' => 'on'],
			[0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled']]
		));
	}

	// -----------------------------------------------------------------------
	// B — fresh install: no-op regardless of what the groups list holds
	// -----------------------------------------------------------------------

	public function testMigrateSkipsGenuinelyFreshInstall(): void
	{
		$this->assertNull(pfb_dnsbl_policy_migrate([self::DNSBL_SECTION => [], self::GROUPS_SECTION => []]));
	}

	public function testMigrateSkipsWhenBothSectionsAbsentFromInput(): void
	{
		// The 'sections' migration form always supplies both keys (pfb_run_migrations()
		// defaults an absent raw read to []), but the pure function must not crash if a
		// caller omits one entirely either.
		$this->assertNull(pfb_dnsbl_policy_migrate([]));
	}

	// -----------------------------------------------------------------------
	// C — old settings WITHOUT an active override (Default policy + 'enabled' mechanism)
	// -----------------------------------------------------------------------

	/**
	 * Row: "Old no-global-override => Default policy + enabled shared mechanism"
	 * (issue #3288 Required semantics). global_log absent entirely.
	 */
	public function testMigrateAbsentGlobalLogDerivesDefaultModeAndEnabledMechanism(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertIsArray($result);
		$this->assertSame('default', $result[self::DNSBL_SECTION]['global_log_mode'] ?? null);
		$this->assertSame('enabled', $result[self::DNSBL_SECTION]['global_log'] ?? null,
			'the migration must materialise a CONCRETE global_log value itself, never leave it \'\'');
	}

	/** Same row, global_log explicitly stored as '' (the retired no-override sentinel). */
	public function testMigrateExplicitEmptyGlobalLogDerivesDefaultModeAndEnabledMechanism(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on', 'global_log' => ''],
			self::GROUPS_SECTION => [],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertSame('default', $result[self::DNSBL_SECTION]['global_log_mode'] ?? null);
		$this->assertSame('enabled', $result[self::DNSBL_SECTION]['global_log'] ?? null);
	}

	/** Existing groups must inherit the legacy VIP default, not the fresh null default. */
	public function testMigrateSettingsEmptyGroupsPresentDerivesDefaultAndConvertsVipGroups(): void
	{
		$sections = [
			self::DNSBL_SECTION  => [],
			self::GROUPS_SECTION => [
				0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled'],
				1 => ['aliasname' => 'Malware', 'logging' => ''],
			],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertIsArray($result, 'a settings-empty, groups-present box must not be treated as fresh');
		$this->assertSame('default', $result[self::DNSBL_SECTION]['global_log_mode'] ?? null);
		$this->assertSame('enabled', $result[self::DNSBL_SECTION]['global_log'] ?? null);
		$this->assertSame('default', $result[self::GROUPS_SECTION][0]['logging'] ?? null);
		$this->assertSame('default', $result[self::GROUPS_SECTION][1]['logging'] ?? null);
	}

	// -----------------------------------------------------------------------
	// D — old settings WITH an active override (Override policy + same mechanism)
	// -----------------------------------------------------------------------

	/**
	 * Row: "Old active global override => Override with same enforced mechanism"
	 * (issue #3288 Required semantics). Every one of the seven concrete tokens must
	 * be preserved verbatim as the enforced mechanism.
	 */
	#[DataProvider('concreteMechanismProvider')]
	public function testMigrateActiveOverrideDerivesOverrideModeAndPreservesTheMechanism(string $token): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on', 'global_log' => $token],
			self::GROUPS_SECTION => [],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertSame('override', $result[self::DNSBL_SECTION]['global_log_mode'] ?? null);
		$this->assertSame($token, $result[self::DNSBL_SECTION]['global_log'] ?? null,
			'an active override\'s enforced mechanism must be preserved verbatim, never altered');
	}

	/**
	 * "VIP group migration must not alter effective behaviour" under an active
	 * override: every group -- VIP or explicit -- already resolved to the SAME
	 * enforced mechanism under the old unconditional-override apply.inc precedence.
	 * Converting the VIP ones to 'default' is therefore a no-op on EFFECTIVE
	 * behaviour (Override always forces the global mechanism regardless of a
	 * group's own value), but it must still happen -- so the group benefits from
	 * live inheritance once policy later returns to Default.
	 */
	public function testMigrateActiveOverrideStillConvertsVipGroupsForFutureDefaultPolicy(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on', 'global_log' => 'nxdomain_log'],
			self::GROUPS_SECTION => [
				0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled'],
				1 => ['aliasname' => 'Explicit', 'logging' => 'nodata'],
			],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertSame('default', $result[self::GROUPS_SECTION][0]['logging'] ?? null,
			'the VIP group must still convert even though the override already masked it');
		$this->assertSame('nodata', $result[self::GROUPS_SECTION][1]['logging'] ?? null,
			'an explicit non-VIP mechanism must never be touched, override or not');
	}

	// -----------------------------------------------------------------------
	// E — VIP group conversion matrix (independent of global override state)
	// -----------------------------------------------------------------------

	#[DataProvider('vipMarkerProvider')]
	public function testMigrateConvertsEveryVipMarkerVariant($stored_logging): void
	{
		$group = ['aliasname' => 'X'];
		if ($stored_logging !== null) {
			$group['logging'] = $stored_logging;
		}
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [0 => $group],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertSame('default', $result[self::GROUPS_SECTION][0]['logging'] ?? null);
	}

	/** @return array<string,array{0:string|null}> */
	public static function vipMarkerProvider(): array
	{
		return [
			'absent (key never set)' => [null],
			'empty string'           => [''],
			'Enabled (title case)'   => ['Enabled'],
			'ENABLED (upper case)'   => ['ENABLED'],
			'enabled (already canonical)' => ['enabled'],
		];
	}

	#[DataProvider('nonVipConcreteMechanismProvider')]
	public function testMigrateNeverTouchesAnExplicitNonVipMechanism(string $token): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [0 => ['aliasname' => 'X', 'logging' => $token]],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertIsArray($result);
		$after = array_replace($sections, $result);
		$this->assertSame('default', $after[self::DNSBL_SECTION]['global_log_mode'] ?? NULL);
		$this->assertSame('enabled', $after[self::DNSBL_SECTION]['global_log'] ?? NULL);
		$this->assertSame($token, $after[self::GROUPS_SECTION][0]['logging'] ?? NULL);
	}

	/** @return array<string,array{0:string}> */
	public static function concreteMechanismProvider(): array
	{
		$cases = [];
		foreach (self::CONCRETE_MECHANISMS as $token) {
			$cases[$token] = [$token];
		}
		return $cases;
	}

	/** @return array<string,array{0:string}> the six concrete tokens that are NOT the VIP marker 'enabled'. */
	public static function nonVipConcreteMechanismProvider(): array
	{
		$cases = self::concreteMechanismProvider();
		unset($cases['enabled']);
		return $cases;
	}

	public function testMigrateConvertsOnlyVipGroupsAmongMany(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [
				0 => ['aliasname' => 'A', 'logging' => 'enabled'],
				1 => ['aliasname' => 'B', 'logging' => 'disabled_log'],
				2 => ['aliasname' => 'C'],
				3 => ['aliasname' => 'D', 'logging' => 'nxdomain'],
			],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertSame('default', $result[self::GROUPS_SECTION][0]['logging'] ?? null);
		$this->assertSame('disabled_log', $result[self::GROUPS_SECTION][1]['logging'] ?? null);
		$this->assertSame('default', $result[self::GROUPS_SECTION][2]['logging'] ?? null);
		$this->assertSame('nxdomain', $result[self::GROUPS_SECTION][3]['logging'] ?? null);
	}

	// -----------------------------------------------------------------------
	// F — idempotency: a run-once marker, not a re-appliable value map
	// -----------------------------------------------------------------------

	/**
	 * "Policy marker presence makes migration idempotent" (issue #3288 Required
	 * semantics): dnsbl/global_log_mode's OWN presence is the marker -- a brand-new
	 * key with no pre-#3288 meaning, so once present the migration never fires
	 * again for this section, regardless of what the groups list still contains.
	 */
	public function testMigrateIsNoOpWhenGlobalLogModeAlreadyPresent(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on', 'global_log' => 'enabled', 'global_log_mode' => 'default'],
			self::GROUPS_SECTION => [0 => ['aliasname' => 'X', 'logging' => 'enabled']],
		];

		$this->assertNull(pfb_dnsbl_policy_migrate($sections));
	}

	/**
	 * "a later explicit VIP choice must not be reconverted upon subsequent upgrades"
	 * (issue #3288 Required semantics): the exact regression a value-based
	 * grandfather map (rather than a run-once marker) would reintroduce. Simulates
	 * the sequence -- migrate once, operator explicitly re-selects VIP on a group,
	 * migrate again (next package upgrade) -- and asserts the second pass leaves
	 * that deliberate choice alone.
	 */
	public function testMigrateDoesNotReconvertAnExplicitPostMigrationVipChoice(): void
	{
		$first_sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [0 => ['aliasname' => 'X', 'logging' => 'enabled']],
		];
		$first = pfb_dnsbl_policy_migrate($first_sections);
		$this->assertSame('default', $first[self::GROUPS_SECTION][0]['logging'] ?? null, 'sanity: first pass converts');

		// The operator visits the group editor and explicitly re-selects VIP --
		// indistinguishable in STORAGE from a pre-migration value, but the marker
		// makes it distinguishable in TIME.
		$second_sections = [
			self::DNSBL_SECTION  => $first[self::DNSBL_SECTION],
			self::GROUPS_SECTION => [0 => ['aliasname' => 'X', 'logging' => 'enabled']],
		];

		$second = pfb_dnsbl_policy_migrate($second_sections);

		$this->assertNull($second, 'the marker must block a second conversion pass entirely');
	}

	// -----------------------------------------------------------------------
	// G — raw bystander preservation (issue #1921 RAW write-back contract)
	// -----------------------------------------------------------------------

	public function testMigratePreservesBystanderDnsblSectionFields(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on', 'top1m_source' => 'alexa', 'dnsbl_interface' => 'lo0'],
			self::GROUPS_SECTION => [],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_dnsbl'] ?? null);
		$this->assertSame('alexa', $result[self::DNSBL_SECTION]['top1m_source'] ?? null,
			'a still-raw legacy bystander token must survive byte-identical -- this migration does not own it');
		$this->assertSame('lo0', $result[self::DNSBL_SECTION]['dnsbl_interface'] ?? null);
	}

	public function testMigratePreservesBystanderGroupFields(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [0 => [
				'aliasname'   => 'ADs_Basic',
				'description' => 'Ad networks',
				'cron'        => 'EveryDay',
				'action'      => 'unbound',
				'logging'     => 'enabled',
				'custom'      => 'base64==',
			]],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$row = $result[self::GROUPS_SECTION][0];
		$this->assertSame('ADs_Basic', $row['aliasname']);
		$this->assertSame('Ad networks', $row['description']);
		$this->assertSame('EveryDay', $row['cron']);
		$this->assertSame('unbound', $row['action']);
		$this->assertSame('base64==', $row['custom']);
		$this->assertSame('default', $row['logging'], 'only \'logging\' itself is converted');
	}

	/**
	 * When NO group needs conversion, the groups section is omitted from the
	 * returned map entirely -- mirrors pfb_legacy_key_rename_migrate()'s partial-
	 * result convention (issue #1898): pfb_run_migrations()'s 'sections' branch
	 * writes back and flushes exactly the sections present in the result, so an
	 * unchanged bystander section must never ride along for a needless write.
	 */
	public function testMigrateOmitsGroupsSectionFromResultWhenNoGroupNeedsConversion(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [0 => ['aliasname' => 'X', 'logging' => 'nodata']],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertIsArray($result);
		$this->assertArrayHasKey(self::DNSBL_SECTION, $result);
		$this->assertArrayNotHasKey(self::GROUPS_SECTION, $result,
			'an unchanged groups section must not be included in the write-back result');
	}

	// -----------------------------------------------------------------------
	// H — malformed input: no data loss, no TypeError
	// -----------------------------------------------------------------------

	public function testMigrateSkipsNonArrayGroupRowWithoutCrashing(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [
				0 => 'not-an-array',
				1 => ['aliasname' => 'Y', 'logging' => 'enabled'],
			],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertSame('not-an-array', $result[self::GROUPS_SECTION][0] ?? null,
			'a malformed row must survive untouched, never dropped and never crash the pass');
		$this->assertSame('default', $result[self::GROUPS_SECTION][1]['logging'] ?? null,
			'a sibling well-formed row must still convert');
	}

	#[DataProvider('malformedGroupLoggingProvider')]
	public function testMigrateLeavesAMalformedLoggingValueUntouched($malformed_logging): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => [0 => ['aliasname' => 'X', 'logging' => $malformed_logging]],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$after = array_replace($sections, $result ?? []);
		$this->assertSame($malformed_logging, $after[self::GROUPS_SECTION][0]['logging'] ?? '__missing__',
			'malformed group data must not be silently rewritten');
	}

	/** @return array<string,array{0:mixed}> */
	public static function malformedGroupLoggingProvider(): array
	{
		return [
			'array'  => [['enabled']],
			'int'    => [0],
			'bool'   => [FALSE],
		];
	}

	public function testMigrateHandlesNonArrayGroupsSectionWithoutCrashing(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on'],
			self::GROUPS_SECTION => 'corrupted-not-an-array',
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertIsArray($result, 'a corrupted groups section must not crash the migration');
		$this->assertSame('default', $result[self::DNSBL_SECTION]['global_log_mode'] ?? null,
			'the settings-section derivation must proceed regardless of the groups section\'s shape');
		$after = array_replace($sections, $result);
		$this->assertSame('corrupted-not-an-array', $after[self::GROUPS_SECTION]);
	}

	public function testMigrateHandlesMalformedGlobalLogWithoutTypeError(): void
	{
		$sections = [
			self::DNSBL_SECTION  => ['pfb_dnsbl' => 'on', 'global_log' => ['not', 'a', 'scalar']],
			self::GROUPS_SECTION => [],
		];

		$result = pfb_dnsbl_policy_migrate($sections);

		$this->assertIsArray($result);
		$this->assertSame('default', $result[self::DNSBL_SECTION]['global_log_mode'] ?? NULL);
		$this->assertSame('enabled', $result[self::DNSBL_SECTION]['global_log'] ?? NULL);
	}

	// A valid write upgrades the policy before persisting current-schema group choices.

	public function testUpgradeFreshInitMaterialisesTheTwoPolicyFields(): void
	{
		// DNSBL_SECTION and GROUPS_SECTION both start genuinely absent from config.
		$ran = pfb_dnsbl_policy_upgrade();

		$this->assertTrue($ran, 'a fresh domain must report a real initialization');
		$this->assertSame('default', config_get_path(self::DNSBL_SECTION . '/global_log_mode'));
		$this->assertSame('disabled_log', config_get_path(self::DNSBL_SECTION . '/global_log'));
		$this->assertSame([], config_get_path(self::GROUPS_SECTION, []),
			'a genuinely fresh groups list must stay untouched -- there is nothing to seed there');
	}

	/** Fresh initialization must preserve bystander defaults through later upgrades. */
	public function testUpgradeFreshInitMaterialisesEveryBystanderFieldsNewcfgDefault(): void
	{
		pfb_dnsbl_policy_upgrade();

		$this->assertSame('off', config_get_path(self::DNSBL_SECTION . '/pfb_dnsbl_lenient'),
			'a bystander registered field must get its own correct NEWCFG default, not stay absent');
	}

	/** Metadata ignored for freshness must still survive initialization unchanged. */
	public function testUpgradeFreshInitPreservesAMetadataOnlyBystanderKey(): void
	{
		config_set_path(self::DNSBL_SECTION, ['settings_family' => '4.0']);

		$ran = pfb_dnsbl_policy_upgrade();

		$this->assertTrue($ran, 'a metadata-only section still reads fresh under the operator view');
		$this->assertSame('4.0', config_get_path(self::DNSBL_SECTION . '/settings_family'),
			'the pre-existing metadata-only key must survive byte-identical, never erased by the init write');
		$this->assertSame('default', config_get_path(self::DNSBL_SECTION . '/global_log_mode'));
		$this->assertSame('disabled_log', config_get_path(self::DNSBL_SECTION . '/global_log'));
	}

	public function testUpgradeFreshInitNeverTouchesUnrelatedSections(): void
	{
		pfb_dnsbl_policy_upgrade();

		$this->assertSame([], config_get_path('installedpackages/pfblockerng/config/0', []),
			'the fresh-init pass computes NEWCFG defaults for gen/ip/ss internally (pfb_registry_pass() spans '
			. 'every registered section) but must discard and never persist anything outside dnsbl');
	}

	/**
	 * Stability: initializing a fresh domain, then adding its first group (the
	 * SAME sequence the facade exists to protect), then running a LATER full
	 * install/upgrade pipeline must change NOTHING further for EITHER the two
	 * #3288 fields or any bystander field -- proves the initialization is a
	 * genuine terminal state, not a half-measure a real install run would still
	 * rewrite.
	 */
	public function testUpgradeFreshInitThenFirstGroupAddThenLaterInstallPipelineIsStable(): void
	{
		pfb_dnsbl_policy_upgrade();
		// The domain's first group, added by category_edit.php's own 'default' producer default.
		config_set_path(self::GROUPS_SECTION, [0 => ['aliasname' => 'ADs_Basic', 'logging' => 'default']]);

		$before = config_get_path(self::DNSBL_SECTION);

		// A later install/upgrade: pfb_registry_pass() alone (the migration itself
		// already no-ops -- global_log_mode is present) using the section's OWN
		// current-state mode (reads OLDCFG now, since it is genuinely non-empty).
		$modes   = pfb_registry_section_modes([self::DNSBL_SECTION => $before]);
		$changed = pfb_registry_pass([self::DNSBL_SECTION => $before], null, $modes);

		$this->assertArrayNotHasKey(self::DNSBL_SECTION, $changed,
			'a later pass must find nothing left to change -- fresh-init already materialised every field');
		$this->assertSame('default', config_get_path(self::GROUPS_SECTION . '/0/logging'),
			'the first group must still correctly live-inherit, never reinterpreted as VIP');
	}

	/** The single persisted image must include both policy fields and group conversion. */
	public function testUpgradeAgainstRealConfigConvertsALegacyBoxAtomically(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::GROUPS_SECTION, [0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled']]);

		$persisted = [];
		$GLOBALS['pfb_test_write_config_hook'] = static function () use (&$persisted): void {
			$persisted[] = [
				'settings' => PfbConfig::readSection(self::DNSBL_SECTION),
				'groups' => PfbConfig::readSection(self::GROUPS_SECTION),
			];
		};
		try {
			$ran = pfb_dnsbl_policy_upgrade();
		} finally {
			unset($GLOBALS['pfb_test_write_config_hook']);
		}

		$this->assertTrue($ran);
		$this->assertCount(1, $persisted, 'policy and group conversion must persist together');
		$this->assertSame('default', $persisted[0]['settings']['global_log_mode'] ?? NULL);
		$this->assertSame('enabled', $persisted[0]['settings']['global_log'] ?? NULL);
		$this->assertSame('default', $persisted[0]['groups'][0]['logging'] ?? NULL);
	}

	/**
	 * A subsequent ordinary section write (what ANY Save handler's normal
	 * read-modify-write does) after the facade has already run must never disturb
	 * the now-converted group -- it lives in a completely different section the
	 * Save never touches.
	 */
	public function testUpgradeThenAnOrdinarySettingsSaveNeverDisturbsTheConvertedGroup(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::GROUPS_SECTION, [0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled']]);
		pfb_dnsbl_policy_upgrade();

		// An ordinary Global Save: read-modify-write touching only an unrelated key.
		$data = PfbConfig::readSection(self::DNSBL_SECTION);
		$data['dnsbl_interface'] = 'lo1';
		PfbConfig::writeSection(self::DNSBL_SECTION, $data);

		$this->assertSame('default', config_get_path(self::GROUPS_SECTION . '/0/logging'));
		$this->assertSame('default', config_get_path(self::DNSBL_SECTION . '/global_log_mode'));
	}

	public function testUpgradeCalledTwiceIsIdempotentAgainstRealConfig(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on', 'global_log' => 'nxdomain']);
		config_set_path(self::GROUPS_SECTION, [0 => ['aliasname' => 'X', 'logging' => 'enabled']]);

		$first = pfb_dnsbl_policy_upgrade();
		$this->assertTrue($first);
		$writes_after_first = count($GLOBALS['pfb_test_write_config_calls'] ?? []);

		$second = pfb_dnsbl_policy_upgrade();

		$this->assertFalse($second);
		$this->assertCount($writes_after_first, $GLOBALS['pfb_test_write_config_calls'] ?? [],
			'a second call must not persist anything further');
	}

	/** An explicit VIP selection made after conversion must survive subsequent upgrades. */
	public function testExplicitVipReselectionSurvivesWhenFacadeRunsBeforeTheGroupSave(): void
	{
		// Given: a legacy box the operator has never saved anything on yet.
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::GROUPS_SECTION, [0 => ['aliasname' => 'X', 'logging' => 'enabled']]);

		// When: the group Save handler correctly calls the facade BEFORE persisting
		// the operator's own posted value (closes the marker-absence window)...
		pfb_dnsbl_policy_upgrade();
		// ...THEN persists the operator's actual POST -- an explicit, deliberate
		// re-selection of VIP (not a stale/rendered value; the operator typed this).
		config_set_path(self::GROUPS_SECTION . '/0/logging', 'enabled');

		$this->assertSame('enabled', config_get_path(self::GROUPS_SECTION . '/0/logging'),
			'sanity: the explicit POST must land');

		// Then: a LATER, unrelated install/upgrade migration attempt must NOT
		// reconvert it -- the marker is already present (set by the facade above),
		// so pfb_dnsbl_policy_migrate()'s run-once guard blocks re-entry entirely.
		$result = pfb_dnsbl_policy_migrate([
			self::DNSBL_SECTION  => config_get_path(self::DNSBL_SECTION),
			self::GROUPS_SECTION => config_get_path(self::GROUPS_SECTION),
		]);

		$this->assertNull($result, 'the marker must already block re-entry -- nothing left to migrate');
		$this->assertSame('enabled', config_get_path(self::GROUPS_SECTION . '/0/logging'),
			'the explicit choice must survive untouched');
	}

}
