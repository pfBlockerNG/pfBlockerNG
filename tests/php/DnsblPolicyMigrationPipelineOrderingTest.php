<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Exercise group-aware freshness, migration, and registry seeding in installer
 * order. Real package-install tests separately cover the installer's wiring.
 */
#[CoversFunction('pfb_dnsbl_policy_migrate')]
#[CoversFunction('pfb_registry_section_modes')]
#[CoversFunction('pfb_run_migrations')]
#[CoversFunction('pfb_migration_registry')]
#[CoversFunction('pfb_registry_pass')]
final class DnsblPolicyMigrationPipelineOrderingTest extends TestCase
{
	private const DNSBL_SECTION  = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const GROUPS_SECTION = 'installedpackages/pfblockerngdnsbl/config';

	/** The seven concrete DNSBL blocking/logging mechanisms (issue #3288 Constraints: unchanged). */
	private const CONCRETE_MECHANISMS = [
		'enabled', 'disabled_log', 'disabled', 'nxdomain_log', 'nxdomain', 'nodata_log', 'nodata',
	];

	protected function setUp(): void
	{
		$GLOBALS['config']                      = [];
		$GLOBALS['pfb_test_write_config_calls']   = [];
		$GLOBALS['pfb_test_file_notices']         = [];
	}

	private function seedDnsbl(array $data): void
	{
		config_set_path(self::DNSBL_SECTION, $data);
	}

	private function seedGroups(array $rows): void
	{
		config_set_path(self::GROUPS_SECTION, $rows);
	}

	private function runInstallSequence(): array
	{
		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		// issue #3288: DNSBL-group evidence folds directly into the canonical mode
		// capture -- a box with real DNSBL groups is never a fresh install, even
		// when its settings section itself is untouched, same shape as the
		// existing #2123 ip-section correction.
		$modes = pfb_registry_section_modes($sections, PfbConfig::readSection(self::GROUPS_SECTION));

		pfb_run_migrations();

		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		foreach (pfb_registry_pass($sections, NULL, $modes) as $section => $blob) {
			PfbConfig::writeSectionRawSystem($section, $blob);
		}

		return [
			'dnsbl'  => PfbConfig::readSection(self::DNSBL_SECTION),
			'groups' => PfbConfig::readSection(self::GROUPS_SECTION),
		];
	}

	// -----------------------------------------------------------------------
	// A — pfb_registry_section_modes()'s DNSBL-group evidence, in isolation
	// -----------------------------------------------------------------------

	public function testRegistryModesDnsblStaysNewcfgWhenGroupsEmpty(): void
	{
		$modes = pfb_registry_section_modes([], []);

		$this->assertSame('NEWCFG', $modes[PFB_SECTIONS['dnsbl']]);
	}

	public function testRegistryModesForcesDnsblSectionToOldcfgWhenGroupsPresent(): void
	{
		$groups = [0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled']];

		$modes = pfb_registry_section_modes([], $groups);

		$this->assertSame('OLDCFG', $modes[PFB_SECTIONS['dnsbl']],
			'a box with real DNSBL groups is never a fresh install, even if its settings section is untouched');
	}

	public function testRegistryModesLeavesAnAlreadyOldcfgSectionAlone(): void
	{
		$sections = [PFB_SECTIONS['dnsbl'] => ['pfb_dnsbl' => 'on']];

		$modes = pfb_registry_section_modes($sections, [0 => ['logging' => 'enabled']]);

		$this->assertSame('OLDCFG', $modes[PFB_SECTIONS['dnsbl']]);
	}

	public function testRegistryModesNeverTouchesUnrelatedSections(): void
	{
		$without_groups = pfb_registry_section_modes([]);
		$with_groups    = pfb_registry_section_modes([], [0 => ['logging' => 'enabled']]);

		foreach (PFB_SECTIONS as $alias => $path) {
			if ($alias === 'dnsbl') {
				continue;
			}
			$this->assertSame($without_groups[$path], $with_groups[$path], "the {$alias} section's mode must be untouched");
		}
	}

	// -----------------------------------------------------------------------
	// B — the bug this correction exists to prevent, and the fix, both demonstrated
	//     by directly executing pfb_registry_pass() -- no source-text matching
	// -----------------------------------------------------------------------

	/**
	 * Demonstrates WHY the correction is necessary: pfb_registry_pass()'s NEWCFG
	 * branch overwrites every registered key UNCONDITIONALLY once a section is
	 * classified NEWCFG -- even a value pfb_dnsbl_policy_migrate() just wrote.
	 * Mirrors InstallRdnsSeedAfterPassTest::testTheNewcfgBranchOverwritesASeedWrittenBeforeThePass.
	 */
	public function testUncorrectedNewcfgModeWouldOverwriteAMigratedGlobalLogMode(): void
	{
		$modes = pfb_registry_section_modes([]); // DNSBL_SECTION captures NEWCFG (empty).

		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = [];
		}
		// What pfb_dnsbl_policy_migrate() would have just written.
		$sections[PFB_SECTIONS['dnsbl']] = ['global_log_mode' => 'default', 'global_log' => 'enabled'];

		$changed = pfb_registry_pass($sections, NULL, $modes);
		$after   = $changed[PFB_SECTIONS['dnsbl']] ?? $sections[PFB_SECTIONS['dnsbl']];

		$this->assertSame('disabled_log', $after['global_log'] ?? null,
			'an uncorrected NEWCFG classification stamps the FRESH default over the migrated grandfathered value');
	}

	/** The fix's other half: OLDCFG preserves exactly what NEWCFG erases above. */
	public function testCorrectedOldcfgModePreservesTheMigratedGlobalLogMode(): void
	{
		$modes = pfb_registry_section_modes([]);
		$modes[PFB_SECTIONS['dnsbl']] = 'OLDCFG'; // what the DNSBL-group evidence would set.

		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = [];
		}
		$sections[PFB_SECTIONS['dnsbl']] = ['global_log_mode' => 'default', 'global_log' => 'enabled'];

		$changed = pfb_registry_pass($sections, NULL, $modes);
		$after   = $changed[PFB_SECTIONS['dnsbl']] ?? $sections[PFB_SECTIONS['dnsbl']];

		$this->assertSame('enabled', $after['global_log'] ?? null, 'OLDCFG must leave the migrated value alone');
		$this->assertSame('default', $after['global_log_mode'] ?? null, 'OLDCFG must leave the migrated mode alone');
	}


	public function testFreshInstallEndsWithDefaultModeAndDisabledLogMechanism(): void
	{
		$result = $this->runInstallSequence();

		$this->assertSame('default', $result['dnsbl']['global_log_mode'] ?? null);
		$this->assertSame('disabled_log', $result['dnsbl']['global_log'] ?? null);
	}

	/**
	 * The load-bearing regression guard mirroring
	 * PslFeedPolicyPipelineOrderingTest::testFreshInstallDoesNotCorruptSiblingFieldGrandfatherMode:
	 * a genuinely fresh install (both sections empty) must not accidentally trip the
	 * #3288 correction and must not corrupt a SIBLING field's own NEWCFG default.
	 */
	public function testFreshInstallDoesNotCorruptSiblingFieldGrandfatherMode(): void
	{
		$result = $this->runInstallSequence();

		$this->assertSame('off', $result['dnsbl']['pfb_dnsbl_lenient'] ?? null,
			'a genuinely fresh install must take the NEWCFG default (off), never the OLDCFG grandfather (on)');
		$this->assertSame([], $result['groups'], 'a genuinely fresh install has no groups to convert');
	}

	public function testOldNoOverrideEndsWithDefaultModeAndEnabledMechanism(): void
	{
		$this->seedDnsbl(['pfb_dnsbl' => 'on']); // global_log absent entirely.

		$result = $this->runInstallSequence();

		$this->assertSame('default', $result['dnsbl']['global_log_mode'] ?? null);
		$this->assertSame('enabled', $result['dnsbl']['global_log'] ?? null);
	}

	#[DataProvider('concreteMechanismProvider')]
	public function testOldActiveOverrideEndsWithOverrideModeAndTheSamePreservedMechanism(string $token): void
	{
		$this->seedDnsbl(['pfb_dnsbl' => 'on', 'global_log' => $token]);

		$result = $this->runInstallSequence();

		$this->assertSame('override', $result['dnsbl']['global_log_mode'] ?? null);
		$this->assertSame($token, $result['dnsbl']['global_log'] ?? null,
			'an existing active override\'s enforced mechanism must never be silently changed by the pipeline');
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

	/** Existing groups make DNSBL an established domain even without a settings section. */
	public function testSettingsEmptyGroupsPresentEndsWithDefaultModeAndConvertedVipGroups(): void
	{
		$this->seedGroups([
			0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled'],
			1 => ['aliasname' => 'Malware', 'logging' => 'disabled_log'],
		]);
		// DNSBL_SECTION is deliberately left untouched (genuinely absent).

		$result = $this->runInstallSequence();

		$this->assertSame('default', $result['dnsbl']['global_log_mode'] ?? null,
			'the corrected OLDCFG classification must survive pfb_registry_pass() intact');
		$this->assertSame('enabled', $result['dnsbl']['global_log'] ?? null,
			'must be the grandfathered VIP mechanism, never the fresh disabled_log default');
		$this->assertSame('default', $result['groups'][0]['logging'] ?? null);
		$this->assertSame('disabled_log', $result['groups'][1]['logging'] ?? null,
			'an explicit non-VIP group mechanism must survive untouched');
	}

	/** Every OTHER dnsbl/* registered field also benefits from the corrected OLDCFG classification. */
	public function testSettingsEmptyGroupsPresentAlsoCorrectsSiblingFieldGrandfathering(): void
	{
		$this->seedGroups([0 => ['aliasname' => 'ADs_Basic', 'logging' => 'enabled']]);

		$result = $this->runInstallSequence();

		$this->assertSame('on', $result['dnsbl']['pfb_dnsbl_lenient'] ?? null,
			'a box with real DNSBL groups is an existing install for EVERY dnsbl/* field, '
			. 'not just the two #3288 introduces');
	}

	// -----------------------------------------------------------------------
	// E — idempotency at the pipeline level
	// -----------------------------------------------------------------------

	public function testSecondPipelineRunIsNoOpForAnAlreadyMigratedInstall(): void
	{
		$this->seedDnsbl(['pfb_dnsbl' => 'on', 'global_log' => 'nxdomain']);
		$this->seedGroups([0 => ['aliasname' => 'X', 'logging' => 'enabled']]);

		$first = $this->runInstallSequence();
		$this->assertSame('override', $first['dnsbl']['global_log_mode'] ?? NULL);
		$this->assertSame('nxdomain', $first['dnsbl']['global_log'] ?? NULL);
		$this->assertSame('default', $first['groups'][0]['logging'] ?? NULL);

		$second = $this->runInstallSequence();
		$this->assertSame($first, $second);
	}

	/**
	 * "a later explicit VIP choice must not be reconverted upon subsequent upgrades"
	 * at the FULL pipeline level: after the first install run converts the group to
	 * 'default', the operator explicitly re-selects 'enabled'; a second install run
	 * (the next package upgrade) must leave that choice alone.
	 */
	public function testSecondPipelineRunDoesNotReconvertAnExplicitPostMigrationChoice(): void
	{
		$this->seedDnsbl(['pfb_dnsbl' => 'on']);
		$this->seedGroups([0 => ['aliasname' => 'X', 'logging' => 'enabled']]);

		$first = $this->runInstallSequence();
		$this->assertSame('default', $first['groups'][0]['logging'] ?? null, 'sanity: first run converts');

		// Operator explicitly re-selects VIP via the group editor.
		$this->seedGroups([0 => ['aliasname' => 'X', 'logging' => 'enabled']]);

		$second = $this->runInstallSequence();

		$this->assertSame('enabled', $second['groups'][0]['logging'] ?? null,
			'the marker (global_log_mode already present) must block reconversion on the next upgrade');
	}
}
