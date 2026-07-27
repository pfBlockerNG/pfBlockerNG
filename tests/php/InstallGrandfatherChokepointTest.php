<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Install-default grandfather chokepoint (issues #1770/#1771).
 *
 * pfblockerng_install.inc seeds 'settings_family' into
 * installedpackages/pfblockerng/config/0 via pfb_settings_family_record()
 * (~line 136) BEFORE the shared $pfb_gcfg read (~line 652) that both
 * install-default grandfathers (pfb_feed_filter_install_default(),
 * pfb_alias_delta_mode_install_default()) consume. Because the marker alone
 * makes $pfb_gcfg non-empty, the "genuinely empty section = fresh install"
 * branch was dead code on EVERY install, including a first-ever install on a
 * virgin box -- the SSRF feed-filter guard shipped OFF (#1770) and aliases
 * were grandfathered to the legacy 'replace' apply mode instead of ADR-40's
 * 'auto' (#1771).
 *
 * install.inc is a procedural migration script (host-absolute requires,
 * real service control) and not loadable by the unit harness (see
 * InstallDnsblMoveRestartGuardTest.php), so the shared call-site region is
 * eval-extracted verbatim from the REAL source, anchored on text stable
 * across both the pre-fix and post-fix code -- the same pattern as
 * CategoryEditPostGuardTest.php.
 */
final class InstallGrandfatherChokepointTest extends TestCase
{
	private ?array $savedConfig = null;

	public static function setUpBeforeClass(): void
	{
		$src = null;
		if (!function_exists('pfb_install_oracle_grandfather_region')
			|| !function_exists('pfb_install_oracle_rdns_seed_region')) {
			$src = file_get_contents(
				dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc'
			);
			if ($src === false) {
				throw new RuntimeException('test bootstrap: failed to read pfblockerng_install.inc');
			}
		}

		if (!function_exists('pfb_install_oracle_grandfather_region')) {
			// The shared grandfather region: from the $pfb_gcfg section read through
			// the closing brace of the alias-delta-mode write. Both grandfather calls
			// consume the same $pfb_gcfg local.
			if (!preg_match(
				'/(\$pfb_gcfg = PfbConfig::readSection\(\'installedpackages\/pfblockerng\/config\/0\'\);\n'
				. '.*?'
				. 'PfbConfig::write\(\'pfb_alias_delta_mode\', \$pfb_delta_default\);\n\}\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: install-default grandfather region not found');
			}

			eval(
				'function pfb_install_oracle_grandfather_region(): array {'
				. $m[1]
				. ' return ['
				. ' \'feed_default\' => $pfb_feed_default,'
				. ' \'delta_default\' => $pfb_delta_default,'
				. ' \'gcfg\' => $pfb_gcfg,'
				. ' ]; }'
			);
		}

		if (!function_exists('pfb_install_oracle_rdns_seed_region')) {
			// issue #1775: the reverse-DNS seed region -- from the pfb_rdns_seed_value()
			// call through the closing brace of its if/else write.
			if (!preg_match(
				'/(\$pfb_rdns_seed = pfb_rdns_seed_value\(\n'
				. '.*?'
				. 'update_status\(" no changes required \.\.\. done\.\\\\n"\);\n\} ?\n)/s',
				$src,
				$m2
			)) {
				throw new RuntimeException('test bootstrap: install-default rdns seed region not found');
			}

			eval(
				'function pfb_install_oracle_rdns_seed_region(): array {'
				. $m2[1]
				. ' return [ \'rdns_seed\' => $pfb_rdns_seed ]; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? null;
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
	}

	private function seedSection(array $section): void
	{
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => [
					'config' => [0 => $section],
				],
			],
		];
	}

	private function seedGenAndIpSections(array $gen, array $ip): void
	{
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => [
					'config' => [0 => $gen],
				],
				'pfblockerngipsettings' => [
					'config' => [0 => $ip],
				],
			],
		];
	}

	// --- #1770: feed-host filter --------------------------------------------

	public function testFreshInstallMarkerOnlySectionLeavesFeedFilterKeyUnset(): void
	{
		// The exact live-probe capture (#1770): section carries ONLY the
		// installer's own settings_family marker -- a genuine first-ever install.
		$this->seedSection(['settings_family' => '4.0']);

		$result = pfb_install_oracle_grandfather_region();

		$this->assertNull(
			$result['feed_default'],
			'a marker-only section is a fresh install -- the feed-filter key must stay unset (default ON)'
		);
		$this->assertNull(
			config_get_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter'),
			'the chokepoint must not have written pfb_feed_internal_filter on a fresh install'
		);
	}

	public function testGenuineUpgradeWithMarkerAndOperatorKeyStillPinsFeedFilterOff(): void
	{
		// Before-state pin: a marker PLUS a genuine operator key is the true
		// upgrade path and must still be grandfathered off.
		$this->seedSection(['settings_family' => '4.0', 'pfb_interval' => '4']);

		$result = pfb_install_oracle_grandfather_region();

		$this->assertSame(
			'off',
			$result['feed_default'],
			'a marker plus genuine operator data is an upgrade -- the feed filter must still be pinned off'
		);
		$this->assertSame(
			'off',
			config_get_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter')
		);
	}

	// --- #1771: alias-apply mode ---------------------------------------------

	public function testFreshInstallMarkerOnlySectionLeavesAliasDeltaModeKeyUnset(): void
	{
		$this->seedSection(['settings_family' => '4.0']);

		$result = pfb_install_oracle_grandfather_region();

		$this->assertNull(
			$result['delta_default'],
			'a marker-only section is a fresh install -- the alias-delta-mode key must stay unset (registry default auto)'
		);
		$this->assertNull(
			config_get_path('installedpackages/pfblockerng/config/0/pfb_alias_delta_mode'),
			'the chokepoint must not have written pfb_alias_delta_mode on a fresh install'
		);
	}

	public function testGenuineUpgradeWithMarkerAndOperatorKeyStillPinsAliasDeltaModeToReplace(): void
	{
		// Before-state pin (ADR-40): a marker PLUS a genuine operator key is the
		// true upgrade path and must still be grandfathered to 'replace'.
		$this->seedSection(['settings_family' => '4.0', 'pfb_interval' => '4']);

		$result = pfb_install_oracle_grandfather_region();

		$this->assertSame('replace', $result['delta_default']);
		$this->assertSame(
			'replace',
			config_get_path('installedpackages/pfblockerng/config/0/pfb_alias_delta_mode')
		);
	}

	// --- #1770 follow-up: pfb_keep is genuine evidence, not a marker --------

	/**
	 * Before-state pin: pfb_keep is never operator-only-typed -- it can be
	 * present on a box that already ran the (buggy) #281 migration, or via a
	 * genuine General save. A section carrying {settings_family, pfb_keep}
	 * must still be treated as a pre-existing install by BOTH grandfathers --
	 * the chokepoint strips ONLY settings_family, never pfb_keep. Green on
	 * both sides of the #1770-follow-up fix.
	 */
	public function testMarkerPlusPfbKeepStillPinsBothGrandfathers(): void
	{
		$this->seedSection(['settings_family' => '4.0', 'pfb_keep' => 'on']);

		$result = pfb_install_oracle_grandfather_region();

		$this->assertSame(
			'off',
			$result['feed_default'],
			'settings_family + pfb_keep is genuine pre-existing config -- feed filter must still pin off'
		);
		$this->assertSame(
			'replace',
			$result['delta_default'],
			'settings_family + pfb_keep is genuine pre-existing config -- alias delta mode must still pin replace'
		);
	}

	// --- #1775: reverse-DNS lookup seed --------------------------------------

	/**
	 * Scenario: General section carries ONLY the installer's settings_family
	 * marker (a genuine fresh install -- General never saved). enable_rdns
	 * (issue #336) defaults OFF for new installs; the marker must not be read
	 * as pre-existing operator config and force the legacy always-on seed.
	 */
	public function testFreshInstallMarkerOnlySectionLeavesRdnsSeedUnset(): void
	{
		$this->seedGenAndIpSections(['settings_family' => '4.0'], []);

		$result = pfb_install_oracle_rdns_seed_region();

		$this->assertNull(
			$result['rdns_seed'],
			'a marker-only section is a fresh install -- enable_rdns must stay unseeded (default OFF)'
		);
		$this->assertNull(
			config_get_path('installedpackages/pfblockerngipsettings/config/0/enable_rdns'),
			'the chokepoint must not have written enable_rdns on a fresh install'
		);
	}

	/**
	 * Before-state pin: a marker PLUS a genuine operator key is the true
	 * upgrade path and must still seed enable_rdns='on' to preserve the
	 * historical always-on behaviour.
	 */
	public function testGenuineUpgradeWithMarkerAndOperatorKeyStillSeedsRdnsOn(): void
	{
		$this->seedGenAndIpSections(['settings_family' => '4.0', 'pfb_interval' => '4'], []);

		$result = pfb_install_oracle_rdns_seed_region();

		$this->assertSame('on', $result['rdns_seed']);
		$this->assertSame(
			'on',
			config_get_path('installedpackages/pfblockerngipsettings/config/0/enable_rdns')
		);
	}
}
