<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Install-default rdns seed chokepoint (issue #1775).
 *
 * pfblockerng_install.inc seeds 'settings_family' into
 * installedpackages/pfblockerng/config/0 via pfb_settings_family_record() BEFORE the
 * reverse-DNS seed read this file exercises. pfb_gconfig_operator_view() is the shared
 * chokepoint that strips the installer's own marker so a marker-only section (General
 * never saved) reads as empty -- a genuine fresh install -- rather than as pre-existing
 * operator config.
 *
 * issue #1921 (S2): the sibling feed-filter (#1770) / alias-delta-mode (#1771)
 * install-default grandfather blocks this file used to pin were DELETED from
 * pfblockerng_install.inc -- that behaviour folded into pfb_registry_pass()
 * (pfblockerng.inc), covered by RegistryPassTest (rows 2, 3, 5, 6) instead. Only the
 * rdns seed region (issue #1775, deliberately left untouched by S2) remains here.
 *
 * install.inc is a procedural migration script (host-absolute requires, real service
 * control) and not loadable by the unit harness (see InstallDnsblMoveRestartGuardTest.php),
 * so the shared call-site region is eval-extracted verbatim from the REAL source, anchored
 * on text stable across both the pre-fix and post-fix code -- the same pattern as
 * CategoryEditPostGuardTest.php.
 */
final class InstallGrandfatherChokepointTest extends TestCase
{
	private ?array $savedConfig = null;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_install_oracle_rdns_seed_region')) {
			return;
		}

		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_install.inc');
		}

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

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? null;
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
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
