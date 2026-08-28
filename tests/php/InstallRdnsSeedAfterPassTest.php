<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #2123 review finding — the enable_rdns seed must be APPLIED after the registry
 * pass, not before it.
 *
 * `pfb_rdns_seed_value()` preserves the historical always-on reverse-DNS behaviour for an
 * install that predates the setting: General section non-empty, `enable_rdns` absent from
 * the IP section. Its predicate is cross-section, so it must be EVALUATED before the pass
 * (which seeds every registered key and would erase the "absent" evidence).
 *
 * Registering `ip/enable_rdns` made the WRITE order load-bearing too. The installer
 * captures each section's mode before migrations (`pfblockerng_install.inc:42`), and an
 * install whose General section is configured but whose IP section was never saved
 * captures IP as NEWCFG. `pfb_registry_pass()`'s NEWCFG branch assigns the registered
 * default unconditionally — so a seed written BEFORE the pass is overwritten with `''`,
 * silently turning reverse-DNS lookups off for exactly the install the seed exists to
 * protect. Before registration the pass ignored the key and the order did not matter.
 *
 * Same shape as `pfb_install_psl_feed_policy_seed()` (issue #2371), which captures its
 * predicate early and applies its seed after `pfb_install_registry_writeback()` for the
 * same reason.
 */
final class InstallRdnsSeedAfterPassTest extends TestCase
{
	private const INSTALLER = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/**
	 * Why the order matters, as behaviour rather than as an assertion about source.
	 *
	 * Scenario:
	 *   Given an install whose IP section was empty when the installer captured modes,
	 *     so its captured mode is NEWCFG.
	 *   And the cross-section rDNS seed has since written 'on' into that section.
	 *   When pfb_registry_pass() runs with the captured modes.
	 *   Then it returns '' for ip/enable_rdns — the registered default — which is why the
	 *     seed cannot be written before the pass.
	 */
	public function testTheNewcfgBranchOverwritesASeedWrittenBeforeThePass(): void
	{
		$ip      = PFB_SECTIONS['ip'];
		$modes   = pfb_registry_section_modes([]);
		$this->assertSame('NEWCFG', $modes[$ip], 'before: an empty IP section captures NEWCFG');

		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = [];
		}
		// The pre-pass seed the installer used to write here.
		$sections[$ip] = ['enable_rdns' => 'on'];

		$changed = pfb_registry_pass($sections, NULL, $modes);
		$after   = $changed[$ip] ?? $sections[$ip];

		$this->assertSame('', $after['enable_rdns'] ?? NULL,
			'a pre-pass enable_rdns seed is overwritten by the NEWCFG branch, so the '
			. 'installer must apply that seed AFTER pfb_install_registry_writeback()');
	}

	/**
	 * OLDCFG preserves what NEWCFG erases -- the other half of the pair, so green proves
	 * the mode is the discriminator rather than that the pass happens to be gentle.
	 */
	public function testTheOldcfgBranchPreservesAPrePassSeedAndAMigratedValue(): void
	{
		$ip       = PFB_SECTIONS['ip'];
		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = [];
		}
		$sections[$ip] = ['enable_rdns' => 'on', 'enable_dup' => 'on', 'killstates' => 'on'];

		$modes      = pfb_registry_section_modes([]);
		$modes[$ip] = 'OLDCFG';

		$changed = pfb_registry_pass($sections, NULL, $modes);
		$after   = $changed[$ip] ?? $sections[$ip];

		foreach (['enable_rdns', 'enable_dup', 'killstates'] as $key) {
			$this->assertSame('on', $after[$key] ?? NULL,
				"OLDCFG must leave a populated {$key} alone");
		}
	}

	/**
	 * And the installer forces that mode wherever it plants operator data into the IP
	 * section before the pass runs.
	 *
	 * Two such places, both of which fire exactly when the captured mode is NEWCFG: the
	 * General -> IP settings reshape (guarded by its own `empty($pfb_ip_section)`) and
	 * the cross-section rDNS preservation seed. A section that has just received migrated
	 * operator data, or a seed whose whole purpose is preserving historical behaviour, IS
	 * an existing install -- so the captured mode must be corrected, not trusted.
	 */
	public function testTheInstallerForcesOldcfgWhereverItPlantsIpDataBeforeThePass(): void
	{
		$src = file_get_contents(self::INSTALLER);
		$this->assertIsString($src, 'installer source must be readable');

		$pattern = '/\\$pfb_registry_modes\\[PFB_SECTIONS\\[.ip.\\]\\]\\s*=\\s*.OLDCFG./';
		$this->assertSame(2, preg_match_all($pattern, $src),
			'both pre-pass IP writers -- the General -> IP reshape and the rDNS seed -- must '
			. "correct the captured mode to OLDCFG, or the pass's NEWCFG branch overwrites "
			. 'what they just planted');

		$pass = strpos($src, 'pfb_install_registry_writeback(');
		$this->assertNotFalse($pass, 'pfb_install_registry_writeback() call not found');
		$this->assertSame(1, preg_match($pattern, $src, $m, PREG_OFFSET_CAPTURE));
		$this->assertLessThan($pass, $m[0][1],
			'the mode correction must happen before the pass consumes the mode map');
	}
}
