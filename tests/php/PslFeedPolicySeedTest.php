<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2371 — pfb_psl_feed_policy_is_fresh_install() + the install-time seed it
 * gates (pfblockerng_install.inc: PfbConfig::writeSystem('dnsbl/pfb_psl_feed_*_policy',
 * 'apex') after pfb_install_registry_writeback()).
 *
 * This is deliberately NOT a pfb_migration_registry() entry -- see
 * pfb_psl_feed_policy_is_fresh_install()'s docblock (pfblockerng.inc) for why folding
 * a fresh-install seed into the migration driver (which runs BEFORE pfb_registry_pass()
 * re-reads the section for its own NEWCFG/OLDCFG mode decision) would wrongly flip that
 * decision for every OTHER registered dnsbl/* field once the seeded keys make the
 * section non-empty. Part 2 of this file (TestFreshInstallPipelineOrdering) proves that
 * ordering choice against the real pipeline rather than reasoning about it.
 */
#[CoversFunction('pfb_psl_feed_policy_is_fresh_install')]
final class PslFeedPolicySeedTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// Part 1 -- pfb_psl_feed_policy_is_fresh_install() unit tests.
	// -----------------------------------------------------------------------

	/** Row 3: a genuinely empty section is fresh. */
	public function testEmptySectionIsFresh(): void
	{
		$this->assertTrue(pfb_psl_feed_policy_is_fresh_install([]));
	}

	/** A marker-only section (installer bookkeeping stripped) is still fresh. */
	public function testSettingsFamilyMarkerOnlySectionIsFresh(): void
	{
		$this->assertTrue(pfb_psl_feed_policy_is_fresh_install(['settings_family' => '4.0']));
	}

	/** Row 4: any genuine operator configuration makes the section non-fresh. */
	public function testPopulatedSectionIsNotFresh(): void
	{
		$this->assertFalse(pfb_psl_feed_policy_is_fresh_install(['pfb_dnsbl' => 'on']));
	}

	/** Row 4 (continued): a section that already carries either seeded key is not fresh. */
	public function testAlreadySeededSectionIsNotFresh(): void
	{
		$this->assertFalse(pfb_psl_feed_policy_is_fresh_install(['pfb_psl_feed_private_policy' => 'apex']));
	}

	/** Non-array input never throws; treated as not fresh (defensive). */
	public function testNonArrayInputIsNotFresh(): void
	{
		$this->assertFalse(pfb_psl_feed_policy_is_fresh_install(null));
	}

	/** Idempotent by construction: a pure predicate returns the same answer every call. */
	public function testIsIdempotentAcrossRepeatedCalls(): void
	{
		$dconfig = [];
		$this->assertSame(
			pfb_psl_feed_policy_is_fresh_install($dconfig),
			pfb_psl_feed_policy_is_fresh_install($dconfig)
		);
	}
}

/**
 * Part 2 -- the full install-order interaction: pfb_run_migrations() ->
 * pfb_registry_pass() -> the #2371 post-pass seed, proving the deviation from
 * pfb_migration_registry() is load-bearing and not just theoretical.
 */
#[CoversFunction('pfb_psl_feed_policy_is_fresh_install')]
#[CoversFunction('pfb_registry_pass')]
#[CoversFunction('pfb_run_migrations')]
final class TestFreshInstallPipelineOrdering extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	/**
	 * Reproduces pfblockerng_install.inc's exact call order for a genuinely fresh
	 * install: capture freshness BEFORE any mutation, run migrations, run the
	 * registry pass, THEN apply the #2371 seed only if freshness was TRUE.
	 */
	private function runInstallSequence(): array
	{
		$fresh = pfb_psl_feed_policy_is_fresh_install(PfbConfig::readSection(self::DNSBL_SECTION));

		pfb_run_migrations();

		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		foreach (pfb_registry_pass($sections) as $section => $blob) {
			PfbConfig::writeSectionRawSystem($section, $blob);
		}

		if ($fresh) {
			PfbConfig::writeSystem('dnsbl/pfb_psl_feed_private_policy', 'apex');
			PfbConfig::writeSystem('dnsbl/pfb_psl_feed_icann_policy', 'apex');
		}

		return PfbConfig::readSection(self::DNSBL_SECTION);
	}

	/**
	 * Row 3: a genuinely fresh install (nothing configured beforehand) ends with both
	 * keys 'apex' after the full pipeline runs.
	 */
	public function testFreshInstallEndsWithBothKeysApex(): void
	{
		$dnsbl = $this->runInstallSequence();

		$this->assertSame('apex', $dnsbl['pfb_psl_feed_private_policy'] ?? NULL);
		$this->assertSame('apex', $dnsbl['pfb_psl_feed_icann_policy'] ?? NULL);
	}

	/**
	 * The load-bearing regression guard for keeping this seed OUT of
	 * pfb_migration_registry(): a genuinely fresh install must not corrupt a SIBLING
	 * registered dnsbl/* field's own NEWCFG default. dnsbl/pfb_dnsbl_lenient carries a
	 * grandfather map (ABSENT -> 'on') that only an OLDCFG (existing-install) section
	 * may apply; its correct fresh-install value is the registered default 'off'.
	 */
	public function testFreshInstallDoesNotCorruptSiblingFieldGrandfatherMode(): void
	{
		$dnsbl = $this->runInstallSequence();

		$this->assertSame('off', $dnsbl['pfb_dnsbl_lenient'] ?? NULL,
			'a genuinely fresh install must take the NEWCFG default (off) for pfb_dnsbl_lenient, '
			. 'never the OLDCFG absent-grandfather (on) -- proves the #2371 seed running AFTER '
			. 'the registry pass, not as a pfb_migration_registry() entry, is load-bearing');
	}

	/**
	 * Row 4: an existing install (already has unrelated operator configuration, but
	 * never touched these two keys) ends the pipeline with BOTH keys still absent --
	 * PfbConfig::read() then resolves that absence to Honor via the registry default.
	 */
	public function testUpgradeInstallLeavesBothKeysAbsent(): void
	{
		PfbConfig::writeSectionRawSystem(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on', 'dnsbl_interface' => 'lo0']);

		$dnsbl = $this->runInstallSequence();

		$this->assertArrayNotHasKey('pfb_psl_feed_private_policy', $dnsbl);
		$this->assertArrayNotHasKey('pfb_psl_feed_icann_policy', $dnsbl);
		$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read('dnsbl/pfb_psl_feed_private_policy'));
		$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read('dnsbl/pfb_psl_feed_icann_policy'));
	}

	/**
	 * Idempotency at the pipeline level: running the WHOLE sequence a second time
	 * (simulating a package reinstall over an already-seeded box) is a no-op for these
	 * two keys -- the section is no longer empty, so freshness reads FALSE and the
	 * seed step never fires again.
	 */
	public function testSecondPipelineRunIsNoOpForAlreadySeededKeys(): void
	{
		$first  = $this->runInstallSequence();
		$second = $this->runInstallSequence();

		$this->assertSame('apex', $first['pfb_psl_feed_private_policy'] ?? NULL);
		$this->assertSame($first['pfb_psl_feed_private_policy'], $second['pfb_psl_feed_private_policy'] ?? NULL);
		$this->assertSame($first['pfb_psl_feed_icann_policy'], $second['pfb_psl_feed_icann_policy'] ?? NULL);
	}
}
