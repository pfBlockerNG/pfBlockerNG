<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2371 — pfb_psl_feed_policy_is_fresh_install() unit tests. The full
 * install-order interaction (pfb_run_migrations() -> pfb_registry_pass() -> the
 * #2371 post-pass seed) is a SEPARATE TestCase in
 * tests/php/PslFeedPolicyPipelineOrderingTest.php -- PHPUnit only discovers ONE
 * TestCase per file, so a second class here would silently never run.
 *
 * This predicate is deliberately NOT a pfb_migration_registry() entry -- see
 * pfb_psl_feed_policy_is_fresh_install()'s docblock (pfblockerng.inc) for why folding
 * a fresh-install seed into the migration driver (which runs BEFORE pfb_registry_pass()
 * re-reads the section for its own NEWCFG/OLDCFG mode decision) would wrongly flip that
 * decision for every OTHER registered dnsbl/* field once the seeded keys make the
 * section non-empty. PslFeedPolicyPipelineOrderingTest proves that ordering choice
 * against the real pipeline rather than reasoning about it.
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
