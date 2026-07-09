<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1002 -- the IP-feed loop's "reuse previous download" skip optimization exists to
 * avoid re-fetching a REAL network feed. DNSBLIP's "download" is actually a near-instant
 * local-file copy of the just-rebuilt {$pfb['dbdir']}/DNSBLIP{$vtype}.txt source, so the
 * optimization must never apply to it: Force Reload forces $pfbreuse to 'on' regardless of
 * the pfb_reuse tunable, and when a prior .orig already exists the row wrongly took the
 * reuse-skip branch instead of re-copying -- so a rebuild that happened earlier in the SAME
 * pass (which touches DNSBLIP's '.update' reprocess marker) never propagated into .orig
 * before the marker was unconditionally deleted, leaving the alias stale indefinitely.
 *
 * Feature: reuse-skip is active iff reuse is wanted, an .orig already exists, AND the row
 *   is NOT the DNSBLIP pseudo-feed.
 *   Full 2x2x2 truth table over (reuse_on, orig_exists, is_dnsblip):
 *     * Rows 1-4 (is_dnsblip=FALSE) pin the pre-existing, UNCHANGED real-feed behaviour --
 *       row 4 (reuse=TRUE, orig=TRUE) is the only TRUE case, exactly the reuse-skip a real
 *       feed relies on to avoid a wasteful re-fetch. A regression here silently breaks
 *       reuse-mode for every non-DNSBLIP IP list.
 *     * Rows 5-8 (is_dnsblip=TRUE) always resolve FALSE -- the DNSBLIP row must always take
 *       the real download (local-copy) path. Row 8 (reuse=TRUE, orig=TRUE, is_dnsblip=TRUE)
 *       is the #1002 bug pin: before the fix this combination wrongly returned TRUE.
 */
#[CoversFunction('pfb_ip_reuse_skip_active')]
final class PfbIpReuseSkipActiveTest extends TestCase
{
	/**
	 * Row 1: reuse off, no prior .orig, real feed -- nothing to reuse, must download.
	 */
	public function testRow1ReuseOffNoOrigRealFeedIsFalse(): void
	{
		$this->assertFalse(
			pfb_ip_reuse_skip_active(FALSE, FALSE, FALSE),
			"reuse=FALSE, orig=FALSE, dnsblip=FALSE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 2: reuse off, prior .orig DOES exist, real feed -- the reuse flag being off makes
	 * the existing .orig irrelevant.
	 */
	public function testRow2ReuseOffOrigExistsRealFeedIsFalse(): void
	{
		$this->assertFalse(
			pfb_ip_reuse_skip_active(FALSE, TRUE, FALSE),
			"reuse=FALSE, orig=TRUE, dnsblip=FALSE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 3: reuse on, no prior .orig, real feed -- reuse is wanted but there is nothing
	 * yet to reuse, so a real download must happen.
	 */
	public function testRow3ReuseOnNoOrigRealFeedIsFalse(): void
	{
		$this->assertFalse(
			pfb_ip_reuse_skip_active(TRUE, FALSE, FALSE),
			"reuse=TRUE, orig=FALSE, dnsblip=FALSE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 4: reuse on, prior .orig exists, real feed -- the pre-existing, correct,
	 * UNCHANGED reuse-skip a real feed relies on. Must stay TRUE or every non-DNSBLIP IP
	 * list's reuse-mode silently breaks.
	 */
	public function testRow4ReuseOnOrigExistsRealFeedIsTrue(): void
	{
		$this->assertTrue(
			pfb_ip_reuse_skip_active(TRUE, TRUE, FALSE),
			"reuse=TRUE, orig=TRUE, dnsblip=FALSE -> TRUE (real-feed reuse-skip, unchanged)\n" .
			"expected: true\n" .
			"got:      false"
		);
	}

	/**
	 * Row 5: reuse off, no prior .orig, DNSBLIP row -- always FALSE for DNSBLIP.
	 */
	public function testRow5ReuseOffNoOrigDnsblipIsFalse(): void
	{
		$this->assertFalse(
			pfb_ip_reuse_skip_active(FALSE, FALSE, TRUE),
			"reuse=FALSE, orig=FALSE, dnsblip=TRUE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 6: reuse off, prior .orig exists, DNSBLIP row -- still FALSE.
	 */
	public function testRow6ReuseOffOrigExistsDnsblipIsFalse(): void
	{
		$this->assertFalse(
			pfb_ip_reuse_skip_active(FALSE, TRUE, TRUE),
			"reuse=FALSE, orig=TRUE, dnsblip=TRUE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 7: reuse on, no prior .orig, DNSBLIP row -- still FALSE.
	 */
	public function testRow7ReuseOnNoOrigDnsblipIsFalse(): void
	{
		$this->assertFalse(
			pfb_ip_reuse_skip_active(TRUE, FALSE, TRUE),
			"reuse=TRUE, orig=FALSE, dnsblip=TRUE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 8 -- THE #1002 BUG PIN: reuse on (Force Reload forces $pfbreuse to 'on'
	 * regardless of the pfb_reuse tunable), a prior .orig already on disk (from before the
	 * in-pass rebuild), DNSBLIP row. Before the fix this wrongly returned TRUE (reuse-skip),
	 * so a rebuild that happened earlier in the SAME pass -- which touches DNSBLIP's
	 * '.update' reprocess marker -- never got propagated into .orig before the marker was
	 * unconditionally deleted at the end of row processing, leaving the alias stale
	 * indefinitely. Must return FALSE: DNSBLIP always takes the real (local-copy) download.
	 */
	public function testRow8ReuseOnOrigExistsDnsblipIsFalseTheBugFix(): void
	{
		$this->assertFalse(
			pfb_ip_reuse_skip_active(TRUE, TRUE, TRUE),
			"reuse=TRUE, orig=TRUE, dnsblip=TRUE -> FALSE (#1002: DNSBLIP must never reuse-skip)\n" .
			"expected: false\n" .
			"got:      true"
		);
	}
}
