<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1960/#1278 -- #1960 gated the IP/DNSBL loops' early verbatim-reuse
 * fast paths on the bare has_user_script term: !$pfb_user_script && <fast
 * path conditions>. That makes a Hold-state row with a configured pre/post
 * script leave the fast path UNCONDITIONALLY, falling through to a real
 * network download every pass -- breaking issue #1278's "download once,
 * never again" Hold contract, which the fast path is the ONLY thing
 * protecting (the DNSBL loop's Hold-specific network skip,
 * pfb_dnsbl_hold_stale_rebuild_skip(), only fires on a stale-generation
 * rebuild, not on a plain script-forced else-branch entry; the IP loop has
 * no Hold-specific network skip at all).
 *
 * The fix: an ordinary pass never downloads ANY feed -- downloads are driven
 * by the '.update'/'.fail' markers and the reuse toggle, and the fast path's
 * own conditions already require those markers to be absent. So a
 * script-configured row only ever needs the LOCAL '.orig' baseline. This
 * predicate lets the script term push a row off the fast path ONLY when a
 * '.orig' baseline exists to reparse -- routing it to the existing
 * local-reuse branch instead of the network. No baseline -> the row stays on
 * the fast path; there is no Hold-specific branch anywhere.
 *
 * Full 2^3 truth table over (verbatim_reuse_ok, has_user_script, orig_exists):
 * all eight rows are asserted below, and only (TRUE, TRUE, TRUE) is TRUE.
 */
#[CoversFunction('pfb_list_script_reparse_active')]
final class PfbListScriptReparseActiveTest extends TestCase
{
	/**
	 * Row 1 -- verbatim-reuse conditions hold, script configured, '.orig'
	 * baseline exists: the local-reparse route. TRUE.
	 */
	public function testVerbatimReuseOkScriptConfiguredOrigExistsIsTrue(): void
	{
		$this->assertTrue(
			pfb_list_script_reparse_active(TRUE, TRUE, TRUE),
			"verbatim_reuse_ok=TRUE, has_user_script=TRUE, orig_exists=TRUE -> TRUE\n" .
			"expected: true\n" .
			"got:      false"
		);
	}

	/**
	 * Row 2 -- THE HOLD FIX. Verbatim-reuse conditions hold, script
	 * configured, but NO '.orig' baseline exists (the archetypal
	 * held-because-dead-URL row that was never downloaded, or a Hold row
	 * whose baseline was removed). Must be FALSE: with no baseline to
	 * reparse locally, the row must stay on the fast path rather than fall
	 * through to a network download that would open a permanent ledger
	 * FAIL entry (#1278 breakage this whole fix exists to close).
	 */
	public function testVerbatimReuseOkScriptConfiguredNoOrigIsFalseTheHoldFix(): void
	{
		$this->assertFalse(
			pfb_list_script_reparse_active(TRUE, TRUE, FALSE),
			"verbatim_reuse_ok=TRUE, has_user_script=TRUE, orig_exists=FALSE -> FALSE " .
			"(#1278 Hold fix: no baseline -> stay on the fast path, never the network)\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 3 -- verbatim-reuse conditions hold, NO script configured: the
	 * ordinary no-script feed keeps its unchanged fast path regardless of
	 * '.orig'. FALSE.
	 */
	public function testVerbatimReuseOkNoScriptIsFalse(): void
	{
		$this->assertFalse(
			pfb_list_script_reparse_active(TRUE, FALSE, TRUE),
			"verbatim_reuse_ok=TRUE, has_user_script=FALSE, orig_exists=TRUE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 4 -- verbatim-reuse conditions already rejected reuse (some
	 * file-state condition failed -- e.g. '.update' or '.fail' present, or
	 * the reuse toggle is on): the normal download/Reload/Rebuild path
	 * already owns this row regardless of the script/orig terms. FALSE.
	 */
	public function testVerbatimReuseRejectedIsFalseRegardlessOfScriptAndOrig(): void
	{
		$this->assertFalse(
			pfb_list_script_reparse_active(FALSE, TRUE, TRUE),
			"verbatim_reuse_ok=FALSE, has_user_script=TRUE, orig_exists=TRUE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 5 -- verbatim-reuse conditions hold, but neither a script nor a
	 * baseline: the plain no-script feed on its unchanged fast path. FALSE.
	 */
	public function testVerbatimReuseOkNoScriptNoOrigIsFalse(): void
	{
		$this->assertFalse(
			pfb_list_script_reparse_active(TRUE, FALSE, FALSE),
			"verbatim_reuse_ok=TRUE, has_user_script=FALSE, orig_exists=FALSE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 6 -- reuse already rejected AND no baseline, script configured: the
	 * normal download path owns this row. FALSE.
	 */
	public function testVerbatimReuseRejectedScriptConfiguredNoOrigIsFalse(): void
	{
		$this->assertFalse(
			pfb_list_script_reparse_active(FALSE, TRUE, FALSE),
			"verbatim_reuse_ok=FALSE, has_user_script=TRUE, orig_exists=FALSE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 7 -- reuse already rejected, no script, but a baseline exists: a
	 * surviving '.orig' alone must never route a row to the reparse branch.
	 * FALSE.
	 */
	public function testVerbatimReuseRejectedNoScriptOrigExistsIsFalse(): void
	{
		$this->assertFalse(
			pfb_list_script_reparse_active(FALSE, FALSE, TRUE),
			"verbatim_reuse_ok=FALSE, has_user_script=FALSE, orig_exists=TRUE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 8 -- full truth table closed: all three conditions FALSE. FALSE.
	 */
	public function testAllThreeFalseIsFalse(): void
	{
		$this->assertFalse(
			pfb_list_script_reparse_active(FALSE, FALSE, FALSE),
			"verbatim_reuse_ok=FALSE, has_user_script=FALSE, orig_exists=FALSE -> FALSE\n" .
			"expected: false\n" .
			"got:      true"
		);
	}
}
