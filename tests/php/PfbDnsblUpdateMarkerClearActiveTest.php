<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1031 -- the DNSBL-domain loop's download-failure path can fall through to a
 * stale-.orig fallback ("Restoring previously downloaded file") instead of `continue`-ing
 * the row. Execution then still reaches the unconditional '.update' marker cleanup at the
 * bottom of the row, clearing the reprocess marker even though the row's content was never
 * actually refreshed. Genuinely producible for a "Blacklist" category feed (Shalla-style
 * multi-category tar.gz): pfb_download()'s Blacklist branch touches a feed-level '.update'
 * sentinel that the DNSBL-list-collection code propagates into a per-category
 * `{title}_{category}.update` marker under $pfb['dnsdir'] -- the exact folder/header the
 * domain loop then processes, with a local-file 'url' that takes the LOCALFILE download
 * branch, the same transient-read-failure trigger shape as #1002/#1022's DNSBLIP case.
 *
 * Feature: the marker may be cleared iff the row's .orig content is NOT stale.
 *   Full truth table over the single boolean input (orig_content_stale):
 *     * Row 1 -- THE #1031 BUG PIN: stale fallback taken -> must NOT clear (FALSE). Before
 *       the fix, wiring was absent and the marker was cleared unconditionally regardless.
 *     * Row 2: no stale fallback (success, reuse-active, first-ever download, or custom
 *       list) -> must clear (TRUE), the pre-existing, unchanged behaviour for every other
 *       path.
 */
#[CoversFunction('pfb_dnsbl_update_marker_clear_active')]
final class PfbDnsblUpdateMarkerClearActiveTest extends TestCase
{
	/**
	 * Row 1 -- THE #1031 BUG PIN: stale-.orig download-failure fallback was taken (e.g. a
	 * Blacklist-category row's local-file re-read failed), so the row's content was never
	 * refreshed. Must return FALSE (do NOT clear the marker), else a pending
	 * rebuild/refresh that touched this row's '.update' marker is silently stranded.
	 */
	public function testRow1StaleFallbackTakenDoesNotClearMarkerTheBugFix(): void
	{
		$this->assertFalse(
			pfb_dnsbl_update_marker_clear_active(TRUE),
			"orig_content_stale=TRUE -> FALSE (#1031: stale fallback must not clear the marker)\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 2: no stale fallback (successful download, reuse-active "File exists/reuse",
	 * first-ever download, or a custom list all leave orig_content_stale FALSE). Must
	 * return TRUE (clear the marker), exactly the pre-existing/unchanged behaviour --
	 * proves the fix doesn't strand the marker on the normal case too.
	 */
	public function testRow2NoStaleFallbackClearsMarkerUnchangedBehaviour(): void
	{
		$this->assertTrue(
			pfb_dnsbl_update_marker_clear_active(FALSE),
			"orig_content_stale=FALSE -> TRUE (normal case, unchanged)\n" .
			"expected: true\n" .
			"got:      false"
		);
	}
}
