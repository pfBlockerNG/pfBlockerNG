<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1022 -- the IP-feed loop's download-failure path can fall through to a stale-.orig
 * fallback ("Restoring previously downloaded file contents") instead of `continue`-ing the
 * row. Execution then still reaches the unconditional '.update' marker cleanup at the bottom
 * of the row, clearing the reprocess marker even though the row's content was never actually
 * refreshed -- stranding a pending rebuild/refresh (DNSBLIP rebuild, GeoIP/ASN DB refresh)
 * exactly like #1002, but reached via the download-failure path instead of the reuse-skip
 * path.
 *
 * Feature: the marker may be cleared iff the row's .orig content is NOT stale.
 *   Full truth table over the single boolean input (orig_content_stale):
 *     * Row 1 -- THE #1022 BUG PIN: stale fallback taken -> must NOT clear (FALSE). Before
 *       the fix, wiring was absent and the marker was cleared unconditionally regardless.
 *     * Row 2: no stale fallback (success, reuse-skip, or first-ever download) -> must clear
 *       (TRUE), the pre-existing, unchanged behaviour for every other path.
 */
#[CoversFunction('pfb_ip_update_marker_clear_active')]
final class PfbIpUpdateMarkerClearActiveTest extends TestCase
{
	/**
	 * Row 1 -- THE #1022 BUG PIN: stale-.orig download-failure fallback was taken, so the
	 * row's content was never refreshed. Must return FALSE (do NOT clear the marker), else a
	 * pending rebuild/refresh that touched this row's '.update' marker is silently stranded.
	 */
	public function testRow1StaleFallbackTakenDoesNotClearMarkerTheBugFix(): void
	{
		$this->assertFalse(
			pfb_ip_update_marker_clear_active(TRUE),
			"orig_content_stale=TRUE -> FALSE (#1022: stale fallback must not clear the marker)\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Row 2: no stale fallback (successful download, reuse-skip-active, or first-ever
	 * download all leave orig_content_stale FALSE). Must return TRUE (clear the marker),
	 * exactly the pre-existing/unchanged behaviour -- proves the fix doesn't strand the
	 * marker on the normal case too.
	 */
	public function testRow2NoStaleFallbackClearsMarkerUnchangedBehaviour(): void
	{
		$this->assertTrue(
			pfb_ip_update_marker_clear_active(FALSE),
			"orig_content_stale=FALSE -> TRUE (normal case, unchanged)\n" .
			"expected: true\n" .
			"got:      false"
		);
	}
}
