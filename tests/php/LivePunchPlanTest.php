<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_live_punch_plan() -- ADR-53 Phase 8: the Alerts "+" / widget live-punch
 * planner that replaces the retired /24-only 254-host re-add loop
 * (pfblockerng_alerts.php's old addsuppress block).
 *
 * BEHAVIOUR CHANGE (ADR-53 §2.1 fork 3 -- full rework, red->green): the old
 * mechanism only understood an exact bare host or an exact /24 table entry --
 * any other containing mask (any v4 mask other than /24, or ANY v6 mask)
 * was refused outright ("blocked by a CIDR other than /24"). This function
 * did not exist before Phase 8, so every test here FAILS with a fatal
 * "undefined function" against the pre-Phase-8 code and PASSES once
 * pfb_live_punch_plan() (and its v4 carve helper pfb_v4_carve_single())
 * land. The counts below are cross-checked against ADR-53 §1.2's measured
 * covering-CIDR bounds ("/16 - /32 = 16", "/64 (v6) - /128 = 64",
 * "/24 - /32 = 8"), not guessed.
 *
 * Issue #1471: $table_entries widens from `array` to `iterable` -- the
 * membership snapshot pfb_live_table_snapshot() hands in is now a streamed
 * \Generator, not a fully materialised array. The tests below prove both
 * shapes work: the existing tests above pass a plain array unchanged, and
 * the generator-input tests below pass a \Generator through the same
 * foreach-driven body.
 */
#[CoversFunction('pfb_live_punch_plan')]
#[CoversFunction('pfb_v4_carve_single')]
final class LivePunchPlanTest extends TestCase
{
	// --- v4: a containing mask the old /24-only mechanism refused outright ---

	public function testV4Slash16ContainingEntryIsCarvedIntoSixteenCoveringCidrs(): void
	{
		$plan = pfb_live_punch_plan('10.0.5.9', ['10.0.0.0/16']);

		$this->assertSame(
			['10.0.0.0/16'],
			$plan['delete'],
			'the containing /16 must be marked for deletion -- the old code refused anything but an exact /24'
		);
		$this->assertCount(
			16,
			$plan['add'],
			'a /16 minus one host is 16 covering CIDRs (ADR-53 §1.2 measured bound), never a 65535-host explosion'
		);
		foreach ($plan['add'] as $cidr) {
			$this->assertFalse(
				ip_in_subnet('10.0.5.9', $cidr),
				"the carved-out host must not fall inside any re-added covering CIDR [ {$cidr} ]"
			);
		}
	}

	// --- v4: a bare host entry -- exact match, nothing to re-add ---

	public function testV4BareHostEntryIsDeletedWithNothingToReAdd(): void
	{
		$plan = pfb_live_punch_plan('198.51.100.7', ['198.51.100.7']);

		$this->assertSame(['198.51.100.7'], $plan['delete']);
		$this->assertSame(
			[],
			$plan['add'],
			'an exact bare-host table entry contains ONLY the punched host -- no covering-CIDR remainder'
		);
	}

	// --- v4: legacy exact /24 shape still carves correctly (8 covering CIDRs) ---

	public function testV4ExactSlash24EntryIsCarvedIntoEightCoveringCidrs(): void
	{
		$plan = pfb_live_punch_plan('203.0.113.5', ['203.0.113.0/24']);

		$this->assertSame(['203.0.113.0/24'], $plan['delete']);
		$this->assertCount(
			8,
			$plan['add'],
			'a /24 minus one host is 8 covering CIDRs (ADR-53 §1.2 measured bound) -- NOT the retired 254-host loop'
		);
	}

	// --- v6: no mask was ever wired to the old mechanism at all ---

	public function testV6Slash64ContainingEntryIsCarvedIntoSixtyFourCoveringCidrs(): void
	{
		$plan = pfb_live_punch_plan('2001:db8::9', ['2001:db8::/64']);

		$this->assertSame(['2001:db8::/64'], $plan['delete']);
		$this->assertCount(
			64,
			$plan['add'],
			'a /64 minus one host is 64 covering CIDRs (ADR-53 §1.2 measured bound) -- v6 was never punchable before'
		);
		foreach ($plan['add'] as $cidr) {
			$this->assertFalse(
				ip_in_subnet('2001:db8::9', $cidr),
				"the carved-out v6 host must not fall inside any re-added covering CIDR [ {$cidr} ]"
			);
		}
	}

	// --- no containing entry -- both empty, never a false punch ---

	public function testIpNotInAnyEntryProducesAnEmptyPlan(): void
	{
		$plan = pfb_live_punch_plan('10.1.0.1', ['10.0.0.0/16']);

		$this->assertSame([], $plan['delete']);
		$this->assertSame([], $plan['add']);
	}

	// --- multiple containing entries: every one gets punched ---

	public function testMultipleContainingEntriesAreAllPunched(): void
	{
		// The host sits inside a containing /24 AND is separately listed as its
		// own exact /32 -- an overlapping table config the old mechanism could
		// not have expressed as a single suppression, but the plan must still
		// carve every containing entry, not just the first match.
		$plan = pfb_live_punch_plan('203.0.113.5', ['203.0.113.0/24', '203.0.113.5']);

		$this->assertSame(['203.0.113.0/24', '203.0.113.5'], $plan['delete']);
		$this->assertCount(
			8,
			$plan['add'],
			'only the /24 leaves a covering-CIDR remainder (8, per ADR-53 §1.2) -- the exact /32 match adds nothing'
		);
	}

	// --- a sibling address outside the hole is never dropped ---

	public function testSiblingEntryOutsideTheHoleIsUntouched(): void
	{
		$plan = pfb_live_punch_plan('198.51.100.99', ['198.51.100.0/16', '198.52.100.9']);

		$this->assertSame(
			['198.51.100.0/16'],
			$plan['delete'],
			'only the containing entry is punched -- an unrelated sibling table entry stays out of the plan entirely'
		);
	}

	// --- blank/comment lines in the membership snapshot are tolerated ---

	public function testBlankAndCommentLinesInTableSnapshotAreSkipped(): void
	{
		$plan = pfb_live_punch_plan('10.0.0.1', ['', '# a comment', '10.0.0.0/24']);

		$this->assertSame(['10.0.0.0/24'], $plan['delete']);
	}

	// --- generator input (issue #1471): the table membership snapshot is
	// now a streamed \Generator, not just an array -- the plan must accept
	// any iterable and consume it correctly in a single pass. ---

	public function testV4GeneratorInputIsCarvedCorrectlyWithNonContainingSiblingConsumed(): void
	{
		$entries = (function (): \Generator {
			yield '198.18.0.0/16';   // containing entry
			yield '198.51.100.0/24'; // sibling, does not contain the host
		})();

		$plan = pfb_live_punch_plan('198.18.6.9', $entries);

		$this->assertSame(['198.18.0.0/16'], $plan['delete']);
		$this->assertCount(16, $plan['add']);
		foreach ($plan['add'] as $cidr) {
			$this->assertFalse(
				ip_in_subnet('198.18.6.9', $cidr),
				"the carved-out host must not fall inside any re-added covering CIDR [ {$cidr} ]"
			);
		}
	}

	public function testV6GeneratorInputIsCarvedCorrectlyWithNonContainingSiblingConsumed(): void
	{
		$entries = (function (): \Generator {
			yield '2001:db8::/64'; // containing entry
			yield '2001:db9::/64'; // sibling, does not contain the host
		})();

		$plan = pfb_live_punch_plan('2001:db8::9', $entries);

		$this->assertSame(['2001:db8::/64'], $plan['delete']);
		$this->assertCount(64, $plan['add']);
		foreach ($plan['add'] as $cidr) {
			$this->assertFalse(
				ip_in_subnet('2001:db8::9', $cidr),
				"the carved-out v6 host must not fall inside any re-added covering CIDR [ {$cidr} ]"
			);
		}
	}

	// --- Nested containing entries must not emit duplicate remainders --
	// wasted execs downstream in pfb_live_punch_apply(). Two containing
	// entries whose remainders overlap near the punched host (a /16 AND a
	// /24 both containing it) carve the SAME near-host covering CIDRs twice,
	// once per containing entry. ---

	public function testNestedV4ContainingEntriesProduceNoDuplicatePlanEntries(): void
	{
		$plan = pfb_live_punch_plan('198.18.0.5', ['198.18.0.0/16', '198.18.0.0/24']);

		$this->assertSame(['198.18.0.0/16', '198.18.0.0/24'], $plan['delete']);
		$this->assertSame(
			count($plan['add']),
			count(array_unique($plan['add'])),
			'the /16 and /24 remainders overlap near the punched host -- the add list must not repeat a covering CIDR'
		);
		$this->assertSame(
			count($plan['delete']),
			count(array_unique($plan['delete'])),
			'the delete list must not repeat a containing entry either'
		);
	}
}
