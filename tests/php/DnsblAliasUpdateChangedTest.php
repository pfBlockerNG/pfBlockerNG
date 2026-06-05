<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-12 Phase 6 (corrected): dnsbl_alias_update() must NOT record the changed-group
 * accumulator. The genuine per-group change signal is $pfb['aliasupdate'] (TRUE only
 * when a feed in the group was actually (re)downloaded+parsed, FALSE on file-reuse),
 * and the recording happens in the per-group feed loop of sync_package_pfblockerng()
 * under `if ($pfb['aliasupdate']) { $pfb['changed_dnsbl_groups'][] = $alias; }` --
 * BEFORE the TLD/non-TLD routing split, so it covers both modes and naturally EXCLUDES
 * the always-rebuilt specials (DNSBL_IDN/DNSBL_TLD_Allow/DNSBL_Regex), which call
 * dnsbl_alias_update('update', ...) from OUTSIDE that loop.
 *
 * The earlier ADR-12 P6 implementation appended $alias from inside dnsbl_alias_update()
 * on $mode=='update'. That over-recorded: it swept in the specials (their update calls
 * are gated on the FEATURE being on, not on a change) and any reuse-path 'update' call,
 * producing PFB_CHANGED_DNSBL_GROUPS noise every pass. The fix removed that line.
 *
 * This unit pins the corrected contract for the one part that is unit-reachable
 * off-appliance: dnsbl_alias_update() (both modes) is INERT w.r.t.
 * $pfb['changed_dnsbl_groups'] -- it never adds (nor removes) entries, regardless of
 * $mode. The per-group aliasupdate-gated recording itself lives inside the full pass
 * (sync_package_pfblockerng) and is covered end-to-end by the live smoke suite
 * (tests/smoke/test_smoke_hooks.py), which asserts a genuinely-changed DNSBL_<group>
 * appears while the specials do NOT.
 */
#[CoversFunction('dnsbl_alias_update')]
final class DnsblAliasUpdateChangedTest extends TestCase
{
	protected function setUp(): void
	{
		// Reset the pass-scoped state these tests inspect (the real pass clears
		// $pfb['changed_dnsbl_groups'] at the top of sync_package_pfblockerng).
		$GLOBALS['pfb']['changed_dnsbl_groups'] = array();
		$GLOBALS['pfb']['dnsbl_info_stats'] = array();
	}

	public function testUpdateModeDoesNotRecordGroup(): void
	{
		global $pfb;

		// BEFORE: empty accumulator.
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);

		// An 'update' call (the seam the specials also use) must NOT touch the
		// accumulator -- recording is the per-group aliasupdate loop's job, not this
		// function's. This is the regression guard for the removed in-function append.
		dnsbl_alias_update('update', 'DNSBL_ads', '', '', 7);

		// AFTER: still empty -- the function recorded nothing.
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);
	}

	public function testSpecialsUpdateCallsDoNotRecord(): void
	{
		global $pfb;

		// The always-rebuilt specials call dnsbl_alias_update('update', ...) from
		// OUTSIDE the per-group loop. None of them may appear in the accumulator: the
		// over-recording bug folded exactly these in every pass.
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);
		dnsbl_alias_update('update', 'DNSBL_IDN', '', '', 1);
		dnsbl_alias_update('update', 'DNSBL_TLD_Allow', '', '', 1);
		dnsbl_alias_update('update', 'DNSBL_Regex', '', '', 1);
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);
	}

	public function testDisabledModeRecordsNothing(): void
	{
		global $pfb;

		// The OFF branch: a disabled alias is not an update; still no recording (it
		// never did, and must not now).
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);
		dnsbl_alias_update('disabled', 'DNSBL_ads', '', '', '');
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);
	}

	public function testAccumulatorPreservedAcrossCalls(): void
	{
		global $pfb;

		// A pre-existing entry (placed by the per-group loop) is left intact by
		// dnsbl_alias_update() -- the function neither adds nor drops members, so a
		// genuinely-recorded group survives the specials' later 'update' calls.
		$pfb['changed_dnsbl_groups'] = array('DNSBL_realfeed');
		dnsbl_alias_update('update', 'DNSBL_Regex', '', '', 1);
		dnsbl_alias_update('disabled', 'DNSBL_other', '', '', '');
		$this->assertSame(array('DNSBL_realfeed'), $pfb['changed_dnsbl_groups']);
	}
}
