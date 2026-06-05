<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-12 Phase 6: dnsbl_alias_update() is the central DNSBL changed-group seam.
 * On $mode == 'update' it must append the DNSBL_<group> $alias to the pass-scoped
 * accumulator $pfb['changed_dnsbl_groups'] (the single source the 'post' hook reads
 * to build PFB_CHANGED_DNSBL_GROUPS); on $mode == 'disabled' it must NOT record
 * anything. DNSBL groups are NOT firewall aliases, so they ride their own
 * accumulator/env var, split from the IP-side $pfb['changed_ip_aliases'].
 *
 * Branch coverage (both modes) + before/after (assert the accumulator is empty
 * BEFORE the 'update' call, then non-empty after, so the green proves the call
 * caused the change). The 'update' call here passes an empty $lists_dnsbl_current
 * ('') so the master-file fopen block is skipped -- only the stats + the accumulator
 * append run, which is exactly the recording behaviour under test (no live config).
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

	public function testUpdateModeRecordsGroupWithBeforeState(): void
	{
		global $pfb;

		// BEFORE: nothing updated yet.
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);

		dnsbl_alias_update('update', 'DNSBL_ads', '', '', 7);

		// AFTER: the 'update' call recorded exactly this DNSBL group.
		$this->assertSame(array('DNSBL_ads'), $pfb['changed_dnsbl_groups']);
	}

	public function testDisabledModeRecordsNothing(): void
	{
		global $pfb;

		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);

		dnsbl_alias_update('disabled', 'DNSBL_ads', '', '', '');

		// The OFF branch: a disabled alias is NOT an update, so it must not appear.
		$this->assertSame(array(), $pfb['changed_dnsbl_groups']);
	}

	public function testMultipleUpdatesAccumulateInOrder(): void
	{
		global $pfb;

		dnsbl_alias_update('update', 'DNSBL_ads', '', '', 1);
		dnsbl_alias_update('update', 'DNSBL_IDN', '', '', 1);
		dnsbl_alias_update('update', 'DNSBL_Regex', '', '', 1);

		// All three 'update' callers fold into the accumulator in call order.
		// (De-dup happens only when the post hook emits the list.)
		$this->assertSame(array('DNSBL_ads', 'DNSBL_IDN', 'DNSBL_Regex'), $pfb['changed_dnsbl_groups']);
	}

	public function testUpdateIsToleratedWhenAccumulatorUnset(): void
	{
		global $pfb;

		// Defensive: if the accumulator was never initialised (e.g. a caller
		// outside the pass), the 'update' append is a guarded no-op, not a fatal.
		unset($pfb['changed_dnsbl_groups']);
		dnsbl_alias_update('update', 'DNSBL_ads', '', '', 1);
		$this->assertArrayNotHasKey('changed_dnsbl_groups', $pfb);
	}
}
