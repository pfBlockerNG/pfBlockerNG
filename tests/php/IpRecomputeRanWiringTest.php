<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1084 review — pfblockerng.inc source tripwires for wiring that cannot be driven
 * as a unit under PHPUnit (the reload pass is thousands of lines of top-level script code,
 * not a callable function): the recompute-invocation loop must record, per family, whether
 * the batch recompute verb actually ran THIS pass, and both the v4/v6 suppression-body
 * gates and the FINAL REPORTING closing-pass gate must consume that signal via the new
 * pure helpers (pfb_ip_suppress_body_active(), pfb_ip_closing_pass_active()) rather than
 * their old feed-changed-only / dedup-only conditions.
 *
 * Each assertion is a real substring check against the CURRENT file content, so it fails
 * for as long as the old condition (or no condition at all) is what is actually wired --
 * a stale rename/refactor of any of these lines fails this oracle immediately.
 */
final class IpRecomputeRanWiringTest extends TestCase
{
	private const PFBLOCKERNG_INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private function source(): string
	{
		return (string) file_get_contents(self::PFBLOCKERNG_INC);
	}

	public function testInvocationLoopRecordsWhetherRecomputeRanPerFamily(): void
	{
		$source = $this->source();
		$this->assertStringContainsString(
			'$pfb_recompute_ran_v4',
			$source,
			'the v4 recompute-ran flag must exist so the suppression/closing gates can consume it'
		);
		$this->assertStringContainsString(
			'$pfb_recompute_ran_v6',
			$source,
			'the v6 recompute-ran flag must exist so the suppression gate can consume it'
		);
	}

	public function testV4SuppressionBodyGateConsumesTheSuppressBodyActiveHelperAndV4Flag(): void
	{
		$source = $this->source();
		$this->assertStringContainsString(
			"pfb_ip_suppress_body_active(\$pfb['supp'] == 'on', \$vtype == '_v4', \$pfb['supp_update'], \$pfbadv, in_array(\$alias, \$final_alias_old), \$pfb_recompute_ran_v4)",
			$source,
			'the v4 suppression-body gate must call pfb_ip_suppress_body_active() with the v4 recompute-ran flag'
		);
	}

	public function testV6SuppressionBodyGateConsumesTheSuppressBodyActiveHelperAndV6Flag(): void
	{
		$source = $this->source();
		$this->assertStringContainsString(
			"pfb_ip_suppress_body_active(\$pfb['supp'] == 'on', \$vtype == '_v6', \$pfb['supp_update'], \$pfbadv, in_array(\$alias, \$final_alias_old), \$pfb_recompute_ran_v6)",
			$source,
			'the v6 suppression-body gate must call pfb_ip_suppress_body_active() with the v6 recompute-ran flag'
		);
	}

	public function testFinalReportingClosingGateConsumesTheClosingPassActiveHelperAndV4Flag(): void
	{
		$source = $this->source();
		$this->assertStringContainsString(
			"pfb_ip_closing_pass_active(\$pfb['dup'] == 'on', \$pfb_recompute_ran_v4)",
			$source,
			'the FINAL REPORTING gate must call pfb_ip_closing_pass_active() with the v4 recompute-ran flag'
		);
	}

	public function testContinentSnapshotWriteIsNoLongerGatedToV4Only(): void
	{
		$source = $this->source();
		$needle = 'pfb_ip_recompute_write_snapshot("{$pfbfolder}/{$cc_alias}.txt", $cc_alias, $pfb[\'snapdir\'], $pfb[\'origdir\']);';
		$pos    = strpos($source, $needle);
		$this->assertNotFalse($pos, "continent snapshot call site not found -- update this oracle if it moved/changed shape\nsource file: " . self::PFBLOCKERNG_INC);

		// The gating "if" immediately precedes the call; a v6 continent's live .txt IS
		// regenerated every GeoIP change (unconditional on $vtype -- see the sibling
		// @copy() calls a few lines up), so a v4-only snapshot gate freezes its recompute
		// memberlist entry at the one-time upgrade seed forever (issue #1084 review).
		$precedingWindow = substr($source, max(0, $pos - 200), 200);
		$this->assertStringNotContainsString(
			"\$vtype == '_v4' && \$pfbadv",
			$precedingWindow,
			'the continent snapshot write must no longer be gated to v4 only -- v6 continents need their own recompute snapshot too'
		);
		$this->assertStringContainsString(
			'if ($pfbadv) {',
			$precedingWindow,
			'expected the gate to be $pfbadv alone (both v4 and v6 continents snapshot)'
		);
	}
}
