<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1960: the IP and DNSBL feed loops' early verbatim-reuse fast paths
 * must carry the same has_user_script term the normalization-level reuse
 * gates (pfb_ip_norm_reuse_skip() / pfb_dnsbl_norm_reuse_skip()) already
 * carry -- a feed with a configured pre/post script must re-run its
 * transform on an ordinary cron pass, never require a Force Reload. The IP
 * and DNSBL loops inside sync_package_pfblockerng() drive real appliance
 * exec and have no PHPUnit harness of their own (issue #993), so -- same
 * technique as DnsblListScriptWiringTest / ListScriptFailureLedgerWiringTest
 * -- the wiring is pinned by source inspection with vacuity-guarded windows.
 *
 * Deliberate asymmetry (see the production comment above the statement):
 * the DNSBL loop's second pfb_dnsbl_verbatim_reuse_active(..., TRUE) re-call
 * (#1083's $stale_generation_rebuild) answers a DIFFERENT question and stays
 * deliberately UNGATED by the user-script term -- pinned here so a future
 * "consistency cleanup" cannot silently change #1083 behaviour.
 */
final class ListScriptTransformRerunWiringTest extends TestCase
{
	private static string $applySource;

	public static function setUpBeforeClass(): void
	{
		$source = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		if ($source === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		self::$applySource = $source;
	}

	// -----------------------------------------------------------------
	// Row 8 -- IP fast-path condition carries !$pfb_user_script.
	// -----------------------------------------------------------------

	public function testIpFastPathCarriesUserScriptTerm(): void
	{
		$asnTouchPos = strpos(self::$applySource, "\$pfb['dbdir']}/asn.update");
		$this->assertNotFalse($asnTouchPos, 'vacuity: the geoip/asn .update touch block must exist before the IP fast path');

		$staticHoldPos = strpos(self::$applySource, 'static hold.', $asnTouchPos);
		$this->assertNotFalse($staticHoldPos, 'vacuity: the IP fast-path "static hold." log must exist after the geoip/asn touches');

		$window = substr(self::$applySource, $asnTouchPos, $staticHoldPos - $asnTouchPos);

		// issue #1278: supersedes the bare !$pfb_user_script gate this row originally pinned --
		// that shape forced a Hold row with a configured script through to a network download
		// every pass (the #1278 regression). The script term now only pushes a row off the fast
		// path when a local '.orig' baseline exists to reparse (see PfbListScriptReparseActiveTest
		// / ListScriptReparseWiringTest for the full fix and its own coverage).
		$this->assertStringContainsString('!$pfb_script_reparse', $window,
			'issue #1960/#1278: the IP fast path must be gated by the script-reparse term (which '
			. 'requires a local .orig baseline) -- a configured script re-runs its transform every '
			. 'pass it has a baseline to reparse, but a Hold row with none stays on the fast path '
			. 'instead of falling through to the network');
	}

	// -----------------------------------------------------------------
	// Row 9 -- $pfb_user_script assigned exactly ONCE in the IP loop and
	// BEFORE the fast path (a leftover second assignment is the bug this
	// row catches).
	// -----------------------------------------------------------------

	public function testIpUserScriptAssignedExactlyOnceBeforeFastPath(): void
	{
		$count = substr_count(self::$applySource, '$pfb_user_script = ');
		$this->assertSame(1, $count,
			'a leftover second assignment is the bug this row catches -- $pfb_user_script must be '
			. 'computed exactly once per row');

		$assignPos = strpos(self::$applySource, '$pfb_user_script = ');
		$this->assertNotFalse($assignPos, 'vacuity: the assignment must exist');

		$asnTouchPos = strpos(self::$applySource, "\$pfb['dbdir']}/asn.update");
		$this->assertNotFalse($asnTouchPos, 'vacuity: the geoip/asn .update touch block must exist');

		$fastPathPos = strpos(self::$applySource, 'static hold.', $asnTouchPos);
		$this->assertNotFalse($fastPathPos, 'vacuity: the IP fast-path log must exist after the geoip/asn touches');

		$this->assertLessThan($fastPathPos, $assignPos,
			'$pfb_user_script must be computed before the fast path that consumes it');
	}

	// -----------------------------------------------------------------
	// Row 10 -- DNSBL fast-path call site carries !$pfb_dnsbl_user_script.
	// -----------------------------------------------------------------

	public function testDnsblFastPathCarriesUserScriptTerm(): void
	{
		// issue #1278: supersedes the bare '!$pfb_dnsbl_user_script && pfb_dnsbl_verbatim_reuse_active('
		// shape this row originally pinned -- that gate forced a Hold row with a configured script
		// through to a network download every pass (the #1278 regression). Pinned as the whole
		// gated statement head rather than a window opened on a bare token: 'pfb_dnsbl_verbatim_reuse_active('
		// also occurs inside the production comments describing this gate and the #1083 asymmetry,
		// so a window anchored on it opens on prose instead of the call it claims to pin.
		$this->assertStringContainsString(
			'if ($pfb_dnsbl_verbatim_reuse && !$pfb_dnsbl_script_reparse) {',
			self::$applySource,
			'issue #1960/#1278: the DNSBL fast path must be gated by the script-reparse term (which '
			. 'requires a local .orig baseline), not the bare has_user_script term -- same contract '
			. 'as the IP loop');

		// The gate must sit on the fast path that logs "exists."/"static hold.", not on
		// some other caller: the gated head is the LAST thing before that log.
		$gatePos = strpos(self::$applySource, 'if ($pfb_dnsbl_verbatim_reuse && !$pfb_dnsbl_script_reparse) {');
		$this->assertNotFalse($gatePos, 'vacuity: the gated DNSBL fast-path statement must exist');
		$existsPos = strpos(self::$applySource, '{$logtab} exists.', $gatePos);
		$this->assertNotFalse($existsPos,
			'the gated statement must be the DNSBL verbatim-reuse fast path -- its branch logs "exists."');
	}

	// -----------------------------------------------------------------
	// Row 11 -- $pfb_dnsbl_user_script assigned exactly ONCE and before
	// BOTH the fast path and the pfb_dnsbl_norm_reuse_skip() call.
	// -----------------------------------------------------------------

	public function testDnsblUserScriptAssignedExactlyOnceBeforeBothCallSites(): void
	{
		$count = substr_count(self::$applySource, '$pfb_dnsbl_user_script = ');
		$this->assertSame(1, $count,
			'a leftover second assignment is the bug this row catches -- $pfb_dnsbl_user_script '
			. 'must be computed exactly once per alias');

		$assignPos = strpos(self::$applySource, '$pfb_dnsbl_user_script = ');
		$this->assertNotFalse($assignPos, 'vacuity: the assignment must exist');

		// Anchored on the gated statement head, not a bare
		// 'pfb_dnsbl_verbatim_reuse_active(' token -- that token also occurs in the
		// production comments above the call, which would move this anchor onto prose.
		// issue #1278: the gate itself moved from the bare user-script term to the
		// script-reparse term, but $pfb_dnsbl_user_script is still consumed just before it
		// (now via pfb_list_script_reparse_active()), so the ordering this row pins is unchanged.
		$fastPathPos = strpos(self::$applySource, 'if ($pfb_dnsbl_verbatim_reuse && !$pfb_dnsbl_script_reparse) {');
		$this->assertNotFalse($fastPathPos, 'vacuity: the gated DNSBL fast path must exist');
		$this->assertLessThan($fastPathPos, $assignPos,
			'$pfb_dnsbl_user_script must be computed before the fast path that consumes it');

		$reuseSkipPos = strpos(self::$applySource, 'pfb_dnsbl_norm_reuse_skip(');
		$this->assertNotFalse($reuseSkipPos, 'vacuity: the DNSBL normalize/reuse-skip call must exist');
		$this->assertLessThan($reuseSkipPos, $assignPos,
			'$pfb_dnsbl_user_script must be computed before the normalize/reuse-skip call too');
	}

	// -----------------------------------------------------------------
	// Row 12 -- the $stale_generation_rebuild re-call is NOT gated by the
	// user-script term (#1083 deliberate asymmetry).
	// -----------------------------------------------------------------

	public function testStaleGenerationRebuildRecallIsNotGatedByUserScript(): void
	{
		$stmtPos = strpos(self::$applySource, '$stale_generation_rebuild = ');
		$this->assertNotFalse($stmtPos, 'vacuity: the #1083 stale-generation rebuild re-call must exist');

		$stmtEnd = strpos(self::$applySource, ';', $stmtPos);
		$this->assertNotFalse($stmtEnd, 'vacuity: the statement must terminate');

		$statement = substr(self::$applySource, $stmtPos, $stmtEnd - $stmtPos);

		$this->assertStringNotContainsString('$pfb_dnsbl_user_script', $statement,
			'issue #1960 deliberate asymmetry: the $stale_generation_rebuild re-call answers a '
			. 'DIFFERENT question (#1083 -- was stale staging generation the ONLY file-state reason '
			. 'reuse was rejected) and must stay ungated -- gating it would force a full network '
			. 'refetch for a stale-generation .txt with a configured script instead of the cheaper '
			. 'reparse-from-.orig path, where the pre-script still reruns anyway '
			. "(pfb_dnsbl_norm_reuse_skip() is FALSE there since \$downloaded_fresh is FALSE), silently "
			. 'changing #1083 Rebuild/pfb_dnsbl_hold_stale_rebuild_skip/'
			. 'pfb_dnsbl_stale_rebuild_converge_txt behaviour that nobody asked for');

		// issue #1278: the same asymmetry applies to the NEW script-reparse term -- this
		// re-call must stay ungated by it too, same reasoning as $pfb_dnsbl_user_script above.
		$this->assertStringNotContainsString('$pfb_dnsbl_script_reparse', $statement,
			'issue #1960/#1278: the #1083 stale-generation rebuild re-call must stay ungated by the '
			. 'new script-reparse term too -- same asymmetry reasoning as $pfb_dnsbl_user_script above');
	}

	// -----------------------------------------------------------------
	// Row 13 -- lock-step: exactly TWO pfb_list_user_script_active( call
	// sites in the file, one per loop.
	// -----------------------------------------------------------------

	public function testExactlyTwoLockStepCallSites(): void
	{
		// '($pfb_' (vs. the definition's '($script_pre') distinguishes an
		// invocation -- both call sites pass a $pfb_*-prefixed variable pair.
		$count = substr_count(self::$applySource, 'pfb_list_user_script_active($pfb_');
		$this->assertSame(2, $count,
			'a term added to one loop only is the exact defect issue #1960 forbids -- both the IP '
			. 'and DNSBL loops must call the shared helper exactly once each');

		// N4: a global count of 2 passes even if BOTH call sites sat inside the SAME loop --
		// prove they straddle the two loops instead. The IP loop's own list-collection
		// comment sits strictly AFTER the whole DNSBL alias loop and BEFORE the IP loop's
		// per-row body, so it is a token that only occurs between the two loops.
		$firstCallPos = strpos(self::$applySource, 'pfb_list_user_script_active($pfb_');
		$this->assertNotFalse($firstCallPos, 'vacuity: the first call site must exist');
		$secondCallPos = strpos(self::$applySource, 'pfb_list_user_script_active($pfb_', $firstCallPos + 1);
		$this->assertNotFalse($secondCallPos, 'vacuity: the second call site must exist');

		$boundaryPos = strpos(self::$applySource,
			'// Collect lists and custom list configuration and format into one array ($lists).');
		$this->assertNotFalse($boundaryPos, "vacuity: the IP loop's list-collection boundary comment must exist");

		$this->assertLessThan($boundaryPos, $firstCallPos,
			'the first pfb_list_user_script_active( call site must sit in the DNSBL loop, before the '
			. "IP loop's boundary comment");
		$this->assertGreaterThan($boundaryPos, $secondCallPos,
			'the second pfb_list_user_script_active( call site must sit in the IP loop, after the '
			. 'DNSBL loop -- a regression that moved both calls into ONE loop must fail here even '
			. 'though the global count above stays 2');
	}

	// -----------------------------------------------------------------
	// Row 14 -- both loops still pass the user-script term to their
	// norm-reuse-skip calls. DNSBL side is already covered by
	// DnsblListScriptWiringTest::testReuseSkipCallSitePassesTheUserScriptFlag
	// (run and cited, not duplicated here).
	// -----------------------------------------------------------------

	public function testIpNormReuseSkipCallSitePassesTheUserScriptFlag(): void
	{
		$reuseSkipPos = strpos(self::$applySource, 'pfb_ip_norm_reuse_skip(');
		$this->assertNotFalse($reuseSkipPos, 'vacuity: the IP normalize/reuse-skip call site must exist');

		$callEnd = strpos(self::$applySource, 'unchanged after normalization.', $reuseSkipPos);
		$this->assertNotFalse($callEnd, 'vacuity: the reuse-skip branch body must exist');

		$call = substr(self::$applySource, $reuseSkipPos, $callEnd - $reuseSkipPos);
		$this->assertStringContainsString('$pfb_user_script', $call,
			'a configured pre/post script must force a full reparse every pass -- same contract as '
			. "the DNSBL loop's pfb_dnsbl_norm_reuse_skip() call "
			. '(DnsblListScriptWiringTest::testReuseSkipCallSitePassesTheUserScriptFlag)');
	}
}
