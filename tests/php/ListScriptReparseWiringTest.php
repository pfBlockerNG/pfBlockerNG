<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1960/#1278 -- #1960 gated both loops' early verbatim-reuse fast
 * paths on the bare has_user_script term (!$pfb_dnsbl_user_script /
 * !$pfb_user_script). That makes a Hold-state row with a configured
 * pre/post script leave the fast path UNCONDITIONALLY and fall through to a
 * real network download every pass, breaking issue #1278's "download once,
 * never again" Hold contract (the fast path is the ONLY thing protecting
 * it -- see PfbListScriptReparseActiveTest's docblock).
 *
 * The fix routes a scripted row off the fast path ONLY when a local '.orig'
 * baseline exists to reparse (pfb_list_script_reparse_active()), sending it
 * to the existing local-reuse branch instead of the network. The IP and
 * DNSBL loops inside sync_package_pfblockerng() drive real appliance exec
 * and have no PHPUnit harness of their own (issue #993), so -- same
 * technique as DnsblListScriptWiringTest / ListScriptTransformRerunWiringTest
 * -- the wiring is pinned by source inspection with vacuity-guarded windows.
 */
final class ListScriptReparseWiringTest extends TestCase
{
	private static string $applySource;

	// The IP loop's own list-collection comment sits strictly AFTER the whole
	// DNSBL alias loop and BEFORE the IP loop's per-row body -- a token that
	// only occurs between the two loops, used to prove a pair of call sites
	// straddles them (one per loop) rather than both landing in one loop.
	private const LOOP_BOUNDARY_COMMENT =
		'// Collect lists and custom list configuration and format into one array ($lists).';

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
	// Row 6 -- DNSBL fast path gated by !$pfb_dnsbl_script_reparse, not by
	// the bare user-script term. Anchored on the gated statement HEAD (not a
	// bare token) so a comment merely mentioning the token cannot satisfy it.
	// -----------------------------------------------------------------

	public function testDnsblFastPathGatedByScriptReparseNotBareUserScriptTerm(): void
	{
		$this->assertStringContainsString(
			'if ($pfb_dnsbl_verbatim_reuse && !$pfb_dnsbl_script_reparse) {',
			self::$applySource,
			'issue #1960/#1278: the DNSBL fast path must be gated by the script-reparse term (which '
			. 'requires a local .orig baseline), not by the bare has_user_script term -- the bare term '
			. 'forces a Hold row with no baseline through to a network download every pass'
		);

		$this->assertStringNotContainsString(
			'if (!$pfb_dnsbl_user_script && pfb_dnsbl_verbatim_reuse_active(',
			self::$applySource,
			'the old bare-user-script gate must be gone -- its presence is the exact #1278 regression '
			. 'this fix closes'
		);

		// The gate must sit on the fast path that logs "exists."/"static hold.", not on
		// some other statement.
		$gatePos = strpos(self::$applySource, 'if ($pfb_dnsbl_verbatim_reuse && !$pfb_dnsbl_script_reparse) {');
		$this->assertNotFalse($gatePos, 'vacuity: the gated DNSBL fast-path statement must exist');
		$existsPos = strpos(self::$applySource, '{$logtab} exists.', $gatePos);
		$this->assertNotFalse($existsPos,
			'the gated statement must be the DNSBL verbatim-reuse fast path -- its branch logs "exists."');
	}

	// -----------------------------------------------------------------
	// Row 7 -- IP fast path likewise gated by !$pfb_script_reparse.
	// -----------------------------------------------------------------

	public function testIpFastPathGatedByScriptReparseNotBareUserScriptTerm(): void
	{
		$this->assertStringContainsString(
			'if ($pfb_ip_verbatim_reuse && !$pfb_script_reparse) {',
			self::$applySource,
			'issue #1960/#1278: the IP fast path must be gated by the script-reparse term (which '
			. 'requires a local .orig baseline), not by the bare has_user_script term -- the bare term '
			. 'forces a Hold row with no baseline through to a network download every pass'
		);

		$this->assertStringNotContainsString(
			'if (!$pfb_user_script &&',
			self::$applySource,
			'the old bare-user-script gate must be gone -- its presence is the exact #1278 regression '
			. 'this fix closes'
		);

		$gatePos = strpos(self::$applySource, 'if ($pfb_ip_verbatim_reuse && !$pfb_script_reparse) {');
		$this->assertNotFalse($gatePos, 'vacuity: the gated IP fast-path statement must exist');
		$existsPos = strpos(self::$applySource, '{$logtab} exists.', $gatePos);
		$this->assertNotFalse($existsPos,
			'the gated statement must be the IP verbatim-reuse fast path -- its branch logs "exists."');
	}

	// -----------------------------------------------------------------
	// Row 8 -- DNSBL $pfbreuse_effective carries the script-reparse term, so
	// a scripted row with a local baseline routes to local reuse, not the
	// network.
	// -----------------------------------------------------------------

	public function testDnsblPfbreuseEffectiveCarriesScriptReparseTerm(): void
	{
		$stmtPos = strpos(self::$applySource, '$pfbreuse_effective = ');
		$this->assertNotFalse($stmtPos, 'vacuity: the $pfbreuse_effective assignment must exist');

		$stmtEnd = strpos(self::$applySource, ';', $stmtPos);
		$this->assertNotFalse($stmtEnd, 'vacuity: the assignment statement must terminate');
		$statement = substr(self::$applySource, $stmtPos, $stmtEnd - $stmtPos);

		$this->assertStringContainsString('$pfb_dnsbl_script_reparse', $statement,
			'issue #1278: $pfbreuse_effective must OR in the script-reparse route so a scripted row '
			. 'with a local .orig baseline reuses it locally (Reload) instead of falling through to a '
			. 'network download');
	}

	// -----------------------------------------------------------------
	// Row 9 -- IP reuse decision carries the script-reparse term at BOTH
	// pfb_ip_reuse_skip_active( call sites (counted from source first), and
	// nothing reassigns the carrying variable between them -- a mismatch
	// there would log "Reload" then download anyway, or vice versa.
	// -----------------------------------------------------------------

	public function testIpReuseSkipActiveBothCallSitesCarryScriptReparseTerm(): void
	{
		$callCount = substr_count(self::$applySource, 'pfb_ip_reuse_skip_active(');
		$this->assertSame(2, $callCount,
			'vacuity: the IP loop must have exactly the two known pfb_ip_reuse_skip_active( call '
			. 'sites (the log-line decision + the actual reuse-vs-download fork) -- a third call site '
			. 'changes the shape this test pins, and this brief forbids weakening the !$is_dnsblip term '
			. 'at any of them (#1002/#1020)');

		$assignPos = strpos(self::$applySource, "\$pfbreuse_on = \$pfbreuse == 'on'");
		$this->assertNotFalse($assignPos, 'vacuity: the $pfbreuse_on assignment must exist');

		$assignEnd = strpos(self::$applySource, ';', $assignPos);
		$this->assertNotFalse($assignEnd, 'vacuity: the assignment statement must terminate');
		$assignStatement = substr(self::$applySource, $assignPos, $assignEnd - $assignPos);
		$this->assertStringContainsString('$pfb_script_reparse', $assignStatement,
			'issue #1278: $pfbreuse_on must OR in the script-reparse route so a scripted row with a '
			. 'local .orig baseline reuses it locally instead of falling through to a network download');

		$firstCallPos = strpos(self::$applySource, 'pfb_ip_reuse_skip_active(', $assignPos);
		$this->assertNotFalse($firstCallPos, 'vacuity: the first call site (after the assignment) must exist');
		$secondCallPos = strpos(self::$applySource, 'pfb_ip_reuse_skip_active(', $firstCallPos + 1);
		$this->assertNotFalse($secondCallPos, 'vacuity: the second call site must exist');

		$firstCallHead = substr(self::$applySource, $firstCallPos, strlen('pfb_ip_reuse_skip_active($pfbreuse_on,'));
		$this->assertSame('pfb_ip_reuse_skip_active($pfbreuse_on,', $firstCallHead,
			'the first pfb_ip_reuse_skip_active( call must feed $pfbreuse_on (the variable carrying '
			. 'the OR\'d script-reparse term) as its reuse_on argument');

		$secondCallHead = substr(self::$applySource, $secondCallPos, strlen('pfb_ip_reuse_skip_active($pfbreuse_on,'));
		$this->assertSame('pfb_ip_reuse_skip_active($pfbreuse_on,', $secondCallHead,
			'the second pfb_ip_reuse_skip_active( call must feed the SAME $pfbreuse_on -- a mismatch '
			. 'here would log "Reload" then download anyway, or vice versa');

		$between = substr(self::$applySource, $firstCallPos, $secondCallPos - $firstCallPos);
		$this->assertStringNotContainsString('$pfbreuse_on = ', $between,
			'no reassignment of $pfbreuse_on may sit between the two call sites -- that would silently '
			. 'drop the script-reparse term for the second call, producing the exact log-vs-action '
			. 'mismatch this row guards against');
	}

	// -----------------------------------------------------------------
	// Row 12 -- pfb_list_script_reparse_active( is called exactly twice,
	// once per loop -- lock-step by construction.
	// -----------------------------------------------------------------

	public function testScriptReparseActiveCalledExactlyTwiceOncePerLoop(): void
	{
		// '($pfb_' (vs. the definition's '(bool $verbatim_reuse_ok') distinguishes an
		// invocation -- both call sites pass a $pfb_*-prefixed verbatim-reuse variable
		// as the first argument (mirrors testExactlyTwoLockStepCallSites' technique for
		// pfb_list_user_script_active( in ListScriptTransformRerunWiringTest).
		$count = substr_count(self::$applySource, 'pfb_list_script_reparse_active($pfb_');
		$this->assertSame(2, $count,
			'lock-step by construction -- both the DNSBL and IP loops must call the shared '
			. 'pfb_list_script_reparse_active() helper exactly once each');

		$firstPos = strpos(self::$applySource, 'pfb_list_script_reparse_active($pfb_');
		$this->assertNotFalse($firstPos, 'vacuity: the first call site must exist');
		$secondPos = strpos(self::$applySource, 'pfb_list_script_reparse_active($pfb_', $firstPos + 1);
		$this->assertNotFalse($secondPos, 'vacuity: the second call site must exist');

		$boundaryPos = strpos(self::$applySource, self::LOOP_BOUNDARY_COMMENT);
		$this->assertNotFalse($boundaryPos, "vacuity: the IP loop's list-collection boundary comment must exist");

		$this->assertLessThan($boundaryPos, $firstPos,
			'the first pfb_list_script_reparse_active( call site must sit in the DNSBL loop, before '
			. "the IP loop's boundary comment");
		$this->assertGreaterThan($boundaryPos, $secondPos,
			'the second pfb_list_script_reparse_active( call site must sit in the IP loop, after the '
			. 'DNSBL loop');
	}
}
