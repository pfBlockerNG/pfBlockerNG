<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1958: a per-feed pre-script that exits non-zero must not let the
 * alias pass close as full success. The IP and DNSBL loops inside
 * sync_package_pfblockerng() drive real appliance exec and have no PHPUnit
 * harness of their own (issue #993), so -- same technique as
 * DnsblListScriptWiringTest / PfbSyncStatusIpWritersTest -- the wiring is
 * pinned by source inspection with vacuity-guarded windows: each window's
 * start/end anchors are asserted present BEFORE the content assertion inside
 * them is trusted.
 *
 * Pins, per loop:
 *   - the pre-script failure branch records the new ADR-61 'script' stage
 *     ledger entry + '.update' retry marker via pfb_list_script_failure_record(),
 *     sets $pfb_script_failed, and STILL falls through to the existing
 *     continue; (DNSBL: the existing #1841-class manifest-row re-emission on a
 *     stale-generation .txt must also survive, untouched).
 *   - the alias-pass end closes the 'script' stage ledger entry, guarded by
 *     !$pfb_script_failed, beside the existing download-ledger close.
 *   - both loops declare their own per-alias-pass $pfb_script_failed reset --
 *     a reset dropped from one loop is the #1048-class bug (a sibling feed's
 *     success masking this feed's still-open failure).
 */
final class ListScriptFailureLedgerWiringTest extends TestCase
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
	// Row 7 -- IP pre-script failure branch.
	// -----------------------------------------------------------------

	public function testIpPreScriptFailureBranchRecordsLedgerAndMarkerBeforeContinue(): void
	{
		$dnsblCallPos = strpos(self::$applySource, 'pfb_list_pre_script_run(');
		$this->assertNotFalse($dnsblCallPos, 'vacuity: the DNSBL pre-script call site must exist (first occurrence)');

		$ipCallPos = strpos(self::$applySource, 'pfb_list_pre_script_run(', $dnsblCallPos + 1);
		$this->assertNotFalse($ipCallPos, 'vacuity: the IP pre-script call site must exist (second occurrence)');

		$ipFopenPos = strpos(self::$applySource, '@fopen($pfb_parse_path', $ipCallPos);
		$this->assertNotFalse($ipFopenPos, 'vacuity: the IP parse-open that follows the IP pre-script call must exist');
		$this->assertGreaterThan($ipCallPos, $ipFopenPos, 'the IP parse-open must sit after the IP pre-script call');

		$window = substr(self::$applySource, $ipCallPos, $ipFopenPos - $ipCallPos);

		$this->assertStringContainsString('" {$list[\'vtype\']} {$elog}"', $window,
			'vacuity: this window must be the IP call (carries the vtype args-tail discriminator, not "dnsbl")');

		$this->assertStringContainsString("pfb_list_script_failure_record('ip', \$alias,", $window,
			'a pre-script failure must record the ADR-61 script-stage ledger entry, keyed on the IP facility');
		$this->assertStringContainsString('$pfb_script_failed = TRUE;', $window,
			'a pre-script failure must raise the per-alias-pass script-failure flag');
		$this->assertStringContainsString('.update"', $window,
			'a pre-script failure must (re)write the .update retry marker so the next ordinary pass retries the transform');
		$this->assertStringContainsString('continue;', $window,
			'the existing continue; (serving last-known-good, #1927) must survive untouched');
	}

	// -----------------------------------------------------------------
	// Row 8 -- DNSBL pre-script failure branch.
	// -----------------------------------------------------------------

	public function testDnsblPreScriptFailureBranchRecordsLedgerAndMarkerKeepingManifestRow(): void
	{
		$dnsblCallPos = strpos(self::$applySource, 'pfb_list_pre_script_run(');
		$this->assertNotFalse($dnsblCallPos, 'vacuity: the DNSBL pre-script call site must exist (first occurrence)');

		$dnsblFopenPos = strpos(self::$applySource, '@fopen($pfb_parse_path', $dnsblCallPos);
		$this->assertNotFalse($dnsblFopenPos, 'vacuity: the DNSBL parse-open that follows the DNSBL pre-script call must exist');
		$this->assertGreaterThan($dnsblCallPos, $dnsblFopenPos, 'the DNSBL parse-open must sit after the DNSBL pre-script call');

		$window = substr(self::$applySource, $dnsblCallPos, $dnsblFopenPos - $dnsblCallPos);

		$this->assertStringContainsString('" dnsbl {$elog}"', $window,
			'vacuity: this window must be the DNSBL call (carries the stable "dnsbl" args-tail discriminator)');

		$this->assertStringContainsString("pfb_list_script_failure_record('dnsbl', \$alias,", $window,
			'a pre-script failure must record the ADR-61 script-stage ledger entry, keyed on the DNSBL facility');
		$this->assertStringContainsString('$pfb_script_failed = TRUE;', $window,
			'a pre-script failure must raise the per-alias-pass script-failure flag');
		$this->assertStringContainsString('.update"', $window,
			'a pre-script failure must (re)write the .update retry marker so the next ordinary pass retries the transform');
		$this->assertStringContainsString('pfb_feed_manifest_row(', $window,
			'the existing manifest-row re-emission on a stale-generation .txt must survive -- '
			. 'dropping it would relocate the outage (#1841-class), not fix it');
		$this->assertStringContainsString('continue;', $window,
			'the existing continue; (serving last-known-good, #1927) must survive untouched');
	}

	// -----------------------------------------------------------------
	// Row 9 -- IP alias-pass close, guarded by !$pfb_script_failed.
	// -----------------------------------------------------------------

	public function testIpAliasPassClosesScriptStageGuardedByScriptFailedFlag(): void
	{
		$closePos = strpos(self::$applySource, "pfb_ip_download_ledger_update(TRUE,");
		$this->assertNotFalse($closePos, 'vacuity: the IP download-ledger success-close call site must exist');

		$endPos = strpos(self::$applySource, 'Remove database update file markers', $closePos);
		$this->assertNotFalse($endPos, 'vacuity: the end-of-loop epilogue marker must exist after the IP close');

		$window = substr(self::$applySource, $closePos, $endPos - $closePos);

		$this->assertStringContainsString("pfb_sync_status_close('ip', \$alias, 'script'", $window,
			'the alias-pass end must close the ADR-61 script-stage entry for this alias');
		$this->assertStringContainsString('!$pfb_script_failed', $window,
			'the script-stage close must be gated by the once-per-alias-pass flag, symmetric with the download-ledger close');
	}

	// -----------------------------------------------------------------
	// Row 10 -- DNSBL alias-pass close, guarded by !$pfb_script_failed.
	// -----------------------------------------------------------------

	public function testDnsblAliasPassClosesScriptStageGuardedByScriptFailedFlag(): void
	{
		$closePos = strpos(self::$applySource, "pfb_dnsbl_download_ledger_update(TRUE,");
		$this->assertNotFalse($closePos, 'vacuity: the DNSBL download-ledger success-close call site must exist');

		$endPos = strpos(self::$applySource, 'ADR-12: record GENUINELY-changed DNSBL groups', $closePos);
		$this->assertNotFalse($endPos, 'vacuity: the ADR-12 change-tracking comment must exist after the DNSBL close');

		$window = substr(self::$applySource, $closePos, $endPos - $closePos);

		$this->assertStringContainsString("pfb_sync_status_close('dnsbl', \$alias, 'script'", $window,
			'the alias-pass end must close the ADR-61 script-stage entry for this alias');
		$this->assertStringContainsString('!$pfb_script_failed', $window,
			'the script-stage close must be gated by the once-per-alias-pass flag, symmetric with the download-ledger close');
	}

	// -----------------------------------------------------------------
	// Row 11 -- both per-alias resets exist, one per loop.
	// -----------------------------------------------------------------

	public function testBothLoopsDeclareTheirOwnPerAliasScriptFailedReset(): void
	{
		$count = preg_match_all('/\$pfb_script_failed\s*=\s*FALSE;/', self::$applySource);
		$this->assertNotFalse($count, 'the reset regex itself must be well-formed');
		$this->assertSame(2, $count,
			'exactly one $pfb_script_failed = FALSE; reset per loop (IP + DNSBL) must exist -- '
			. 'a reset dropped from one loop is the #1048-class bug (a sibling feed\'s success '
			. 'masking this feed\'s still-open failure)'
		);
	}
}
