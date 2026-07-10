<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #1083 P4 -- the DNSBL staging-generation guard. A field box upgrading with a
 * pre-NDJSON staging '.txt' on a never-redownloaded feed (group frequency 'Never',
 * row state 'Hold') must not verbatim-reuse it forever: pfb_unbound_python_sources()
 * silently skips every pre-#1083 line, blanking the feed. These three PURE helpers
 * (pfblockerng.inc, beside pfb_ip_reuse_skip_active()) are brand-new code (#1083
 * P4) -- no red run against pre-P4 code is possible (the symbols do not exist
 * there; an existence probe would be coverage theater per CLAUDE.md's carve-out).
 * Their own tests below are the coverage this new code ships with.
 */
#[CoversFunction('pfb_dnsbl_staging_is_current_generation')]
#[CoversFunction('pfb_dnsbl_staging_first_line')]
#[CoversFunction('pfb_dnsbl_verbatim_reuse_active')]
final class DnsblStagingGenerationGuardTest extends TestCase
{
	// --- pfb_dnsbl_staging_is_current_generation() ---------------------------------

	public function testEmptyFirstLineIsCurrentGeneration(): void
	{
		$this->assertTrue(pfb_dnsbl_staging_is_current_generation(''));
	}

	public function testNdjsonFirstLineIsCurrentGeneration(): void
	{
		$this->assertTrue(pfb_dnsbl_staging_is_current_generation(
			'{"kind":"domain","domain":"x.example.com","log":"1","feed":"F","group":"G"}'));
	}

	public function testOldCsvCommaLedLineIsStale(): void
	{
		$this->assertFalse(pfb_dnsbl_staging_is_current_generation(',x.example.com,,1,F,ALIAS'));
	}

	/** Old-dialect verbatim-captured ABP lines: every ADR-62-era capture shape. */
	public function testOldAbpVerbatimShapesAreStale(): void
	{
		foreach (['||ads.example^', '@@||good.example^', '/re/', '##.ad-banner'] as $line) {
			$this->assertFalse(pfb_dnsbl_staging_is_current_generation($line), "expected stale for [ {$line} ]");
		}
	}

	public function testOldBareDomainLineIsStale(): void
	{
		// A pre-#1083 6-col CSV's bare-domain reduction would never itself be the
		// FIRST byte of a row (the row always led with a comma) -- but a corrupt or
		// truly ancient staging file could; the byte check must still call it stale.
		$this->assertFalse(pfb_dnsbl_staging_is_current_generation('0'));
		$this->assertFalse(pfb_dnsbl_staging_is_current_generation('#not-json'));
	}

	// --- pfb_dnsbl_staging_first_line() ---------------------------------------------

	public function testFirstLineOfAbsentFileIsEmpty(): void
	{
		$this->assertSame('', pfb_dnsbl_staging_first_line('/no/such/path/xyz.txt'));
	}

	public function testFirstLineOfEmptyFileIsEmpty(): void
	{
		$path = sys_get_temp_dir() . '/pfb_staging_' . uniqid('', true) . '.txt';
		file_put_contents($path, '');
		try {
			$this->assertSame('', pfb_dnsbl_staging_first_line($path));
		} finally {
			unlink($path);
		}
	}

	public function testFirstLineStripsTrailingNewlineAndIgnoresLaterLines(): void
	{
		$path = sys_get_temp_dir() . '/pfb_staging_' . uniqid('', true) . '.txt';
		file_put_contents($path, "{\"kind\":\"domain\"}\r\n||second-line-ignored^\n");
		try {
			$this->assertSame('{"kind":"domain"}', pfb_dnsbl_staging_first_line($path));
		} finally {
			unlink($path);
		}
	}

	// --- review: a blank leading line / an unparseable '{' prefix must not slip
	// --- through as current-generation (issue #1083 review) -------------------------

	public function testBlankFirstLineThenStaleCsvIsNotCurrentGeneration(): void
	{
		$path = sys_get_temp_dir() . '/pfb_staging_' . uniqid('', true) . '.txt';
		file_put_contents($path, "\n,x.example.com,,1,F,ALIAS\n");
		try {
			$firstLine = pfb_dnsbl_staging_first_line($path);
			$this->assertFalse(
				pfb_dnsbl_staging_is_current_generation($firstLine),
				'a blank leading line hiding stale CSV content must not read as current-generation'
			);
		} finally {
			unlink($path);
		}
	}

	public function testGarbageBracePrefixIsNotCurrentGeneration(): void
	{
		$path = sys_get_temp_dir() . '/pfb_staging_' . uniqid('', true) . '.txt';
		file_put_contents($path, "{garbage\n");
		try {
			$firstLine = pfb_dnsbl_staging_first_line($path);
			$this->assertFalse(
				pfb_dnsbl_staging_is_current_generation($firstLine),
				'a byte-check-only leading "{" must not pass as current-generation without actually parsing'
			);
		} finally {
			unlink($path);
		}
	}

	// --- pfb_dnsbl_verbatim_reuse_active() -- the fork condition --------------------

	public function testAllConditionsPassingAndCurrentGenerationReusesVerbatim(): void
	{
		$this->assertTrue(pfb_dnsbl_verbatim_reuse_active(TRUE, FALSE, FALSE, TRUE, TRUE));
	}

	public function testStaleGenerationAloneVetoesReuse(): void
	{
		// Every OTHER condition passes; only the generation term flips -- isolates
		// the #1083 P4 addition from the four pre-existing gate conditions.
		$this->assertFalse(pfb_dnsbl_verbatim_reuse_active(TRUE, FALSE, FALSE, TRUE, FALSE));
	}

	public function testTxtAbsentVetoesReuseRegardlessOfGeneration(): void
	{
		$this->assertFalse(pfb_dnsbl_verbatim_reuse_active(FALSE, FALSE, FALSE, TRUE, TRUE));
	}

	public function testUpdateMarkerVetoesReuseRegardlessOfGeneration(): void
	{
		$this->assertFalse(pfb_dnsbl_verbatim_reuse_active(TRUE, TRUE, FALSE, TRUE, TRUE));
	}

	public function testFailMarkerVetoesReuseRegardlessOfGeneration(): void
	{
		$this->assertFalse(pfb_dnsbl_verbatim_reuse_active(TRUE, FALSE, TRUE, TRUE, TRUE));
	}

	public function testReuseConfiguredOnVetoesTheVerbatimForkRegardlessOfGeneration(): void
	{
		// $pfbreuse=='on' (reuse_unset=FALSE) already takes the OTHER branch today
		// (Reload/Download) -- current-generation staging changes nothing here.
		$this->assertFalse(pfb_dnsbl_verbatim_reuse_active(TRUE, FALSE, FALSE, FALSE, TRUE));
	}

	// --- #1105 defect, real production reader ---------------------------------------

	/**
	 * issue #1105's exact defect, reproduced with the REAL production reader
	 * (pfb_unbound_python_sources(), landed #1083 P1-3): an old-dialect staging
	 * '.txt' mixing a stale verbatim-ABP line and a stale 6-col-CSV bare-domain
	 * line -- if verbatim-reused as-is, EVERY line fails NDJSON parse and the
	 * manifest raw comes out EMPTY (the domain silently vanishes). The guard's
	 * decision (pfb_dnsbl_verbatim_reuse_active(), THIS phase) correctly identifies
	 * this exact staging file as reuse-ineligible, vetoing the path that drops it.
	 * The sync loop's actual reparse-from-.orig machinery has no off-appliance
	 * driver (sync_package_pfblockerng() needs live pfb_download()/full config
	 * state -- same limitation DnsblAliasUpdateChangedTest.php documents for this
	 * loop); that half is a P5 live-VM smoke row.
	 */
	public function testOldDialectStagingWouldSilentlyBlankViaVerbatimReuseButGuardVetoesIt(): void
	{
		$tmp = sys_get_temp_dir() . '/pfb_1105_' . uniqid('', false);
		mkdir("{$tmp}/dnsbl", 0777, true);
		$header = 'stalefeed';
		$path = "{$tmp}/dnsbl/{$header}.txt";
		file_put_contents($path,
			"||ads.example^\n" .
			",uuid-bare.example.com,,1,F,ALIAS\n");

		global $pfb;
		$saved = $pfb ?? [];
		$pfb = array_merge($saved, [
			'log'                => "{$tmp}/pfblockerng.log",
			'errlog'             => "{$tmp}/error.log",
			'unbound_py_rawdir'  => "{$tmp}/pfb_py_raw",
			'dnsdir'             => "{$tmp}/dnsbl",
			'unbound_py_sources' => "{$tmp}/pfb_py_sources.json",
			'dbdir'              => "{$tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_tld_data'     => "{$tmp}/does_not_exist",
			'dnsbl_unlock'       => "{$tmp}/dnsbl_unlock",
			'dnsblconfig'        => ['tldblacklist' => '', 'tldexclusion' => '', 'suppression' => ''],
		]);
		try {
			// Given: the fork VERBATIM-REUSED this stale file (today's pre-guard
			// behaviour) -- pfb_unbound_python_sources() reads it as-is.
			pfb_unbound_python_sources([
				['header' => $header, 'group' => 'G', 'log' => '1', 'provenance' => 'feed'],
			]);
			$raw = @file_get_contents("{$tmp}/pfb_py_raw/{$header}.raw");
			$this->assertSame('', $raw, 'old-dialect verbatim reuse silently blanks the feed (#1105)');

			// Then: the guard's decision for this exact file vetoes that reuse.
			$firstLine = pfb_dnsbl_staging_first_line($path);
			$currentGen = pfb_dnsbl_staging_is_current_generation($firstLine);
			$this->assertFalse($currentGen, 'stale-dialect first line must not read as current-generation');
			$this->assertFalse(
				pfb_dnsbl_verbatim_reuse_active(TRUE, FALSE, FALSE, TRUE, $currentGen),
				'the fork must not verbatim-reuse this stale-dialect file'
			);
		} finally {
			$pfb = $saved;
			rmdir_recursive($tmp);
		}
	}

	// --- review: stale-generation rebuild non-convergence ---------------------------

	/**
	 * issue #1083 review: a stale-generation REBUILD (the 'Rebuild' log branch) that
	 * reparses '.orig' and finds ZERO parseable domains (e.g. an HTML error page) must
	 * still converge staging to empty/current-generation -- else the pre-NDJSON '.txt'
	 * survives untouched (the sync loop's 'No Domains Found!' branch only unlinks
	 * '.bk', never the pre-existing stale '.txt'), its stale lines get silently
	 * double-counted into $alias_cnt, and the guard re-detects stale-generation on
	 * every subsequent pass, re-logging 'Rebuild' forever.
	 *
	 * sync_package_pfblockerng() has no PHPUnit harness (issue #993 -- confirmed by
	 * DnsblAliasUpdateChangedTest.php/PfbSyncStatusIpWritersTest.php and, in-session,
	 * by reading its boot-time config/syslog/VIP dependencies): this drives the REAL
	 * guard functions (pfb_dnsbl_staging_first_line/_is_current_generation/
	 * _verbatim_reuse_active) plus pfb_dnsbl_stale_rebuild_converge_txt() (the fix)
	 * through the exact two-pass decision sequence the loop performs, extending
	 * testOldDialectStagingWouldSilentlyBlankViaVerbatimReuseButGuardVetoesIt()'s
	 * technique.
	 */
	public function testStaleGenerationRebuildFindingZeroDomainsConverges(): void
	{
		$path = sys_get_temp_dir() . '/pfb_1083_item3_' . uniqid('', true) . '.txt';
		file_put_contents($path,
			"||ads.example^\n" .
			",uuid-bare.example.com,,1,F,ALIAS\n");
		try {
			// Pass 1: reproduce the loop's actual decision inputs for this file.
			$firstLine = pfb_dnsbl_staging_first_line($path);
			$stagingCurrent = pfb_dnsbl_staging_is_current_generation($firstLine);
			$this->assertFalse($stagingCurrent, 'precondition: staging is stale-generation');
			$staleGenerationRebuild = !$stagingCurrent &&
				pfb_dnsbl_verbatim_reuse_active(TRUE, FALSE, FALSE, TRUE, TRUE);
			$this->assertTrue($staleGenerationRebuild, 'precondition: this pass takes the stale-generation-rebuild fork');

			// The '.orig' reparse found zero parseable domains this pass -- the fix under test.
			pfb_dnsbl_stale_rebuild_converge_txt($staleGenerationRebuild, $path);
			// The loop's existing shared placeholder step (unconditional; untouched by this fix).
			if (!file_exists($path)) {
				touch($path);
			}

			$this->assertSame('', file_get_contents($path), 'staging must converge to empty, not retain stale bytes');

			// Pass 2: the guard must read this as current-generation and take the reuse
			// fork -- never re-detect stale-generation / re-log 'Rebuild' again.
			$firstLine2 = pfb_dnsbl_staging_first_line($path);
			$stagingCurrent2 = pfb_dnsbl_staging_is_current_generation($firstLine2);
			$this->assertTrue($stagingCurrent2, 'pass 2 must read the converged file as current-generation');
			$staleGenerationRebuild2 = !$stagingCurrent2 &&
				pfb_dnsbl_verbatim_reuse_active(TRUE, FALSE, FALSE, TRUE, $stagingCurrent2);
			$this->assertFalse($staleGenerationRebuild2, 'pass 2 must NOT re-trigger Rebuild -- convergence achieved');
		} finally {
			unlink_if_exists($path);
		}
	}

	public function testConvergeTxtLeavesNonStaleRebuildUntouched(): void
	{
		// A non-stale-generation zero-domain result (the pre-existing fail-safe: keep
		// the previous good '.txt') must be unaffected by this fix.
		$path = sys_get_temp_dir() . '/pfb_1083_item3_' . uniqid('', true) . '.txt';
		file_put_contents($path, "{\"kind\":\"domain\",\"domain\":\"kept.example\",\"log\":\"1\",\"feed\":\"F\",\"group\":\"G\"}\n");
		try {
			pfb_dnsbl_stale_rebuild_converge_txt(FALSE, $path);
			$this->assertStringContainsString('kept.example', file_get_contents($path));
		} finally {
			unlink_if_exists($path);
		}
	}
}
