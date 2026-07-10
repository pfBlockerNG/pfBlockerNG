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
}
