<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_csv_extract() -- issue #1118 extraction of the DNSBL download/parse
 * loop's 6-type upstream-CSV classify/extract switch (`if ($csv_parser) { ... }`)
 * into a pure, unit-testable helper, mirroring pfb_dnsbl_extract_host()'s
 * sentinel-action return contract. Pins every case's column-count guard + the
 * extracted column, the h3x/otx skip-without-fail sites, the pon IP side-effect
 * (via pfb_dnsbl_collect_feed_ip), the 5 header-autodetect sub-branches, and the
 * no-match reset that re-arms the caller's autodetect from scratch.
 */
#[CoversFunction('pfb_dnsbl_csv_extract')]
final class PfbDnsblCsvExtractTest extends TestCase
{
	private string $parseErr = '';
	private array $alienvaultTypes;

	protected function setUp(): void
	{
		$this->parseErr = tempnam(sys_get_temp_dir(), 'pfbcsvextract');
		@unlink($this->parseErr);
		$this->alienvaultTypes = array_flip(['domain', 'hostname', 'URL']);

		// pon's IP collection routes through pfb_dnsbl_collect_feed_ip() ->
		// sanitize_ipaddr(), which reads $pfb['supp'] -- suppression OFF matches
		// Adr62DnsblCollectFeedIpTest's setUp.
		$GLOBALS['pfb']['supp'] = PfbToggle::Off;
	}

	protected function tearDown(): void
	{
		if ($this->parseErr !== '' && is_file($this->parseErr)) {
			unlink($this->parseErr);
		}
	}

	private function extract(string $line, array $csvline, string $csvType, bool $csvParser,
		bool $runOnce = TRUE, bool $dnsblIpEnabled = TRUE): array
	{
		$ip4 = [];
		$ip6 = [];
		return pfb_dnsbl_csv_extract($line, $csvline, $csvType, $csvParser, $runOnce,
			$this->alienvaultTypes, $dnsblIpEnabled, FALSE, $ip4, $ip6, 'hdr', $line, 5, $this->parseErr);
	}

	// -- $csv_parser === FALSE: pure passthrough (mirrors "first line has <2 commas") --

	public function testCsvParserFalseIsPureNoOp(): void
	{
		// Block A (the caller, untouched by this extraction) never flipped
		// csv_parser TRUE -- the helper must do nothing at all.
		$r = $this->extract('unrelated line', ['unrelated', 'line'], 'pt', FALSE, TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('unrelated line', $r['line']);
		$this->assertSame('pt', $r['csv_type'], 'csv_type must pass through unchanged');
		$this->assertFalse($r['csv_parser']);
		$this->assertTrue($r['run_once']);
		$this->assertFalse($r['ip_collected']);
		$this->assertFileDoesNotExist($this->parseErr, 'a passthrough must never touch the parse-error log');
	}

	// -- pt (Phishtank): 8 columns, col-1, space-stripped -----------------------------

	public function testPtWithEightColumnsAndSpaceInColumnOneStripsSpaces(): void
	{
		$csvline = ['1', 'http://evil example.com', 'detail', '', '', '', '', ''];
		$r = $this->extract('raw', $csvline, 'pt', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('http://evilexample.com', $r['line']);
	}

	public function testPtWithEightColumnsAndNoSpaceInColumnOneUsesAsIs(): void
	{
		$csvline = ['1', 'http://evil.example.com', 'detail', '', '', '', '', ''];
		$r = $this->extract('raw', $csvline, 'pt', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('http://evil.example.com', $r['line']);
	}

	public function testPtWithWrongColumnCountFails(): void
	{
		$csvline = ['1', 'http://x']; // 2 cols, not 8
		$r = $this->extract('raw-pt', $csvline, 'pt', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertStringContainsString('raw-pt', (string) file_get_contents($this->parseErr));
	}

	// -- bbc (Bambenek): 4 columns, col-0 ----------------------------------------------

	public function testBbcWithFourColumnsExtractsColumnZero(): void
	{
		$csvline = ['bbc-malicious.example.com', 'x', 'y', 'z'];
		$r = $this->extract('raw', $csvline, 'bbc', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('bbc-malicious.example.com', $r['line']);
	}

	public function testBbcWithWrongColumnCountFails(): void
	{
		$csvline = ['bbc-malicious.example.com', 'x']; // 2 cols, not 4
		$r = $this->extract('raw-bbc', $csvline, 'bbc', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertStringContainsString('raw-bbc', (string) file_get_contents($this->parseErr));
	}

	// Hostile input: a quoted CSV field with an embedded comma is ONE column after
	// str_getcsv() (the CALLER's job) -- the helper must read it verbatim, never
	// re-split it.
	public function testBbcColumnWithEmbeddedCommaFromQuotedFieldSurvivesIntact(): void
	{
		$csvline = str_getcsv('"sub,domain.example.com",x,y,z', ',', '"', '"');
		$this->assertCount(4, $csvline, 'sanity: str_getcsv must merge the quoted comma into ONE field');
		$r = $this->extract('raw', $csvline, 'bbc', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('sub,domain.example.com', $r['line']);
	}

	// -- h3x (hostsfile): 8 columns, col-2, btc:// skip --------------------------------

	public function testH3xWithEightColumnsExtractsColumnTwo(): void
	{
		$csvline = ['a', 'b', 'normal.example.com', 'd', 'e', 'f', 'g', 'h'];
		$r = $this->extract('raw', $csvline, 'h3x', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('normal.example.com', $r['line']);
	}

	public function testH3xBtcSchemeInColumnTwoSkipsWithoutFailRecord(): void
	{
		$csvline = ['a', 'b', 'btc://1abcDEF', 'd', 'e', 'f', 'g', 'h'];
		$r = $this->extract('raw', $csvline, 'h3x', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertFileDoesNotExist($this->parseErr, 'a btc:// skip must NOT record a parse-error');
	}

	public function testH3xWithWrongColumnCountFails(): void
	{
		$csvline = ['a', 'b', 'c']; // 3 cols, not 8
		$r = $this->extract('raw-h3x', $csvline, 'h3x', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertStringContainsString('raw-h3x', (string) file_get_contents($this->parseErr));
	}

	// -- otx (AlienVault OTX): 3 columns, col-1 gated by a known indicator type -------

	public function testOtxWithKnownIndicatorTypeExtractsColumnOne(): void
	{
		$csvline = ['domain', 'malicious.example.com', 'desc'];
		$r = $this->extract('raw', $csvline, 'otx', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('malicious.example.com', $r['line']);
	}

	public function testOtxWithUnknownIndicatorTypeSkipsWithoutFailRecord(): void
	{
		$csvline = ['FileHash-MD5', 'deadbeef', 'desc'];
		$r = $this->extract('raw', $csvline, 'otx', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertFileDoesNotExist($this->parseErr, 'an unknown indicator type must NOT record a parse-error');
	}

	public function testOtxWithWrongColumnCountFails(): void
	{
		$csvline = ['domain', 'malicious.example.com']; // 2 cols, not 3
		$r = $this->extract('raw-otx', $csvline, 'otx', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertStringContainsString('raw-otx', (string) file_get_contents($this->parseErr));
	}

	// -- pon (Ponmocup): 9 columns, col-2, plus the col-0-guarded IP side-effect ------

	public function testPonWithNineColumnsExtractsColumnTwoDomain(): void
	{
		// Typical shape: col-0 is a non-IP value (e.g. a timestamp), so
		// pfb_dnsbl_collect_feed_ip()'s is_ipaddrv4/6($guard_value) family check
		// never passes -- the domain is still extracted, nothing is collected.
		$csvline = ['2024-01-01T00:00:00Z', 'x', 'malicious-pon.example.com', 'd', 'e', 'f', 'g', 'h', 'i'];
		$ip4 = [];
		$ip6 = [];
		$r = pfb_dnsbl_csv_extract('raw', $csvline, 'pon', TRUE, TRUE, $this->alienvaultTypes,
			TRUE, FALSE, $ip4, $ip6, 'hdr', 'raw', 5, $this->parseErr);
		$this->assertSame('use', $r['action']);
		$this->assertSame('malicious-pon.example.com', $r['line']);
		$this->assertFalse($r['ip_collected']);
		$this->assertSame([], $ip4);
	}

	public function testPonWithIpv4GuardAndCandidateCollectsTheCandidate(): void
	{
		// pfb_dnsbl_collect_feed_ip()'s asymmetry (Adr62DnsblCollectFeedIpTest):
		// csvline[0] (guard) drives ONLY the family check; the appended value is
		// the CANDIDATE (csvline[2], i.e. $line) -- proving the pon call site's
		// guard-vs-candidate wiring survived the extraction unchanged.
		$csvline = ['198.51.100.7', 'x', '198.51.100.20', 'd', 'e', 'f', 'g', 'h', 'i'];
		$ip4 = [];
		$ip6 = [];
		$r = pfb_dnsbl_csv_extract('raw', $csvline, 'pon', TRUE, TRUE, $this->alienvaultTypes,
			TRUE, FALSE, $ip4, $ip6, 'hdr', 'raw', 5, $this->parseErr);
		$this->assertSame('use', $r['action']);
		$this->assertSame('198.51.100.20', $r['line']);
		$this->assertTrue($r['ip_collected']);
		$this->assertSame(['198.51.100.20'], $ip4);
	}

	public function testPonIpCollectionGatedByDnsblIpEnabled(): void
	{
		$csvline = ['198.51.100.8', 'x', '198.51.100.21', 'd', 'e', 'f', 'g', 'h', 'i'];
		$ip4 = [];
		$ip6 = [];
		$r = pfb_dnsbl_csv_extract('raw', $csvline, 'pon', TRUE, TRUE, $this->alienvaultTypes,
			FALSE, FALSE, $ip4, $ip6, 'hdr', 'raw', 5, $this->parseErr);
		$this->assertSame('use', $r['action']);
		$this->assertFalse($r['ip_collected'], 'dnsbl_ip Disabled must gate the IP collection off');
		$this->assertSame([], $ip4, 'no IP must land when dnsbl_ip is Disabled');
	}

	public function testPonWithWrongColumnCountFails(): void
	{
		$csvline = ['198.51.100.9', 'x', 'y']; // 3 cols, not 9
		$ip4 = [];
		$ip6 = [];
		$r = pfb_dnsbl_csv_extract('raw-pon', $csvline, 'pon', TRUE, TRUE, $this->alienvaultTypes,
			TRUE, FALSE, $ip4, $ip6, 'hdr', 'raw-pon', 5, $this->parseErr);
		$this->assertSame('skip', $r['action']);
		$this->assertStringContainsString('raw-pon', (string) file_get_contents($this->parseErr));
	}

	// -- et (Proofpoint/ET): 3 columns, col-0 ------------------------------------------

	public function testEtWithThreeColumnsExtractsColumnZero(): void
	{
		$csvline = ['et-malicious.example.com', 'category', 'score'];
		$r = $this->extract('raw', $csvline, 'et', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('et-malicious.example.com', $r['line']);
	}

	public function testEtWithWrongColumnCountFails(): void
	{
		$csvline = ['et-malicious.example.com', 'category']; // 2 cols, not 3
		$r = $this->extract('raw-et', $csvline, 'et', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertStringContainsString('raw-et', (string) file_get_contents($this->parseErr));
	}

	// -- default: header autodetect (csv_type not yet known) ---------------------------

	public function testDefaultDetectsPtHeaderAndSkipsWithoutFailRecord(): void
	{
		$line = 'phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target';
		$csvline = str_getcsv($line, ',', '"', '"');
		$r = $this->extract($line, $csvline, '', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertSame('pt', $r['csv_type']);
		$this->assertFileDoesNotExist($this->parseErr);
	}

	public function testDefaultDetectsBbcHeaderAndUsesColumnZero(): void
	{
		$line = 'bbc-detected.example.com,x,y,osint.bambenekconsulting.com';
		$csvline = str_getcsv($line, ',', '"', '"');
		$r = $this->extract($line, $csvline, '', TRUE);
		$this->assertSame('use', $r['action']);
		$this->assertSame('bbc', $r['csv_type']);
		$this->assertSame('bbc-detected.example.com', $r['line']);
	}

	public function testDefaultDetectsOtxHeaderAndSkipsWithoutFailRecord(): void
	{
		$line = 'Indicator type,Indicator,Description';
		$csvline = str_getcsv($line, ',', '"', '"');
		$r = $this->extract($line, $csvline, '', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertSame('otx', $r['csv_type']);
		$this->assertFileDoesNotExist($this->parseErr);
	}

	public function testDefaultDetectsPonHeaderAndSkipsWithoutFailRecord(): void
	{
		$line = 'timestamp,ip,domain,x,y,z,a,b,c';
		$csvline = str_getcsv($line, ',', '"', '"');
		$r = $this->extract($line, $csvline, '', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertSame('pon', $r['csv_type']);
		$this->assertFileDoesNotExist($this->parseErr);
	}

	public function testDefaultDetectsEtHeaderAndSkipsWithoutFailRecord(): void
	{
		$line = 'domain, category, score';
		$csvline = str_getcsv($line, ',', '"', '"');
		$r = $this->extract($line, $csvline, '', TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertSame('et', $r['csv_type']);
		$this->assertFileDoesNotExist($this->parseErr);
	}

	public function testDefaultWithNoHeaderMatchResetsStateAndFails(): void
	{
		// Autodetect's first-line false positive (issue #1118 brief): a
		// comma-bearing but non-CSV domain line reaches here with csv_type still
		// '' -- no header matches, so the helper resets csv_parser/run_once (the
		// caller's autodetect must re-arm from scratch on the NEXT line) and
		// records the parse failure for THIS line only.
		$line = 'uuid-example.com,a,b,c';
		$csvline = str_getcsv($line, ',', '"', '"');
		$r = $this->extract($line, $csvline, '', TRUE, TRUE);
		$this->assertSame('skip', $r['action']);
		$this->assertFalse($r['csv_parser'], 'no header match must reset csv_parser to FALSE');
		$this->assertFalse($r['run_once'], 'no header match must reset run_once to FALSE');
		$this->assertStringContainsString($line, (string) file_get_contents($this->parseErr));
	}

	// issue #1118: the real otx/et feed headers are 3-column lines, so the default
	// case's bbc sniff must not access an undefined $csvline[3] (a spurious PHP
	// warning on every otx/et feed's header line). Any E_WARNING fails this test.
	public function testShortFirstLineDoesNotWarnOnBbcSniffColumnThree(): void
	{
		$line = 'Indicator type,Indicator,Description';   // real otx header: 3 fields, no $csvline[3]
		$csvline = str_getcsv($line, ',', '"', '"');
		set_error_handler(static function (int $errno, string $errstr): bool {
			throw new \RuntimeException("unexpected PHP warning: {$errstr}");
		}, E_WARNING);
		try {
			$r = $this->extract($line, $csvline, '', TRUE);
		} finally {
			restore_error_handler();
		}
		$this->assertSame('skip', $r['action']);
		$this->assertSame('otx', $r['csv_type'], 'the 3-column line must still classify as otx');
	}
}
