<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * tld_analysis() — ABP-line skipping in the concatenated pfb_dnsbl.raw.
 *
 * Issue #1060: a plain feed can carry ADR-21 verbatim ABP lines (||x^ /
 * @@||x^) with ZERO '.abp' markers on disk. The empty/unset-feed-column skip
 * must run unconditionally — gated on a non-empty marker set, the verbatim
 * line reached the CSV explode and produced a malformed ',,' row in the
 * python data output.
 */
#[CoversFunction('tld_analysis')]
final class TldAnalysisAbpVerbatimTest extends TestCase
{
	private string $tmpDir;

	protected function setUp(): void
	{
		global $pfb, $tlds;

		$this->tmpDir = sys_get_temp_dir() . '/pfb_tld_abp_' . getmypid() . '_' . mt_rand();
		mkdir($this->tmpDir, 0700, TRUE);
		mkdir("{$this->tmpDir}/dnsdir", 0700, TRUE);

		$tlds = array();
		$pfb['dnsbl_file']	= "{$this->tmpDir}/pfb_dnsbl";
		$pfb['dnsbl_tld_data']	= "{$this->tmpDir}/tld_master";
		$pfb['unbound_py_data']	= "{$this->tmpDir}/pfb_py_data";
		$pfb['unbound_py_zone']	= "{$this->tmpDir}/pfb_py_zone";
		$pfb['dnsdir']		= "{$this->tmpDir}/dnsdir";
		$pfb['dnsbl_tmpdir']	= "{$this->tmpDir}/tmpdir";
		$pfb['dnsbl_tld_txt']	= "{$this->tmpDir}/dnsbl_tld.txt";
		$pfb['dnsbl_tmp']	= "{$this->tmpDir}/dnsbl_tmp";
		$pfb['dnsbl_info']	= "{$this->tmpDir}/dnsbl_info.db";
		$pfb['errlog']		= "{$this->tmpDir}/error.log";
		$pfb['log']		= "{$this->tmpDir}/pfblockerng.log";
		$pfb['domain_max_cnt']	= 100000;
		$pfb['sqlite_timeout']	= 5000;
		$pfb['dnsblconfig']	= array('tldblacklist' => '', 'tldexclusion' => '');
		$pfb['dnsbl_info_stats'] = array();
		$pfb['alias_dnsbl_all']	= array();
		$pfb['tld_update']	= array();

		file_put_contents($pfb['dnsbl_tld_data'], "com\n");
	}

	protected function tearDown(): void
	{
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->tmpDir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($files as $f) {
			$f->isDir() ? rmdir((string) $f) : unlink((string) $f);
		}
		rmdir($this->tmpDir);
	}

	/**
	 * Scenario: verbatim ABP lines in a plain feed, no ABP feed configured.
	 *
	 * Given:  pfb_dnsbl.raw holding one plain CSV row plus verbatim ||x^ and
	 *         @@||x^ lines, and ZERO .abp markers in dnsdir
	 * When:   tld_analysis() runs
	 * Then:   the CSV row lands in the zone output and the verbatim lines are
	 *         skipped — no malformed ',,' row in the data output
	 */
	public function testVerbatimAbpLinesSkippedWithZeroAbpMarkers(): void
	{
		global $pfb;

		file_put_contents(
			"{$pfb['dnsbl_file']}.raw",
			",example.com,,1,PlainFeed,GroupA\n"
			. "||evil-verbatim.example^\n"
			. "@@||allow-verbatim.example^\n"
		);

		@tld_analysis();

		$this->assertFileExists($pfb['unbound_py_zone']);
		$zone = (string) file_get_contents($pfb['unbound_py_zone']);
		$data = file_exists($pfb['unbound_py_data'])
			? (string) file_get_contents($pfb['unbound_py_data']) : '';

		$this->assertSame(
			",example.com,,1,PlainFeed,GroupA\n",
			$zone,
			"zone output must carry exactly the plain CSV row; got: " . var_export($zone, TRUE)
		);
		$this->assertSame(
			'',
			$data,
			"verbatim ABP lines must be skipped, not CSV-mangled; got: " . var_export($data, TRUE)
		);
	}

	/**
	 * Scenario: a marked ABP feed's comma-bearing line is still skipped by name.
	 *
	 * Given:  an AbpFeed.abp marker and a raw line whose column 4 says AbpFeed
	 * When:   tld_analysis() runs
	 * Then:   the marked feed's line is skipped; the plain row still processes
	 *         (pins the marker-based skip across the #1060 refactor)
	 */
	public function testMarkedAbpFeedLineStillSkippedByFeedName(): void
	{
		global $pfb;

		touch("{$pfb['dnsdir']}/AbpFeed.abp");
		file_put_contents(
			"{$pfb['dnsbl_file']}.raw",
			",example.com,,1,PlainFeed,GroupA\n"
			. ",abp-carried.example,,1,AbpFeed,GroupB\n"
		);

		@tld_analysis();

		$this->assertFileExists($pfb['unbound_py_zone']);
		$zone = (string) file_get_contents($pfb['unbound_py_zone']);

		$this->assertStringContainsString(',example.com,', $zone);
		$this->assertStringNotContainsString(
			'abp-carried.example',
			$zone,
			"marked-feed line must be skipped by feed name; got: " . var_export($zone, TRUE)
		);
	}
}
