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

	/** Saved bootstrap globals, restored in tearDown (issue #1063 hygiene). */
	private mixed $savedPfb  = null;
	private mixed $savedTlds = null;

	protected function setUp(): void
	{
		global $pfb, $tlds;

		$this->savedPfb  = $pfb ?? null;
		$this->savedTlds = $tlds ?? null;

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
		global $pfb, $tlds;

		$pfb  = $this->savedPfb;
		$tlds = $this->savedTlds;

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
	 * Run tld_analysis() collecting every PHP diagnostic it raises (instead of
	 * blanket-@-suppression, per PR #1066 review): callers assert on the list.
	 *
	 * @return list<string>
	 */
	private function runTldAnalysis(): array
	{
		$warnings = [];
		set_error_handler(
			static function (int $errno, string $errstr) use (&$warnings): bool {
				$warnings[] = $errstr;
				return TRUE;
			}
		);
		try {
			tld_analysis();
		} finally {
			restore_error_handler();
		}
		return $warnings;
	}

	/**
	 * Scenario: verbatim ABP lines in a plain feed, no ABP feed configured.
	 *
	 * Given:  pfb_dnsbl.raw holding one plain CSV row plus verbatim ||x^ and
	 *         @@||x^ lines — one with >=5 comma-separated ABP options — and
	 *         ZERO .abp markers in dnsdir
	 * When:   tld_analysis() runs
	 * Then:   the CSV row lands in the zone output and every verbatim line is
	 *         skipped — no malformed row in the data output, no numeric
	 *         undefined-array-key warning from the CSV explode
	 */
	public function testVerbatimAbpLinesSkippedWithZeroAbpMarkers(): void
	{
		global $pfb;

		file_put_contents(
			"{$pfb['dnsbl_file']}.raw",
			",example.com,,1,PlainFeed,GroupA\n"
			. "||evil-verbatim.example^\n"
			. "@@||allow-verbatim.example^\n"
			. "||opt-verbatim.example^\$script,third-party,domain=x.com,match-case,important,other\n"
		);

		$warnings = $this->runTldAnalysis();

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

		$numeric = array_values(array_filter(
			$warnings,
			static fn (string $w): bool => preg_match('/Undefined array key \d/', $w) === 1
		));
		$this->assertSame(
			[],
			$numeric,
			'no verbatim line may reach the CSV explode; got: ' . var_export($numeric, TRUE)
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

		$this->runTldAnalysis();

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
