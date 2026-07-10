<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-62 -- byte-identity corpus, TLD-analysis surface (c).
 *
 * Drives the REAL tld_analysis() (standalone -- reads "{dnsbl_file}.raw"
 * directly, independent of the download loop) over a committed
 * pfb_dnsbl.raw fixture (tests/fixtures/dnsbl_corpus/tld/) built from the
 * plain 6-col dialect, and asserts the classified pfb_py_data/pfb_py_zone
 * output is byte-identical to the committed golden fixtures.
 *
 * Pins: 2-label domain -> unconditional ZONE; a 3-label domain whose 2-label
 * suffix is a known public suffix -> ZONE at the whole domain (tld_search);
 * a deeper sub-domain with NO known-suffix match -> DATA (transparent); any
 * non-comma-first line (a verbatim-captured ABP/regex shape) is skipped by
 * prefix (issue #1060/PR fix); a comma-first row with an empty/unset feed
 * column is skipped UNCONDITIONALLY -- no '.abp'-marker mechanism remains.
 */
#[CoversFunction('tld_analysis')]
final class Adr62TldAnalysisCorpusTest extends TestCase
{
	private const FIXTURE_DIR = __DIR__ . '/../fixtures/dnsbl_corpus/tld';

	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];
	private $hadTlds = false;
	private $originalTlds = null;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		// tld_analysis() accumulates into the GLOBAL $tlds by reference across
		// calls (no reset at entry) -- isolate this test class from any prior
		// run's residue and restore it afterward.
		$this->hadTlds = array_key_exists('tlds', $GLOBALS);
		$this->originalTlds = $GLOBALS['tlds'] ?? null;
		// Seed an empty array (never unset): tld_analysis()'s master-TLD loader
		// dereferences $tlds[$tld] and warns on a null global (PR #1107 review).
		$GLOBALS['tlds'] = array();

		$this->tmp = sys_get_temp_dir() . '/adr62_tld_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/dnsalias", 0777, true);

		// pfb_dnsbl.raw = concatenation of the plain 6-col rows + the verbatim
		// ABP lines (mirrors inc:17158-17169's concat step across feeds).
		$raw = file_get_contents(self::FIXTURE_DIR . '/pfb_dnsbl_plain.txt')
			. file_get_contents(self::FIXTURE_DIR . '/pfb_dnsbl_abp.txt');
		file_put_contents("{$this->tmp}/pfb_dnsbl.raw", $raw);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'              => "{$this->tmp}/pfblockerng.log",
			'errlog'           => "{$this->tmp}/error.log",
			'dnsdir'           => "{$this->tmp}/dnsbl",
			'dnsbl_file'       => "{$this->tmp}/pfb_dnsbl",
			'dnsbl_tmpdir'     => "{$this->tmp}/DNSBL_TMP",
			'dnsbl_tmp'        => "{$this->tmp}/dnsbl_tmp",
			'dnsbl_tld_txt'    => "{$this->tmp}/dnsbl/DNSBL_TLD.txt",
			'dnsbl_tld_data'   => self::FIXTURE_DIR . '/tld_master.txt',
			'unbound_py_data'  => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone'  => "{$this->tmp}/pfb_py_zone.txt",
			'domain_max_cnt'   => 1000000,
			'dnsbl_info'       => "{$this->tmp}/dnsbl_info.sqlite",
			'sqlite_timeout'   => 2000,
			'alias_dnsbl_all'  => [],
			'dnsbl_info_stats' => [],
			'tld_update'       => [],
			'dnsalias'         => "{$this->tmp}/dnsalias",
			'dnsblconfig'      => [
				'tldblacklist' => '',
				'tldexclusion' => '',
			],
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadTlds) {
			$GLOBALS['tlds'] = $this->originalTlds;
		} else {
			unset($GLOBALS['tlds']);
		}
		rmdir_recursive($this->tmp);
	}

	public function testDataAndZoneClassificationMatchesGolden(): void
	{
		tld_analysis();

		$this->assertFileExists("{$this->tmp}/pfb_py_data.txt", 'tld_analysis must produce a data file');
		$this->assertFileExists("{$this->tmp}/pfb_py_zone.txt", 'tld_analysis must produce a zone file');

		$this->assertSame(
			file_get_contents(self::FIXTURE_DIR . '/golden_pfb_py_data.txt'),
			file_get_contents("{$this->tmp}/pfb_py_data.txt"),
			'pfb_py_data (transparent/exact) classification drifted'
		);
		$this->assertSame(
			file_get_contents(self::FIXTURE_DIR . '/golden_pfb_py_zone.txt'),
			file_get_contents("{$this->tmp}/pfb_py_zone.txt"),
			'pfb_py_zone (redirect/wildcard) classification drifted'
		);
	}

	/** The ABP feed's raw lines never reach data/zone (they never start with ',', ADR.md SS1.5). */
	public function testAbpFeedLinesAreSkippedNotMangled(): void
	{
		tld_analysis();
		$data = file_get_contents("{$this->tmp}/pfb_py_data.txt");
		$zone = file_get_contents("{$this->tmp}/pfb_py_zone.txt");
		$this->assertStringNotContainsString('adline', $data . $zone);
		$this->assertStringNotContainsString('safe.zzsuffix', $data . $zone);
	}

	/**
	 * A broadened-capture verbatim line ('sneaky.zzsuffix.example##.ad',
	 * pfb_dnsbl_plain.txt) reaches a PLAIN feed's raw dialect too -- the TLD
	 * pass's comma-prefix guard skips any non-CSV-shaped line unconditionally,
	 * so it is never CSV-mangled here regardless of which feed it came from.
	 */
	public function testBroadenedCaptureVerbatimLineInPlainFeedIsSkippedNotMangled(): void
	{
		tld_analysis();
		$data = file_get_contents("{$this->tmp}/pfb_py_data.txt");
		$zone = file_get_contents("{$this->tmp}/pfb_py_zone.txt");
		$this->assertStringNotContainsString('sneaky', $data . $zone);
	}

	/**
	 * The empty-feed-column skip fires unconditionally -- no '.abp' marker
	 * mechanism gates it (issue #1060's latent gate bug: the skip used to fire
	 * only when at least one marker existed on disk).
	 */
	public function testEmptyFeedColumnRowSkippedUnconditionallyWithNoAbpMarkerPresent(): void
	{
		file_put_contents("{$this->tmp}/pfb_dnsbl.raw", ",tldbad.example,,1,,agroup\n", FILE_APPEND);

		tld_analysis();

		$data = file_get_contents("{$this->tmp}/pfb_py_data.txt");
		$zone = file_get_contents("{$this->tmp}/pfb_py_zone.txt");
		$this->assertStringContainsString('twolabelzone.example', $zone, 'sanity: a real row must still classify');
		$this->assertStringNotContainsString('tldbad', $data . $zone);
	}
}
