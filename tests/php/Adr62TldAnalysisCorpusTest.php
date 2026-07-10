<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-62 Phase 1 -- byte-identity corpus, TLD-analysis surface (c).
 *
 * Drives the REAL tld_analysis() (inc:~7652, standalone -- reads
 * "{dnsbl_file}.raw" directly, independent of the download loop) over a
 * committed pfb_dnsbl.raw fixture (tests/fixtures/dnsbl_corpus/tld/) built
 * from the plain 6-col dialect + a persisted feed carrying the CURRENT '.abp'
 * marker (inc:16910-16911), and asserts the classified pfb_py_data/pfb_py_zone
 * output is byte-identical to the committed golden fixtures.
 *
 * Pins: 2-label domain -> unconditional ZONE (inc:~7865-7867); a 3-label
 * domain whose 2-label suffix is a known public suffix -> ZONE at the whole
 * domain (tld_search, inc:~7639); a deeper sub-domain with NO known-suffix
 * match -> DATA (transparent); an ABP-feed's verbatim lines are SKIPPED via
 * the CURRENT '.abp'-marker-gated unconditional-empty-feed-column rule
 * (inc:7804-7826) -- issue #1060's latent gate bug (only fires when
 * $abp_feeds is non-empty) is pinned here as TODAY's behaviour; Phase 5 fixes
 * it structurally (ADR.md SS1.5).
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
		unset($GLOBALS['tlds']);

		$this->tmp = sys_get_temp_dir() . '/adr62_tld_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/dnsalias", 0777, true);

		// pfb_dnsbl.raw = concatenation of the plain 6-col rows + the verbatim
		// ABP lines (mirrors inc:17158-17169's concat step across feeds).
		$raw = file_get_contents(self::FIXTURE_DIR . '/pfb_dnsbl_plain.txt')
			. file_get_contents(self::FIXTURE_DIR . '/pfb_dnsbl_abp.txt');
		file_put_contents("{$this->tmp}/pfb_dnsbl.raw", $raw);
		// The ABP feed's persisted marker (inc:16910-16911) -- glob-matched by
		// tld_analysis()'s CURRENT skip gate (inc:7804-7807).
		touch("{$this->tmp}/dnsbl/tld_abp_feed.abp");

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

	/** The ABP feed's raw lines never reach data/zone (today's marker-gated skip, ADR.md SS1.5). */
	public function testAbpFeedLinesAreSkippedNotMangled(): void
	{
		tld_analysis();
		$data = file_get_contents("{$this->tmp}/pfb_py_data.txt");
		$zone = file_get_contents("{$this->tmp}/pfb_py_zone.txt");
		$this->assertStringNotContainsString('adline', $data . $zone);
		$this->assertStringNotContainsString('safe.zzsuffix', $data . $zone);
	}

	/**
	 * ADR-62 Phase 4: a broadened-capture verbatim line ('sneaky.zzsuffix.example##.ad',
	 * pfb_dnsbl_plain.txt) now reaches a PLAIN feed's raw dialect too -- the TLD pass's
	 * own comma-prefix guard (inc:7887, PR #1066) skips any non-CSV-shaped line
	 * unconditionally, independent of the '.abp' marker mechanism, so it is never
	 * CSV-mangled here regardless of feed classification.
	 */
	public function testBroadenedCaptureVerbatimLineInPlainFeedIsSkippedNotMangled(): void
	{
		tld_analysis();
		$data = file_get_contents("{$this->tmp}/pfb_py_data.txt");
		$zone = file_get_contents("{$this->tmp}/pfb_py_zone.txt");
		$this->assertStringNotContainsString('sneaky', $data . $zone);
	}
}
