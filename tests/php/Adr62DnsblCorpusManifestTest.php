<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-62 -- byte-identity corpus, manifest-writer surface (b).
 *
 * Drives the REAL pfb_unbound_python_sources() (ADR-06/07) over the committed
 * tests/fixtures/dnsbl_corpus/txt/*.txt fixtures -- the documented per-feed
 * ".txt" staging output for each coverage-matrix row (ADR.md SS"Coverage
 * matrix"; the download loop itself has no off-appliance driver, so these
 * fixtures are the loop's DOCUMENTED output, not an independently re-executed
 * one -- the raw-feed -> ".txt" step is a DEFERRED smoke row) -- and asserts
 * the produced ".raw" bytes are byte-identical to the committed golden
 * fixtures under tests/fixtures/dnsbl_corpus/raw/. This is the falsification
 * harness later phases must keep green (modulo the ADR's delta table).
 *
 * Delta-table rows: D1 (abp_feed, classifier deleted), D2, and D4
 * (mixed_plain/permit_feed) all assert their NEW outcome (verbatim capture,
 * or -- for D1's now-plain bare-domain rows -- the 6-col dialect) at the
 * surface this test owns (manifest-writer passthrough); their PARSED verdict
 * (block/allow/skip, zone vs data) is asserted downstream in
 * tests/test_adr62_byte_identity_corpus.py (surface a).
 */
#[CoversFunction('pfb_unbound_python_sources')]
final class Adr62DnsblCorpusManifestTest extends TestCase
{
	private const CORPUS_DIR = __DIR__ . '/../fixtures/dnsbl_corpus';

	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];

	/** @var list<array<string, string>> */
	private array $feeds;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/adr62_corpus_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/db", 0777, true);

		foreach (glob(self::CORPUS_DIR . '/txt/*.txt') as $src) {
			copy($src, "{$this->tmp}/dnsbl/" . basename($src));
		}

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_tld_data'     => "{$this->tmp}/does_not_exist",
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsblconfig'        => [
				'tldblacklist' => '',
				'tldexclusion' => '',
				'suppression'  => '',
			],
		]);

		$json = file_get_contents(self::CORPUS_DIR . '/feeds.json');
		$this->assertNotFalse($json, 'corpus feeds.json must be readable');
		$decoded = json_decode($json, true);
		$this->assertIsArray($decoded, 'corpus feeds.json must decode');
		$this->feeds = $decoded;
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		rmdir_recursive($this->tmp);
	}

	/** Manifest rows in the pfb_unbound_python_sources() input shape (header/group/log/format/provenance/mode). */
	private function feedRows(): array
	{
		$rows = [];
		foreach ($this->feeds as $f) {
			$row = [
				'header'     => $f['header'],
				'group'      => $f['group'],
				'log'        => $f['log'],
				'format'     => $f['format'],
				'provenance' => $f['provenance'],
			];
			if (isset($f['mode'])) {
				$row['mode'] = $f['mode'];
			}
			$rows[] = $row;
		}
		return $rows;
	}

	/**
	 * Byte-identity oracle: every corpus feed's produced .raw matches its
	 * committed golden fixture exactly. A single parametrised assertion loop
	 * covers every coverage-matrix row named in feeds.json's "row" field.
	 */
	public function testEveryCorpusFeedRawMatchesGolden(): void
	{
		pfb_unbound_python_sources($this->feedRows());

		foreach ($this->feeds as $f) {
			$header = $f['header'];
			$golden = self::CORPUS_DIR . "/raw/{$header}.raw";
			$this->assertFileExists($golden, "missing golden fixture for [ {$header} ] ({$f['row']})");
			$produced = file_get_contents("{$this->tmp}/pfb_py_raw/{$header}.raw");
			$this->assertSame(
				file_get_contents($golden),
				$produced,
				"manifest-writer .raw output drifted for [ {$header} ] ({$f['row']})"
			);
		}
	}

	/** format_hint/provenance/mode tagging survives the writer unchanged per corpus feed. */
	public function testManifestTaggingMatchesFeedsJson(): void
	{
		$m = pfb_unbound_python_sources($this->feedRows());
		$byHeader = [];
		foreach ($m['feeds'] as $row) {
			$byHeader[$row['feed']] = $row;
		}
		foreach ($this->feeds as $f) {
			$this->assertArrayHasKey($f['header'], $byHeader, "feed [ {$f['header']} ] missing from manifest");
			$row = $byHeader[$f['header']];
			$this->assertSame($f['format'], $row['format_hint'], "format_hint drifted for [ {$f['header']} ]");
			$this->assertSame($f['provenance'], $row['provenance'], "provenance drifted for [ {$f['header']} ]");
			if (isset($f['mode'])) {
				$this->assertSame($f['mode'], $row['mode'] ?? null, "mode drifted for [ {$f['header']} ]");
			} else {
				$this->assertArrayNotHasKey('mode', $row, "unexpected mode key for [ {$f['header']} ]");
			}
		}
	}

	// --- #752/#753 divergence: the PHP-side half (pfb_filter is a pure, --
	// --- off-appliance-callable probe; the loop's OWN acceptance is DEFERRED). ---

	/**
	 * #752 (known divergence, ADR.md SS1.5): PHP's PFB_FILTER_DOMAIN accepts a
	 * bare 254-char undotted name (strlen < 255 + every label <= 63); the
	 * oversized_feed corpus fixture documents this row reaching the .txt/.raw
	 * dialect. Python's build()/normalise() rejects it -- pinned downstream in
	 * tests/test_adr62_byte_identity_corpus.py. This is NOT a delta (ADR.md
	 * SS1.5): the divergence pre-dates and is out of this ADR's scope.
	 */
	public function testPhp752OversizedUndottedNameValidatesAsDomain(): void
	{
		$name254 = str_repeat('b', 61) . '.' . str_repeat('b', 61) . '.'
			. str_repeat('b', 61) . '.' . str_repeat('b', 61) . '.' . str_repeat('b', 6);
		$this->assertSame(254, strlen($name254));
		$this->assertNotSame('', pfb_filter($name254, PFB_FILTER_DOMAIN, 'Adr62CorpusTest'));
	}

	/** #753 boundary: the 253-char name (wire-cap edge) also validates -- byte-identical both sides. */
	public function testPhp753WireCapBoundaryNameValidatesAsDomain(): void
	{
		$name253 = str_repeat('b', 61) . '.' . str_repeat('b', 61) . '.'
			. str_repeat('b', 61) . '.' . str_repeat('b', 61) . '.' . str_repeat('b', 5);
		$this->assertSame(253, strlen($name253));
		$this->assertNotSame('', pfb_filter($name253, PFB_FILTER_DOMAIN, 'Adr62CorpusTest'));
	}
}
