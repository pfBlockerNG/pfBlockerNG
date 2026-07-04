<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-49: the offline false-positive survey over the committed feed corpus.
 *
 * The corpus (tests/fixtures/feed_corpus/) is a ONE-TIME polite fetch of the
 * first bytes of every catalogue feed (scripts/fetch_feed_corpus.py) -- the
 * live catalogue is never fetched at test time, so the survey is repeatable,
 * rate-limit-proof, and mockable. Two layers:
 *
 * - Corpus integrity (always runs): the manifest and its sample files are
 *   present and coherent, so corpus rot is caught the moment it happens.
 * - The survey itself (activates with ADR-49 Phase 1): pfb_text_sanity() must
 *   return NULL for EVERY real text feed sample -- one confirmed false
 *   positive on the live catalogue blocks the ADR's acceptance (its §7 gate).
 *   Archive-typed samples (gzip/zip/bz2/7z magics) are not text feeds and are
 *   excluded; unreachable-at-fetch-time feeds have no sample to judge.
 *
 * #[CoversFunction] re-added in Phase 3: pfb_text_sanity() now exists (ADR-49
 * Phase 1 landed it), so the covers-target is no longer a PHPUnit warning
 * (undefined-covers-target was the reason it was removed in PR #827).
 */
#[CoversFunction('pfb_text_sanity')]
final class FeedCorpusSurveyTest extends TestCase
{
	private const CORPUS_DIR = __DIR__ . '/../fixtures/feed_corpus';

	/** @return array{sample_bytes_cap: int, feeds: list<array<string, mixed>>} */
	private static function manifest(): array
	{
		$raw = file_get_contents(self::CORPUS_DIR . '/manifest.json');
		if ($raw === FALSE) {
			self::fail('feed corpus manifest missing — run scripts/fetch_feed_corpus.py and commit the corpus');
		}
		$manifest = json_decode($raw, TRUE);
		self::assertIsArray($manifest, 'manifest.json is not valid JSON');
		return $manifest;
	}

	/** @return list<array<string, mixed>> the fetched, non-archive (text) samples */
	private static function textSamples(): array
	{
		$texty = [];
		foreach (self::manifest()['feeds'] as $feed) {
			if (isset($feed['sample_file']) && empty($feed['archive']) && ($feed['sample_bytes'] ?? 0) > 0) {
				$texty[] = $feed;
			}
		}
		return $texty;
	}

	public function testCorpusIsPresentAndCoherent(): void
	{
		$manifest = self::manifest();
		$fetched = 0;
		// A case-insensitive filesystem (macOS APFS) collapses two sample names that
		// differ only in case onto one file, so the manifest can name more samples than
		// exist on disk — coherent where it was generated, broken on case-sensitive
		// Linux CI. Track lowercased names to catch the collision at its source.
		$seenLower = [];
		foreach ($manifest['feeds'] as $feed) {
			$this->assertArrayHasKey('url', $feed);
			if (!isset($feed['sample_file'])) {
				$this->assertArrayHasKey('error', $feed, "feed {$feed['url']} has neither a sample nor an error");
				continue;
			}
			$lower = strtolower($feed['sample_file']);
			$prior = $seenLower[$lower] ?? '';
			$this->assertArrayNotHasKey(
				$lower,
				$seenLower,
				"two samples collide case-insensitively ({$feed['sample_file']} vs {$prior}) "
				. '— fetch_feed_corpus.py must dedup slugs case-insensitively'
			);
			$seenLower[$lower] = $feed['sample_file'];
			$path = self::CORPUS_DIR . '/' . $feed['sample_file'];
			$this->assertFileExists($path, "manifest names a missing sample for {$feed['url']}");
			$this->assertSame(
				$feed['sample_bytes'],
				filesize($path),
				"sample size drifted from the manifest for {$feed['url']} — re-run scripts/fetch_feed_corpus.py"
			);
			// The corpus feeds byte-exact bytes to a byte-sensitive scanner, so verify the
			// content, not merely its length: a length-preserving corruption (a byte flip, or
			// an EOL rewrite that keeps the byte count) passes the size check but silently
			// changes what the survey scans. sha256 also catches accidental EOL normalisation
			// on a checkout that ignores the .gitattributes pin.
			$this->assertSame(
				$feed['sample_sha256'],
				hash_file('sha256', $path),
				"sample content drifted from the manifest for {$feed['url']} — re-run scripts/fetch_feed_corpus.py"
			);
			$fetched++;
		}
		// Reverse coherence: every on-disk sample must be named by the manifest. The loop
		// above only walks manifest→disk, so a stale sample orphaned by a catalogue rename
		// (the fetch now wipes samples/ to prevent this) would otherwise go uncaught and
		// bloat the committed corpus.
		$named = [];
		foreach ($manifest['feeds'] as $feed) {
			if (isset($feed['sample_file'])) {
				$named[basename($feed['sample_file'])] = TRUE;
			}
		}
		foreach (scandir(self::CORPUS_DIR . '/samples') as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$this->assertArrayHasKey(
				$entry,
				$named,
				"orphan sample samples/{$entry} is not named by the manifest — re-run scripts/fetch_feed_corpus.py"
			);
		}
		// The catalogue has ~295 url entries; a healthy fetch reaches the large
		// majority. A collapse below this floor means the corpus (or the fetch)
		// rotted — refresh it rather than surveying a sliver of reality.
		$this->assertGreaterThan(
			150,
			$fetched,
			"only {$fetched} fetched samples in the corpus — too few for the survey to mean anything"
		);
		$this->assertGreaterThan(100, count(self::textSamples()), 'too few TEXT samples for the survey');
	}

	/**
	 * Corpus samples that are NOT real feed bodies, so a non-null verdict on them is
	 * the scanner working correctly, NOT a false positive. Keyed by feed header ->
	 * the documented reason. The one-time PR #827 capture caught these five: two are
	 * catalogue-marked `discontinued`, and three are dead/gated feeds whose captured
	 * body is a header-only stub or an auth wall. Each is asserted below to STILL be
	 * flagged, so a stale entry (a feed that came back to life) fails loudly rather
	 * than silently masking a real regression.
	 */
	private const KNOWN_NON_FEED = [
		'MaxMind_BD_Proxy' => 'catalogue status=discontinued — the url is MaxMind\'s HTML sample-list webpage, not a raw feed (html_error_page)',
		'Abuse_SSLBL'      => 'catalogue status=discontinued — abuse.ch retired the SSLBL IP blacklist; the body is header-only, zero data rows (below_min_content)',
		'Abuse_SSLBL_Agr'  => 'the retired SSLBL aggressive list — sibling of the discontinued Abuse_SSLBL (catalogue status unset); header-only, zero data rows (below_min_content)',
		'Darklist'         => 'header-only at capture — darklist.de/raw.php returned its 2-line header with zero IP rows (below_min_content)',
		'MPatrol'          => 'API-key gated — the catalogue url is an _API_KEY_ template; the capture hit the "access denied" auth wall, not the feed (below_min_content)',
	];

	public function testCatalogueSurveyHasZeroFalsePositives(): void
	{
		if (!function_exists('pfb_text_sanity')) {
			$this->markTestSkipped(
				'pfb_text_sanity() not implemented yet — this survey activates with ADR-49 Phase 1 '
				. 'and gates the ADR\'s flip to Accepted (§7)'
			);
		}
		$flagged = [];
		$stale = [];
		foreach (self::textSamples() as $feed) {
			$sample = (string) file_get_contents(self::CORPUS_DIR . '/' . $feed['sample_file']);
			$verdict = pfb_text_sanity($sample);
			if (isset(self::KNOWN_NON_FEED[$feed['header']])) {
				// A known non-feed sample MUST stay flagged: if it now passes, the feed
				// came back or the capture changed, so the exclusion is stale.
				if ($verdict === NULL) {
					$stale[] = "{$feed['header']} — now passes pfb_text_sanity(); re-check the feed and drop it from KNOWN_NON_FEED";
				}
				continue;
			}
			if ($verdict !== NULL) {
				$flagged[] = "{$feed['header']} ({$feed['url']}) -> {$verdict}";
			}
		}
		$this->assertSame(
			[],
			$flagged,
			"pfb_text_sanity() flagged REAL catalogue feeds (false positives — each would drop a live blocklist):\n"
			. implode("\n", $flagged)
		);
		$this->assertSame(
			[],
			$stale,
			"KNOWN_NON_FEED exclusions that are no longer flagged (stale — re-check the feed and remove the entry):\n"
			. implode("\n", $stale)
		);
	}
}
