<?php

declare(strict_types=1);

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
 * No #[CoversFunction] here: pfb_text_sanity() does not exist until ADR-49 Phase 1,
 * and a covers-target for an undefined function is a PHPUnit warning that the CI
 * suite (run with --fail-on-warning) turns into a failure. The survey test guards on
 * function_exists() instead; add the covers attribute when the scanner lands.
 */
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

	public function testCatalogueSurveyHasZeroFalsePositives(): void
	{
		if (!function_exists('pfb_text_sanity')) {
			$this->markTestSkipped(
				'pfb_text_sanity() not implemented yet — this survey activates with ADR-49 Phase 1 '
				. 'and gates the ADR\'s flip to Accepted (§7)'
			);
		}
		$flagged = [];
		foreach (self::textSamples() as $feed) {
			$sample = (string) file_get_contents(self::CORPUS_DIR . '/' . $feed['sample_file']);
			$verdict = pfb_text_sanity($sample);
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
	}
}
