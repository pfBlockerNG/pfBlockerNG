<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-42 Phase 1 — hash helpers and local-feed change-detection oracle.
 *
 * Tests cover:
 *   pfb_content_hash()      — xxh128 of a file or a string; known-answer vector.
 *   pfb_hash_read()         — tagged sidecar read: .xxhash128 (new), .md5 (legacy),
 *                             bare/untagged → md5, unknown tag → "changed" sentinel.
 *   pfb_hash_write()        — writes .xxhash128, deletes superseded .md5; round-trip.
 *   pfb_local_feed_changed() — oracle-pin of today's mtime+md5-confirm decision.
 *
 * Every test carries a failable assertion. Behaviour-preserving phase: the
 * pfb_local_feed_changed() oracle tests pin TODAY's decision and must stay green across
 * the refactor. The new helper tests (hash, read/write, round-trip) are new assertions.
 */
#[CoversFunction('pfb_content_hash')]
#[CoversFunction('pfb_hash_read')]
#[CoversFunction('pfb_hash_write')]
#[CoversFunction('pfb_local_feed_changed')]
final class FeedChangeHashHelpersTest extends TestCase
{
	/** @var string Writable temp directory for this test class. */
	private string $dir;

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_hash_test_' . getmypid() . '_' . mt_rand(0, 0xffff);
		if (!mkdir($base, 0777, TRUE)) {
			$this->fail("Could not create temp dir: {$base}");
		}
		$this->dir = $base;
	}

	protected function tearDown(): void
	{
		// Recursively remove the temp dir.
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($it as $f) {
			$f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
		}
		rmdir($this->dir);
	}

	// -------------------------------------------------------------------------
	// pfb_content_hash() — xxh128, known-answer, file and string modes
	// -------------------------------------------------------------------------

	/**
	 * Known-answer vector: PHP hash('xxh128', 'pfBlockerNG') must equal the value
	 * produced by the `xxh128sum` CLI for the same bytes. Both were confirmed at
	 * ADR-42 authoring time. If this test ever fails, the algorithm or its PHP binding
	 * has changed — the entire hash convention breaks.
	 *
	 *   echo -n 'pfBlockerNG' | xxh128sum  →  4a2690170244f2e853151c59fbcb2105
	 *   php -r 'echo hash("xxh128", "pfBlockerNG");'  →  4a2690170244f2e853151c59fbcb2105
	 *
	 * Pinned as a literal constant so any drift is caught immediately.
	 */
	public function test_content_hash_string_known_answer_vector(): void
	{
		// The pinned value is the ground truth — a future algorithm change MUST fail
		// this test rather than silently produce a different digest.
		$expected = '4a2690170244f2e853151c59fbcb2105';

		$result = pfb_content_hash('pfBlockerNG', FALSE);

		$this->assertSame(
			$expected,
			$result,
			sprintf(
				'pfb_content_hash("pfBlockerNG", FALSE) expected %s, got %s — '
				. 'the xxh128 known-answer vector has drifted; check the PHP xxh128 binding.',
				$expected,
				var_export($result, TRUE)
			)
		);
	}

	/**
	 * File-mode: hashing a file produces the same digest as hashing its contents
	 * directly (file mode equals string mode for the same bytes).
	 *
	 *  GIVEN a file whose contents are a known byte string;
	 *   WHEN pfb_content_hash($file, TRUE) and pfb_content_hash($string, FALSE) are called;
	 *   THEN both return the same non-empty hex digest.
	 */
	public function test_content_hash_file_matches_string_mode(): void
	{
		$content = 'hello pfBlockerNG';
		$path    = $this->dir . '/test.txt';
		file_put_contents($path, $content);

		$from_file   = pfb_content_hash($path, TRUE);
		$from_string = pfb_content_hash($content, FALSE);

		$this->assertNotEmpty(
			$from_file,
			'pfb_content_hash(file) must return a non-empty digest'
		);
		$this->assertSame(
			$from_file,
			$from_string,
			sprintf(
				'File-mode and string-mode must produce identical digests for the same bytes '
				. '(file=%s, string=%s)',
				var_export($from_file, TRUE),
				var_export($from_string, TRUE)
			)
		);
	}

	/**
	 * File-mode: missing file returns FALSE (not an empty string or 0).
	 *
	 *  GIVEN a path that does not exist;
	 *   WHEN pfb_content_hash($path, TRUE) is called;
	 *   THEN it returns FALSE.
	 */
	public function test_content_hash_missing_file_returns_false(): void
	{
		$missing = $this->dir . '/nonexistent.txt';
		$result  = pfb_content_hash($missing, TRUE);

		$this->assertFalse(
			$result,
			sprintf('Expected FALSE for missing file, got %s', var_export($result, TRUE))
		);
	}

	/**
	 * Idempotence: hashing the same content twice yields the same digest.
	 * Pinned contract from ADR-42 §2 ("Determinism / idempotence").
	 *
	 *  GIVEN a file with fixed content;
	 *   WHEN pfb_content_hash() is called twice on it;
	 *   THEN both calls return the same digest.
	 */
	public function test_content_hash_is_deterministic(): void
	{
		$path = $this->dir . '/deterministic.txt';
		file_put_contents($path, 'same bytes every time');

		$first  = pfb_content_hash($path, TRUE);
		$second = pfb_content_hash($path, TRUE);

		$this->assertSame(
			$first,
			$second,
			sprintf(
				'pfb_content_hash() must be deterministic (first=%s, second=%s)',
				var_export($first, TRUE),
				var_export($second, TRUE)
			)
		);
	}

	// -------------------------------------------------------------------------
	// pfb_hash_read() / pfb_hash_write() — tagged sidecar read/write
	// -------------------------------------------------------------------------

	/**
	 * Round-trip: write a digest, read it back — same value, same algo.
	 * ADR-42 §2 contract: "A written .xxhash128 reads back to the same value and
	 * compares equal to a re-hash of unchanged content."
	 *
	 *  GIVEN a file with known content;
	 *   WHEN pfb_hash_write($base, $file) is called and then pfb_hash_read($base);
	 *   THEN the read returns ['algo' => 'xxh128', 'digest' => <same hex>].
	 */
	public function test_hash_write_then_read_round_trips(): void
	{
		$content = 'round-trip test content';
		$path    = $this->dir . '/feed.orig';
		$base    = $this->dir . '/feed.orig';
		file_put_contents($path, $content);

		$write_ok = pfb_hash_write($base, $path);
		$this->assertTrue($write_ok, 'pfb_hash_write() must return TRUE on success');

		// Sidecar file must exist.
		$this->assertFileExists(
			$this->dir . '/feed.orig.xxhash128',
			'pfb_hash_write() must create the .xxhash128 sidecar'
		);

		$result = pfb_hash_read($base);

		$this->assertSame(
			'xxh128',
			$result['algo'],
			sprintf('Expected algo=xxh128, got %s', var_export($result['algo'], TRUE))
		);

		// Digest must match the direct hash of the same bytes.
		$expected_digest = pfb_content_hash($path, TRUE);
		$this->assertSame(
			$expected_digest,
			$result['digest'],
			sprintf(
				'Round-trip digest mismatch: expected %s, got %s',
				$expected_digest,
				$result['digest']
			)
		);
	}

	/**
	 * Write removes superseded .md5 sidecar — migration step.
	 * ADR-42 §2: "write .xxhash128 and delete the superseded .md5."
	 *
	 *  GIVEN a .md5 sidecar is present alongside the base;
	 *   WHEN pfb_hash_write() is called;
	 *   THEN the .xxhash128 sidecar is created AND the .md5 sidecar is removed.
	 */
	public function test_hash_write_removes_legacy_md5_sidecar(): void
	{
		$path = $this->dir . '/feed2.orig';
		$base = $this->dir . '/feed2.orig';
		file_put_contents($path, 'migrate me');
		// Plant a legacy .md5 sidecar.
		file_put_contents($base . '.md5', md5('migrate me'));

		$this->assertFileExists($base . '.md5', 'Precondition: .md5 sidecar must exist before write');

		pfb_hash_write($base, $path);

		$this->assertFileExists(
			$base . '.xxhash128',
			'pfb_hash_write() must create .xxhash128 sidecar'
		);
		$this->assertFileDoesNotExist(
			$base . '.md5',
			'pfb_hash_write() must delete superseded .md5 sidecar'
		);
	}

	/**
	 * Legacy .md5 sidecar reads with algo=md5.
	 * ADR-42 §2 contract: "an install carrying a legacy .md5/untagged digest compares
	 * correctly with md5 on the first post-upgrade pass."
	 *
	 *  GIVEN a .md5 sidecar (no .xxhash128) exists;
	 *   WHEN pfb_hash_read($base) is called;
	 *   THEN it returns ['algo' => 'md5', 'digest' => <32 hex chars>].
	 */
	public function test_hash_read_legacy_md5_sidecar(): void
	{
		$base   = $this->dir . '/legacy.orig';
		$digest = md5('legacy content');
		file_put_contents($base . '.md5', $digest);

		// No .xxhash128 present — must fall back to .md5.
		$this->assertFileDoesNotExist($base . '.xxhash128', 'Precondition: no .xxhash128 sidecar');

		$result = pfb_hash_read($base);

		$this->assertSame(
			'md5',
			$result['algo'],
			sprintf('Expected algo=md5 for legacy sidecar, got %s', var_export($result['algo'], TRUE))
		);
		$this->assertSame(
			$digest,
			$result['digest'],
			sprintf('Expected digest %s, got %s', $digest, $result['digest'])
		);
	}

	/**
	 * No sidecar found → "changed" sentinel (fail-safe / downgrade-safe).
	 * ADR-42 §2: "An older release meeting an unknown .xxhash128 it cannot read must
	 * fail safe → treat as changed → re-ingest."
	 *
	 *  GIVEN neither .xxhash128 nor .md5 exists for the base;
	 *   WHEN pfb_hash_read($base) is called;
	 *   THEN it returns ['algo' => 'changed', 'digest' => ''].
	 */
	public function test_hash_read_no_sidecar_returns_changed_sentinel(): void
	{
		$base = $this->dir . '/nosidecar.orig';
		// No sidecar files created.
		$this->assertFileDoesNotExist($base . '.xxhash128', 'Precondition: no .xxhash128');
		$this->assertFileDoesNotExist($base . '.md5', 'Precondition: no .md5');

		$result = pfb_hash_read($base);

		$this->assertSame(
			'changed',
			$result['algo'],
			sprintf(
				'Expected algo=changed sentinel for missing sidecar, got %s',
				var_export($result['algo'], TRUE)
			)
		);
		$this->assertSame(
			'',
			$result['digest'],
			sprintf('Expected empty digest for changed sentinel, got %s', var_export($result['digest'], TRUE))
		);
	}

	/**
	 * .xxhash128 sidecar with invalid/truncated content → "changed" sentinel.
	 * Downgrade-safety: an unreadable or malformed sidecar must trigger re-ingest,
	 * never a false "unchanged" skip.
	 *
	 *  GIVEN a .xxhash128 sidecar containing non-hex garbage;
	 *   WHEN pfb_hash_read($base) is called;
	 *   THEN it returns the "changed" sentinel.
	 */
	public function test_hash_read_corrupt_xxhash128_returns_changed_sentinel(): void
	{
		$base = $this->dir . '/corrupt.orig';
		// Write a sidecar with invalid (non-hex) content.
		file_put_contents($base . '.xxhash128', 'NOT-A-VALID-HEX-DIGEST-GARBAGE');

		$result = pfb_hash_read($base);

		$this->assertSame(
			'changed',
			$result['algo'],
			sprintf(
				'Expected changed sentinel for corrupt .xxhash128, got %s',
				var_export($result['algo'], TRUE)
			)
		);
	}

	/**
	 * .xxhash128 preferred over .md5 when both sidecars exist.
	 * The new extension takes priority on every read so a partial migration (both
	 * files present) always uses xxh128, never falls back to the stale md5.
	 *
	 *  GIVEN both .xxhash128 and .md5 sidecars exist;
	 *   WHEN pfb_hash_read($base) is called;
	 *   THEN it returns algo=xxh128 (the new sidecar wins).
	 */
	public function test_hash_read_xxhash128_preferred_over_md5(): void
	{
		$base    = $this->dir . '/both.orig';
		$content = 'content for priority test';
		$path    = $base;
		file_put_contents($path, $content);
		$xxh = pfb_content_hash($content, FALSE);
		$md5 = md5($content);

		file_put_contents($base . '.xxhash128', $xxh);
		file_put_contents($base . '.md5', $md5);

		$result = pfb_hash_read($base);

		$this->assertSame(
			'xxh128',
			$result['algo'],
			sprintf(
				'Expected .xxhash128 to be preferred over .md5 when both present, got algo=%s',
				var_export($result['algo'], TRUE)
			)
		);
		$this->assertSame(
			$xxh,
			$result['digest'],
			sprintf('Expected xxh128 digest %s, got %s', $xxh, $result['digest'])
		);
	}

	// -------------------------------------------------------------------------
	// pfb_local_feed_changed() — oracle-pin of today's decision
	// -------------------------------------------------------------------------

	/**
	 * Scenario: source file absent → changed (treat as first run / missing baseline).
	 * Fail-safe: absence of a file cannot mean "not changed."
	 *
	 *  GIVEN the source file does not exist;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns TRUE (changed).
	 */
	public function test_local_feed_changed_missing_source_is_changed(): void
	{
		$source = $this->dir . '/missing_source.txt';
		$orig   = $this->dir . '/feed.orig';
		file_put_contents($orig, 'some baseline');

		$this->assertFileDoesNotExist($source, 'Precondition: source must be absent');
		$result = pfb_local_feed_changed($source, $orig);

		$this->assertTrue(
			$result,
			'pfb_local_feed_changed() must return TRUE when source is missing'
		);
	}

	/**
	 * Scenario: .orig baseline absent → changed (no baseline = must re-ingest).
	 *
	 *  GIVEN the .orig file does not exist;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns TRUE (changed).
	 */
	public function test_local_feed_changed_missing_orig_is_changed(): void
	{
		$source = $this->dir . '/source.txt';
		$orig   = $this->dir . '/missing_orig.orig';
		file_put_contents($source, 'some source');

		$this->assertFileDoesNotExist($orig, 'Precondition: .orig must be absent');
		$result = pfb_local_feed_changed($source, $orig);

		$this->assertTrue(
			$result,
			'pfb_local_feed_changed() must return TRUE when .orig baseline is missing'
		);
	}

	/**
	 * Oracle: identical content + same mtime → not changed.
	 * Pins today's fast-path behaviour: same mtime = unchanged, skip md5.
	 *
	 *  GIVEN source and .orig with identical bytes and identical mtimes;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns FALSE (not changed).
	 */
	public function test_local_feed_changed_same_mtime_is_not_changed(): void
	{
		$source = $this->dir . '/same_mtime_source.txt';
		$orig   = $this->dir . '/same_mtime.orig';
		$content = 'identical content';
		file_put_contents($source, $content);
		file_put_contents($orig, $content);
		// Force both to the same mtime.
		$ts = time() - 100;
		touch($source, $ts);
		touch($orig, $ts);

		// Assert before-state: both files exist and share mtime.
		$this->assertSame(filemtime($source), filemtime($orig), 'Precondition: mtimes must be equal');

		$result = pfb_local_feed_changed($source, $orig);

		$this->assertFalse(
			$result,
			'pfb_local_feed_changed() must return FALSE when source and .orig have the same mtime'
		);
	}

	/**
	 * Oracle: different mtime AND identical content → not changed (#540 confirm).
	 * Pins the md5-confirm behaviour: a touch/cp that bumps mtime without changing
	 * bytes must NOT trigger re-ingest.
	 *
	 *  GIVEN source and .orig with the same bytes but different mtimes;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns FALSE (not changed — mtime was a false positive, md5 confirms).
	 */
	public function test_local_feed_changed_mtime_differs_but_content_same_is_not_changed(): void
	{
		$source  = $this->dir . '/mtime_differs_source.txt';
		$orig    = $this->dir . '/mtime_differs.orig';
		$content = 'byte-identical content';
		file_put_contents($source, $content);
		file_put_contents($orig, $content);
		// Force different mtimes.
		touch($source, time() - 200);
		touch($orig, time() - 100);

		// Assert before-state: files differ in mtime but have the same bytes.
		$this->assertNotSame(filemtime($source), filemtime($orig), 'Precondition: mtimes must differ');
		$this->assertSame(md5_file($source), md5_file($orig), 'Precondition: content must be identical');

		$result = pfb_local_feed_changed($source, $orig);

		$this->assertFalse(
			$result,
			'pfb_local_feed_changed() must return FALSE when bytes are identical (mtime-changed content-same)'
		);
	}

	/**
	 * Oracle: different mtime AND different content → changed.
	 * The core detection case: a real content change must always be detected.
	 *
	 *  GIVEN source and .orig with different bytes and different mtimes;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns TRUE (changed).
	 */
	public function test_local_feed_changed_different_content_is_changed(): void
	{
		$source = $this->dir . '/changed_source.txt';
		$orig   = $this->dir . '/changed.orig';
		file_put_contents($source, 'NEW content');
		file_put_contents($orig, 'OLD content');
		// Different mtimes.
		touch($source, time() - 50);
		touch($orig, time() - 200);

		// Assert before-state: content differs.
		$this->assertNotSame(md5_file($source), md5_file($orig), 'Precondition: content must differ');

		$result = pfb_local_feed_changed($source, $orig);

		$this->assertTrue(
			$result,
			'pfb_local_feed_changed() must return TRUE when source content has changed'
		);
	}

	/**
	 * Idempotence: calling pfb_local_feed_changed() twice in a row on the same
	 * unchanged pair returns FALSE both times.
	 * ADR-42 §2: "Identical content ⇒ identical hash ⇒ no re-ingest."
	 *
	 *  GIVEN an unchanged source + .orig pair (same mtime);
	 *   WHEN pfb_local_feed_changed() is called twice;
	 *   THEN both calls return FALSE.
	 */
	public function test_local_feed_changed_idempotent_on_unchanged_pair(): void
	{
		$source  = $this->dir . '/idem_source.txt';
		$orig    = $this->dir . '/idem.orig';
		$content = 'idempotence test';
		file_put_contents($source, $content);
		file_put_contents($orig, $content);
		$ts = time() - 100;
		touch($source, $ts);
		touch($orig, $ts);

		$first  = pfb_local_feed_changed($source, $orig);
		$second = pfb_local_feed_changed($source, $orig);

		$this->assertFalse(
			$first,
			sprintf('First call must return FALSE, got %s', var_export($first, TRUE))
		);
		$this->assertFalse(
			$second,
			sprintf('Second call must return FALSE (idempotent), got %s', var_export($second, TRUE))
		);
	}
}
