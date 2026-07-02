<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-42 Phase 1 + Phase 2 — hash helpers and local-feed change-detection.
 *
 * Tests cover:
 *   pfb_content_hash()      — xxh128 of a file or a string; known-answer vector.
 *   pfb_hash_read()         — tagged sidecar read: .xxhash128 (new), .md5 (legacy),
 *                             no sidecar → "changed" sentinel.
 *   pfb_hash_write()        — writes .xxhash128, deletes superseded .md5; round-trip.
 *   pfb_local_feed_changed() — ADR-42 Phase 2 content-hash gate (mtime removed):
 *                             content-identical → FALSE; content-different → TRUE;
 *                             legacy .md5 sidecar read + migration; absent sidecar
 *                             falls back to live .orig hash; idempotence guard.
 *   pfb_source_hash_target() — issue #713 bug 5: resolves which on-disk file (the raw
 *                             '.raw' download or the finalised '.orig') holds the SAME
 *                             bytes the change-detection probe hashes, so a compressed
 *                             feed's persisted sidecar and the probe's body hash cover
 *                             one consistent domain of bytes instead of silently
 *                             comparing compressed-vs-decompressed and never matching.
 *
 * Every test carries a failable assertion.
 */
#[CoversFunction('pfb_content_hash')]
#[CoversFunction('pfb_hash_read')]
#[CoversFunction('pfb_hash_write')]
#[CoversFunction('pfb_local_feed_changed')]
#[CoversFunction('pfb_source_hash_target')]
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
	// pfb_local_feed_changed() — ADR-42 Phase 2 content-hash gate
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
	 * Phase 2: identical content with .xxhash128 sidecar → not changed.
	 * The core no-change path: source == .orig bytes, sidecar present and valid.
	 * Mtime is irrelevant — the gate is entirely content-addressed.
	 *
	 *  GIVEN source and .orig with identical bytes and a matching .xxhash128 sidecar;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns FALSE (not changed).
	 */
	public function test_local_feed_changed_identical_content_with_sidecar_is_not_changed(): void
	{
		$content = 'identical content';
		$source  = $this->dir . '/identical_source.txt';
		$orig    = $this->dir . '/identical.orig';
		file_put_contents($source, $content);
		file_put_contents($orig, $content);
		// Write the sidecar that pfb_download would have written at last ingest.
		pfb_hash_write($orig, $orig);

		// Precondition: .xxhash128 sidecar exists and reads back xxh128.
		$sidecar = pfb_hash_read($orig);
		$this->assertSame('xxh128', $sidecar['algo'], 'Precondition: sidecar must be xxh128');

		$result = pfb_local_feed_changed($source, $orig);

		$this->assertFalse(
			$result,
			'pfb_local_feed_changed() must return FALSE when source content matches the .xxhash128 sidecar'
		);
	}

	/**
	 * Phase 2: different content with .xxhash128 sidecar → changed.
	 * The core detection case: a real content change must always be detected,
	 * regardless of mtime. The sidecar holds the OLD .orig hash; the new source differs.
	 *
	 *  GIVEN a .xxhash128 sidecar seeded from OLD content, then source rewritten with NEW content;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns TRUE (changed).
	 *
	 * RED on pre-Phase-2 code: equal mtime (explicitly forced) would return FALSE here.
	 */
	public function test_local_feed_changed_different_content_with_sidecar_is_changed(): void
	{
		$source = $this->dir . '/changed_source.txt';
		$orig   = $this->dir . '/changed.orig';
		file_put_contents($source, 'OLD content');
		file_put_contents($orig,   'OLD content');
		// Seed sidecar from OLD .orig — simulates a completed prior ingest.
		pfb_hash_write($orig, $orig);
		// Now rewrite source WITHOUT updating the .orig or sidecar — simulates an
		// in-place local feed edit.
		file_put_contents($source, 'NEW content');

		// Force EQUAL mtime so the old mtime gate would have returned FALSE here
		// (this is the pre-Phase-2 blind spot: same mtime, different content).
		$ts = time() - 100;
		touch($source, $ts);
		touch($orig,   $ts);

		// Precondition: mtimes equal, content differs.
		$this->assertSame(filemtime($source), filemtime($orig), 'Precondition: mtimes forced equal');
		$this->assertNotSame(
			pfb_content_hash($source, TRUE),
			pfb_content_hash($orig, TRUE),
			'Precondition: source and .orig must have different hashes'
		);

		$result = pfb_local_feed_changed($source, $orig);

		$this->assertTrue(
			$result,
			'pfb_local_feed_changed() must return TRUE when source hash differs from sidecar '
			. '(the same-second blind spot: equal mtime but different content)'
		);
	}

	/**
	 * Phase 2: legacy .md5 sidecar — reads correctly as md5 and detects a content change.
	 * After detection and a simulated ingest (pfb_hash_write), the legacy sidecar is
	 * migrated: .md5 removed, .xxhash128 written.
	 *
	 *  GIVEN a .md5 sidecar seeded from OLD content, source rewritten with NEW content;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called (step 1 — detect);
	 *   THEN it returns TRUE (legacy md5 baseline compared correctly, change detected).
	 *  WHEN pfb_hash_write($orig, $orig) is called (step 2 — simulate ingest);
	 *   THEN the .md5 sidecar is removed and a .xxhash128 sidecar is present.
	 */
	public function test_local_feed_changed_legacy_md5_sidecar_detects_change_and_migrates(): void
	{
		$source = $this->dir . '/legacy_source.txt';
		$orig   = $this->dir . '/legacy.orig';
		file_put_contents($source, 'OLD');
		file_put_contents($orig,   'OLD');
		// Plant a legacy .md5 sidecar (as if written by the pre-Phase-2 code).
		file_put_contents($orig . '.md5', md5_file($orig));
		$this->assertFileDoesNotExist($orig . '.xxhash128', 'Precondition: no .xxhash128 yet');

		// Rewrite source with new content — simulates an in-place feed edit.
		file_put_contents($source, 'NEW');

		// Step 1: detect.
		$result = pfb_local_feed_changed($source, $orig);
		$this->assertTrue(
			$result,
			'pfb_local_feed_changed() must return TRUE when source md5 differs from legacy .md5 sidecar'
		);

		// Step 2: simulate ingest — pfb_hash_write runs inside pfb_download after .orig update.
		file_put_contents($orig, 'NEW'); // .orig updated to new content
		pfb_hash_write($orig, $orig);

		// Migration: .md5 gone, .xxhash128 present.
		$this->assertFileDoesNotExist($orig . '.md5', 'pfb_hash_write() must delete legacy .md5 sidecar');
		$this->assertFileExists($orig . '.xxhash128', 'pfb_hash_write() must create .xxhash128 sidecar');
	}

	/**
	 * Phase 2: absent sidecar — falls back to live-hashing the .orig as baseline.
	 * Covers the first-pass-after-upgrade case: .orig exists but no sidecar yet.
	 * If source == .orig bytes → not changed (new install / upgrade, no prior sidecar).
	 *
	 *  GIVEN source == .orig bytes, no sidecar;
	 *   WHEN pfb_local_feed_changed($source, $orig) is called;
	 *   THEN it returns FALSE (content matches live .orig hash).
	 */
	public function test_local_feed_changed_absent_sidecar_falls_back_to_live_orig_hash(): void
	{
		$content = 'first run content';
		$source  = $this->dir . '/nosidecar_source.txt';
		$orig    = $this->dir . '/nosidecar.orig';
		file_put_contents($source, $content);
		file_put_contents($orig,   $content);
		// Ensure no sidecar exists.
		$this->assertFileDoesNotExist($orig . '.xxhash128', 'Precondition: no .xxhash128');
		$this->assertFileDoesNotExist($orig . '.md5', 'Precondition: no .md5');

		$result = pfb_local_feed_changed($source, $orig);

		$this->assertFalse(
			$result,
			'pfb_local_feed_changed() must return FALSE when source matches the live .orig (no sidecar)'
		);
	}

	/**
	 * Phase 2 idempotence: calling pfb_local_feed_changed() twice after a completed ingest
	 * (sidecar written by pfb_hash_write) returns FALSE BOTH times — no perpetual re-ingest.
	 *
	 * This is the anti-staleness guard: if the sidecar were NOT refreshed at ingest, the
	 * second call would compare the new source against the OLD sidecar and falsely return TRUE.
	 *
	 *  GIVEN a fresh .xxhash128 sidecar matching unchanged source and .orig;
	 *   WHEN pfb_local_feed_changed() is called twice;
	 *   THEN both return FALSE (the sidecar is correct, no re-ingest triggered).
	 *
	 * RED on pre-Phase-2 code: if pfb_local_feed_changed writes the sidecar (instead of
	 * pfb_download), the second call would see a stale sidecar and return TRUE.
	 */
	public function test_local_feed_changed_idempotent_after_ingest_with_sidecar(): void
	{
		$content = 'idempotence test';
		$source  = $this->dir . '/idem_source.txt';
		$orig    = $this->dir . '/idem.orig';
		file_put_contents($source, $content);
		file_put_contents($orig,   $content);
		// Simulate a completed ingest: pfb_hash_write writes the sidecar from the .orig.
		pfb_hash_write($orig, $orig);

		// Precondition: sidecar present.
		$this->assertFileExists($orig . '.xxhash128', 'Precondition: .xxhash128 sidecar must exist');

		$first  = pfb_local_feed_changed($source, $orig);
		$second = pfb_local_feed_changed($source, $orig);

		$this->assertFalse(
			$first,
			sprintf('First call must return FALSE (content unchanged), got %s', var_export($first, TRUE))
		);
		$this->assertFalse(
			$second,
			sprintf('Second call must return FALSE (idempotent — no perpetual re-ingest), got %s', var_export($second, TRUE))
		);
	}

	// -------------------------------------------------------------------------
	// pfb_source_hash_target() — issue #713 bug 5: raw-vs-orig sidecar target
	// -------------------------------------------------------------------------

	/**
	 * Compressed feed: the raw '.raw' download is still on disk (gunzip/bzip2/tar/7z
	 * never delete their source archive) — it must be preferred, since it holds the
	 * SAME bytes the probe hashes (pfb_download() in change_detect mode returns before
	 * any decompression).
	 *
	 *  GIVEN both the raw download and the decompressed .orig exist on disk;
	 *   WHEN pfb_source_hash_target($file_download, $orig_download) is called;
	 *   THEN it returns the raw download path, not the decompressed .orig.
	 */
	public function test_source_hash_target_prefers_raw_when_present(): void
	{
		$raw  = $this->dir . '/compressed.raw';
		$orig = $this->dir . '/compressed.orig';
		file_put_contents($raw, 'RAW COMPRESSED BYTES');
		file_put_contents($orig, 'DECOMPRESSED BYTES');

		$target = pfb_source_hash_target($raw, $orig);

		$this->assertSame(
			$raw,
			$target,
			sprintf(
				'When the raw fetched download still exists (compressed feed), it must be '
				. 'preferred over the decompressed .orig — the probe hashes these same raw '
				. 'bytes (expected %s, got %s)',
				$raw,
				var_export($target, TRUE)
			)
		);
	}

	/**
	 * Uncompressed feed: pfb_download() @rename()s the raw download straight onto
	 * $orig_download, so the raw path no longer exists on disk by the time the sidecar
	 * is written. Falling back to $orig_download is exact (byte-identical), not an
	 * approximation.
	 *
	 *  GIVEN the raw download path does not exist (already renamed onto .orig);
	 *   WHEN pfb_source_hash_target($file_download, $orig_download) is called;
	 *   THEN it returns the .orig path.
	 */
	public function test_source_hash_target_falls_back_to_orig_when_raw_absent(): void
	{
		$missing_raw = $this->dir . '/uncompressed.raw';
		$orig        = $this->dir . '/uncompressed.orig';
		file_put_contents($orig, 'plain feed content');

		$this->assertFileDoesNotExist(
			$missing_raw,
			'Precondition: the raw download was renamed onto .orig and no longer exists'
		);

		$target = pfb_source_hash_target($missing_raw, $orig);

		$this->assertSame(
			$orig,
			$target,
			sprintf(
				'When the raw download no longer exists, fall back to .orig (expected %s, got %s)',
				$orig,
				var_export($target, TRUE)
			)
		);
	}

	// -------------------------------------------------------------------------
	// Integration: the probe and the persisted sidecar must agree on a compressed feed
	// -------------------------------------------------------------------------

	/**
	 * The bug (issue #713 bug 5): the change-detection probe (pfb_update_check ->
	 * pfb_download($type='change_detect')) hashes the RAW fetched body — it returns
	 * before any decompression. For a compressed feed, ingest used to persist the
	 * sidecar from the DECOMPRESSED .orig instead, so the two hashes covered different
	 * bytes and could never match — every cron re-ingested a compressed feed even when
	 * the server returned byte-identical content.
	 *
	 * This test reproduces both sides of that comparison with the real hash helpers:
	 * ingest persists via pfb_source_hash_target() (the fix), the probe re-fetches the
	 * SAME compressed bytes (server unchanged), and pfb_conditional_get_decision() must
	 * report "unchanged".
	 *
	 *  GIVEN a compressed feed ingested once (raw gzip body decompressed to .orig, sidecar
	 *        persisted from pfb_source_hash_target($file_download, $orig_download));
	 *   WHEN a later probe re-fetches byte-identical compressed bytes and its body hash is
	 *        compared against the persisted sidecar via pfb_conditional_get_decision();
	 *   THEN the decision is "unchanged" (FALSE) — no needless re-ingest.
	 *
	 * RED on the pre-fix code: pfb_source_hash_target() does not exist there, and the old
	 * call site hashed $orig_download (decompressed) directly — the sanity assertion below
	 * proves that would have produced a DIFFERENT digest than the probe's raw body hash,
	 * i.e. pfb_conditional_get_decision() would have returned TRUE (changed) instead.
	 */
	public function test_compressed_feed_unchanged_is_detected_via_raw_hash(): void
	{
		// GIVEN: a compressed feed body, ingested once.
		$content   = "ip 192.0.2.1\nip 192.0.2.2\n";
		$raw_bytes = gzencode($content, 9);

		$file_download = $this->dir . '/feed.raw';
		$orig_download = $this->dir . '/feed.orig';
		file_put_contents($file_download, $raw_bytes);
		// Mirrors `gunzip -c {raw} > {orig}` in pfb_download(): decompressed content,
		// raw archive left intact on disk.
		file_put_contents($orig_download, gzdecode($raw_bytes));

		// Ingest persists the source-hash sidecar via the fixed target-resolution helper.
		$hash_target = pfb_source_hash_target($file_download, $orig_download);
		$write_ok    = pfb_hash_write($orig_download, $hash_target);
		$this->assertTrue($write_ok, 'Precondition: pfb_hash_write() must succeed for the ingest sidecar');

		$persisted = pfb_hash_read($orig_download);
		$this->assertSame(
			'xxh128',
			$persisted['algo'],
			'Precondition: the ingest sidecar must be written as xxh128'
		);

		// WHEN: a later cron probe re-fetches the SAME compressed bytes (server unchanged
		// — pfb_download($type='change_detect') writes the raw body to {header}.md5.raw
		// and returns before decompressing).
		$probe_raw = $this->dir . '/feed.md5.raw';
		file_put_contents($probe_raw, $raw_bytes);
		$body_hash = pfb_content_hash($probe_raw, TRUE);

		$changed = pfb_conditional_get_decision('200', $body_hash, $persisted['digest']);

		// THEN: correctly detected as unchanged — no needless re-ingest.
		$this->assertFalse(
			$changed,
			sprintf(
				'A compressed feed with byte-identical content on re-fetch must be reported '
				. 'unchanged (body_hash=%s, persisted_hash=%s)',
				var_export($body_hash, TRUE),
				var_export($persisted['digest'], TRUE)
			)
		);

		// RED-proof sanity check: hashing the DECOMPRESSED .orig directly (the pre-fix
		// call site: pfb_hash_write($orig_download, $orig_download)) produces a digest
		// that can NEVER equal the probe's raw (compressed) body hash — proving the two
		// sides compared different bytes before this fix.
		$broken_persisted_hash = pfb_content_hash($orig_download, TRUE);
		$this->assertNotSame(
			$body_hash,
			$broken_persisted_hash,
			'Sanity: the probe\'s raw (compressed) body hash must differ from the hash of the '
			. 'decompressed .orig — this is exactly why the pre-fix code (which persisted the '
			. 'latter) could never match and forced a false "changed" on every cron'
		);
		$this->assertTrue(
			pfb_conditional_get_decision('200', $body_hash, $broken_persisted_hash),
			'Sanity: comparing the probe body hash against the pre-fix (decompressed) '
			. 'persisted hash must yield "changed" — reproducing the reported defect'
		);
	}

	/**
	 * Branch coverage: a REAL content change on a compressed feed must still be detected
	 * as "changed" — the fix must not overcorrect into a false "unchanged".
	 *
	 *  GIVEN a compressed feed ingested once, then the upstream body genuinely changes;
	 *   WHEN the probe's re-fetched (different) compressed bytes are compared against the
	 *        persisted sidecar via pfb_conditional_get_decision();
	 *   THEN the decision is "changed" (TRUE) — re-ingest happens.
	 */
	public function test_compressed_feed_real_change_is_still_detected(): void
	{
		$old_bytes = gzencode("ip 192.0.2.1\n", 9);
		$new_bytes = gzencode("ip 192.0.2.1\nip 192.0.2.99\n", 9);

		$file_download = $this->dir . '/feed2.raw';
		$orig_download = $this->dir . '/feed2.orig';
		file_put_contents($file_download, $old_bytes);
		file_put_contents($orig_download, gzdecode($old_bytes));

		pfb_hash_write($orig_download, pfb_source_hash_target($file_download, $orig_download));
		$persisted = pfb_hash_read($orig_download);

		// A later probe fetches the genuinely-updated compressed body.
		$probe_raw = $this->dir . '/feed2.md5.raw';
		file_put_contents($probe_raw, $new_bytes);
		$body_hash = pfb_content_hash($probe_raw, TRUE);

		$changed = pfb_conditional_get_decision('200', $body_hash, $persisted['digest']);

		$this->assertTrue(
			$changed,
			'A genuinely updated compressed feed body must still be detected as changed'
		);
	}

	/**
	 * Regression guard: an UNCOMPRESSED feed's unchanged round-trip must be unaffected by
	 * this fix — pfb_source_hash_target() falls back to .orig there, which already holds
	 * the exact fetched bytes (no decompression step).
	 *
	 *  GIVEN an uncompressed feed ingested once via pfb_source_hash_target();
	 *   WHEN a later probe re-fetches byte-identical content;
	 *   THEN pfb_conditional_get_decision() still reports "unchanged".
	 */
	public function test_uncompressed_feed_unchanged_round_trip_is_unaffected(): void
	{
		$content = "ip 192.0.2.1\nip 192.0.2.2\n";

		// Mirrors pfb_download(): the raw download is @rename()'d onto .orig for an
		// uncompressed feed, so only .orig exists by ingest-sidecar time.
		$missing_raw   = $this->dir . '/plain.raw';
		$orig_download = $this->dir . '/plain.orig';
		file_put_contents($orig_download, $content);

		pfb_hash_write($orig_download, pfb_source_hash_target($missing_raw, $orig_download));
		$persisted = pfb_hash_read($orig_download);
		$this->assertSame('xxh128', $persisted['algo'], 'Precondition: ingest sidecar written as xxh128');

		// The probe's raw body for an uncompressed feed IS the fetched content verbatim.
		$probe_raw = $this->dir . '/plain.md5.raw';
		file_put_contents($probe_raw, $content);
		$body_hash = pfb_content_hash($probe_raw, TRUE);

		$changed = pfb_conditional_get_decision('200', $body_hash, $persisted['digest']);

		$this->assertFalse(
			$changed,
			'An uncompressed feed with byte-identical content on re-fetch must still be '
			. 'reported unchanged (regression guard for this fix)'
		);
	}
}
