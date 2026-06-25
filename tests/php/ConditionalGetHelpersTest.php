<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-42 Phase 3 — conditional-GET helpers.
 *
 * Tests cover:
 *   pfb_validator_read()           — reads .etag and .lastmod sidecars; absent / corrupt = FALSE.
 *   pfb_validator_write()          — writes .etag and .lastmod sidecars; skips empty/zero values.
 *   pfb_conditional_get_decision() — pure decision: 304→unchanged; 200+same→unchanged;
 *                                    200+different→changed; 200+no-baseline→changed (fail-safe);
 *                                    unknown status→changed (fail-safe).
 *
 * Every test carries a failable assertion.  The curl wiring (sending If-None-Match /
 * CURLOPT_TIMECONDITION and receiving the real 304) is exercised by Phase 5 live-VM smoke cases.
 */
#[CoversFunction('pfb_validator_read')]
#[CoversFunction('pfb_validator_write')]
#[CoversFunction('pfb_conditional_get_decision')]
final class ConditionalGetHelpersTest extends TestCase
{
	/** @var string Writable temp directory for this test class. */
	private string $dir;

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_cget_test_' . getmypid() . '_' . mt_rand(0, 0xffff);
		if (!mkdir($base, 0777, TRUE)) {
			$this->fail("Could not create temp dir: {$base}");
		}
		$this->dir = $base;
	}

	protected function tearDown(): void
	{
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
	// pfb_validator_read() — reads .etag and .lastmod sidecars
	// -------------------------------------------------------------------------

	/**
	 * No sidecars → both values are FALSE.
	 *
	 *  GIVEN neither .etag nor .lastmod sidecar exists;
	 *   WHEN pfb_validator_read($base) is called;
	 *   THEN it returns ['etag' => FALSE, 'lastmod' => FALSE].
	 */
	public function test_validator_read_no_sidecars_returns_false(): void
	{
		$base   = $this->dir . '/feed.orig';
		$result = pfb_validator_read($base);

		$this->assertFalse(
			$result['etag'],
			sprintf('Expected etag=FALSE when no .etag sidecar, got %s', var_export($result['etag'], TRUE))
		);
		$this->assertFalse(
			$result['lastmod'],
			sprintf('Expected lastmod=FALSE when no .lastmod sidecar, got %s', var_export($result['lastmod'], TRUE))
		);
	}

	/**
	 * Both sidecars present → both values returned correctly.
	 *
	 *  GIVEN .etag and .lastmod sidecars with valid contents;
	 *   WHEN pfb_validator_read($base) is called;
	 *   THEN it returns the stored ETag string and the stored epoch integer.
	 */
	public function test_validator_read_returns_stored_values(): void
	{
		$base  = $this->dir . '/feed2.orig';
		$etag  = '"abc123def456"';
		$epoch = 1700000000;
		file_put_contents($base . '.etag',    $etag);
		file_put_contents($base . '.lastmod', (string) $epoch);

		$result = pfb_validator_read($base);

		$this->assertSame(
			$etag,
			$result['etag'],
			sprintf('Expected etag=%s, got %s', $etag, var_export($result['etag'], TRUE))
		);
		$this->assertSame(
			$epoch,
			$result['lastmod'],
			sprintf('Expected lastmod=%d, got %s', $epoch, var_export($result['lastmod'], TRUE))
		);
	}

	/**
	 * .lastmod sidecar with non-numeric content → FALSE (corrupt/invalid).
	 *
	 *  GIVEN a .lastmod sidecar containing non-decimal garbage;
	 *   WHEN pfb_validator_read($base) is called;
	 *   THEN lastmod is FALSE (corrupt → ignored, fail-safe).
	 */
	public function test_validator_read_corrupt_lastmod_returns_false(): void
	{
		$base = $this->dir . '/feed3.orig';
		file_put_contents($base . '.lastmod', 'NOT-A-NUMBER');

		$result = pfb_validator_read($base);

		$this->assertFalse(
			$result['lastmod'],
			sprintf('Expected lastmod=FALSE for corrupt sidecar, got %s', var_export($result['lastmod'], TRUE))
		);
	}

	/**
	 * .etag sidecar with empty content → FALSE (blank is not a valid ETag).
	 *
	 *  GIVEN a .etag sidecar containing only whitespace;
	 *   WHEN pfb_validator_read($base) is called;
	 *   THEN etag is FALSE.
	 */
	public function test_validator_read_empty_etag_returns_false(): void
	{
		$base = $this->dir . '/feed4.orig';
		file_put_contents($base . '.etag', "  \n");

		$result = pfb_validator_read($base);

		$this->assertFalse(
			$result['etag'],
			sprintf('Expected etag=FALSE for empty/whitespace sidecar, got %s', var_export($result['etag'], TRUE))
		);
	}

	// -------------------------------------------------------------------------
	// pfb_validator_write() — writes .etag and .lastmod sidecars
	// -------------------------------------------------------------------------

	/**
	 * Write both values → sidecars created with correct content.
	 *
	 *  GIVEN a valid ETag string and a positive lastmod epoch;
	 *   WHEN pfb_validator_write($base, $etag, $lastmod) is called;
	 *   THEN both sidecar files are created and readable by pfb_validator_read().
	 */
	public function test_validator_write_creates_sidecars(): void
	{
		$base    = $this->dir . '/feed5.orig';
		$etag    = '"strongETag"';
		$lastmod = 1750000000;

		pfb_validator_write($base, $etag, $lastmod);

		$this->assertFileExists($base . '.etag',    'pfb_validator_write must create .etag sidecar');
		$this->assertFileExists($base . '.lastmod', 'pfb_validator_write must create .lastmod sidecar');

		$result = pfb_validator_read($base);
		$this->assertSame(
			$etag,
			$result['etag'],
			sprintf('Round-trip: expected etag=%s, got %s', $etag, var_export($result['etag'], TRUE))
		);
		$this->assertSame(
			$lastmod,
			$result['lastmod'],
			sprintf('Round-trip: expected lastmod=%d, got %s', $lastmod, var_export($result['lastmod'], TRUE))
		);
	}

	/**
	 * Write with FALSE/empty etag and zero lastmod → NO sidecars created.
	 * pfb_validator_write must skip writing empty/zero values — writing an empty sidecar
	 * would be worse than no sidecar (it would return FALSE on read, same as absent).
	 *
	 *  GIVEN etag=FALSE and lastmod=0;
	 *   WHEN pfb_validator_write($base, FALSE, 0) is called;
	 *   THEN no .etag or .lastmod file is created.
	 */
	public function test_validator_write_skips_empty_values(): void
	{
		$base = $this->dir . '/feed6.orig';

		pfb_validator_write($base, FALSE, 0);

		$this->assertFileDoesNotExist($base . '.etag',    'pfb_validator_write must NOT write .etag for FALSE');
		$this->assertFileDoesNotExist($base . '.lastmod', 'pfb_validator_write must NOT write .lastmod for 0');
	}

	// -------------------------------------------------------------------------
	// pfb_conditional_get_decision() — pure decision helper
	// -------------------------------------------------------------------------

	/**
	 * 304 → unchanged (the primary conditional-GET win).
	 *
	 *  GIVEN http_status='304';
	 *   WHEN pfb_conditional_get_decision('304', any, any) is called;
	 *   THEN it returns FALSE (not changed — server confirmed).
	 *
	 * RED on a broken impl that treats 304 as 200 or ignores it.
	 */
	public function test_decision_304_is_unchanged(): void
	{
		$result = pfb_conditional_get_decision('304', 'somehash', 'somehash');

		$this->assertFalse(
			$result,
			'304 response must return FALSE (unchanged — server confirmed not-modified)'
		);
	}

	/**
	 * 304 is unchanged even when body_hash and persisted_hash differ (body was not sent).
	 * The 304 contract: the server PROMISES the body is the same; body_hash is irrelevant.
	 *
	 *  GIVEN http_status='304' and intentionally mismatched hashes;
	 *   WHEN pfb_conditional_get_decision is called;
	 *   THEN it still returns FALSE (304 wins regardless of hash arguments).
	 */
	public function test_decision_304_unchanged_regardless_of_hash_arguments(): void
	{
		$result = pfb_conditional_get_decision('304', 'aaaa', 'bbbb');

		$this->assertFalse(
			$result,
			'304 must return FALSE even when hashes differ (body was not sent; hash is irrelevant)'
		);
	}

	/**
	 * 200 with matching hashes → unchanged (spurious 200; server returned same bytes).
	 * ADR-42 §2 contract #5: a spurious 200 with identical bytes does NOT re-ingest.
	 *
	 *  GIVEN http_status='200', body_hash == persisted_hash;
	 *   WHEN pfb_conditional_get_decision is called;
	 *   THEN it returns FALSE (not changed).
	 *
	 * RED on a broken impl that treats every 200 as changed.
	 */
	public function test_decision_200_same_bytes_is_unchanged(): void
	{
		$digest = '4a2690170244f2e853151c59fbcb2105'; // known xxh128 vector
		$result = pfb_conditional_get_decision('200', $digest, $digest);

		$this->assertFalse(
			$result,
			sprintf(
				'200 with same body_hash and persisted_hash must return FALSE (spurious 200, same bytes) '
				. '(body_hash=%s, persisted=%s)',
				$digest,
				$digest
			)
		);
	}

	/**
	 * 200 with different hashes → changed (real update detected).
	 *
	 *  GIVEN http_status='200', body_hash != persisted_hash;
	 *   WHEN pfb_conditional_get_decision is called;
	 *   THEN it returns TRUE (changed — re-ingest needed).
	 *
	 * RED on a broken impl that only checks status and ignores the hash comparison.
	 */
	public function test_decision_200_different_bytes_is_changed(): void
	{
		$result = pfb_conditional_get_decision('200', 'aaaabbbbccccdddd', 'xxxxyyyyzzzz0000');

		$this->assertTrue(
			$result,
			'200 with different body_hash and persisted_hash must return TRUE (changed — real update)'
		);
	}

	/**
	 * 200 with no persisted hash (empty string) → changed (fail-safe; no baseline).
	 * ADR-42 §2 contract #6: absence of a baseline cannot confirm unchanged.
	 *
	 *  GIVEN http_status='200', persisted_hash='';
	 *   WHEN pfb_conditional_get_decision is called;
	 *   THEN it returns TRUE (fail-safe — cannot confirm unchanged without a baseline).
	 *
	 * RED on a broken impl that treats no-baseline as unchanged.
	 */
	public function test_decision_200_no_persisted_hash_is_changed(): void
	{
		$result = pfb_conditional_get_decision('200', 'somehash', '');

		$this->assertTrue(
			$result,
			'200 with empty persisted_hash must return TRUE (fail-safe — no baseline to compare)'
		);
	}

	/**
	 * 200 with body_hash=FALSE (unreadable body) → changed (fail-safe).
	 *
	 *  GIVEN http_status='200', body_hash=FALSE;
	 *   WHEN pfb_conditional_get_decision is called;
	 *   THEN it returns TRUE (fail-safe — body unreadable, cannot confirm unchanged).
	 */
	public function test_decision_200_unreadable_body_is_changed(): void
	{
		$result = pfb_conditional_get_decision('200', FALSE, 'somehash');

		$this->assertTrue(
			$result,
			'200 with body_hash=FALSE must return TRUE (fail-safe — body unreadable)'
		);
	}

	/**
	 * Unknown / error status → changed (fail-safe).
	 * ADR-42 §2 contract #6: ambiguity must never produce a false "unchanged" skip.
	 *
	 *  GIVEN http_status is neither '200' nor '304' (e.g. '500', '000', '');
	 *   WHEN pfb_conditional_get_decision is called;
	 *   THEN it returns TRUE (fail-safe — re-ingest rather than skip on ambiguity).
	 *
	 * RED on a broken impl that defaults to FALSE for unknown statuses.
	 */
	public function test_decision_unknown_status_is_changed(): void
	{
		foreach (['500', '000', '', '403', '503'] as $status) {
			$result = pfb_conditional_get_decision($status, 'samehash', 'samehash');
			$this->assertTrue(
				$result,
				sprintf(
					'Unknown/error status %s must return TRUE (fail-safe — re-ingest on ambiguity)',
					var_export($status, TRUE)
				)
			);
		}
	}
}
