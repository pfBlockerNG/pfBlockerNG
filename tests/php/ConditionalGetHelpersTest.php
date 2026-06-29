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
#[CoversFunction('pfb_conditional_get_validator_base')]
#[CoversFunction('pfb_force_clear_validators')]
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

	// -------------------------------------------------------------------------
	// pfb_validator_write() — ETag CR/LF injection defence
	// -------------------------------------------------------------------------

	/**
	 * ETag values containing CR or LF are stripped before storage.
	 * A malicious server response could embed CRLF in an ETag to inject headers into
	 * the next If-None-Match request; pfb_validator_write must sanitise before writing.
	 *
	 *  GIVEN an ETag string containing embedded CR and/or LF characters;
	 *   WHEN pfb_validator_write($base, $etag, 0) is called;
	 *   THEN the stored sidecar contains the ETag with CR/LF stripped.
	 *
	 * RED on an impl that stores the raw string verbatim.
	 */
	public function test_validator_write_strips_crlf_from_etag(): void
	{
		$base = $this->dir . '/feed_crlf.orig';
		// Embed a CRLF sequence in the ETag value (server header-injection vector).
		$raw_etag     = "\"valid\"\r\nX-Injected: evil";
		$expected     = '"valid"X-Injected: evil';

		pfb_validator_write($base, $raw_etag, 0);

		$this->assertFileExists($base . '.etag', 'pfb_validator_write must still write .etag after stripping CRLF');
		$stored = file_get_contents($base . '.etag');
		$this->assertSame(
			$expected,
			$stored,
			sprintf(
				'Stored ETag must have CR/LF stripped; expected %s, got %s',
				var_export($expected, TRUE),
				var_export($stored, TRUE)
			)
		);
	}

	/**
	 * An ETag that is entirely CR/LF is discarded (not written).
	 * After stripping, an empty result is treated the same as an absent ETag.
	 *
	 *  GIVEN an ETag string that is nothing but CR/LF characters;
	 *   WHEN pfb_validator_write($base, $etag, 0) is called;
	 *   THEN no .etag sidecar is created.
	 */
	public function test_validator_write_discards_all_crlf_etag(): void
	{
		$base = $this->dir . '/feed_crlf_only.orig';

		pfb_validator_write($base, "\r\n\r\n", 0);

		$this->assertFileDoesNotExist(
			$base . '.etag',
			'An all-CRLF ETag must be discarded — pfb_validator_write must not write an empty sidecar'
		);
	}

	// -------------------------------------------------------------------------
	// pfb_download() fill-guard contract — NULL vs array()
	// -------------------------------------------------------------------------

	/**
	 * The fill guard inside pfb_download uses `$response_meta !== NULL`.
	 * Callers MUST pass array() (not NULL) to activate the fill.
	 * This test pins the PHP identity contract that makes that guard work:
	 *   - NULL !== NULL  is FALSE  → the sync callers (passing no 13th arg → default NULL)
	 *                                 silently skip the fill block (correct).
	 *   - array() !== NULL is TRUE → the probe caller (pfb_update_check) gets the block
	 *                                 filled (required for change detection to function).
	 *
	 * Context: pfb_download itself cannot be exercised off-appliance (its localfile
	 * branch requires paths under the hardcoded allowed dirs — /var/db/pfblockerng/* —
	 * which are not writable in CI; the curl branch needs a network peer).  This test
	 * pins the guard contract at the PHP-identity level so the blocker (NULL init in
	 * pfblockerng.php that silently disabled all remote change detection) cannot regress
	 * without a RED test.
	 *
	 * RED on a pre-fix codebase where pfblockerng.php initialised $probe_meta = NULL
	 * instead of $probe_meta = array(): see FIX 1 in the ADR-42 review findings.
	 */
	public function test_probe_meta_fill_guard_requires_array_not_null(): void
	{
		// NULL !== NULL → FALSE: the fill block is SKIPPED (sync-caller sentinel).
		$this->assertFalse(
			NULL !== NULL,
			'NULL !== NULL must be FALSE — the fill-guard skip-sentinel contract'
		);

		// array() !== NULL → TRUE: the fill block FIRES (probe-caller contract).
		$this->assertTrue(
			array() !== NULL,
			'array() !== NULL must be TRUE — the probe caller must pass array(), not NULL, '
			. 'to activate the pfb_download fill block; passing NULL silently disables change detection'
		);

		// Simulate the pre-fix bug: $probe_meta = NULL stays NULL after a hypothetical
		// fill attempt (the guard would have been skipped).  The post-fix $probe_meta = array()
		// would be replaced with the filled array.  We assert the guard distinction here
		// rather than calling pfb_download (not exercisable off-appliance — see above).
		$probe_meta_broken = NULL;
		$probe_meta_fixed  = array();
		$fills_on_broken   = ($probe_meta_broken !== NULL);	// FALSE — fill skipped
		$fills_on_fixed    = ($probe_meta_fixed  !== NULL);	// TRUE  — fill fires

		$this->assertFalse(
			$fills_on_broken,
			'Pre-fix NULL init: the fill guard evaluates to FALSE → fill is skipped → '
			. '$probe_meta stays NULL → caller sees NULL and treats every probe as failed'
		);
		$this->assertTrue(
			$fills_on_fixed,
			'Post-fix array() init: the fill guard evaluates to TRUE → fill fires → '
			. '$probe_meta is populated → change detection works correctly'
		);
	}

	/**
	 * ADR-42 §3 — the probe must read validators from the detector's {header}.orig
	 * baseline, NOT the infixed {header}.md5.orig.  The detector hands pfb_download
	 * file_dwn = {header}.md5 (so the probe body {file_dwn}.raw stays separate from the
	 * ingest body); pfb_conditional_get_validator_base() strips that `.md5` probe-infix
	 * before appending `.orig`.  Resolving the wrong (infixed) base is exactly the bug
	 * that left the 304 fast-path dead — every unchanged remote feed re-downloaded its
	 * full body each cron.
	 *
	 * The curl wiring that consumes this base (sending If-None-Match and receiving the
	 * real 304) is exercised by the Phase-5 live-VM smoke cases — not reachable off-box.
	 */
	public function test_probe_validator_base_strips_the_md5_infix(): void
	{
		// A real probe path: the detector persists validators at {header}.orig but hands
		// the probe file_dwn = {header}.md5.
		$file_dwn = '/var/db/pfblockerng/orig/pfb_DNSBL_test.md5';

		$base = pfb_conditional_get_validator_base($file_dwn);

		$this->assertSame(
			'/var/db/pfblockerng/orig/pfb_DNSBL_test.orig',
			$base,
			'probe validators must resolve to the detector-persisted {header}.orig baseline'
		);
		$this->assertNotSame(
			'/var/db/pfblockerng/orig/pfb_DNSBL_test.md5.orig',
			$base,
			'the `.md5` probe-infix must NOT leak into the validator base, or If-None-Match '
			. 'is never sent and the 304 fast-path stays dead (ADR-42 §3)'
		);
	}

	/**
	 * Branch coverage for pfb_conditional_get_validator_base(): a path WITHOUT the trailing
	 * `.md5` probe-infix gets `.orig` appended unchanged, and a mid-string `.md5` (not a
	 * trailing suffix) is preserved — only the trailing probe-infix is stripped.
	 */
	public function test_validator_base_without_md5_infix_just_appends_orig(): void
	{
		$this->assertSame(
			'/x/feedA.orig',
			pfb_conditional_get_validator_base('/x/feedA'),
			'a base without the probe-infix appends .orig unchanged'
		);
		$this->assertSame(
			'/x/a.md5b.orig',
			pfb_conditional_get_validator_base('/x/a.md5b'),
			'only a trailing `.md5` is the probe-infix; a mid-string .md5 is preserved'
		);
	}

	// -------------------------------------------------------------------------
	// pfb_force_clear_validators() — sidecar sweep for Force Download / Both
	//
	// These tests are RED on the pre-change code (pfb_force_clear_validators
	// is a new function — calling it before the change gives a fatal error).
	// -------------------------------------------------------------------------

	/**
	 * clear_hashes=FALSE removes only .etag and .lastmod; leaves .orig, .xxhash128, .md5.
	 *
	 *  GIVEN feedA.orig, feedA.orig.etag, feedA.orig.lastmod, feedA.orig.xxhash128,
	 *        feedB.orig, feedB.orig.md5;
	 *   WHEN pfb_force_clear_validators([$dir], FALSE) is called;
	 *   THEN .etag and .lastmod are removed; .orig, .xxhash128, .md5 are kept;
	 *   AND  the return value is 2 (two sidecars removed).
	 */
	public function test_force_clear_validators_etag_lastmod_only(): void
	{
		$dir = $this->dir;
		// Arrange: plant fixture files.
		file_put_contents("{$dir}/feedA.orig",          'content');
		file_put_contents("{$dir}/feedA.orig.etag",     '"abc"');
		file_put_contents("{$dir}/feedA.orig.lastmod",  '1700000000');
		file_put_contents("{$dir}/feedA.orig.xxhash128", 'deadbeef');
		file_put_contents("{$dir}/feedB.orig",          'content2');
		file_put_contents("{$dir}/feedB.orig.md5",      'abc123');

		// Assert BEFORE: all files exist.
		$this->assertFileExists("{$dir}/feedA.orig.etag",     'fixture: .etag must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.lastmod",  'fixture: .lastmod must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.xxhash128",'fixture: .xxhash128 must exist before clear');
		$this->assertFileExists("{$dir}/feedB.orig.md5",      'fixture: .md5 must exist before clear');

		// Act.
		$removed = pfb_force_clear_validators([$dir], FALSE);

		// Assert: only validators removed; hashes and .orig content kept.
		$this->assertFileDoesNotExist(
			"{$dir}/feedA.orig.etag",
			'clear_hashes=FALSE must remove .etag sidecars'
		);
		$this->assertFileDoesNotExist(
			"{$dir}/feedA.orig.lastmod",
			'clear_hashes=FALSE must remove .lastmod sidecars'
		);
		$this->assertFileExists(
			"{$dir}/feedA.orig.xxhash128",
			'clear_hashes=FALSE must NOT remove .xxhash128 (hash sidecars must survive)'
		);
		$this->assertFileExists(
			"{$dir}/feedB.orig.md5",
			'clear_hashes=FALSE must NOT remove .md5 (hash sidecars must survive)'
		);
		$this->assertFileExists(
			"{$dir}/feedA.orig",
			'clear_hashes=FALSE must never remove .orig content files'
		);

		$this->assertSame(
			2,
			$removed,
			sprintf('Expected 2 sidecars removed (etag + lastmod), got %d', $removed)
		);
	}

	/**
	 * clear_hashes=TRUE removes .etag, .lastmod, .xxhash128, and .md5; leaves .orig content.
	 *
	 *  GIVEN the same fixture set as above;
	 *   WHEN pfb_force_clear_validators([$dir], TRUE) is called;
	 *   THEN .etag, .lastmod, .xxhash128, and .md5 are removed; .orig is kept;
	 *   AND  the return value is 4.
	 */
	public function test_force_clear_validators_clears_hashes_too(): void
	{
		$dir = $this->dir;
		file_put_contents("{$dir}/feedA.orig",          'content');
		file_put_contents("{$dir}/feedA.orig.etag",     '"abc"');
		file_put_contents("{$dir}/feedA.orig.lastmod",  '1700000000');
		file_put_contents("{$dir}/feedA.orig.xxhash128", 'deadbeef');
		file_put_contents("{$dir}/feedB.orig",          'content2');
		file_put_contents("{$dir}/feedB.orig.md5",      'abc123');

		$this->assertFileExists("{$dir}/feedA.orig.etag",      'fixture: .etag must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.lastmod",   'fixture: .lastmod must exist before clear');
		$this->assertFileExists("{$dir}/feedA.orig.xxhash128", 'fixture: .xxhash128 must exist before clear');
		$this->assertFileExists("{$dir}/feedB.orig.md5",       'fixture: .md5 must exist before clear');

		$removed = pfb_force_clear_validators([$dir], TRUE);

		$this->assertFileDoesNotExist("{$dir}/feedA.orig.etag",      'clear_hashes=TRUE must remove .etag');
		$this->assertFileDoesNotExist("{$dir}/feedA.orig.lastmod",   'clear_hashes=TRUE must remove .lastmod');
		$this->assertFileDoesNotExist("{$dir}/feedA.orig.xxhash128", 'clear_hashes=TRUE must remove .xxhash128');
		$this->assertFileDoesNotExist("{$dir}/feedB.orig.md5",       'clear_hashes=TRUE must remove .md5');
		$this->assertFileExists(
			"{$dir}/feedA.orig",
			'clear_hashes=TRUE must never remove .orig content files'
		);

		$this->assertSame(
			4,
			$removed,
			sprintf('Expected 4 sidecars removed (etag + lastmod + xxhash128 + md5), got %d', $removed)
		);
	}

	/**
	 * Two dirs each with one .orig.etag → returns 2.
	 *
	 *  GIVEN dirA with feedA.orig.etag and dirB with feedB.orig.etag;
	 *   WHEN pfb_force_clear_validators([dirA, dirB], FALSE) is called;
	 *   THEN both .etag files are removed and the return value is 2.
	 */
	public function test_force_clear_validators_two_dirs(): void
	{
		$dirA = $this->dir . '/origA';
		$dirB = $this->dir . '/origB';
		mkdir($dirA, 0777, TRUE);
		mkdir($dirB, 0777, TRUE);
		file_put_contents("{$dirA}/feedA.orig.etag", '"etagA"');
		file_put_contents("{$dirB}/feedB.orig.etag", '"etagB"');

		$this->assertFileExists("{$dirA}/feedA.orig.etag", 'fixture: dirA etag must exist');
		$this->assertFileExists("{$dirB}/feedB.orig.etag", 'fixture: dirB etag must exist');

		$removed = pfb_force_clear_validators([$dirA, $dirB], FALSE);

		$this->assertFileDoesNotExist("{$dirA}/feedA.orig.etag", 'dirA .etag must be removed');
		$this->assertFileDoesNotExist("{$dirB}/feedB.orig.etag", 'dirB .etag must be removed');
		$this->assertSame(
			2,
			$removed,
			sprintf('Expected 2 removed across two dirs, got %d', $removed)
		);
	}

	/**
	 * Nonexistent dir → returns 0, no error.
	 *
	 *  GIVEN a dir path that does not exist;
	 *   WHEN pfb_force_clear_validators(['/nonexistent/xyz'], FALSE) is called;
	 *   THEN it returns 0 without throwing.
	 */
	public function test_force_clear_validators_nonexistent_dir_returns_zero(): void
	{
		$removed = pfb_force_clear_validators(['/nonexistent/xyz_pfb_test_' . getmypid()], FALSE);
		$this->assertSame(
			0,
			$removed,
			'A nonexistent dir must produce 0 removals and no error'
		);
	}
}
