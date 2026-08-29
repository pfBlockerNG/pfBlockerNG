<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for pfb_mime_normalise() — ADR-44 Phase 2.
 *
 * pfb_mime_normalise() canonicalises known ZIP-variant strings and any other
 * non-gzip/bzip "zip"-bearing string (via a stripos catch-all) to application/zip.
 * It is a pure function: string in, string out. Non-archive strings (e.g.
 * application/octet-stream) pass through unchanged; the catch-all is bounded by
 * the gzip/bzip guards, not by an explicit whitelist of archive MIME types.
 *
 * Critical correctness: the substring "zip" also appears inside "gzip" and
 * "bzip2". Those are distinct, valid archive types that MUST pass through
 * unchanged. test_normalise_x_bzip2_unchanged and test_normalise_gzip_unchanged
 * pin the guards that prevent them from being misrouted to application/zip.
 */
#[CoversFunction('pfb_mime_normalise')]
final class PfbMimeNormaliseTest extends TestCase
{
	public function test_normalise_x_zip_compressed_to_zip(): void
	{
		// application/x-zip-compressed is absent from stock FreeBSD libmagic (it
		// is a Windows / HTTP-header MIME). This normalisation is defensive — it
		// canonicalises the string should a custom magic file or future libmagic
		// build ever emit it, ensuring it passes the allow-list gate.
		$this->assertSame('application/zip', pfb_mime_normalise('application/x-zip-compressed'));
	}

	public function test_normalise_x_zip_to_zip(): void
	{
		// application/x-zip is bound only to Mozilla omni.ja in libmagic — not
		// emitted for ordinary ZIPs. Defensive: canonicalised to application/zip
		// in case a non-stock magic database emits it for a feed archive.
		$this->assertSame('application/zip', pfb_mime_normalise('application/x-zip'));
	}

	public function test_normalise_zip_substring_case_insensitive(): void
	{
		// Substring "zip" match is case-insensitive (stripos), so upper-cased
		// variant strings are also normalised to application/zip.
		$this->assertSame('application/zip', pfb_mime_normalise('Application/X-ZIP'));
	}

	public function test_normalise_x_gzip_to_gzip(): void
	{
		// application/x-gzip is a known variant of application/gzip.
		// The switch-case maps it to application/gzip — NOT application/zip —
		// because "gzip" contains "zip" and must not be caught by the substring rule.
		$this->assertSame('application/gzip', pfb_mime_normalise('application/x-gzip'));
	}

	public function test_normalise_x_bzip2_unchanged(): void
	{
		// application/x-bzip2 contains the substring "zip" (via "bzip").
		// The bzip guard in the catch-all ensures it is NOT rewritten to
		// application/zip — it must pass through unchanged.
		$this->assertSame('application/x-bzip2', pfb_mime_normalise('application/x-bzip2'));
	}

	public function test_normalise_gzip_unchanged(): void
	{
		// application/gzip is already canonical and in the allow-list.
		// The gzip guard ensures the substring "zip" inside "gzip" does NOT
		// trigger the catch-all rewrite — it must pass through unchanged.
		$this->assertSame('application/gzip', pfb_mime_normalise('application/gzip'));
	}

	public function test_normalise_octet_stream_unchanged(): void
	{
		// application/octet-stream is not an archive type and must never be promoted.
		$this->assertSame('application/octet-stream', pfb_mime_normalise('application/octet-stream'));
	}

	public function test_normalise_text_plain_unchanged(): void
	{
		// Non-archive types must pass through unchanged.
		$this->assertSame('text/plain', pfb_mime_normalise('text/plain'));
	}

	public function test_normalise_empty_string_unchanged(): void
	{
		// Empty string must not be modified (no division-by-zero-equivalent path).
		$this->assertSame('', pfb_mime_normalise(''));
	}

	public function test_normalise_canonical_zip_unchanged(): void
	{
		// application/zip is already canonical; calling normalise must be idempotent.
		$this->assertSame('application/zip', pfb_mime_normalise('application/zip'));
	}

	public function test_normalise_then_allowlist_composes_for_x_zip_compressed(): void
	{
		// Composes the two pure helpers (pfb_mime_normalise + pfb_mime_in_allowlist)
		// to show their intended contract: raw x-zip-compressed is rejected by the
		// allow-list alone, but passes after normalisation maps it to application/zip.
		// Does NOT call pfb_filter() — see PfbFileMimeNormaliseWiringTest for the gate.
		$global = $GLOBALS['pfb']['mime_types'] ?? [];
		$allowlist = !empty($global) ? $global : array_flip([
			'inode/x-empty', 'text/x-file',
			'text/plain', 'text/html', 'text/xml', 'text/csv',
			'application/csv', 'application/json', 'application/x-ndjson',
			'application/gzip', 'application/x-gzip',
			'application/x-bzip2',
			'application/zip',
		]);

		// Before-state: raw string is rejected.
		$this->assertFalse(
			pfb_mime_in_allowlist('application/x-zip-compressed', $allowlist),
			'Pre-condition: raw x-zip-compressed must be absent from the allow-list'
		);

		// After normalisation: canonical string is accepted.
		$this->assertTrue(
			pfb_mime_in_allowlist(pfb_mime_normalise('application/x-zip-compressed'), $allowlist),
			'Post-condition: normalised x-zip-compressed must be accepted by the allow-list'
		);
	}
}
