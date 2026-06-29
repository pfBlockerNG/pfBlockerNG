<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Oracle tests for pfb_mime_in_allowlist() — extracted pure helper that
 * encapsulates the $pfb['mime_types'] membership lookup.
 *
 * These tests pin the shipped allow-list behaviour. setUp() repopulates
 * $pfb['mime_types'] from the canonical list on every run so sibling-test
 * tearDown() calls that unset the global do not affect these oracles.
 *
 * Entries (b) and (c) pin defensive baseline strings — types NOT emitted by
 * stock FreeBSD libmagic for real ZIPs, but canonicalised by pfb_mime_normalise()
 * (ADR-44) in case a non-stock magic database emits them. The raw strings remain
 * absent from the allow-list; pfb_mime_normalise() maps them to application/zip
 * before the lookup — wiring proven by PfbFileMimeNormaliseWiringTest.
 */
#[CoversFunction('pfb_mime_in_allowlist')]
final class PfbMimeAllowlistTest extends TestCase
{
	private array $allowlist;

	protected function setUp(): void
	{
		// Always repopulate from the canonical shipped list (pfblockerng.inc:274-289)
		// so sibling-test tearDown() calls that unset $pfb['mime_types'] cannot
		// affect these oracles. If the shipped list changes, update this mirror.
		$GLOBALS['pfb']['mime_types'] = array_flip([
			'inode/x-empty', 'text/x-file',
			'text/plain', 'text/html', 'text/xml', 'text/csv',
			'application/csv', 'application/json', 'application/x-ndjson',
			'application/x-tar',
			'application/gzip', 'application/x-gzip',
			'application/x-bzip2',
			'application/zip',
			'application/x-7z-compressed',
		]);
		$this->allowlist = $GLOBALS['pfb']['mime_types'];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb']['mime_types']);
	}

	public function test_pfb_mime_allowlist_accepts_canonical_zip(): void
	{
		// 'application/zip' is in the shipped allow-list → must be accepted.
		$this->assertTrue(pfb_mime_in_allowlist('application/zip', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_rejects_x_zip_compressed(): void
	{
		// application/x-zip-compressed is NOT emitted by stock FreeBSD libmagic for
		// real ZIPs (it is a Windows / HTTP-header MIME). The allow-list does not
		// include it; pfb_mime_normalise() maps it to application/zip before lookup.
		$this->assertFalse(pfb_mime_in_allowlist('application/x-zip-compressed', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_rejects_x_zip(): void
	{
		// application/x-zip is bound only to Mozilla omni.ja in libmagic — not
		// emitted for ordinary ZIPs. The allow-list does not include it;
		// pfb_mime_normalise() maps it to application/zip before lookup.
		$this->assertFalse(pfb_mime_in_allowlist('application/x-zip', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_accepts_canonical_gzip(): void
	{
		// 'application/gzip' is in the shipped allow-list → must be accepted.
		$this->assertTrue(pfb_mime_in_allowlist('application/gzip', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_accepts_x_gzip(): void
	{
		// 'application/x-gzip' IS in the shipped allow-list → must be accepted.
		$this->assertTrue(pfb_mime_in_allowlist('application/x-gzip', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_rejects_octet_stream(): void
	{
		// 'application/octet-stream' is NOT in the allow-list and must never
		// be promoted — normalisation must not touch this string.
		$this->assertFalse(pfb_mime_in_allowlist('application/octet-stream', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_accepts_text_plain(): void
	{
		// 'text/plain' is in the shipped allow-list → must be accepted.
		$this->assertTrue(pfb_mime_in_allowlist('text/plain', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_accepts_x_7z_compressed(): void
	{
		// ADR-45: 'application/x-7z-compressed' is now a first-class archive type
		// in the shipped allow-list → must be accepted. file(1) reports this MIME
		// for real 7-Zip archives; the pfb_download() 7z branch (structural-probe
		// guarded) handles extraction.
		$this->assertTrue(pfb_mime_in_allowlist('application/x-7z-compressed', $this->allowlist));
	}

	public function test_shipped_allowlist_includes_x_7z_compressed(): void
	{
		// Asserts against the REAL shipped $pfb['mime_types'] captured at bootstrap
		// (not the hand-mirror above), so reverting the pfblockerng.inc allow-list
		// entry makes this fail — genuine red→green for the ADR-45 7z addition.
		$shipped = $GLOBALS['pfb_shipped_mime_types'] ?? [];

		// Sanity: the snapshot is the real, populated list (not empty / not the mirror).
		$this->assertNotEmpty($shipped, 'shipped mime_types snapshot is empty — bootstrap capture broke');
		$this->assertTrue(
			pfb_mime_in_allowlist('application/zip', $shipped),
			'baseline: application/zip must be in the shipped allow-list'
		);
		$this->assertFalse(
			pfb_mime_in_allowlist('application/octet-stream', $shipped),
			'baseline: application/octet-stream must NOT be in the shipped allow-list'
		);

		// The ADR-45 change: 7z is now shipped.
		$this->assertTrue(
			pfb_mime_in_allowlist('application/x-7z-compressed', $shipped),
			'ADR-45: application/x-7z-compressed must be in the shipped allow-list'
		);
	}
}
