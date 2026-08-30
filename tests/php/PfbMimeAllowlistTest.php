<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Oracle tests for pfb_mime_in_allowlist() — extracted pure helper that
 * encapsulates the $pfb['mime_types'] membership lookup.
 *
 * These tests pin the shipped allow-list behaviour. setUp() installs the
 * canonical fixture for each run; tearDown() restores the prior global state.
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

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$this->saved['mime_types'] = array_key_exists('mime_types', $GLOBALS['pfb'] ?? [])
			? $GLOBALS['pfb']['mime_types']
			: FALSE;

		// Use the canonical shipped-list mirror for these allow-list oracles.
		// If the shipped list changes, update this mirror.
		$GLOBALS['pfb']['mime_types'] = array_flip([
			'inode/x-empty', 'text/x-file',
			'text/plain', 'text/html', 'text/xml', 'text/csv',
			'application/csv', 'application/json', 'application/x-ndjson',
			'application/gzip', 'application/x-gzip',
			'application/x-bzip2',
			'application/zip',
		]);
		$this->allowlist = $GLOBALS['pfb']['mime_types'];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
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

	public function test_shipped_allowlist_accepts_tar_feeds(): void
	{
		$shipped = $GLOBALS['pfb_shipped_mime_types'] ?? [];

		$this->assertNotEmpty($shipped, 'shipped mime_types snapshot is empty — bootstrap capture broke');
		$this->assertTrue(
			pfb_mime_in_allowlist('application/gzip', $shipped),
			'plain gzip feeds must still reach the compressed MIME gate'
		);
		$this->assertTrue(
			pfb_mime_in_allowlist('application/x-bzip2', $shipped),
			'plain bzip2 feeds must still reach the compressed MIME gate'
		);
		$this->assertTrue(
			pfb_mime_in_allowlist('application/x-tar', $shipped),
			'issue #2638: a tar is extractable — outer and inner gates must admit it'
		);
	}

	public function test_shipped_allowlist_excludes_x_7z_compressed(): void
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

		// 7z is not an active feed format.
		$this->assertFalse(
			pfb_mime_in_allowlist('application/x-7z-compressed', $shipped),
			'application/x-7z-compressed must NOT be in the shipped allow-list'
		);
	}

	public function test_shipped_allowlist_accepts_empty_bodies(): void
	{
		// issue #2682 / ADR-49: an empty body is its own signal, and this one list
		// gates the OUTER download of every feed type -- dropping the entry rejects
		// legitimately empty bodies of every kind.
		$shipped = $GLOBALS['pfb_shipped_mime_types'] ?? [];

		$this->assertNotEmpty($shipped, 'shipped mime_types snapshot is empty — bootstrap capture broke');
		$this->assertTrue(
			pfb_mime_in_allowlist('inode/x-empty', $shipped),
			'an empty body must still reach the download gates, not be rejected as a MIME violation'
		);
	}
}
