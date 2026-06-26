<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Oracle tests for pfb_mime_in_allowlist() — extracted pure helper that
 * encapsulates the $pfb['mime_types'] membership lookup.
 *
 * These tests pin the CURRENT shipped allow-list behaviour before Phase 2
 * normalisation is introduced. They use $GLOBALS['pfb']['mime_types'] as
 * populated by bootstrap (the real shipped array_flip list) so they are
 * genuine oracles of the shipped allow-list, not a private copy.
 *
 * Entries (b) and (c) record known RED baselines — types file(1) can return
 * for a valid ZIP that the current allow-list rejects. Phase 2 will flip
 * these to true via normalisation before the lookup.
 */
#[CoversFunction('pfb_mime_in_allowlist')]
final class PfbMimeAllowlistTest extends TestCase
{
	private array $allowlist;

	protected function setUp(): void
	{
		// Prefer the real shipped allow-list as populated by bootstrap (the
		// array_flip of pfblockerng.inc:274-287). Fall back to constructing it
		// directly when a sibling test's tearDown() has unset the global
		// (PfbFileMimeSinkEscapeTest does this), so these oracles stay
		// isolated and always test against the canonical shipped list.
		$global = $GLOBALS['pfb']['mime_types'] ?? [];
		$this->allowlist = !empty($global) ? $global : array_flip([
			'inode/x-empty', 'text/x-file',
			'text/plain', 'text/html', 'text/xml', 'text/csv',
			'application/csv', 'application/json', 'application/x-ndjson',
			'application/x-tar',
			'application/gzip', 'application/x-gzip',
			'application/x-bzip2',
			'application/zip',
		]);
	}

	public function test_pfb_mime_allowlist_accepts_canonical_zip(): void
	{
		// 'application/zip' is in the shipped allow-list → must be accepted.
		$this->assertTrue(pfb_mime_in_allowlist('application/zip', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_rejects_x_zip_compressed(): void
	{
		// RED BASELINE (Phase 2 will fix via normalisation):
		// file(1) returns 'application/x-zip-compressed' for many valid ZIPs.
		// Current allow-list does NOT include it → currently rejected.
		$this->assertFalse(pfb_mime_in_allowlist('application/x-zip-compressed', $this->allowlist));
	}

	public function test_pfb_mime_allowlist_rejects_x_zip(): void
	{
		// RED BASELINE (Phase 2 will fix via normalisation):
		// file(1) may return 'application/x-zip' for some ZIP creators.
		// Current allow-list does NOT include it → currently rejected.
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
}
