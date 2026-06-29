<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Oracle tests for pfb_archive_probe() — ADR-45 Phase 1.
 *
 * pfb_archive_probe() is a pure mapping function: canonical archive MIME type in,
 * base argv array (binary + flags, no file path) out, or NULL for non-archive types.
 * Each test pins the exact argv returned for a supported type, and the NULL contract
 * for anything that has no structural probe.
 */
#[CoversFunction('pfb_archive_probe')]
final class ArchiveProbeTest extends TestCase
{
	public function test_probe_zip_returns_tar_tf(): void
	{
		// application/zip → bsdtar (/usr/bin/tar on FreeBSD) -tf: the same tool
		// pfb_download() already uses for ZIP listing (L8350/L8376). File is NOT
		// part of the output — pfb_validate_archive() appends it at call time.
		$this->assertSame(['/usr/bin/tar', '-tf'], pfb_archive_probe('application/zip'));
	}

	public function test_probe_gzip_returns_gunzip_t(): void
	{
		// application/gzip → gunzip -t: integrity test, exits 0 on a valid gzip stream.
		$this->assertSame(['/usr/bin/gunzip', '-t'], pfb_archive_probe('application/gzip'));
	}

	public function test_probe_x_gzip_alias_returns_gunzip_t(): void
	{
		// application/x-gzip is an alias for application/gzip; must map to the same
		// argv so both MIME variants of a gzip feed get the same integrity probe.
		$this->assertSame(['/usr/bin/gunzip', '-t'], pfb_archive_probe('application/x-gzip'));
	}

	public function test_probe_x_bzip2_returns_bzip2_t(): void
	{
		// application/x-bzip2 → bzip2 -t: integrity test, exits 0 on a valid bzip2 stream.
		$this->assertSame(['/usr/bin/bzip2', '-t'], pfb_archive_probe('application/x-bzip2'));
	}

	public function test_probe_x_7z_compressed_returns_7z_t(): void
	{
		// application/x-7z-compressed → 7z t: structural test, exits 0 on a valid 7z archive.
		// /usr/local/bin/7z is the non-base path; the binary is already used by pfb_download().
		$this->assertSame(['/usr/local/bin/7z', 't'], pfb_archive_probe('application/x-7z-compressed'));
	}

	public function test_probe_text_plain_returns_null(): void
	{
		// text/plain is not an archive — there is no structural probe for it.
		// NULL signals "nothing to test" to pfb_validate_archive().
		$this->assertNull(pfb_archive_probe('text/plain'));
	}

	public function test_probe_application_json_returns_null(): void
	{
		// application/json is not an archive — must return NULL.
		$this->assertNull(pfb_archive_probe('application/json'));
	}

	public function test_probe_empty_string_returns_null(): void
	{
		// Empty string is not a recognised archive type — defensive NULL.
		$this->assertNull(pfb_archive_probe(''));
	}

	public function test_probe_octet_stream_returns_null(): void
	{
		// application/octet-stream is not a recognised canonical archive type.
		// The octet-stream recovery path (Phase 3) probes each archive type
		// in turn via pfb_validate_archive(); pfb_archive_probe() never matches
		// octet-stream itself — it maps only canonical archive types.
		$this->assertNull(pfb_archive_probe('application/octet-stream'));
	}
}
