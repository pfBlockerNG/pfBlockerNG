<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for pfb_archive_missing_tool() — ADR-45.
 *
 * The helper lets pfb_download() tell "the 7-Zip extractor is not installed" apart from
 * "the archive is corrupt": it returns the structural-probe binary for a type WHEN that
 * binary is absent, or NULL when the tool is present (or the type is a non-archive).
 * 7-Zip is the only optional extractor — gunzip/bzip2/tar are FreeBSD base — so in
 * production this only ever fires for application/x-7z-compressed; the helper itself is
 * generic, which these tests pin via the zip/gzip cases.
 *
 * The is_executable check is injected so the decision is exercised with no filesystem
 * dependency.
 */
#[CoversFunction('pfb_archive_missing_tool')]
final class ArchiveMissingToolTest extends TestCase
{
	public function test_7z_missing_returns_the_7z_binary(): void
	{
		// The behaviour this enables: a 7z feed on a box without 7-Zip is identified as
		// "tool missing" (so pfb_download logs "install 7-zip"), not "corrupt archive".
		$this->assertSame(
			'/usr/local/bin/7z',
			pfb_archive_missing_tool('application/x-7z-compressed', static fn (string $p): bool => FALSE)
		);
	}

	public function test_7z_present_returns_null(): void
	{
		// 7-Zip installed → no message, proceed to the structural probe.
		$this->assertNull(
			pfb_archive_missing_tool('application/x-7z-compressed', static fn (string $p): bool => TRUE)
		);
	}

	public function test_non_archive_returns_null_without_checking(): void
	{
		// A non-archive type needs no extractor; the checker must not even be consulted.
		$this->assertNull(
			pfb_archive_missing_tool('text/plain', function (string $p): bool {
				$this->fail('checker must not be called for a non-archive type');
			})
		);
	}

	public function test_generic_not_7z_hardcoded_zip(): void
	{
		// The helper is generic: for a (hypothetically) missing zip tool it returns tar,
		// proving it keys off pfb_archive_probe(), not a hardcoded 7z path. (In practice
		// /usr/bin/tar is always present, so this branch never fires for zip in production.)
		$this->assertSame(
			'/usr/bin/tar',
			pfb_archive_missing_tool('application/zip', static fn (string $p): bool => FALSE)
		);
	}

	public function test_generic_not_7z_hardcoded_gzip(): void
	{
		$this->assertSame(
			'/usr/bin/gunzip',
			pfb_archive_missing_tool('application/gzip', static fn (string $p): bool => FALSE)
		);
	}

	public function test_checker_receives_the_probe_binary(): void
	{
		// The injected checker is called with the type's probe binary (its argv[0]).
		$seen = NULL;
		pfb_archive_missing_tool('application/x-bzip2', function (string $p) use (&$seen): bool {
			$seen = $p;
			return TRUE;
		});
		$this->assertSame('/usr/bin/bzip2', $seen);
	}
}
