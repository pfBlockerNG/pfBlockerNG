<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #3195: verify platform-aware archiver resolution in test bootstrap.
 *
 * FreeBSD and macOS appliance environments ship bsdtar at /usr/bin/tar.
 * Linux development hosts provide bsdtar via libarchive-tools (typically at /usr/bin/bsdtar).
 * Bootstrap resolves this cleanly without mutating host system binaries via dpkg-divert.
 */
final class BootstrapArchiverResolutionTest extends TestCase
{
	public function test_bootstrap_populates_executable_tar_in_globals(): void
	{
		$this->assertArrayHasKey('tar', $GLOBALS['pfb'], '$GLOBALS[\'pfb\'][\'tar\'] must be populated by bootstrap');
		$tar = $GLOBALS['pfb']['tar'];
		$this->assertIsString($tar);
		$this->assertNotEmpty($tar);
		$this->assertFileExists($tar);
		$this->assertTrue(is_executable($tar), "Resolved archiver [{$tar}] must be executable");
		$this->assertSame($tar, pfb_test_tar(), 'pfb_test_tar() helper must return the resolved tar binary');
	}

	public function test_bootstrap_tar_is_bsdtar(): void
	{
		$tar = pfb_test_tar();
		$output = [];
		$retval = 1;
		exec(escapeshellcmd($tar) . ' --version 2>&1', $output, $retval);
		$this->assertSame(0, $retval, "Failed to execute [{$tar} --version]");
		$firstLine = (string) ($output[0] ?? '');
		$this->assertTrue(
			str_contains($firstLine, 'bsdtar') || str_contains($firstLine, 'libarchive'),
			"Archiver [{$tar}] must be bsdtar/libarchive, got: [{$firstLine}]"
		);
	}

	public function test_bootstrap_tar_can_read_zip_container(): void
	{
		$tar = pfb_test_tar();
		$tmpZip = tempnam(sys_get_temp_dir(), 'pfb_zip_test_');
		$this->assertNotFalse($tmpZip);
		$zip = new ZipArchive();
		$this->assertTrue($zip->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE));
		$this->assertTrue($zip->addFromString('test.txt', "hello\n"));
		$this->assertTrue($zip->close());

		$output = [];
		$retval = 1;
		exec(escapeshellcmd($tar) . ' -tf ' . escapeshellarg($tmpZip) . ' 2>/dev/null', $output, $retval);
		unlink($tmpZip);

		$this->assertSame(0, $retval, "Archiver [{$tar}] must be capable of reading ZIP containers");
		$this->assertContains('test.txt', $output);
	}

	public function test_archiver_resolver_fails_fast_when_missing(): void
	{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('bsdtar binary missing on host (Linux)');

		pfb_resolve_archiver('Linux', static fn(string $cmd): string => '');
	}

	public function test_archiver_resolver_selects_usr_bin_tar_on_bsd(): void
	{
		$resolved = pfb_resolve_archiver('BSD', static fn(string $cmd): string => '/unused/path');
		$this->assertSame('/usr/bin/tar', $resolved);
	}

	public function test_archiver_resolver_selects_usr_bin_tar_on_darwin(): void
	{
		$resolved = pfb_resolve_archiver('Darwin', static fn(string $cmd): string => '/unused/path');
		$this->assertSame('/usr/bin/tar', $resolved);
	}

	public function test_archiver_resolver_locates_bsdtar_on_linux(): void
	{
		$resolved = pfb_resolve_archiver('Linux', static fn(string $cmd): string => '/custom/bin/bsdtar');
		$this->assertSame('/custom/bin/bsdtar', $resolved);
	}
}
