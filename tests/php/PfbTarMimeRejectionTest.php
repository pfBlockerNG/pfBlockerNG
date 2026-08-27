<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_filter')]
final class PfbTarMimeRejectionTest extends TestCase
{
	private const FEED = "192.0.2.65/32\n198.51.100.65\n";

	private string $dir;
	private ?array $previousMimeTypes;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_tar_mime_' . uniqid('', true);
		mkdir($this->dir);

		$this->previousMimeTypes = $GLOBALS['pfb']['mime_types'] ?? NULL;
		$shipped = $GLOBALS['pfb_shipped_mime_types'] ?? [];
		$this->assertNotEmpty($shipped, 'shipped mime_types snapshot is empty — bootstrap capture broke');
		$GLOBALS['pfb']['mime_types'] = $shipped;

		$tar = new PharData($this->path('feed.tar'));
		$tar->addFromString('ips.txt', self::FEED);
		unset($tar);

		$tarBytes = file_get_contents($this->path('feed.tar'));
		$this->writeGzip('feed.tar.gz', $tarBytes);
		$this->writeGzip('feed.txt.gz', self::FEED);
		if (function_exists('bzcompress')) {
			$this->writeBzip2('feed.tar.bz2', $tarBytes);
			$this->writeBzip2('feed.txt.bz2', self::FEED);
		}

		$zip = new ZipArchive();
		if ($zip->open($this->path('feed.zip'), ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE ||
		    !$zip->addFromString('ips.txt', self::FEED) || !$zip->close()) {
			throw new RuntimeException('failed to create ZIP MIME fixture');
		}
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);

		if ($this->previousMimeTypes === NULL) {
			unset($GLOBALS['pfb']['mime_types']);
		} else {
			$GLOBALS['pfb']['mime_types'] = $this->previousMimeTypes;
		}
	}

	public function test_raw_tar_is_accepted_at_outer_gate(): void
	{
		$path = $this->path('feed.tar');
		$this->assertSame('application/x-tar', $this->filter($path, PFB_FILTER_FILE_MIME));
		$this->assertFileExists($path);
	}

	public function test_tar_gzip_is_accepted_at_inner_gate(): void
	{
		$path = $this->path('feed.tar.gz');
		$this->assertSame('application/gzip', $this->filter($path, PFB_FILTER_FILE_MIME));
		$this->assertSame('application/x-tar', $this->filter($path, PFB_FILTER_FILE_MIME_COMPRESSED));
		$this->assertFileExists($path);
	}

	public function test_tar_bzip2_is_accepted_at_inner_gate(): void
	{
		if (!function_exists('bzcompress')) {
			$this->markTestSkipped('ext-bz2 is not loaded');
		}
		$path = $this->path('feed.tar.bz2');
		$this->assertSame('application/x-bzip2', $this->filter($path, PFB_FILTER_FILE_MIME));
		$this->assertSame('application/x-tar', $this->filter($path, PFB_FILTER_FILE_MIME_COMPRESSED));
		$this->assertFileExists($path);
	}

	public function test_plain_gzip_remains_accepted(): void
	{
		$path = $this->path('feed.txt.gz');
		$this->assertSame('application/gzip', $this->filter($path, PFB_FILTER_FILE_MIME));
		$this->assertSame('text/plain', $this->filter($path, PFB_FILTER_FILE_MIME_COMPRESSED));
		$this->assertFileExists($path);
	}

	public function test_plain_bzip2_remains_accepted(): void
	{
		if (!function_exists('bzcompress')) {
			$this->markTestSkipped('ext-bz2 is not loaded');
		}
		$path = $this->path('feed.txt.bz2');
		$this->assertSame('application/x-bzip2', $this->filter($path, PFB_FILTER_FILE_MIME));
		$this->assertSame('text/plain', $this->filter($path, PFB_FILTER_FILE_MIME_COMPRESSED));
		$this->assertFileExists($path);
	}

	public function test_zip_remains_accepted(): void
	{
		$path = $this->path('feed.zip');
		$this->assertSame('application/zip', $this->filter($path, PFB_FILTER_FILE_MIME));
		$this->assertFileExists($path);
	}

	private function filter(string $path, int $filter, ?array &$detail = NULL): string|false
	{
		return pfb_filter(['unused', $path, 'https://feed.example/list'], $filter, 'test', '', FALSE, $detail);
	}

	private function path(string $name): string
	{
		return "{$this->dir}/{$name}";
	}

	private function writeGzip(string $name, string $content): void
	{
		$compressed = gzencode($content, 9);
		if ($compressed === FALSE || file_put_contents($this->path($name), $compressed) === FALSE) {
			throw new RuntimeException("failed to create {$name}");
		}
	}

	private function writeBzip2(string $name, string $content): void
	{
		$compressed = bzcompress($content, 9);
		if (!is_string($compressed) || file_put_contents($this->path($name), $compressed) === FALSE) {
			throw new RuntimeException("failed to create {$name}");
		}
	}
}
