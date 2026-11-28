<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1542 — TOP1M's cached-source baseline helpers.
 *
 * Issue #3977 removed the PHP DCC detector, the TOP1M download path and its dispatch; what remains here are the
 * baseline invalidation and the settings-reprocess decision, which survive the cutover.
 */
#[CoversFunction('pfb_top1m_invalidate_baseline')]
#[CoversFunction('pfb_top1m_settings_reprocess')]
final class Top1mDccDetectorTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_top1m_dcc_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
	}

	protected function tearDown(): void
	{
		if (is_dir($this->dir)) {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ($it as $file) {
				$file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
			}
			rmdir($this->dir);
		}
	}

	public function testProviderChangeInvalidatesActualValidatorsButRetainsActiveDerivedSource(): void
	{
		$base = $this->dir . '/top-1m.csv.zip';
		$validator_base = "{$base}.orig";
		// The conditional-GET sidecars as the removed pfb_validator_write() stored them.
		file_put_contents("{$validator_base}.etag", '"old-etag"');
		file_put_contents("{$validator_base}.lastmod", '1700000000');
		file_put_contents("{$base}.orig", 'old raw');
		file_put_contents("{$base}.xxhash128", str_repeat('a', 32));
		file_put_contents("{$base}.source", 'old identity');
		$active = $this->dir . '/top-1m.csv';
		file_put_contents($active, 'old derived');

		pfb_top1m_invalidate_baseline($base);

		$this->assertFileDoesNotExist("{$base}.orig");
		$this->assertFileDoesNotExist("{$validator_base}.etag");
		$this->assertFileDoesNotExist("{$validator_base}.lastmod");
		$this->assertFileDoesNotExist("{$base}.xxhash128");
		$this->assertFileDoesNotExist("{$base}.source");
		$this->assertSame('old derived', file_get_contents($active));
	}

	public function testOnlyLocalFilteringSettingsRequestCachedSourceReprocess(): void
	{
		$before = ['enable' => 'on', 'count' => '1000', 'tld' => 'com', 'provider' => 'tranco'];
		$this->assertFalse(pfb_top1m_settings_reprocess($before, $before));
		$provider = $before;
		$provider['provider'] = 'cisco';
		$this->assertFalse(pfb_top1m_settings_reprocess($before, $provider));
		foreach (['enable', 'count', 'tld'] as $key) {
			$after = $before;
			$after[$key] = $key === 'enable' ? 'off' : ($key === 'count' ? '500' : 'net');
			$this->assertTrue(pfb_top1m_settings_reprocess($before, $after), "{$key} change must reprocess cached source");
		}
	}
}
