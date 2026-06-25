<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_localfile_feed_changed() — issue #533.
 *
 * Local-file feeds had no content-change detection: a remote feed is re-fetched + re-parsed
 * when it changes (pfb_download sets the '{header}.update' marker), but a local file was
 * reused from cache until '.update' was forced or the cache cleared, so edits were never
 * picked up. This helper restores parity — for a feed whose URL is an actual local file it
 * compares the source's md5 against the md5 recorded at the last ingest and touches
 * '{header}.update' on a real change, so the existing IP/DNSBL reuse gate re-parses it.
 *
 * Detection is content-based (a full md5), deliberately not mtime-gated: PHP's filemtime() is
 * whole-second granular and stat-cached, which would miss a same-second rewrite. The live
 * re-parse driven by the marker is the smoke's job (ADR-04); here every branch (first-seen,
 * unchanged, changed, non-local URL, missing/empty path) is pinned off-appliance.
 */
#[CoversFunction('pfb_localfile_feed_changed')]
final class LocalFileFeedChangedTest extends TestCase
{
	private string $dir;
	private string $src;
	private string $header = 'feedx';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_lff_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, true);
		$this->src = $this->dir . '/source.txt';
	}

	protected function tearDown(): void
	{
		array_map('unlink', glob($this->dir . '/*') ?: []);
		@rmdir($this->dir);
	}

	private function updateMarker(): string
	{
		return "{$this->dir}/{$this->header}.update";
	}

	private function lmd5(): string
	{
		return "{$this->dir}/{$this->header}.lmd5";
	}

	private function call(string $url): bool
	{
		return pfb_localfile_feed_changed($url, $this->dir, $this->header);
	}

	public function testFirstSeenLocalFileIsTreatedAsChanged(): void
	{
		// Given a local feed never ingested before (no .lmd5 baseline)...
		file_put_contents($this->src, "1.1.1.1\n");
		// When the helper runs...
		$changed = $this->call($this->src);
		// Then it reports a change, touches .update (forcing the reuse gate to re-parse),
		// and records the source md5 as the baseline.
		$this->assertTrue($changed, 'a first-seen local feed must be treated as changed');
		$this->assertFileExists($this->updateMarker());
		$this->assertSame(md5_file($this->src), trim((string) file_get_contents($this->lmd5())));
	}

	public function testUnchangedContentIsNotReingested(): void
	{
		file_put_contents($this->src, "1.1.1.1\n");
		$this->call($this->src);            // establish the baseline
		@unlink($this->updateMarker());     // clear the marker the first call set
		// When the content is byte-identical, no re-parse is forced.
		$changed = $this->call($this->src);
		$this->assertFalse($changed, 'an unchanged feed must not be re-ingested');
		$this->assertFileDoesNotExist($this->updateMarker());
	}

	public function testChangedContentForcesReingest(): void
	{
		file_put_contents($this->src, "1.1.1.1\n");
		$this->call($this->src);
		@unlink($this->updateMarker());
		// When the content changes (even with the same byte length), it must be re-ingested.
		file_put_contents($this->src, "2.2.2.2\n");
		$changed = $this->call($this->src);
		$this->assertTrue($changed, 'a changed local feed must be re-ingested');
		$this->assertFileExists($this->updateMarker());
		$this->assertSame(md5_file($this->src), trim((string) file_get_contents($this->lmd5())));
	}

	public function testRemoteUrlIsIgnored(): void
	{
		// A real URL is the download path's job, not local-file change detection.
		$this->assertFalse($this->call('https://example.com/list.txt'));
		$this->assertFileDoesNotExist($this->updateMarker());
	}

	public function testEmptyOrMissingPathIsIgnored(): void
	{
		$this->assertFalse($this->call(''), 'a custom/inline list has no URL');
		$this->assertFalse($this->call("{$this->dir}/does-not-exist.txt"), 'a missing file is not a change');
		$this->assertFileDoesNotExist($this->updateMarker());
	}
}
