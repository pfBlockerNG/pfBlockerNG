<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-10 P5 atomic-publish primitive: the staging->fsync->rename writer (pfb_unbound_py_atomic_write). Run against a temp
 * $pfb sandbox (no live box, no chroot).
 */
#[CoversFunction('pfb_unbound_py_atomic_write')]
#[CoversFunction('pfb_unbound_py_stream_sync')]
final class UnboundPyPublishTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private bool $hadPfb = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_publish_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $this->tmp,
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		$this->rrmdir($this->tmp);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $f) {
			if ($f === '.' || $f === '..') {
				continue;
			}
			$p = "{$dir}/{$f}";
			is_dir($p) ? $this->rrmdir($p) : @unlink($p);
		}
		@rmdir($dir);
	}

	// --- atomic write -------------------------------------------------------

	public function testAtomicWriteCreatesFileWithExactContent(): void
	{
		$path = "{$this->tmp}/manifest.json";
		$this->assertFileDoesNotExist($path);

		$this->assertTrue(pfb_unbound_py_atomic_write($path, "hello\nworld\n"));
		$this->assertFileExists($path);
		$this->assertSame("hello\nworld\n", file_get_contents($path));
	}

	public function testAtomicWriteReplacesExistingFile(): void
	{
		$path = "{$this->tmp}/manifest.json";
		file_put_contents($path, 'OLD-CONTENT');
		$this->assertSame('OLD-CONTENT', file_get_contents($path));

		$this->assertTrue(pfb_unbound_py_atomic_write($path, 'NEW'));
		$this->assertSame('NEW', file_get_contents($path));
	}

	public function testAtomicWriteLeavesNoStagingTempBehind(): void
	{
		$path = "{$this->tmp}/manifest.json";
		$this->assertTrue(pfb_unbound_py_atomic_write($path, 'x'));

		// The only files in the dir must be the published one -- no '.pfbpub_*' temp.
		$leftover = array_filter(scandir($this->tmp), static function ($f) {
			return strpos($f, '.pfbpub_') === 0;
		});
		$this->assertSame([], array_values($leftover));
	}

	public function testAtomicWriteFailsWhenDirMissing(): void
	{
		// Staging dir does not exist -> tempnam fails -> FALSE, fail-safe (no crash).
		$this->assertFalse(
			pfb_unbound_py_atomic_write("{$this->tmp}/nope/deep/manifest.json", 'x')
		);
	}

	/**
	 * tempnam() falls back to the system temporary folder when it cannot create the stage beside the target; a rename from
	 * there would be a copy over the target. Such a stage is refused before anything is written to it.
	 */
	public function testAtomicWriteRefusesAStageOutsideTheTargetsFolder(): void
	{
		$written = [];
		$write = static function ($stream, string $bytes) use (&$written) {
			$written[] = $bytes;
			return strlen($bytes);
		};

		$this->assertFalse(pfb_unbound_py_atomic_write("{$this->tmp}/nope/manifest.json", 'x', ['write' => $write]));
		$this->assertSame([], $written, 'a stage outside the target\'s folder was written');
	}

	public function testStreamSyncRejectsShortWriteFlushAndFsyncFailures(): void
	{
		$fh = tmpfile();
		$this->assertIsResource($fh);
		$full = static fn($stream, string $bytes): int => strlen($bytes);
		$short = static fn($stream, string $bytes): int => strlen($bytes) - 1;
		$yes = static fn($stream): bool => TRUE;
		$no = static fn($stream): bool => FALSE;

		$this->assertFalse(pfb_unbound_py_stream_sync($fh, 'abc', $short, $yes, $yes));
		$this->assertFalse(pfb_unbound_py_stream_sync($fh, 'abc', $full, $no, $yes));
		$this->assertFalse(pfb_unbound_py_stream_sync($fh, 'abc', $full, $yes, $no));
		$this->assertTrue(pfb_unbound_py_stream_sync($fh, 'abc', $full, $yes, $yes));
		fclose($fh);
	}

	public function testAtomicWriteFailuresKeepOldFileAndCleanTemporaryFile(): void
	{
		$path = "{$this->tmp}/manifest.json";
		$full = static fn($stream, string $bytes): int => strlen($bytes);
		$short = static fn($stream, string $bytes): int => strlen($bytes) - 1;
		$yes = static fn($stream): bool => TRUE;
		$no = static fn($stream): bool => FALSE;
		$renameNo = static fn(string $from, string $to): bool => FALSE;
		$failures = [
			'short write' => ['write' => $short, 'flush' => $yes, 'fsync' => $yes],
			'flush' => ['write' => $full, 'flush' => $no, 'fsync' => $yes],
			'fsync' => ['write' => $full, 'flush' => $yes, 'fsync' => $no],
			'rename' => ['rename' => $renameNo],
		];

		foreach ($failures as $label => $ops) {
			file_put_contents($path, 'OLD');
			$this->assertFalse(pfb_unbound_py_atomic_write($path, 'NEW', $ops), $label);
			$this->assertSame('OLD', file_get_contents($path), "{$label} changed the published file");
			$this->assertSame([], glob("{$this->tmp}/.pfbpub_*") ?: [], "{$label} leaked a temp file");
		}
	}
}
