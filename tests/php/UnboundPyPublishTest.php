<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-10 P5 atomic-publish primitives: the staging->fsync->rename writer
 * (pfb_unbound_py_atomic_write) and the reload-sentinel generation flip
 * (pfb_unbound_py_flip_sentinel). These pin the Phase-4 sentinel contract the
 * Python reload-watcher honours verbatim:
 *   - host path /var/unbound/pfb_py_reload (here redirected to a temp dnsbldir);
 *   - a monotonically NON-DECREASING base-10 integer on the FIRST line;
 *   - PHP writes current+1 (or 1 when absent/empty/non-integer).
 * Run against a temp $pfb sandbox (no live box, no chroot).
 */
#[CoversFunction('pfb_unbound_py_atomic_write')]
#[CoversFunction('pfb_unbound_py_stream_sync')]
#[CoversFunction('pfb_unbound_py_flip_sentinel')]
#[CoversFunction('pfb_unbound_py_wait_applied')]
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

		// dnsbldir is the chroot root; the sentinel lives at "{dnsbldir}/pfb_py_reload".
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

	private function sentinel(): string
	{
		return "{$this->tmp}/pfb_py_reload";
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

	// --- sentinel flip (the generation contract) ----------------------------

	public function testFlipFromAbsentWritesGenerationOne(): void
	{
		$this->assertFileDoesNotExist($this->sentinel());

		$this->assertSame(1, pfb_unbound_py_flip_sentinel());	// returns the published gen.
		$this->assertFileExists($this->sentinel());
		$this->assertSame('1', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipAdvancesByOne(): void
	{
		// Before: generation 7 (with a trailing newline, as written).
		file_put_contents($this->sentinel(), "7\n");
		$this->assertSame('7', trim(file_get_contents($this->sentinel())));

		// After: strictly advanced to 8 (current+1); the return value IS that gen.
		$this->assertSame(8, pfb_unbound_py_flip_sentinel());
		$this->assertSame('8', trim(file_get_contents($this->sentinel())));

		// And again -> 9: proves the advance reads the CURRENT value each time.
		$this->assertSame(9, pfb_unbound_py_flip_sentinel());
		$this->assertSame('9', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipUsesOnlyFirstLine(): void
	{
		// Any lines after the first are ignored (Phase-4 reader contract).
		file_put_contents($this->sentinel(), "41\nignored junk\nmore\n");
		$this->assertSame(42, pfb_unbound_py_flip_sentinel());
		$this->assertSame('42', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipFromEmptyOrNonIntegerTreatsAsZero(): void
	{
		// Empty file -> treated as gen 0 -> writes 1.
		file_put_contents($this->sentinel(), '');
		$this->assertSame(1, pfb_unbound_py_flip_sentinel());
		$this->assertSame('1', trim(file_get_contents($this->sentinel())));

		// Non-integer first line -> treated as gen 0 -> writes 1.
		file_put_contents($this->sentinel(), "garbage\n9\n");
		$this->assertSame(1, pfb_unbound_py_flip_sentinel());
		$this->assertSame('1', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipWritesFirstLineAsBareIntegerPlusNewline(): void
	{
		// The exact on-disk shape: "<int>\n" (first line is a clean base-10 integer).
		$this->assertSame(1, pfb_unbound_py_flip_sentinel());
		$raw = file_get_contents($this->sentinel());
		$this->assertSame("1\n", $raw);
		$first = strtok($raw, "\n");
		$this->assertTrue(ctype_digit($first));
	}

	// --- wait-for-apply (the ADR-10 readiness handshake) --------------------

	private function applied(): string
	{
		return "{$this->tmp}/pfb_py_reload.applied";
	}

	public function testWaitAppliedReturnsTrueWhenMarkerReachesGen(): void
	{
		// The watcher has published the applied generation -> the swap is LIVE.
		file_put_contents($this->applied(), "5\n");
		$this->assertTrue(pfb_unbound_py_wait_applied(5, 2));
		// A marker AHEAD of the target also counts as applied (>=, a later swap landed).
		$this->assertTrue(pfb_unbound_py_wait_applied(4, 2));
	}

	public function testWaitAppliedTimesOutWhenMarkerAbsentOrBehind(): void
	{
		// BEFORE: no marker -> the swap never confirms -> times out FALSE (caller then
		// falls back to the restart so the lists still load).
		$this->assertFileDoesNotExist($this->applied());
		$this->assertFalse(pfb_unbound_py_wait_applied(1, 1));

		// A marker BEHIND the target also times out (watcher has not caught up yet).
		file_put_contents($this->applied(), "3\n");
		$this->assertFalse(pfb_unbound_py_wait_applied(4, 1));
	}
}
