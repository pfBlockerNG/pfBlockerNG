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
#[CoversFunction('pfb_unbound_py_flip_sentinel')]
final class UnboundPyPublishTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private bool $hadPfb = false;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_publish_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

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

	// --- sentinel flip (the generation contract) ----------------------------

	public function testFlipFromAbsentWritesGenerationOne(): void
	{
		$this->assertFileDoesNotExist($this->sentinel());

		$this->assertTrue(pfb_unbound_py_flip_sentinel());
		$this->assertFileExists($this->sentinel());
		$this->assertSame('1', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipAdvancesByOne(): void
	{
		// Before: generation 7 (with a trailing newline, as written).
		file_put_contents($this->sentinel(), "7\n");
		$this->assertSame('7', trim(file_get_contents($this->sentinel())));

		// After: strictly advanced to 8 (current+1).
		$this->assertTrue(pfb_unbound_py_flip_sentinel());
		$this->assertSame('8', trim(file_get_contents($this->sentinel())));

		// And again -> 9: proves the advance reads the CURRENT value each time.
		$this->assertTrue(pfb_unbound_py_flip_sentinel());
		$this->assertSame('9', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipUsesOnlyFirstLine(): void
	{
		// Any lines after the first are ignored (Phase-4 reader contract).
		file_put_contents($this->sentinel(), "41\nignored junk\nmore\n");
		$this->assertTrue(pfb_unbound_py_flip_sentinel());
		$this->assertSame('42', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipFromEmptyOrNonIntegerTreatsAsZero(): void
	{
		// Empty file -> treated as gen 0 -> writes 1.
		file_put_contents($this->sentinel(), '');
		$this->assertTrue(pfb_unbound_py_flip_sentinel());
		$this->assertSame('1', trim(file_get_contents($this->sentinel())));

		// Non-integer first line -> treated as gen 0 -> writes 1.
		file_put_contents($this->sentinel(), "garbage\n9\n");
		$this->assertTrue(pfb_unbound_py_flip_sentinel());
		$this->assertSame('1', trim(file_get_contents($this->sentinel())));
	}

	public function testFlipWritesFirstLineAsBareIntegerPlusNewline(): void
	{
		// The exact on-disk shape: "<int>\n" (first line is a clean base-10 integer).
		$this->assertTrue(pfb_unbound_py_flip_sentinel());
		$raw = file_get_contents($this->sentinel());
		$this->assertSame("1\n", $raw);
		$first = strtok($raw, "\n");
		$this->assertTrue(ctype_digit($first));
	}
}
