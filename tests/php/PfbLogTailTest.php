<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_tail() — returns the last N lines of a file as a string, used to prefill the
 * Update/Software page log textareas on a plain GET.
 *
 * Pins the branch contract:
 *   - a missing or unreadable file → '' (the textarea renders empty, never a warning);
 *   - a file shorter than the limit → every line, joined by "\n" (no trailing newline);
 *   - a file longer than the limit → only the LAST N lines (the tail, not the head);
 *   - the default limit returns the whole short file.
 *
 * Off-appliance: /usr/bin/tail exists on the Linux CI host, so no exec double is needed.
 */
#[CoversFunction('pfb_log_tail')]
final class PfbLogTailTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_log_tail_' . getmypid() . '_' . mt_rand(0, 0xffff);
		if (!mkdir($base, 0777, TRUE)) {
			$this->fail("Could not create temp dir: {$base}");
		}
		$this->dir = $base;
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: array() as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
	}

	public function testMissingFileReturnsEmptyString(): void
	{
		$result = pfb_log_tail($this->dir . '/does-not-exist.log');
		$this->assertSame('', $result, 'A missing file must yield the empty string, not a warning.');
	}

	public function testReturnsAllLinesWhenShorterThanLimit(): void
	{
		$file = $this->dir . '/short.log';
		file_put_contents($file, "alpha\nbravo\ncharlie\n");

		$result = pfb_log_tail($file, 10);

		$this->assertSame(
			"alpha\nbravo\ncharlie",
			$result,
			'A file shorter than the limit must return every line joined by a newline (no trailing newline).'
		);
	}

	public function testReturnsOnlyTheLastNLines(): void
	{
		$file = $this->dir . '/long.log';
		file_put_contents($file, "l1\nl2\nl3\nl4\nl5\n");

		$result = pfb_log_tail($file, 2);

		$this->assertSame(
			"l4\nl5",
			$result,
			'A file longer than the limit must return the TAIL (last N lines), not the head.'
		);
	}

	public function testDefaultLimitReturnsWholeShortFile(): void
	{
		$file = $this->dir . '/default.log';
		file_put_contents($file, "one\ntwo\nthree\n");

		$result = pfb_log_tail($file);

		$this->assertSame(
			"one\ntwo\nthree",
			$result,
			'The default limit (1000) must return the whole short file.'
		);
	}
}
