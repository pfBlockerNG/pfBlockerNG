<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_line_count() -- issue #1109: pure-PHP '\n' byte count feeding
 * pfb_log_trim_needed()'s line-cap high-water check (no exec()/wc). Any
 * probe failure (unopenable path, short/failed read) -> PHP_INT_MAX so the
 * guard FIRES -- fail-open, same direction as #1052's probe: a probe failure
 * must never silently disable retention.
 */
#[CoversFunction('pfb_log_line_count')]
final class LogLineCountTest extends TestCase
{
	private string $tmpFile;

	protected function setUp(): void
	{
		$this->tmpFile = (string) tempnam(sys_get_temp_dir(), 'pfb_line_count_');
	}

	protected function tearDown(): void
	{
		if (is_file($this->tmpFile)) {
			unlink($this->tmpFile);
		}
	}

	public function testTrailingNewlineCountsExactLines(): void
	{
		file_put_contents($this->tmpFile, "a\nb\nc\n");
		$this->assertSame(3, pfb_log_line_count($this->tmpFile), '3 newline-terminated lines must count as 3');
	}

	public function testNoTrailingNewlineUndercountsByOneHarmlessly(): void
	{
		// Documented, harmless undercount at a cap x (1+margin) threshold --
		// pinned as intended (issue #1109); no added complexity to fix it.
		file_put_contents($this->tmpFile, "a\nb\nc");
		$this->assertSame(2, pfb_log_line_count($this->tmpFile), '3 lines with no trailing newline must count as 2');
	}

	public function testEmptyFileCountsZero(): void
	{
		file_put_contents($this->tmpFile, '');
		$this->assertSame(0, pfb_log_line_count($this->tmpFile), 'an empty file must count as 0');
	}

	public function testMissingPathReturnsPhpIntMaxSoGuardFires(): void
	{
		$missing = $this->tmpFile . '-does-not-exist';
		$this->assertSame(
			PHP_INT_MAX,
			pfb_log_line_count($missing),
			'a missing/unopenable path must return PHP_INT_MAX so the high-water guard fires'
		);
	}
}
