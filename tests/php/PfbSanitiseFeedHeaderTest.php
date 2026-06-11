<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_sanitise_feed_header() — the PFBL-01 feed-header validation helper used at
 * the manifest choke point (pfb_unbound_python_sources). Contract, pinned from
 * both sides:
 *
 *   - a PFB_FILTER_WORD-valid header is returned UNCHANGED (===) and writes
 *     nothing to the log;
 *   - any other value returns strict FALSE, after logging a line carrying the
 *     caller-supplied $reference and a truncated (max 100 chars)
 *     htmlspecialchars()-encoded copy of the value — a rejection is never silent.
 */
#[CoversFunction('pfb_sanitise_feed_header')]
final class PfbSanitiseFeedHeaderTest extends TestCase
{
	private string $tmp;
	private array $savedPfbKeys = [];

	protected function setUp(): void
	{
		// Point the logger at fresh per-test files so log assertions are isolated.
		$this->tmp = sys_get_temp_dir() . '/pfb_header_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);
		foreach (['log', 'errlog'] as $key) {
			$this->savedPfbKeys[$key] = $GLOBALS['pfb'][$key] ?? null;
			$GLOBALS['pfb'][$key] = "{$this->tmp}/{$key}";
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfbKeys as $key => $value) {
			if ($value === null) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $value;
			}
		}
		rmdir_recursive($this->tmp);
	}

	private function logContents(): string
	{
		$path = $GLOBALS['pfb']['log'];
		return file_exists($path) ? (string) file_get_contents($path) : '';
	}

	/** @return array<string, array{0: string}> label => header accepted unchanged */
	public static function acceptedHeaderProvider(): array
	{
		return [
			'plain header'       => ['EasyList'],
			'header with vtype'  => ['Abuse_ch_v4'],
			'custom-list header' => ['MyAlias_custom'],
			'digits'             => ['Feed2024'],
		];
	}

	#[DataProvider('acceptedHeaderProvider')]
	public function testValidHeaderReturnedUnchangedWithoutLogging(string $header): void
	{
		$this->assertSame('', $this->logContents(), 'log must start empty');

		$this->assertSame($header, pfb_sanitise_feed_header($header, 'unit_test'));

		$this->assertSame('', $this->logContents(), 'a valid header must not be logged');
	}

	/** @return array<string, array{0: string}> label => header that must be rejected */
	public static function rejectedHeaderProvider(): array
	{
		return [
			'parent-dir sequence' => ['../feed'],
			'embedded slash'      => ['feeds/evil'],
			'dot (device-style)'  => ['igb1.100'],
			'dash'                => ['feed-name'],
			'embedded space'      => ['feed name'],
			'semicolon'           => ['feed;ls'],
			'quote'               => ["feed'x"],
			'newline'             => ["feed\nx"],
			'empty string'        => [''],
		];
	}

	#[DataProvider('rejectedHeaderProvider')]
	public function testInvalidHeaderReturnsStrictFalseAndLogs(string $header): void
	{
		$this->assertSame('', $this->logContents(), 'log must start empty');

		$this->assertFalse(pfb_sanitise_feed_header($header, 'unit_test'));

		$log = $this->logContents();
		$this->assertStringContainsString('unit_test', $log, 'log line carries the caller reference');
		$this->assertStringContainsString('Feed header failed validation', $log);
		if ($header !== '') {
			$this->assertStringContainsString(substr(htmlspecialchars($header), 0, 100), $log);
		}
	}

	public function testRejectionLogTruncatesEncodedValueTo100Chars(): void
	{
		// 150 'a's plus a space (the space forces rejection; the value is metachar-free
		// so the encoded copy equals the raw one and the cut point is unambiguous).
		$header = str_repeat('a', 150) . ' x';

		$this->assertFalse(pfb_sanitise_feed_header($header, 'unit_test'));

		$log = $this->logContents();
		$this->assertStringContainsString(str_repeat('a', 100), $log, 'first 100 encoded chars are logged');
		$this->assertStringNotContainsString(str_repeat('a', 101), $log, 'nothing beyond 100 chars is logged');
	}

	public function testDefaultReferenceIsTheHelperName(): void
	{
		$this->assertFalse(pfb_sanitise_feed_header('bad header'));
		$this->assertStringContainsString('pfb_sanitise_feed_header:', $this->logContents());
	}
}
