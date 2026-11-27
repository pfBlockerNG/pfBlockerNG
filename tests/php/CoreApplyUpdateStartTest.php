<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3977 (owner, 2026-11-27): a page save that changes what the Outpost applies (General, CrowdSec, the Alerts page's whitelist
 * and custom-list edits) asks Core for an `apply` Update instead of running a PHP pass. An Update already running answers
 * `conflict`: the change is then marked pending, which the next Update applies, and the person is told so. A Core that does
 * not answer is said too, and the change stays pending as well.
 */
#[CoversFunction('pfb_apply_update_start')]
final class CoreApplyUpdateStartTest extends TestCase
{
	private string $marker;

	protected function setUp(): void
	{
		$this->marker = (string) tempnam(sys_get_temp_dir(), 'pfb_pending_');
		@unlink($this->marker);
		$GLOBALS['pfb']['pending_marker'] = $this->marker;
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb']['pending_marker']);
		@unlink($this->marker);
	}

	/** @return array{0: callable, 1: ArrayObject<int, array{string, array}>} */
	private static function core(array $answer): array
	{
		$calls = new ArrayObject();
		return [function (string $method, array $params) use ($answer, $calls): array {
			$calls[] = [$method, $params];
			return $answer;
		}, $calls];
	}

	public function testItStartsAnApplyUpdate(): void
	{
		[$call, $calls] = self::core(['status' => 200, 'body' => [], 'error' => NULL]);
		$this->assertNull(pfb_apply_update_start($call));
		$this->assertSame('StartUpdate', $calls[0][0]);
		$this->assertSame('apply', $calls[0][1]['trigger']);
		$this->assertArrayNotHasKey('scope', $calls[0][1]);
		$this->assertFileDoesNotExist($this->marker);
	}

	public function testAConflictMarksTheChangePendingAndSaysSo(): void
	{
		[$call] = self::core(['status' => 409, 'body' => ['error' => ['code' => 'conflict', 'message' => 'an Update is running']], 'error' => NULL]);
		$this->assertStringContainsString('after the Update that runs ends', (string) pfb_apply_update_start($call));
		$this->assertFileExists($this->marker);
	}

	public function testACoreThatDoesNotAnswerMarksTheChangePendingAndSaysWhy(): void
	{
		[$call] = self::core(['status' => 0, 'body' => NULL, 'error' => 'the Core API is not running']);
		$this->assertStringContainsString('the Core API is not running', (string) pfb_apply_update_start($call));
		$this->assertFileExists($this->marker);
	}
}
