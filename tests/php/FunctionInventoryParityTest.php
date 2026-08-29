<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Phase-0 parity oracle for the pfblockerng.inc domain split (#1122).
 *
 * Pins the full function surface the package defines when loaded through the
 * umbrella include: every function name plus its Reflection signature
 * (parameter names, by-ref flags, variadics, types, defaults, return type),
 * against the committed golden snapshot in fixtures/function_inventory.json.
 * Any extraction phase that drops, renames, duplicates (PHP fatals), or
 * re-signatures a function fails here loudly; once a function is in the
 * package, a pure byte-for-byte move between package files stays green
 * because the snapshot records no file-of-origin.
 *
 * The snapshot is captured at the end of tests/php/bootstrap.php (before any
 * test runs), so this oracle is independent of test ordering.
 *
 * Legitimate signature changes regenerate the golden:
 *   PFB_UPDATE_FUNCTION_INVENTORY=1 vendor/bin/phpunit --filter FunctionInventoryParityTest
 */
final class FunctionInventoryParityTest extends TestCase
{
	private const GOLDEN = __DIR__ . '/fixtures/function_inventory.json';

	public function testPackageFunctionInventoryMatchesGolden(): void
	{
		$actual = $GLOBALS['pfb_function_inventory'] ?? null;
		self::assertIsArray($actual, 'bootstrap did not capture the function inventory');
		self::assertNotEmpty($actual, 'bootstrap captured zero package functions — the capture filter is broken');

		if (getenv('PFB_UPDATE_FUNCTION_INVENTORY') === '1') {
			$encoded = json_encode(
				$actual,
				JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
			);
			self::assertNotFalse(file_put_contents(self::GOLDEN, $encoded . "\n"));
			// A regeneration run must never read as a plain PASS: if the env var
			// ever leaked into CI, the oracle would be silently disabled.
			self::markTestIncomplete('golden regenerated from the live capture — commit it and re-run without PFB_UPDATE_FUNCTION_INVENTORY');
		}

		self::assertFileExists(self::GOLDEN);
		$golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);
		self::assertIsArray($golden);

		self::assertSame(
			array_keys($golden),
			array_keys($actual),
			'function inventory diverged from the golden snapshot: a change dropped, renamed, or added a package function'
		);
		self::assertSame(
			$golden,
			$actual,
			'function signature(s) diverged from the golden snapshot (parameters / by-ref / defaults / types)'
		);
	}
}
