<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * SafeSearch save: its two selects are single selects, so only a known option string is stored. A crafted array, nested or
 * not, falls back to the default (stored as Disable) instead of throwing a TypeError (a 500) or storing an array in
 * config.xml (issue #4000).
 *
 * The page cannot be required off-appliance, so its real option arrays and select-validation region are extracted from the
 * shipped source and evaluated (PageStatementLoader.php).
 */
#[CoversNothing]
final class SafeSearchSelectOptionTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_safesearch.php';

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function tearDown(): void
	{
		$_POST = [];
	}

	/**
	 * Run the page's select validation over $post; returns what the page would store from and every PHP diagnostic it raised.
	 *
	 * @param array<string, mixed> $post
	 * @return array{post: array<string, mixed>, diagnostics: list<string>}
	 */
	private static function validateSelects(array $post): array
	{
		$_POST = $post;
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			pfb_test_page_eval(
				pfb_test_page_region(self::PAGE, '// Select field options', '// $input_errors is read')
				. pfb_test_page_region(self::PAGE, '// Validate Select field (array) options', "\tif (!\$input_errors) {"),
				[]
			);
		} finally {
			restore_error_handler();
		}
		return ['post' => $_POST, 'diagnostics' => $diagnostics];
	}

	public function testValidSelectsAreKept(): void
	{
		$result = self::validateSelects(['save' => '1', 'safesearch_enable' => 'Enable', 'safesearch_youtube' => 'Strict']);

		$this->assertSame([], $result['diagnostics']);
		$this->assertSame('Enable', $result['post']['safesearch_enable']);
		$this->assertSame('Strict', $result['post']['safesearch_youtube']);
	}

	public function testAnArrayPostedToASingleSelectFallsBackToTheDefault(): void
	{
		foreach ([[['x']], ['Enable', ['x']], ['Enable']] as $value) {
			$result = self::validateSelects(['save' => '1', 'safesearch_enable' => $value, 'safesearch_youtube' => $value]);

			$this->assertSame([], $result['diagnostics'], json_encode($value));
			$this->assertSame('', $result['post']['safesearch_enable'], json_encode($value));
			$this->assertSame('', $result['post']['safesearch_youtube'], json_encode($value));
		}
	}
}
