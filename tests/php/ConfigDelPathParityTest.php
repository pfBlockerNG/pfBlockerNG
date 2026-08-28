<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Upstream parity matrix for the config_del_path() double (issue #2000).
 *
 * Pins the wrapper guards and array_del_path() walker semantics from pfSense
 * config.lib.inc and util.inc across master, ed6c2eb8, and 9363ac5b.
 */
final class ConfigDelPathParityTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = [];
	}

	public static function parityProvider(): array
	{
		$default = 'DEFAULT';

		return [
			'successful removal returns removed value' => [
				['section' => ['leaf' => 'value', 'keep' => 'x']], 'section/leaf', $default,
				'value', ['section' => ['keep' => 'x']],
			],
			'missing leaf returns default' => [
				['section' => ['keep' => 'x']], 'section/leaf', $default,
				$default, ['section' => ['keep' => 'x']],
			],
			'missing intermediate returns default' => [
				['other' => ['leaf' => 'value']], 'section/leaf', $default,
				$default, ['other' => ['leaf' => 'value']],
			],
			'scalar intermediate returns default' => [
				['section' => 'occupied'], 'section/leaf', $default,
				$default, ['section' => 'occupied'],
			],
			'exact trailing slash rejected without mutation' => [
				['section' => ['leaf' => 'value']], 'section/leaf/', $default,
				$default, ['section' => ['leaf' => 'value']],
			],
			'trailing slash with surrounding whitespace rejected without mutation' => [
				['section' => ['leaf' => 'value']], " section/leaf/ \t", $default,
				$default, ['section' => ['leaf' => 'value']],
			],
			'double slash rejected without mutation' => [
				['section' => ['leaf' => 'value']], 'section//leaf', $default,
				$default, ['section' => ['leaf' => 'value']],
			],
			'single leading slash is ignored and deletes' => [
				['section' => ['leaf' => 'value']], '/section/leaf', $default,
				'value', ['section' => []],
			],
			'non-array config returns default without mutation' => [
				'not-an-array', 'section/leaf', $default,
				$default, 'not-an-array',
			],
			'empty path deletes empty-string root key' => [
				['' => 'root', 'keep' => 'x'], '', $default,
				'root', ['keep' => 'x'],
			],
			'null leaf is removed and returned' => [
				['section' => ['leaf' => null]], 'section/leaf', $default,
				null, ['section' => []],
			],
		];
	}

	#[DataProvider('parityProvider')]
	public function testConfigDelPathMatchesUpstreamParity(
		mixed $initial,
		string $path,
		mixed $default,
		mixed $expectedReturn,
		mixed $expectedConfigAfter
	): void {
		$GLOBALS['config'] = $initial;

		$actualReturn = config_del_path($path, $default);

		$this->assertSame($expectedReturn, $actualReturn, "{$this->dataName()}: return value mismatch");
		$this->assertSame($expectedConfigAfter, $GLOBALS['config'], "{$this->dataName()}: config after mismatch");
	}

	public function testMissingPathWithoutDefaultReturnsNull(): void
	{
		$GLOBALS['config'] = ['section' => ['keep' => 'x']];

		$this->assertNull(config_del_path('section/missing'));
		$this->assertSame(['section' => ['keep' => 'x']], $GLOBALS['config']);
	}
}
