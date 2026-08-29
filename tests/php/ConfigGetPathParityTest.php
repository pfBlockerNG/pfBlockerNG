<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Upstream parity matrix for the config_get_path() double (issue #1999).
 *
 * Pins the wrapper guards and array_get_path() walker semantics from pfSense
 * config.lib.inc and util.inc across master, ed6c2eb8, and 9363ac5b.
 */
final class ConfigGetPathParityTest extends TestCase
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
			'plain hit' => [
				['section' => ['leaf' => 'value']], 'section/leaf', $default,
				'value', ['section' => ['leaf' => 'value']],
			],
			'missing leaf' => [
				['section' => []], 'section/leaf', $default,
				$default, ['section' => []],
			],
			'scalar intermediate' => [
				['section' => 'occupied'], 'section/leaf', $default,
				$default, ['section' => 'occupied'],
			],
			'exact trailing slash rejected' => [
				['section' => ['leaf' => 'value']], 'section/leaf/', $default,
				$default, ['section' => ['leaf' => 'value']],
			],
			'trailing slash with surrounding whitespace rejected' => [
				['section' => ['leaf' => 'value']], " section/leaf/ \t", $default,
				$default, ['section' => ['leaf' => 'value']],
			],
			'double slash rejected' => [
				['section' => ['leaf' => 'value']], 'section//leaf', $default,
				$default, ['section' => ['leaf' => 'value']],
			],
			'empty-string leaf uses non-null default' => [
				['section' => ['leaf' => '']], 'section/leaf', $default,
				$default, ['section' => ['leaf' => '']],
			],
			'empty-string leaf is returned with null default' => [
				['section' => ['leaf' => '']], 'section/leaf', null,
				'', ['section' => ['leaf' => '']],
			],
			'single leading slash is ignored' => [
				['section' => ['leaf' => 'value']], '/section/leaf', $default,
				'value', ['section' => ['leaf' => 'value']],
			],
			'non-array config returns default' => [
				'not-an-array', 'section/leaf', $default,
				$default, 'not-an-array',
			],
			'empty path returns whole config' => [
				['section' => ['leaf' => 'value']], '', $default,
				['section' => ['leaf' => 'value']], ['section' => ['leaf' => 'value']],
			],
		];
	}

	#[DataProvider('parityProvider')]
	public function testConfigGetPathMatchesUpstreamParity(
		mixed $initial,
		string $path,
		mixed $default,
		mixed $expectedReturn,
		mixed $expectedConfigAfter
	): void {
		$GLOBALS['config'] = $initial;

		$actualReturn = config_get_path($path, $default);

		$this->assertSame($expectedReturn, $actualReturn, "{$this->dataName()}: return value mismatch");
		$this->assertSame($expectedConfigAfter, $GLOBALS['config'], "{$this->dataName()}: config after mismatch");
	}
}
