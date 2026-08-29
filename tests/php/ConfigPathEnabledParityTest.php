<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Upstream parity matrix for the config_path_enabled() double (issue #2001).
 *
 * Pins the wrapper guards and array_path_enabled() semantics from pfSense
 * config.lib.inc and util.inc across master, ed6c2eb8, and 9363ac5b.
 */
final class ConfigPathEnabledParityTest extends TestCase
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
		return [
			'enable key absent returns false' => [
				['section' => ['other' => 'x']], 'section', 'enable', false,
				false, ['section' => ['other' => 'x']],
			],
			'enable key null returns false' => [
				['section' => ['enable' => null]], 'section', 'enable', false,
				false, ['section' => ['enable' => null]],
			],
			'enable key empty string returns true' => [
				['section' => ['enable' => '']], 'section', 'enable', false,
				true, ['section' => ['enable' => '']],
			],
			'enable key nonempty value returns true' => [
				['section' => ['enable' => 'on']], 'section', 'enable', false,
				true, ['section' => ['enable' => 'on']],
			],
			'custom enable key returns true' => [
				['section' => ['custom' => 'yes']], 'section', 'custom', false,
				true, ['section' => ['custom' => 'yes']],
			],
			'scalar node returns custom default' => [
				['section' => 'occupied'], 'section', 'enable', 'SCALAR_DEFAULT',
				'SCALAR_DEFAULT', ['section' => 'occupied'],
			],
			'missing node returns custom default' => [
				['section' => []], 'section/missing', 'enable', 'MISSING_DEFAULT',
				'MISSING_DEFAULT', ['section' => []],
			],
			'exact trailing slash returns custom default' => [
				['section' => ['enable' => 'on']], 'section/', 'enable', 'TRAILING_DEFAULT',
				'TRAILING_DEFAULT', ['section' => ['enable' => 'on']],
			],
			'trailing slash with surrounding whitespace returns custom default' => [
				['section' => ['enable' => 'on']], " section/ \t", 'enable', 'TRAILING_DEFAULT',
				'TRAILING_DEFAULT', ['section' => ['enable' => 'on']],
			],
			'double slash returns custom default' => [
				['section' => ['enable' => 'on']], 'section//enable', 'enable', 'DOUBLE_DEFAULT',
				'DOUBLE_DEFAULT', ['section' => ['enable' => 'on']],
			],
			'non-array config returns custom default' => [
				'not-an-array', 'section', 'enable', 'CONFIG_DEFAULT',
				'CONFIG_DEFAULT', 'not-an-array',
			],
			'non-array config preserves array default with enable key' => [
				'not-an-array', 'section', 'enable', ['enable' => 'on'],
				['enable' => 'on'], 'not-an-array',
			],
			'null config preserves array default without enable key' => [
				null, 'section', 'enable', ['other' => 'x'],
				['other' => 'x'], null,
			],
			'custom true default is preserved' => [
				['section' => []], 'section/missing', 'enable', true,
				true, ['section' => []],
			],
			'empty path checks root enable key' => [
				['enable' => 'on', 'section' => []], '', 'enable', false,
				true, ['enable' => 'on', 'section' => []],
			],
		];
	}

	#[DataProvider('parityProvider')]
	public function testConfigPathEnabledMatchesUpstreamParity(
		mixed $initial,
		string $path,
		string $enableKey,
		mixed $default,
		mixed $expectedReturn,
		mixed $expectedConfigAfter
	): void {
		$GLOBALS['config'] = $initial;

		$actualReturn = config_path_enabled($path, $enableKey, $default);

		$this->assertSame($expectedReturn, $actualReturn, "{$this->dataName()}: return value mismatch");
		$this->assertSame($expectedConfigAfter, $GLOBALS['config'], "{$this->dataName()}: config after mismatch");
	}
}
