<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Upstream parity matrix for the config_set_path() double (issue #1918).
 *
 * Pins tests/php/pfsense_doubles.php's config_set_path() against pfSense
 * config.lib.inc's config_set_path() + util.inc's array_set_path() it wraps.
 * array_set_path() is byte-identical across all three refs checked:
 * pfsense/pfsense `master`, `ed6c2eb8` (CE 2.8.0), `9363ac5b`.
 *
 * Every row asserts BOTH the return value and the resulting whole
 * $GLOBALS['config'] with assertSame, except row "NOTE-A" (config unset,
 * plain path) -- see the relaxed-assertion comment on that row below.
 * $default is always the distinguishable sentinel 'DEFAULT' (never null),
 * so a null return can never fake a "returns $default" pass.
 */
final class ConfigSetPathParityTest extends TestCase
{
	// Sentinel marking "the initial $GLOBALS['config'] is UNSET" in a
	// provider row -- distinct from any real value (array/string/null) any
	// row here uses, so it can share the provider's $initial slot.
	private const CONFIG_UNSET = "\0__CONFIG_UNSET__\0";

	// Sentinel marking "skip the assertSame(cfg after) check, use the NOTE-A
	// relaxed check instead" -- see testConfigSetPathMatchesUpstreamParity().
	private const NOTE_A_RELAXED_CHECK = "\0__NOTE_A_RELAXED_CHECK__\0";

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
			'append: trailing slash onto existing leaf array (#1912)' => [
				['items' => ['first']], 'items/', 'second', $default,
				'second', ['items' => ['first', 'second']],
			],
			'replace: plain path onto existing leaf array (#1912)' => [
				['items' => ['first']], 'items', 'second', $default,
				'second', ['items' => 'second'],
			],
			'non-empty scalar intermediate, append path' => [
				['group' => 'occupied'], 'group/items/', 'second', $default,
				$default, ['group' => 'occupied'],
			],
			'non-empty scalar intermediate, plain path' => [
				['group' => 'occupied'], 'group/items', 'second', $default,
				$default, ['group' => 'occupied'],
			],
			'non-empty scalar intermediate, deep path' => [
				['a' => ['b' => 'occupied']], 'a/b/c/d', 'v', $default,
				$default, ['a' => ['b' => 'occupied']],
			],
			'empty-string intermediate is overwritten' => [
				['group' => ''], 'group/items', 'second', $default,
				'second', ['group' => ['items' => 'second']],
			],
			"string-'0' intermediate is overwritten (upstream empty() quirk)" => [
				['group' => '0'], 'group/items', 'second', $default,
				'second', ['group' => ['items' => 'second']],
			],
			'int-0 intermediate is overwritten' => [
				['group' => 0], 'group/items', 'second', $default,
				'second', ['group' => ['items' => 'second']],
			],
			'false intermediate is overwritten' => [
				['group' => false], 'group/items', 'second', $default,
				'second', ['group' => ['items' => 'second']],
			],
			'null intermediate is overwritten' => [
				['group' => null], 'group/items', 'second', $default,
				'second', ['group' => ['items' => 'second']],
			],
			'empty-array intermediate is reset to [] then descended' => [
				['group' => []], 'group/items', 'second', $default,
				'second', ['group' => ['items' => 'second']],
			],
			'non-empty-array intermediate is descended, siblings preserved' => [
				['group' => ['keep' => 'x']], 'group/items', 'second', $default,
				'second', ['group' => ['keep' => 'x', 'items' => 'second']],
			],
			// Row 13 (scalar intermediate, no $default arg) is its own test
			// method -- the 2-arg call is a different shape than this
			// provider's rows, not a bent version of it.
			'append onto non-empty scalar leaf wraps it' => [
				['items' => 'scalar'], 'items/', 'x', $default,
				'x', ['items' => ['x']],
			],
			'append onto missing leaf creates a list' => [
				[], 'items/', 'x', $default,
				'x', ['items' => ['x']],
			],
			'append onto empty-string leaf wraps it' => [
				['items' => ''], 'items/', 'x', $default,
				'x', ['items' => ['x']],
			],
			'plain path creates missing intermediates' => [
				[], 'a/b/c', 'v', $default,
				'v', ['a' => ['b' => ['c' => 'v']]],
			],
			'array value onto missing path' => [
				[], 'a/b', ['k' => 'v'], $default,
				['k' => 'v'], ['a' => ['b' => ['k' => 'v']]],
			],
			"'//' mid-path rejected, no mutation" => [
				['a' => ['b' => 'keep']], 'a//b', 'v', $default,
				$default, ['a' => ['b' => 'keep']],
			],
			"'//' leading rejected, no mutation" => [
				['a' => ['b' => 'keep']], '//a/b', 'v', $default,
				$default, ['a' => ['b' => 'keep']],
			],
			"'//' trailing rejected, no mutation" => [
				['a' => ['b' => 'keep']], 'a/b//', 'v', $default,
				$default, ['a' => ['b' => 'keep']],
			],
			"'///' rejected, no mutation" => [
				['a' => 'keep'], '///', 'v', $default,
				$default, ['a' => 'keep'],
			],
			'empty path + array value replaces the whole config' => [
				['old' => 1], '', ['new' => 2], $default,
				['new' => 2], ['new' => 2],
			],
			'empty path + scalar value rejected, no mutation' => [
				['old' => 1], '', 'scalar', $default,
				$default, ['old' => 1],
			],
			"'/' + array value rejected, no mutation" => [
				['old' => 1], '/', ['new' => 2], $default,
				$default, ['old' => 1],
			],
			"'/' + scalar value rejected, no mutation" => [
				['old' => 1], '/', 'scalar', $default,
				$default, ['old' => 1],
			],
			'single leading slash is ignored (existing path)' => [
				['a' => ['b' => 'keep']], '/a/b', 'v', $default,
				'v', ['a' => ['b' => 'v']],
			],
			'single leading slash is ignored (missing path)' => [
				[], '/a/b', 'v', $default,
				'v', ['a' => ['b' => 'v']],
			],
			'leading slash + trailing slash = ignore + append' => [
				['a' => ['b' => ['keep']]], '/a/b/', 'v', $default,
				'v', ['a' => ['b' => ['keep', 'v']]],
			],
			'numeric-string key leaf' => [
				['a' => [0 => 'old']], 'a/0', 'v', $default,
				'v', ['a' => [0 => 'v']],
			],
			'numeric-0 intermediate array is descended, not treated as root' => [
				['a' => [0 => ['x' => 1]]], 'a/0/y', 'v', $default,
				'v', ['a' => [0 => ['x' => 1, 'y' => 'v']]],
			],
			// NOTE-A: upstream's `global $config;` itself materialises
			// $GLOBALS['config'] = null when the global did not exist, so
			// upstream leaves it present-and-null. The double reads the
			// global without `global`, so it leaves it absent. Behaviourally
			// identical for every consumer (config_get_path() returns its
			// default either way) -- the ONLY row where a literal-parity
			// assertion is relaxed (see the NOTE_A_RELAXED_CHECK handling
			// below).
			'$config unset -> $default, no config fabricated (NOTE-A)' => [
				self::CONFIG_UNSET, 'a/b', 'v', $default,
				$default, self::NOTE_A_RELAXED_CHECK,
			],
			'$config is a scalar string -> $default, preserved' => [
				'notanarray', 'a/b', 'v', $default,
				$default, 'notanarray',
			],
			'$config is null -> $default, preserved' => [
				null, 'a/b', 'v', $default,
				$default, null,
			],
			'$config unset + empty path + array value -> initialised and replaced' => [
				self::CONFIG_UNSET, '', ['new' => 2], $default,
				['new' => 2], ['new' => 2],
			],
			'$config scalar + empty path + array value -> initialised and replaced' => [
				'notanarray', '', ['new' => 2], $default,
				['new' => 2], ['new' => 2],
			],
		];
	}

	#[DataProvider('parityProvider')]
	public function testConfigSetPathMatchesUpstreamParity(
		mixed $initial,
		string $path,
		mixed $value,
		mixed $default,
		mixed $expectedReturn,
		mixed $expectedConfigAfter
	): void {
		$label = (string) $this->dataName();

		if ($initial === self::CONFIG_UNSET) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $initial;
		}

		$actualReturn = config_set_path($path, $value, $default);

		$this->assertSame($expectedReturn, $actualReturn, "{$label}: return value mismatch");

		if ($expectedConfigAfter === self::NOTE_A_RELAXED_CHECK) {
			// The ONLY relaxation in this matrix, and only in one direction:
			// absent and present-and-null are the two states this row accepts,
			// because upstream's `global $config;` materialises the null while
			// the double leaves the global absent. Any OTHER config the double
			// might invent -- a scalar, an array, an empty string -- still fails.
			$this->assertNull(
				$GLOBALS['config'] ?? null,
				"{$label}: double must not fabricate a config"
			);

			return;
		}

		// Read through array_key_exists(), not `?? null`: the "$config is null"
		// row expects a present-and-null config, and `??` would collapse an
		// erroneously unset() config onto that same null -- passing a row whose
		// whole point is that the rejection branch mutates nothing.
		$actualConfigAfter = array_key_exists('config', $GLOBALS)
			? $GLOBALS['config']
			: self::CONFIG_UNSET;
		$this->assertSame($expectedConfigAfter, $actualConfigAfter, "{$label}: \$GLOBALS['config'] after mismatch");
	}

	/**
	 * Row 13: a scalar intermediate with NO $default argument returns null
	 * (the 2-arg call) -- kept out of parityProvider() because its call
	 * shape differs from every other row (no 4th argument), not because its
	 * assertions differ.
	 */
	public function testScalarIntermediateWithNoDefaultArgReturnsNull(): void
	{
		$GLOBALS['config'] = ['group' => 'occupied'];

		$this->assertNull(config_set_path('group/items', 'second'));
		$this->assertSame(['group' => 'occupied'], $GLOBALS['config']);
	}
}
