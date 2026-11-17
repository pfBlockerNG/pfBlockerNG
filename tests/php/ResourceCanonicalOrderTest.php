<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4032 (map #3813): PHP's pfb_canonical_alias_set() and Go's resources.Canonical order a resource body the same way.
 * Both run the shared fixture go/pfb_core/resources/testdata/canonical.json (Go: TestCanonicalFixture); a case that diverges
 * fails on one side or the other.
 */
#[CoversFunction('pfb_canonical_alias_set')]
final class ResourceCanonicalOrderTest extends TestCase
{
	public const FIXTURE = __DIR__ . '/../../go/pfb_core/resources/testdata/canonical.json';

	/** @return list<array{name: string, input: list<string>, want: list<string>}> */
	private static function fixture(): array
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 8, JSON_THROW_ON_ERROR);
		if (!is_array($doc) || !is_array($doc['cases'] ?? NULL)) {
			throw new RuntimeException('canonical.json must be {"cases": [...]}');
		}
		return $doc['cases'];
	}

	/** @return array<string, array{list<string>, list<string>}> */
	public static function cases(): array
	{
		$out = [];
		foreach (self::fixture() as $case) {
			$out[$case['name']] = [$case['input'], $case['want']];
		}
		return $out;
	}

	public function testTheFixtureHoldsCases(): void
	{
		$this->assertGreaterThanOrEqual(6, count(self::fixture()), 'canonical.json must hold the shared cases');
	}

	/**
	 * @param list<string> $input
	 * @param list<string> $want
	 */
	#[DataProvider('cases')]
	public function testPhpOrdersLikeGo(array $input, array $want): void
	{
		$this->assertSame($want, pfb_canonical_alias_set(implode("\n", $input)));
	}
}
