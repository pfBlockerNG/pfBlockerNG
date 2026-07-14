<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1246: pfblockerng_uc_countries() hardcodes two continent-level
 * pseudo-country bucket entries (geoname_ids 6255147/6255148) so MaxMind's
 * continent-only Locations rows still resolve to a synthetic pseudo-country
 * instead of hitting an undefined-array-key warning. Unexercised by the
 * existing suite.
 *
 * The file carries top-level execution and cannot be require()d
 * off-appliance (house precedent: CountryNetworksCountGuardTest.php). Each
 * bucket assignment is eval-extracted independently so the oracle tracks
 * whichever literal is actually in source.
 *
 * Feature: the Asia/Europe "undefined" pseudo-country buckets are built
 *          with their expected continent, name, iso and continent_en
 *
 *   Scenario: geoname_id 6255147 (Asia continent-only rows)
 *   Scenario: geoname_id 6255148 (Europe continent-only rows)
 */
final class GeoipContinentUndefinedBucketTest extends TestCase
{
	// Oracle: each hardcoded bucket-assignment statement extracted independently
	// (not as one adjacency-bound pair), so an unrelated edit between the two
	// real lines can't spuriously break this test.
	private static function extractBucketOracle(string $geonameId): array
	{
		$fn = "pfb_geoip_undefined_continent_oracle_{$geonameId}";
		if (!function_exists($fn)) {
			$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php';
			$src = file_get_contents($path);
			if ($src === FALSE) {
				throw new RuntimeException('test bootstrap: failed to read pfblockerng.php');
			}
			if (!preg_match(
				'/\$pfb_geoip\[\'country\'\]\[\'' . preg_quote($geonameId, '/') . '\'\]\s*=\s*array\(.*?\);/s',
				$src,
				$m
			)) {
				throw new RuntimeException("oracle extraction failed: the {$geonameId} bucket assignment was not found in pfblockerng.php");
			}
			eval(
				"function {$fn}(): array {"
				. ' $pfb_geoip = ["country" => []];'
				. ' ' . $m[0]
				. ' return $pfb_geoip["country"];'
				. ' }'
			);
		}
		return $fn();
	}

	public function testAsiaUndefinedBucketShape(): void
	{
		$country = self::extractBucketOracle('6255147');
		$this->assertArrayHasKey(
			'6255147',
			$country,
			'issue #1246: geoname_id 6255147 (Asia continent-only rows) must resolve to a pseudo-country bucket'
		);
		$this->assertSame(
			['continent' => 'Asia', 'name' => 'AA ASIA UNDEFINED', 'iso' => ['6255147'], 'continent_en' => 'Asia'],
			$country['6255147']
		);
	}

	public function testEuropeUndefinedBucketShape(): void
	{
		$country = self::extractBucketOracle('6255148');
		$this->assertArrayHasKey(
			'6255148',
			$country,
			'issue #1246: geoname_id 6255148 (Europe continent-only rows) must resolve to a pseudo-country bucket'
		);
		$this->assertSame(
			['continent' => 'Europe', 'name' => 'AA EUROPE UNDEFINED', 'iso' => ['6255148'], 'continent_en' => 'Europe'],
			$country['6255148']
		);
	}
}
