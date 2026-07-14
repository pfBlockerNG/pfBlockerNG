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
 * off-appliance (house precedent: CountryNetworksCountGuardTest.php). The
 * two-statement block is eval-extracted verbatim so the oracle tracks
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
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php';
		$src = file_get_contents($path);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.php');
		}
		self::$src = $src;

		// Oracle: the two hardcoded bucket-assignment statements, extracted
		// verbatim so the test tracks whichever literal is actually in source.
		if (!function_exists('pfb_geoip_undefined_continent_oracle')) {
			if (!preg_match(
				'/\$pfb_geoip\[\'country\'\]\[\'6255147\'\]\s*=\s*array\(.*?\);'
				. '\s*\$pfb_geoip\[\'country\'\]\[\'6255148\'\]\s*=\s*array\(.*?\);/s',
				$src,
				$m
			)) {
				throw new RuntimeException('oracle extraction failed: the 6255147/6255148 bucket assignments were not found in pfblockerng.php');
			}
			eval(
				'function pfb_geoip_undefined_continent_oracle(): array {'
				. ' $pfb_geoip = ["country" => []];'
				. ' ' . $m[0]
				. ' return $pfb_geoip["country"];'
				. ' }'
			);
		}
	}

	public function testAsiaUndefinedBucketShape(): void
	{
		$country = pfb_geoip_undefined_continent_oracle();
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
		$country = pfb_geoip_undefined_continent_oracle();
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
