<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * #3977 (owner, 2026-11-27, "Next Update redoes"): a MaxMind locale change on the IP page only saves the setting. The Core
 * Updater records the locale it built the GeoIP lists with and converts them again on the next Update when the configured one
 * differs, so the page starts no `ugc` conversion and checks no running one. The locale is still validated. The save region is
 * top-level page code with no callable seam, so it is pinned on php_strip_whitespace() output.
 */
final class IpPageLocaleSaveOnlyTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php');
	}

	public function testALocaleChangeStartsNoConversion(): void
	{
		foreach (['pfblockerng.php ugc', 'mwexec_bg(', '(uc|gc|ugc)', 'MaxMind GeoIP conversion already in process!'] as $gone) {
			$this->assertStringNotContainsString($gone, self::$source, "{$gone} is gone with the cutover");
		}
	}

	public function testALocaleChangeSaysTheNextUpdateConvertsTheLists(): void
	{
		$this->assertStringContainsString('The next Update converts the MaxMind GeoIP lists to the new language locale', self::$source);
	}

	public function testAnInvalidLocaleIsStillRefused(): void
	{
		$this->assertStringContainsString("\$input_errors[] = 'MaxMind Locale is not valid!';", self::$source);
	}
}
