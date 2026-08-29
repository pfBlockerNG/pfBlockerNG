<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Shipped Alerts event-row defaults must meet WCAG 2 AA (4.5:1).
 * Light values are measured against #212121; dark values against #ffffff.
 */
final class AlertsPaletteContrastTest extends TestCase
{
	private const LIGHT_FG = '#212121';
	private const DARK_FG = '#ffffff';
	private const AA = 4.5;

	public function testUniDefaultsListsSixEvents(): void
	{
		$this->assertCount(6, self::parseUniDefaults(), 'uni_defaults must list six events');
	}

	/** @return array<string, array{string, string, string, string}> */
	public static function shippedDefaultProvider(): array
	{
		$out = [];
		foreach (self::parseUniDefaults() as $event => $pair) {
			$out["{$event} light"] = [$event, 'light', $pair['light_default'], self::LIGHT_FG];
			$out["{$event} dark"] = [$event, 'dark', $pair['dark_default'], self::DARK_FG];
		}
		return $out;
	}

	#[DataProvider('shippedDefaultProvider')]
	public function testShippedDefaultMeetsAa(string $event, string $theme, string $hex, string $fg): void
	{
		$ratio = self::contrastRatio($hex, $fg);
		$this->assertGreaterThanOrEqual(
			self::AA,
			$ratio,
			sprintf('%s %s %s contrast %.3f:1 against %s (need >= 4.5:1)', $event, $theme, $hex, $ratio, $fg)
		);
	}

	/** @return array<string, array{light_default: string, dark_default: string}> */
	private static function parseUniDefaults(): array
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read alerts.php');
		}
		$start = strpos($source, '$uni_defaults = array(');
		if ($start === FALSE) {
			throw new RuntimeException('uni_defaults not found');
		}
		$end = strpos($source, ');', $start);
		if ($end === FALSE) {
			throw new RuntimeException('uni_defaults unterminated');
		}
		$chunk = substr($source, $start, $end - $start);
		if (preg_match_all(
			"/'(\w+)'\s*=>\s*array\('light_default'\s*=>\s*'(#[0-9A-Fa-f]{6})',\s*'dark_default'\s*=>\s*'(#[0-9A-Fa-f]{6})'/",
			$chunk,
			$m,
			PREG_SET_ORDER
		) === FALSE) {
			throw new RuntimeException('uni_defaults parse failed');
		}
		$out = [];
		foreach ($m as $row) {
			$out[$row[1]] = ['light_default' => $row[2], 'dark_default' => $row[3]];
		}
		return $out;
	}

	private static function contrastRatio(string $a, string $b): float
	{
		$la = self::relativeLuminance($a);
		$lb = self::relativeLuminance($b);
		$hi = max($la, $lb);
		$lo = min($la, $lb);
		return ($hi + 0.05) / ($lo + 0.05);
	}

	private static function relativeLuminance(string $hex): float
	{
		$hex = ltrim($hex, '#');
		$r = hexdec(substr($hex, 0, 2));
		$g = hexdec(substr($hex, 2, 2));
		$b = hexdec(substr($hex, 4, 2));
		return 0.2126 * self::srgbToLinear($r)
			+ 0.7152 * self::srgbToLinear($g)
			+ 0.0722 * self::srgbToLinear($b);
	}

	private static function srgbToLinear(float $channel): float
	{
		$c = $channel / 255.0;
		return $c <= 0.04045 ? $c / 12.92 : (($c + 0.055) / 1.055) ** 2.4;
	}
}
