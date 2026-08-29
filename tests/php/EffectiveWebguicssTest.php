<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Alerts palette must follow the theme head.inc actually renders, including
 * the missing-file fallback to pfSense.css.
 */
final class EffectiveWebguicssTest extends TestCase
{
	public function testMissingUserThemeFileSelectsLightPalette(): void
	{
		$exists = static fn(string $path): bool => basename($path) === 'pfSense.css';
		$css = pfb_effective_webguicss(
			['webgui' => ['webguicss' => 'pfSense-dark.css']],
			$exists
		);
		$this->assertSame('pfSense.css', $css);
		$this->assertFalse(strpos($css, 'dark') !== FALSE);
	}

	public function testMissingUserThemeFileDoesNotFallThroughToAPresentSystemTheme(): void
	{
		$exists = static fn(string $path): bool => in_array(basename($path), ['pfSense.css', 'pfSense-dark.css'], TRUE);
		$css = pfb_effective_webguicss(
			['webgui' => ['webguicss' => 'gone.css']],
			$exists
		);
		$this->assertSame('pfSense.css', $css);
	}

	public function testMissingUserSettingsFallsBackToPfSenseCss(): void
	{
		$exists = static fn(string $path): bool => basename($path) === 'pfSense.css';
		$css = pfb_effective_webguicss(null, $exists);
		$this->assertSame('pfSense.css', $css);
		$this->assertFalse(strpos($css, 'dark') !== FALSE);
	}

	public function testPresentUserDarkThemeIsUsed(): void
	{
		$exists = static fn(string $path): bool => in_array(basename($path), ['pfSense.css', 'pfSense-dark.css'], TRUE);
		$css = pfb_effective_webguicss(
			['webgui' => ['webguicss' => 'pfSense-dark.css']],
			$exists
		);
		$this->assertSame('pfSense-dark.css', $css);
		$this->assertTrue(strpos($css, 'dark') !== FALSE);
	}

	public function testPathSeparatorsAreStrippedBeforeTheFilesystemCheck(): void
	{
		$seen = [];
		$exists = static function (string $path) use (&$seen): bool {
			$seen[] = $path;
			return FALSE;
		};
		pfb_effective_webguicss(
			['webgui' => ['webguicss' => '../pfSense-dark.css']],
			$exists
		);
		foreach ($seen as $path) {
			$this->assertStringNotContainsString('..', $path);
		}
	}
}
