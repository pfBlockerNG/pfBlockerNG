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
			'pfSense-dark.css',
			$exists
		);
		$this->assertSame('pfSense.css', $css);
		$this->assertFalse(strpos($css, 'dark') !== FALSE);
	}

	public function testMissingSystemThemeFileSelectsLightPalette(): void
	{
		$exists = static fn(string $path): bool => basename($path) === 'pfSense.css';
		$css = pfb_effective_webguicss(null, 'gone-dark.css', $exists);
		$this->assertSame('pfSense.css', $css);
		$this->assertFalse(strpos($css, 'dark') !== FALSE);
	}

	public function testPresentUserDarkThemeWinsOverSystemLight(): void
	{
		$exists = static fn(string $path): bool => in_array(basename($path), ['pfSense.css', 'pfSense-dark.css'], TRUE);
		$css = pfb_effective_webguicss(
			['webgui' => ['webguicss' => 'pfSense-dark.css']],
			'pfSense.css',
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
			'foo/bar.css',
			$exists
		);
		foreach ($seen as $path) {
			$this->assertStringNotContainsString('..', $path);
			$this->assertStringNotContainsString('foo/bar', $path);
		}
	}

	public function testAlertsPageUsesTheHelper(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$this->assertNotFalse($source);
		$this->assertStringContainsString(
			'pfb_effective_webguicss($user_settings ?? null, config_get_path(\'system/webgui/webguicss\'))',
			$source
		);
		$this->assertDoesNotMatchRegularExpression(
			'/\$pfb_webgui_css\s*=\s*\(string\)\s*config_get_path\(\'system\/webgui\/webguicss\'\)\s*;/',
			$source
		);
	}
}
