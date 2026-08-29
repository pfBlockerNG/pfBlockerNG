<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Unified colour selection must treat strpos()===0 as a dark-theme match. */
final class AlertsDarkThemeStrposTest extends TestCase
{
	public function testDarkThemeMatchUsesStrictStrpos(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$this->assertNotFalse($source);
		$this->assertStringContainsString("strpos(\$pfb_webgui_css, 'dark') !== FALSE", $source);
		$this->assertStringNotContainsString("strpos(config_get_path('system/webgui/webguicss'), 'dark') ?", $source);
	}

	public function testUnifiedPaletteFollowsEffectiveThemeNotSystemKeyAlone(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$this->assertNotFalse($source);
		$this->assertDoesNotMatchRegularExpression(
			'/\$pfb_webgui_css\s*=\s*\(string\)\s*config_get_path\(\'system\/webgui\/webguicss\'\)\s*;/',
			$source,
			'palette must not bind the system theme key alone; a user with customsettings can differ'
		);
		$this->assertStringContainsString('pfb_effective_webguicss($user_settings ?? null)', $source);
		$this->assertStringContainsString("strpos(\$pfb_webgui_css, 'dark') !== FALSE", $source);
		$this->assertSame(1, substr_count($source, "strpos(\$pfb_webgui_css, 'dark')"));
	}
}
