<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyPostInstallCaptureTest extends TestCase
{
	public function testPostInstallCapturesSourceBeforeTargetRestoreAndMigrations(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$this->assertIsString($source);
		$start = strpos($source, 'global $g, $pfb;');
		$source_current = strpos($source, '$pfb_source_family = pfb_settings_family_current();', $start);
		$source_save = strpos($source, 'pfb_settings_family_save($pfb_source_family)', $start);
		$target_current = strpos($source, '$pfb_installed_family = pfb_settings_family_from_version((string) pfb_pkg_ver());', $start);
		$target_replace = strpos($source, 'pfb_settings_family_replace($pfb_installed_family)', $start);
		$migrations = strpos($source, 'pfb_run_migrations();', $start);

		$this->assertNotFalse($source_current);
		$this->assertNotFalse($source_save);
		$this->assertNotFalse($target_current);
		$this->assertNotFalse($target_replace);
		$this->assertNotFalse($migrations);
		$this->assertStringContainsString('$pfb_source_family === NULL || !pfb_settings_family_save($pfb_source_family)', $source);
		$this->assertLessThan($target_current, $source_current);
		$this->assertLessThan($target_replace, $source_save);
		$this->assertLessThan($migrations, $target_replace);
	}
}
