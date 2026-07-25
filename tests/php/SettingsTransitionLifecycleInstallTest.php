<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Regression coverage for the settings-transition lifecycle boundary.
 *
 * The package installer and pre-deinstall hook execute appliance-only work, so
 * this test pins their source-level ordering and safety guards rather than
 * loading either procedural script in the unit harness.
 */
final class SettingsTransitionLifecycleInstallTest extends TestCase
{
	private static function source(string $relativePath): string
	{
		$path = dirname(__DIR__, 2) . '/' . $relativePath;
		$source = @file_get_contents($path);
		self::assertIsString($source, "could not read {$path}");
		return $source;
	}

	public function testInstallerRecordsSchemaFamilyImmediatelyAfterMigrations(): void
	{
		$source = self::source('src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$migrations = strpos($source, 'pfb_run_migrations();');
		$this->assertNotFalse($migrations, 'installer migration driver is missing');
		$remainingFlow = strpos($source, '// MaxMind Database', $migrations);
		$this->assertNotFalse($remainingFlow, 'installer remaining flow boundary is missing');

		$markerBlock = substr($source, $migrations, $remainingFlow - $migrations);
		$this->assertMatchesRegularExpression(
			"/if \\(PfbConfig::read\\('pfb_schema_family'\\) !== '4\\.0'\\) \\{.*?PfbConfig::write\\('pfb_schema_family', '4\\.0'\\);.*?write_config\\(/s",
			$markerBlock,
			'installer must persist the schema-family marker only when it changes'
		);
		$this->assertSame(
			1,
			substr_count($markerBlock, "PfbConfig::write('pfb_schema_family', '4.0');"),
			'schema-family marker must have one guarded write'
		);
		$this->assertSame(
			1,
			substr_count($markerBlock, 'write_config('),
			'schema-family marker must have one config persistence call'
		);
	}

	public function testPreDeinstallDeletesTransitionArtifactsOnlyForKeepOff(): void
	{
		$source = self::source('src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$function = strpos($source, 'function pfblockerng_php_pre_deinstall_command()');
		$this->assertNotFalse($function, 'pre-deinstall hook is missing');
		$teardownGuard = strpos($source, 'if (!pfb_pkg_op_tears_down($pfb_pkg_op))', $function);
		$this->assertNotFalse($teardownGuard, 'pre-deinstall teardown guard is missing');
		$keepOff = strpos($source, "if (\$pfb['keep'] != 'on')", $teardownGuard);
		$this->assertNotFalse($keepOff, 'keep-off cleanup branch is missing');
		$retained = strpos($source, "else {", $keepOff);
		$this->assertNotFalse($retained, 'keep-on retention branch is missing');

		$this->assertLessThan($keepOff, $teardownGuard, 'cleanup must remain behind the genuine-removal guard');
		$cleanup = substr($source, $keepOff, $retained - $keepOff);
		$this->assertStringContainsString("'/cf/conf/pfblockerng'", $cleanup);
		$this->assertStringContainsString(
			'_pfb_settings_validate_dir($pfb_transition_root);',
			$cleanup,
			'cleanup must validate the root without following symlinks or accepting unsafe ownership/mode'
		);
		$this->assertStringContainsString('rmdir_recursive(', $cleanup, 'cleanup must remove the transition artifact tree');

		$retention = substr($source, $retained, 1200);
		$this->assertStringNotContainsString("'/cf/conf/pfblockerng'", $retention);
	}
}
