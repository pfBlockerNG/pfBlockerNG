<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_family_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->root;
		$GLOBALS['pfb']['downgrade_context_path'] = $this->root . '/context.json';
		$GLOBALS['config'] = [
			'system' => ['hostname' => 'unchanged'],
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => [
					'pfb_keep' => 'off',
					'credential' => 'secret-canary',
					'empty' => [],
				]]],
				'pfblockerngglobal' => ['unknown_future' => ['nested' => ['value' => 'keep-me']]],
				'otherpackage' => ['config' => ['untouched' => 'yes']],
			],
		];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb']['downgrade_context_path']);
		$this->removeTree($this->root);
	}

	public function testMissingMarkerDefaultsToThreeTwoAndRecordUsesGateway(): void
	{
		$this->assertSame('3.2', pfb_settings_family_current());
		$this->assertSame('3.2', PfbConfig::read('settings_family'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$this->assertSame('4.0', pfb_settings_family_current());
		$this->assertSame('4.0', PfbConfig::read('settings_family'));
	}

	public function testInvalidMarkerAndUnknownVersionFailClosed(): void
	{
		PfbConfig::write('settings_family', '9.0');
		$this->assertNull(pfb_settings_family_current());
		$this->assertSame('3.2', pfb_settings_family_from_version('3.2.0'));
		$this->assertSame('4.0', pfb_settings_family_from_version('4.0.0'));
		$this->assertSame('4.1', pfb_settings_family_from_version('4.1.0'));
		$this->assertNull(pfb_settings_family_from_version('5.0.1'));
	}

	public function testSaveAndReplacePreserveOwnedSubtreeAndUnrelatedConfig(): void
	{
		$owned = [
			'pfblockerng' => $GLOBALS['config']['installedpackages']['pfblockerng'],
			'pfblockerngglobal' => $GLOBALS['config']['installedpackages']['pfblockerngglobal'],
		];
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'changed';
		$GLOBALS['config']['installedpackages']['otherpackage']['config']['untouched'] = 'changed';
		$this->assertTrue(pfb_settings_family_replace('3.2'));
		$this->assertSame($owned['pfblockerng'], $GLOBALS['config']['installedpackages']['pfblockerng']);
		$this->assertSame($owned['pfblockerngglobal'], $GLOBALS['config']['installedpackages']['pfblockerngglobal']);
		$this->assertSame('changed', $GLOBALS['config']['installedpackages']['otherpackage']['config']['untouched']);
		$this->assertSame('unchanged', $GLOBALS['config']['system']['hostname']);
	}

	public function testMissingSlotLeavesLiveConfigUntouched(): void
	{
		$before = $GLOBALS['config'];
		$this->assertTrue(pfb_settings_family_replace('4.0'));
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testRawDowngradeWithoutContextDoesNotReplaceV3(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		$this->assertSame('current-v4', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
	}

	public function testValidGuiContextRestoresExactLowerSlotAndConsumes(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		$this->assertSame('3.2', pfb_settings_downgrade_context_target('4.0'));
		$this->assertTrue(pfb_settings_family_replace('3.2'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());
		$this->assertSame('secret-canary', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
	}

	public function testInvalidContextsRejectAndRegularFilesAreConsumed(): void
	{
		$contexts = [
			['version' => 2, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()],
			['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time() - 301],
			['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time() + 1],
			['version' => 1, 'source_family' => '3.2', 'target_family' => '3.2', 'created_at' => time()],
			['version' => 1, 'source_family' => '4.0', 'target_family' => '4.0', 'created_at' => time()],
			['version' => '1', 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()],
			['version' => 1, 'source_family' => ['4.0'], 'target_family' => '3.2', 'created_at' => time()],
		];
		foreach ($contexts as $context) {
			$this->writeContext($context);
			$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
			pfb_settings_downgrade_context_consume();
			$this->assertFileDoesNotExist($this->contextPath());
		}

		file_put_contents($this->contextPath(), '{malformed');
		chmod($this->contextPath(), 0600);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time(), 'future' => TRUE]);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		file_put_contents($this->contextPath(), str_repeat('x', 513));
		chmod($this->contextPath(), 0600);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		chmod($this->contextPath(), 0644);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		$target = $this->root . '/context-target.json';
		file_put_contents($target, '{}');
		symlink($target, $this->contextPath());
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileExists($this->contextPath());
	}

	public function testValidContextWithMissingTargetIsConsumedWithoutMutation(): void
	{
		$before = $GLOBALS['config'];
		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		$this->assertSame('3.2', pfb_settings_downgrade_context_target('4.0'));
		$this->assertTrue(pfb_settings_family_replace('3.2'));
		pfb_settings_downgrade_context_consume();
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertFileDoesNotExist($this->contextPath());
	}

	public function testKeepOffIsPreservedAtLegacyBoundary(): void
	{
		$this->assertSame(PfbLenient::Off, PfbConfig::read('pfb_keep'));
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertSame(PfbLenient::Off, PfbConfig::read('pfb_keep'));
	}

	public function testSaveWithNoOwnedConfigIsNoOpWithoutCreatingSlot(): void
	{
		foreach (array_keys($GLOBALS['config']['installedpackages']) as $section) {
			if (str_starts_with((string) $section, 'pfblockerng')) {
				unset($GLOBALS['config']['installedpackages'][$section]);
			}
		}
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertFileDoesNotExist($this->root . '/settings-3.2.xml');
	}

	public function testSaveCreatesSecureSlotAndOverwritesExisting(): void
	{
		$rootMode = fileperms($this->root) & 0777;
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$slot = $this->root . '/settings-3.2.xml';
		$this->assertSame($rootMode, fileperms($this->root) & 0777);
		$this->assertSame(0600, fileperms($slot) & 0777);
		$first = file_get_contents($slot);
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'overwrite-proof';
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$second = file_get_contents($slot);
		$this->assertNotSame($first, $second);
	}

	public function testCorruptSlotFailsWithoutMutatingLiveConfig(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$slot = $this->root . '/settings-3.2.xml';
		file_put_contents($slot, 'corrupt');
		chmod($slot, 0600);
		$before = $GLOBALS['config'];
		$this->assertFalse(pfb_settings_family_replace('3.2'));
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testPreUninstallRawPathSavesCurrentFamilyWithoutRestoringLowerSlot(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		pfb_settings_family_pre_uninstall();
		$this->assertFileExists($this->root . '/settings-4.0.xml');
		$this->assertSame('current-v4', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
	}

	public function testPreUninstallValidContextSavesCurrentRestoresLowerAndConsumes(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		pfb_settings_family_pre_uninstall();
		$this->assertFileExists($this->root . '/settings-4.0.xml');
		$this->assertSame('secret-canary', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
		$this->assertFileDoesNotExist($this->contextPath());
	}

	public function testPreUninstallInvalidContextSavesOnlyAndConsumes(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->writeContext(['version' => 2, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		pfb_settings_family_pre_uninstall();
		$this->assertFileExists($this->root . '/settings-4.0.xml');
		$this->assertSame('current-v4', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
		$this->assertFileDoesNotExist($this->contextPath());
	}

	public function testLifecycleOrdersReplaceAndContextConsumptionBeforeMigrations(): void
	{
		$install = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$this->assertIsString($install);
		$replace = strpos($install, 'pfb_settings_family_replace');
		$migrations = strpos($install, 'pfb_run_migrations();');
		$this->assertNotFalse($replace);
		$this->assertNotFalse($migrations);
		$this->assertLessThan($migrations, $replace);

		$extra = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
		$this->assertIsString($extra);
		$this->assertStringContainsString('/var/run/pfblockerng-downgrade-context.json', $extra);
		$this->assertStringContainsString('pfb_settings_downgrade_context_consume', $extra);

		$installed = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$this->assertIsString($installed);
		$installMigrations = strpos($installed, 'pfb_run_migrations();');
		$installRecord = strpos($installed, 'pfb_settings_family_record');
		$installReplace = strpos($installed, 'pfb_settings_family_replace');
		$installFamily = strpos($installed, '$pfb_installed_family = pfb_settings_family_from_version((string) pfb_pkg_ver());');
		$this->assertNotFalse($installFamily);
		$this->assertNotFalse(strpos($installed, 'pfb_settings_family_replace($pfb_installed_family)'));
		$this->assertNotFalse(strpos($installed, 'pfb_settings_family_record($pfb_installed_family)'));
		$this->assertLessThan($installReplace, $installFamily);
		$this->assertLessThan($installMigrations, $installReplace);
		$this->assertLessThan($installRecord, $installMigrations);
		$this->assertStringContainsString('installedpackages/pfblockerng', $installed);
	}

	public function testLifecycleSavePrecedesOperationAndConditionalRestore(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertIsString($source);
		$start = strpos($source, 'function pfblockerng_php_pre_deinstall_command');
		$pre = strpos($source, 'pfb_settings_family_pre_uninstall()', $start);
		$operation = strpos($source, 'pfb_pkg_operation()', $start);
		$this->assertNotFalse($start);
		$this->assertNotFalse($pre);
		$this->assertLessThan($operation, $pre);
		$this->assertStringContainsString('Keep Settings', $source);
	}

	private function contextPath(): string
	{
		return $GLOBALS['pfb']['downgrade_context_path'];
	}

	private function writeContext(array $context): void
	{
		file_put_contents($this->contextPath(), json_encode($context, JSON_THROW_ON_ERROR));
		chmod($this->contextPath(), 0600);
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path)) {
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$child = $path . '/' . $entry;
			is_dir($child) && !is_link($child) ? $this->removeTree($child) : @unlink($child);
		}
		@rmdir($path);
	}
}
