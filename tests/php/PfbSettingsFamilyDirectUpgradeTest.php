<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyDirectUpgradeTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_direct_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->root;
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['pfb_keep' => 'off']]],
			],
		];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb']['dbdir']);
		if (!is_dir($this->root)) {
			return;
		}
		foreach (scandir($this->root) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			@unlink($this->root . '/' . $entry);
		}
		@rmdir($this->root);
	}

	public function testUnmarkedLegacySettingsUpgradeDirectlyAndRestoreOnThreeThree(): void
	{
		$GLOBALS['config']['installedpackages'] = [
			'pfblockerng' => ['config' => ['0' => ['pfb_keep' => 'off']]],
			'pfblockerngdnsblsettings' => ['config' => [[
				'maxmind_key' => 'secret',
				'empty' => '',
				'nested' => ['a' => '1'],
			]]],
			'other' => ['x' => '1'],
			'package' => [['name' => 'pfSense-pkg-pfBlockerNG', 'version' => '4.0.0']],
		];
		$before = pfb_settings_family_owned_sections();
		$this->assertSame('3.3', pfb_settings_family_current());

		$installed = pfb_install_settings_family_capture_restore();
		$this->assertSame('4.0', $installed);
		$this->assertFileExists($this->root . '/settings-3.3.xml');
		$this->assertFileDoesNotExist($this->root . '/settings-3.2.xml');

		$GLOBALS['config']['installedpackages']['pfblockerngdnsblsettings'] = ['config' => [['v4only' => 'on']]];
		$this->assertTrue(pfb_settings_family_replace('3.3'));
		$this->assertSame($before, pfb_settings_family_owned_sections());
		$this->assertSame(['x' => '1'], $GLOBALS['config']['installedpackages']['other']);
	}
}
