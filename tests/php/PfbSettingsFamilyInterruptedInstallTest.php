<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyInterruptedInstallTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_int_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->root;
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['pfb_keep' => 'on', 'canary' => 'pristine']]],
				'other' => ['config' => ['0' => ['keep' => 'foreign']]],
				'package' => [['name' => 'pfSense-pkg-pfBlockerNG', 'version' => '4.0.0']],
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

	public function testRetryAfterInterruptedInstallKeepsTheSourceSnapshot(): void
	{
		pfb_install_settings_family_capture_restore();
		$before = file_get_contents($this->root . '/settings-3.3.xml');
		$this->assertIsString($before, 'source snapshot must exist after the first capture');

		// Interrupted mid-migration: migrations mutated live config and the install never finished.
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['canary'] = 'half-migrated';

		$this->assertSame('4.0', pfb_settings_family_current(), 'installed family must be recorded before migrations');
		$this->assertSame('4.0', pfb_install_settings_family_capture_restore());
		$this->assertSame($before, file_get_contents($this->root . '/settings-3.3.xml'), 'retry must not rewrite the source snapshot');

		$this->assertTrue(pfb_settings_family_replace('3.3'));
		$this->assertSame('pristine', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['canary']);
	}
}
