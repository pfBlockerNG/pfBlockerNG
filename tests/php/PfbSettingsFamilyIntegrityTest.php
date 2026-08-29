<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyIntegrityTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_family_integrity_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->root;
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['credential' => 'snapshot']]],
				'pfblockerngglobal' => ['config' => ['0' => ['marker' => 'snapshot']]],
				'otherpackage' => ['config' => ['0' => ['marker' => 'keep']]],
			],
		];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testSaveRejectsGroupOrWorldWritableDbdir(): void
	{
		chmod($this->root, 0777);

		$this->assertFalse(pfb_settings_family_save('3.2'));
		$this->assertFileDoesNotExist($this->root . '/settings-3.2.xml');
	}

	public function testReplaceRejectsGroupOrWorldWritableDbdir(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		chmod($this->root, 0777);
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'live';

		$this->assertFalse(pfb_settings_family_replace('3.2'));
		$this->assertSame('live', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
	}

	public function testReplaceRestoresSnapshotOwnedOrderAroundUnrelatedEntries(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$GLOBALS['config']['installedpackages'] = [
			'pfblockerngglobal' => ['config' => ['0' => ['marker' => 'live-global']]],
			'otherpackage' => ['config' => ['0' => ['marker' => 'keep']]],
			'pfblockerng' => ['config' => ['0' => ['credential' => 'live']]],
		];

		$this->assertTrue(pfb_settings_family_replace('3.2'));
		$this->assertSame(
			['pfblockerng', 'otherpackage', 'pfblockerngglobal'],
			array_keys($GLOBALS['config']['installedpackages'])
		);
		$this->assertSame('keep', $GLOBALS['config']['installedpackages']['otherpackage']['config']['0']['marker']);
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
