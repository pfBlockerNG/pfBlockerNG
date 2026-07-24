<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionRestoreFailureTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_restore_failure_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_write_config_failure'] = FALSE;
		unset($GLOBALS['pfb_test_persisted_config'], $GLOBALS['pfb_test_readback_config']);
	}

	protected function tearDown(): void
	{
		unset(
			$GLOBALS['pfb_test_write_config_failure'],
			$GLOBALS['pfb_test_persisted_config'],
			$GLOBALS['pfb_test_readback_config']
		);
		$this->removeTree($this->root);
	}

	public function testFamilyIdentityAllowsDifferentTargetPackageProvenance(): void
	{
		$target = ['pfblockerng' => ['config' => ['0' => ['source' => '3.2.15']]]];
		$GLOBALS['config'] = ['installedpackages' => $target];
		$record = pfb_settings_snapshot_create('3.2', 'pfSense-pkg-pfBlockerNG', '3.2.15', $this->root);
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngstale' => ['drop' => TRUE]]];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];

		$head = pfb_settings_snapshot_head('3.2', 'pfSense-pkg-pfBlockerNG-devel', '4.0.0', $this->root);
		$this->assertSame($record['path'], $head['path']);
		$this->assertSame('pfSense-pkg-pfBlockerNG', $head['source_package_name']);
		$this->assertSame('3.2.15', $head['source_package_version']);
		$result = pfb_settings_snapshot_restore('3.2', 'pfSense-pkg-pfBlockerNG-devel', '4.0.0', $this->root);
		$this->assertSame($target, ['pfblockerng' => $result['owned']['pfblockerng']]);
		$this->assertSame($target, $GLOBALS['config']['installedpackages']);
	}

	public function testSuccessfulWriteLeavesActualReadbackOnMismatch(): void
	{
		$target = ['pfblockerng' => ['config' => ['0' => ['source' => 'target']]]];
		$GLOBALS['config'] = ['installedpackages' => $target];
		pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$before = ['installedpackages' => ['pfblockerngstale' => ['old' => TRUE], 'outside' => ['v' => 'before']]];
		$third = ['installedpackages' => ['outside' => ['v' => 'third']]];
		$GLOBALS['config'] = $before;
		$GLOBALS['pfb_test_persisted_config'] = $before;
		$GLOBALS['pfb_test_readback_config'] = $third;

		try {
			pfb_settings_snapshot_restore('3.2', 'pkg', '1', $this->root);
			$this->fail('readback mismatch must abort after a successful write');
		} catch (Throwable) {
			$this->assertSame($third, $GLOBALS['config']);
			$this->assertSame(
				['installedpackages' => ['pfblockerng' => $target['pfblockerng'], 'outside' => ['v' => 'before']]],
				$GLOBALS['pfb_test_persisted_config']
			);
		}
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
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
			$child = $path . DIRECTORY_SEPARATOR . $entry;
			is_dir($child) && !is_link($child) ? $this->removeTree($child) : @unlink($child);
		}
		@rmdir($path);
	}
}
