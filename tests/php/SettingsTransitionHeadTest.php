<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionHeadTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_head_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['marker' => 'stable']]],
			],
		];
		$GLOBALS['pfb_test_corrupt_head_write'] = false;
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_corrupt_head_write']);
		$this->removeTree($this->root);
	}

	public function testCorruptHeadTempCannotReplaceVerifiedHead(): void
	{
		$first = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$head_path = dirname($first['path']) . '/head.json';
		$old_head = file_get_contents($head_path);
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['marker'] = 'changed';
		$GLOBALS['pfb_test_corrupt_head_write'] = true;

		$failed = false;
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		} catch (Throwable) {
			$failed = true;
		}

		$this->assertTrue($failed, 'corrupt head publication must fail closed');
		$this->assertSame($old_head, file_get_contents($head_path));
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
