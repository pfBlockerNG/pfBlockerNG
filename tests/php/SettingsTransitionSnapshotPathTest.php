<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionSnapshotPathTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_path_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['secret' => 'snapshot-secret']]],
			],
		];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testRootSymlinkCannotCreateTarget(): void
	{
		$target = $this->root . '/target';
		mkdir($target, 0700);
		$link = $this->root . '/link';
		$this->assertTrue(symlink($target, $link));
		$failed = false;
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '1', $link);
		} catch (Throwable) {
			$failed = true;
		}
		$this->assertTrue($failed);
		$this->assertDirectoryDoesNotExist($target . '/3.2');
	}

	public function testRootAndFamilyModesFailWithoutChangingHeadOrConfig(): void
	{
		$record = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$head_path = dirname($record['path']) . '/head.json';
		$head = file_get_contents($head_path);
		chmod($this->root, 0755);
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['changed'] = 'yes';
		$config = $GLOBALS['config'];
		$read_failed = false;
		try {
			pfb_settings_snapshot_read('3.2', $record['path'], 'pkg', '1', $this->root);
		} catch (Throwable) {
			$read_failed = true;
		}
		$this->assertTrue($read_failed);
		$failed = false;
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '2', $this->root);
		} catch (Throwable) {
			$failed = true;
		}
		$this->assertTrue($failed);
		$this->assertSame($head, file_get_contents($head_path));
		$this->assertSame($config, $GLOBALS['config']);

		chmod($this->root, 0700);
		chmod(dirname($record['path']), 0755);
		$read_failed = false;
		try {
			pfb_settings_snapshot_read('3.2', $record['path'], 'pkg', '1', $this->root);
		} catch (Throwable) {
			$read_failed = true;
		}
		$this->assertTrue($read_failed);
		$failed = false;
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '3', $this->root);
		} catch (Throwable) {
			$failed = true;
		}
		$this->assertTrue($failed);
		$this->assertSame($head, file_get_contents($head_path));
	}

	public function testStandaloneDtdFailsWithoutSecretDisclosure(): void
	{
		$record = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$xml = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY secret 'snapshot-secret'>]><pfblockerng-settings><owned_payload>&secret;</owned_payload></pfblockerng-settings>";
		file_put_contents($record['path'], gzencode($xml));
		chmod($record['path'], 0600);
		$message = '';
		try {
			pfb_settings_snapshot_read('3.2', $record['path'], 'pkg', '1', $this->root);
		} catch (Throwable $error) {
			$message = $error->getMessage();
		}
		$this->assertNotSame('', $message);
		$this->assertStringNotContainsString('snapshot-secret', $message);
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
