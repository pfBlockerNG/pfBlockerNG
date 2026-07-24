<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionSnapshotDurabilityTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_durability_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['secret' => 'snapshot-secret']]],
			],
		];
		unset(
			$GLOBALS['pfb_test_snapshot_artifact_dir_sync_failure'],
			$GLOBALS['pfb_test_snapshot_head_dir_sync_failure']
		);
	}

	protected function tearDown(): void
	{
		unset(
			$GLOBALS['pfb_test_snapshot_artifact_dir_sync_failure'],
			$GLOBALS['pfb_test_snapshot_head_dir_sync_failure']
		);
		$this->removeTree($this->root);
	}

	public function testArtifactRenameSyncFailureLeavesReadableSnapshotWithoutHeadOrTemp(): void
	{
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_snapshot_artifact_dir_sync_failure'] = TRUE;
		$message = '';
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		} catch (Throwable $error) {
			$message = $error->getMessage();
		}

		$this->assertNotSame('', $message);
		$this->assertStringNotContainsString('snapshot-secret', $message);
		$dir = $this->root . '/3.2';
		$snapshots = glob($dir . '/*.xml.gz') ?: [];
		$this->assertCount(1, $snapshots);
		$this->assertFileDoesNotExist($dir . '/head.json');
		$this->assertSame([], glob($dir . '/.*.tmp') ?: []);
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame(
			['pfblockerng' => ['config' => ['0' => ['secret' => 'snapshot-secret']]]],
			pfb_settings_snapshot_read('3.2', $snapshots[0], 'pkg', '1', $this->root)
		);
	}

	public function testHeadRenameSyncFailureLeavesValidOldOrNewHeadWithoutTemp(): void
	{
		$first = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$head_path = dirname($first['path']) . '/head.json';
		$old_head = file_get_contents($head_path);
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['marker'] = 'changed';
		$GLOBALS['pfb_test_snapshot_head_dir_sync_failure'] = TRUE;
		$message = '';
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '2', $this->root);
		} catch (Throwable $error) {
			$message = $error->getMessage();
		}

		$this->assertNotSame('', $message);
		$this->assertStringNotContainsString('snapshot-secret', $message);
		$this->assertFileExists($head_path);
		$this->assertSame([], glob(dirname($head_path) . '/.*.tmp') ?: []);
		$snapshots = glob(dirname($head_path) . '/*.xml.gz') ?: [];
		$head = pfb_settings_snapshot_head('3.2', 'pkg', '2', $this->root);
		$this->assertContains($head['path'], $snapshots);
		$this->assertFileExists($head['path']);
		$this->assertSame($head['payload_sha256'], substr(basename($head['path']), 0, 64));
		$this->assertNotSame('', $old_head);
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
