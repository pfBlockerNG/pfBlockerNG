<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionSnapshotPathTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_path_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
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
		$failed = FALSE;
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '1', $link);
		} catch (Throwable) {
			$failed = TRUE;
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
		$read_failed = FALSE;
		try {
			pfb_settings_snapshot_read('3.2', $record['path'], 'pkg', '1', $this->root);
		} catch (Throwable) {
			$read_failed = TRUE;
		}
		$this->assertTrue($read_failed);
		$failed = FALSE;
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '2', $this->root);
		} catch (Throwable) {
			$failed = TRUE;
		}
		$this->assertTrue($failed);
		$this->assertSame($head, file_get_contents($head_path));
		$this->assertSame($config, $GLOBALS['config']);

		chmod($this->root, 0700);
		chmod(dirname($record['path']), 0755);
		$read_failed = FALSE;
		try {
			pfb_settings_snapshot_read('3.2', $record['path'], 'pkg', '1', $this->root);
		} catch (Throwable) {
			$read_failed = TRUE;
		}
		$this->assertTrue($read_failed);
		$failed = FALSE;
		try {
			pfb_settings_snapshot_create('3.2', 'pkg', '3', $this->root);
		} catch (Throwable) {
			$failed = TRUE;
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

	public function testDuplicateWrapperMetadataIsRejected(): void
	{
		$record = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$xml = '<?xml version="1.0"?><pfblockerng-settings>'
			. '<format_version>1</format_version><family>3.2</family><family>3.2</family>'
			. '<source_package_name>pkg</source_package_name><source_package_version>1</source_package_version>'
			. '<created_utc>2026-01-01T00:00:00Z</created_utc><payload_sha256>'
			. str_repeat('0', 64) . '</payload_sha256><owned/></pfblockerng-settings>';
		file_put_contents($record['path'], gzencode($xml));
		chmod($record['path'], 0600);

		$this->expectException(InvalidArgumentException::class);
		pfb_settings_snapshot_read('3.2', $record['path'], 'pkg', '1', $this->root);
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
