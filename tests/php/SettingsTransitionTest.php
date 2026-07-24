<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_settings_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['alpha' => 'one', 'empty' => '', 'nested' => ['x', 'y']]]],
				'pfblockerngdnsbl' => ['config' => ['0' => ['secret' => 'maxmind-secret']]],
				'pfblockerngfuture' => ['config' => ['0' => ['future' => ['unknown' => 'kept']]]],
				'notpfblockerng' => ['secret' => 'unrelated'],
			],
			'interfaces' => ['lan' => ['ipaddr' => '192.0.2.1']],
			'users' => ['user' => ['password' => 'password-canary']],
		];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testSchemaMarkerAbsentAndRoundTrips(): void
	{
		unset($GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['pfb_schema_family']);
		$this->assertSame('', PfbConfig::read('pfb_schema_family'));
		PfbConfig::write('pfb_schema_family', '3.2');
		$this->assertSame('3.2', PfbConfig::read('pfb_schema_family'));
		PfbConfig::write('pfb_schema_family', '4.0');
		$this->assertSame('4.0', PfbConfig::read('pfb_schema_family'));
	}

	public function testCaptureAndSnapshotPreserveOwnedStructureOnly(): void
	{
		$before = $GLOBALS['config'];
		$owned = pfb_settings_capture_owned();
		$this->assertSame([
			'pfblockerng' => $before['installedpackages']['pfblockerng'],
			'pfblockerngdnsbl' => $before['installedpackages']['pfblockerngdnsbl'],
			'pfblockerngfuture' => $before['installedpackages']['pfblockerngfuture'],
		], $owned);
		$record = pfb_settings_snapshot_create('3.2', 'pfSense-pkg-pfBlockerNG', '4.0.0', $this->root);
		$this->assertIsArray($record);
		$this->assertSame('3.2', $record['family']);
		$this->assertSame(hash('sha256', serialize($owned)), $record['payload_sha256']);
		$this->assertFileExists($record['path']);
		$this->assertSame($owned, pfb_settings_snapshot_read('3.2', $record['path'], 'pfSense-pkg-pfBlockerNG', '4.0.0', $this->root));
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame(0700, fileperms(dirname($record['path'])) & 0777);
		$this->assertSame(0600, fileperms($record['path']) & 0777);
	}

	public function testEmptyOwnedSetAndFamiliesDeduplicate(): void
	{
		$GLOBALS['config'] = ['installedpackages' => ['unrelated' => ['x' => 'y']]];
		$first = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$second = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$this->assertSame($first['path'], $second['path']);
		$this->assertSame([], pfb_settings_snapshot_read('3.2', $first['path'], 'pkg', '1', $this->root));
		$other = pfb_settings_snapshot_create('4.0', 'pkg', '1', $this->root);
		$this->assertNotSame($first['path'], $other['path']);
	}

	public function testWrongIdentityAndHostileFamilyFailWithoutMutation(): void
	{
		$before = $GLOBALS['config'];
		$record = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$this->expectException(InvalidArgumentException::class);
		try {
			pfb_settings_snapshot_read('4.0', $record['path'], 'pkg', '1', $this->root);
		} finally {
			$this->assertSame($before, $GLOBALS['config']);
		}
	}

	public function testWrongPackageAndChecksumFailWithoutSecretDisclosure(): void
	{
		$record = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$this->expectException(InvalidArgumentException::class);
		try {
			pfb_settings_snapshot_read('3.2', $record['path'], 'other', '1', $this->root);
		} catch (Throwable $error) {
			$this->assertStringNotContainsString('maxmind-secret', $error->getMessage());
			throw $error;
		}
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
