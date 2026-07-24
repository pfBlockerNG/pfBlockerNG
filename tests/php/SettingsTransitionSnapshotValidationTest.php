<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionSnapshotValidationTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_snapshot_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => [
					'first' => 'one',
					'empty' => '',
					'nested' => ['row' => [['name' => 'a'], ['name' => 'b']], 'items' => ['x', 'y'], 'unknown' => 'kept'],
					'credential' => 'snapshot-secret',
				]]],
				'pfblockerngdnsbl' => ['config' => ['0' => ['scalar' => 'two']]],
				'unrelated' => ['secret' => 'not-owned'],
			],
		];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testSnapshotUsesDirectOwnedXmlAndRoundTripsExactly(): void
	{
		$owned = pfb_settings_capture_owned();
		$record = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$xml = gzdecode((string) file_get_contents($record['path']));
		$this->assertStringContainsString('<owned>', $xml);
		$this->assertStringContainsString('<pfblockerng>', $xml);
		$this->assertStringContainsString('<pfblockerngdnsbl>', $xml);
		$this->assertSame(2, substr_count($xml, '<config>'));
		$this->assertSame(2, substr_count($xml, '<row>'));
		$this->assertSame(2, substr_count($xml, '<item>'));
		$this->assertStringNotContainsString('<payload_encoding>', $xml);
		$this->assertStringNotContainsString('<owned_payload>', $xml);
		$this->assertSame($owned, pfb_settings_snapshot_read('3.2', $record['path'], 'pkg', '1', $this->root));
		preg_match('/<payload_sha256>([^<]+)<\/payload_sha256>/', $xml, $checksum);
		$this->assertSame(hash('sha256', serialize($owned)), $checksum[1]);
	}

	public function testEmptyOwnedSetIsNativeEmptyOwnedWrapper(): void
	{
		$GLOBALS['config'] = ['installedpackages' => ['unrelated' => ['x' => 'y']]];
		$record = pfb_settings_snapshot_create('4.0', 'pkg', '1', $this->root);
		$xml = gzdecode((string) file_get_contents($record['path']));
		$this->assertStringContainsString('<owned', $xml);
		$this->assertStringNotContainsString('<owned_payload>', $xml);
		$this->assertSame([], pfb_settings_snapshot_read('4.0', $record['path'], 'pkg', '1', $this->root));
	}

	public function testSamePayloadDifferentProvenanceDeduplicatesFirstProvenance(): void
	{
		$first = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$second = pfb_settings_snapshot_create('3.2', 'pkg', '2', $this->root);
		$this->assertSame($first['path'], $second['path']);
		$this->assertSame('pkg', $second['source_package_name']);
		$this->assertSame('1', $second['source_package_version']);
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
