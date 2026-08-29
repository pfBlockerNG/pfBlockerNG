<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyObjectSlotTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_family_object_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->root;
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['credential' => 'live']]],
				'otherpackage' => ['config' => ['0' => ['marker' => 'keep']]],
			],
		];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testNestedObjectPayloadIsRejectedBeforeConfigMutation(): void
	{
		$payload = [
			'pfblockerng' => ['config' => ['0' => ['credential' => 'snapshot', 'nested' => new stdClass()]]],
		];
		$encoded = base64_encode(serialize($payload));
		$xml = '<pfblockerng-settings><family>3.2</family><payload>' . $encoded
			. '</payload></pfblockerng-settings>';
		$slot = $this->root . '/settings-3.2.xml';
		file_put_contents($slot, $xml);
		chmod($slot, 0600);
		$before = $GLOBALS['config'];

		$this->assertFalse(pfb_settings_family_replace('3.2'));
		$this->assertSame($before, $GLOBALS['config']);
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
