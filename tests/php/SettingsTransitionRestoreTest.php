<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionRestoreTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_restore_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_write_config_failure'] = false;
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

	public function testRestoreReplacesOwnedChildrenAndPreservesUnrelatedOrder(): void
	{
		$target = [
			'pfblockerng' => ['config' => ['0' => ['credential' => 'target-secret', 'empty' => '', 'unknown' => ['x', 'y']]]],
			'pfblockerngdnsbl' => ['config' => ['0' => ['marker' => 'target']]],
		];
		$GLOBALS['config'] = ['installedpackages' => $target];
		pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);

		$GLOBALS['config'] = [
			'installedpackages' => [
				'before' => ['v' => 'before'],
				'pfblockerngold' => ['stale' => true],
				'between' => ['v' => 'between'],
				'pfblockerngstale' => ['stale' => true],
				'after' => ['v' => 'after'],
			],
			'unrelated' => ['keep' => 'yes'],
		];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];

		$result = pfb_settings_snapshot_restore('3.2', 'pkg', '1', $this->root);

		$this->assertSame($target, [
			'pfblockerng' => $result['owned']['pfblockerng'],
			'pfblockerngdnsbl' => $result['owned']['pfblockerngdnsbl'],
		]);
		$this->assertSame([
			'before' => ['v' => 'before'],
			'pfblockerng' => $target['pfblockerng'],
			'pfblockerngdnsbl' => $target['pfblockerngdnsbl'],
			'between' => ['v' => 'between'],
			'after' => ['v' => 'after'],
		], $GLOBALS['config']['installedpackages']);
		$this->assertSame(1, count($GLOBALS['pfb_test_write_config_calls']));
	}

	public function testEmptyTargetClearsOnlyOwnedChildrenAndNoOwnedTargetAppends(): void
	{
		$GLOBALS['config'] = ['installedpackages' => ['outside' => ['keep' => 'yes']]];
		pfb_settings_snapshot_create('3.2', 'pkg', 'empty', $this->root);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'outside' => ['keep' => 'yes'],
				'pfblockerngstale' => ['drop' => true],
			],
		];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
		pfb_settings_snapshot_restore('3.2', 'pkg', 'empty', $this->root);
		$this->assertSame(['outside' => ['keep' => 'yes']], $GLOBALS['config']['installedpackages']);

		$GLOBALS['config'] = ['installedpackages' => ['outside' => ['keep' => 'yes']]];
		$target = ['pfblockerng' => ['config' => ['0' => ['new' => 'target']]]];
		$GLOBALS['config']['installedpackages'] = $target;
		pfb_settings_snapshot_create('3.2', 'pkg', 'append', $this->root);
		$GLOBALS['config'] = ['installedpackages' => ['outside' => ['keep' => 'yes']]];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
		pfb_settings_snapshot_restore('3.2', 'pkg', 'append', $this->root);
		$this->assertSame(['outside' => ['keep' => 'yes'], 'pfblockerng' => $target['pfblockerng']], $GLOBALS['config']['installedpackages']);
	}

	public function testWriteFailureAndReadbackMismatchLeaveCurrentConfigUntouched(): void
	{
		$old = ['installedpackages' => ['pfblockerngstale' => ['old' => true], 'outside' => ['v' => 'keep']]];
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerng' => ['old' => 'snapshot']]];
		pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$GLOBALS['config'] = $old;
		$GLOBALS['pfb_test_persisted_config'] = $old;
		$GLOBALS['pfb_test_write_config_failure'] = true;
		try {
			pfb_settings_snapshot_restore('3.2', 'pkg', '1', $this->root);
			$this->fail('write failure must abort restore');
		} catch (Throwable) {
			$this->assertSame($old, $GLOBALS['config']);
		}
		$this->assertSame(1, count($GLOBALS['pfb_test_write_config_calls']));

		$GLOBALS['pfb_test_write_config_failure'] = false;
		$GLOBALS['pfb_test_readback_config'] = $old;
		try {
			pfb_settings_snapshot_restore('3.2', 'pkg', '1', $this->root);
			$this->fail('readback mismatch must abort restore');
		} catch (Throwable) {
			$this->assertSame($old, $GLOBALS['config']);
		}
		$this->assertSame(2, count($GLOBALS['pfb_test_write_config_calls']));
	}

	public function testInvalidHeadAndSnapshotFailClosedWithoutSecretDisclosure(): void
	{
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerng' => ['config' => ['0' => ['secret' => 'restore-secret']]]]];
		$record = pfb_settings_snapshot_create('3.2', 'pkg', '1', $this->root);
		$head = dirname($record['path']) . '/head.json';
		$before = $GLOBALS['config'];
		file_put_contents($head, '{"family":"4.0","snapshot":"wrong.xml.gz","payload_sha256":"' . str_repeat('0', 64) . '"}');
		chmod($head, 0600);
		try {
			pfb_settings_snapshot_restore('3.2', 'pkg', '1', $this->root);
			$this->fail('wrong-family head must fail');
		} catch (Throwable $error) {
			$this->assertStringNotContainsString('restore-secret', $error->getMessage());
		}
		$this->assertSame($before, $GLOBALS['config']);
		unlink($head);
		$this->expectException(Throwable::class);
		pfb_settings_snapshot_restore('3.2', 'pkg', '1', $this->root);
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
