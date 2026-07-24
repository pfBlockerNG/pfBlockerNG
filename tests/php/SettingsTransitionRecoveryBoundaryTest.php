<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionRecoveryBoundaryTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_recovery_boundary_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_write_config_failure'] = false;
		unset($GLOBALS['pfb_test_persisted_config'], $GLOBALS['pfb_test_readback_config']);
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_write_config_failure'], $GLOBALS['pfb_test_persisted_config'], $GLOBALS['pfb_test_readback_config']);
		$this->removeTree($this->root);
	}

	public function testFirstUpgradeRestoresSourceFamilyWhenLiveDiffersFromSnapshot(): void
	{
		$snapshot = ['pfblockerng' => ['config' => ['0' => ['value' => 'snapshot']]]];
		$live = ['pfblockerng' => ['config' => ['0' => ['value' => 'live']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $snapshot);
		$this->seedConfig($live);
		$sourceHash = $this->snapshotHash('3.2');
		$liveHash = hash('sha256', serialize($live));
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $sourceHash, $sourceHash, $liveHash);

		$result = pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root);
		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame($snapshot, pfb_settings_capture_owned());
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testClearPreservesUnrelatedInstalledPackageAndTopLevelConfig(): void
	{
		$owned = ['pfblockerng' => ['config' => ['0' => ['value' => 'owned']]]];
		$this->seedSnapshot('4.0', 'source-pkg', '1', $owned + ['otherpkg' => ['keep' => 'child']]);
		$this->seedConfig($owned + ['otherpkg' => ['keep' => 'child']], ['unrelated' => ['keep' => 'top']]);
		$this->createJournal('clear', '4.0', 'source-pkg', '1', $this->snapshotHash('4.0'), '', null, '3.2');

		$result = pfb_settings_transition_apply('3.2', 'target-pkg', '2', $this->root);
		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame(['otherpkg' => ['keep' => 'child']], $GLOBALS['config']['installedpackages']);
		$this->assertSame(['keep' => 'top'], $GLOBALS['config']['unrelated']);
	}

	public function testPreserveRejectsCrossFamilyJournalBeforePhaseAdvance(): void
	{
		$owned = ['pfblockerng' => ['config' => ['0' => ['value' => 'owned']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $owned);
		$this->seedConfig($owned);
		$sourceHash = $this->snapshotHash('3.2');
		$this->createJournal('preserve', '3.2', 'source-pkg', '1', $sourceHash, $sourceHash);

		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame('prepared', pfb_settings_journal_read($this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testRestoreRejectsSameFamilyJournalBeforePhaseAdvance(): void
	{
		$owned = ['pfblockerng' => ['config' => ['0' => ['value' => 'owned']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $owned);
		$this->seedConfig($owned);
		$sourceHash = $this->snapshotHash('3.2');
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $sourceHash, $sourceHash, null, '3.2');

		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_apply('3.2', 'target-pkg', '2', $this->root));
		$this->assertSame('prepared', pfb_settings_journal_read($this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testClearRejectsSameFamilyJournalBeforePhaseAdvance(): void
	{
		$owned = ['pfblockerng' => ['config' => ['0' => ['value' => 'owned']]]];
		$this->seedSnapshot('4.0', 'source-pkg', '1', $owned);
		$this->seedConfig($owned);
		$this->createJournal('clear', '4.0', 'source-pkg', '1', $this->snapshotHash('4.0'), '', null, '4.0');

		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame('prepared', pfb_settings_journal_read($this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	private function seedSnapshot(string $family, string $package, string $version, array $config): void
	{
		$this->seedConfig($config);
		pfb_settings_snapshot_create($family, $package, $version, $this->root);
	}

	private function seedConfig(array $owned, array $topLevel = []): void
	{
		$GLOBALS['config'] = ['installedpackages' => $owned] + $topLevel;
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
	}

	private function snapshotHash(string $family): string
	{
		return pfb_settings_snapshot_head($family, 'unused', 'unused', $this->root)['payload_sha256'];
	}

	private function createJournal(
		string $action,
		string $sourceFamily,
		string $sourcePackage,
		string $sourceVersion,
		string $sourceHash,
		string $targetHash,
		?string $sourceLiveHash = null,
		string $targetFamily = '4.0'
	): void
	{
		pfb_settings_journal_create([
			'journal_version' => 1,
			'phase' => 'prepared',
			'action' => $action,
			'source_family' => $sourceFamily,
			'source_package_name' => $sourcePackage,
			'source_package_version' => $sourceVersion,
			'source_snapshot_sha256' => $sourceHash,
			'source_live_sha256' => $sourceLiveHash ?? $sourceHash,
			'target_family' => $targetFamily,
			'target_package_name' => 'target-pkg',
			'target_package_version' => '2',
			'target_snapshot_sha256' => $targetHash,
			'target_artifact' => '/var/db/pfblockerng/target.pkg',
			'target_artifact_sha256' => str_repeat('a', 64),
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:recovery-boundary-test',
			'authorization_sha256' => '',
		], $this->root);
	}

	private function assertThrows(string $class, Closure $call): void
	{
		try {
			$call();
		} catch (Throwable $error) {
			$this->assertInstanceOf($class, $error);
			return;
		}
		$this->fail('expected ' . $class);
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path) || is_link($path)) {
			@unlink($path);
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry !== '.' && $entry !== '..') {
				$this->removeTree($path . '/' . $entry);
			}
		}
		@rmdir($path);
	}
}
