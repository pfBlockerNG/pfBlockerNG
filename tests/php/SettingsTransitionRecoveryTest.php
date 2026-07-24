<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionRecoveryTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_recovery_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_write_config_failure'] = false;
		unset(
			$GLOBALS['pfb_test_persisted_config'],
			$GLOBALS['pfb_test_readback_config'],
			$GLOBALS['pfb_test_journal_rename_failure']
		);
	}

	protected function tearDown(): void
	{
		unset(
			$GLOBALS['pfb_test_write_config_failure'],
			$GLOBALS['pfb_test_persisted_config'],
			$GLOBALS['pfb_test_readback_config'],
			$GLOBALS['pfb_test_journal_rename_failure']
		);
		$this->removeTree($this->root);
	}

	public function testPreparedSourceRestoreFailureAfterWriteCanRetryWithoutSecondWrite(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['secret' => 'source-secret']]]];
		$target = ['pfblockerng' => ['config' => ['0' => ['value' => 'target']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '3.2.15', $source);
		$this->seedSnapshot('4.0', 'old-target-pkg', 'old-version', $target);
		$this->seedConfig($source);
		$this->createJournal('restore', '3.2', 'source-pkg', '3.2.15', $this->snapshotHash('3.2'), $this->snapshotHash('4.0'));
		pfb_settings_journal_advance('prepared', 'settings-applying', $this->root);

		$GLOBALS['pfb_test_journal_rename_failure'] = true;
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame('settings-applying', pfb_settings_journal_read($this->root)['phase']);
		$this->assertSame($target, pfb_settings_capture_owned());
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);

		$GLOBALS['pfb_test_journal_rename_failure'] = false;
		$result = pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root);
		$this->assertSame('settings-applied', $result['phase']);
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame('settings-applied', pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root)['phase']);
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
		$this->assertStringNotContainsString('source-secret', json_encode($result, JSON_THROW_ON_ERROR));
	}

	public function testTargetLiveRestoreAdvancesWithoutWritingAndAllowsDifferentProvenance(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]];
		$target = ['pfblockerng' => ['config' => ['0' => ['value' => 'target']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedSnapshot('4.0', 'old-target-pkg', 'old-version', $target);
		$this->seedConfig($target);
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $this->snapshotHash('3.2'), $this->snapshotHash('4.0'));

		$result = pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root);
		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame('settings-applied', pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testEqualSourceAndTargetLiveRestoreDoesNotWrite(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'same']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedSnapshot('4.0', 'target-pkg', '2', $source);
		$this->seedConfig($source);
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $this->snapshotHash('3.2'), $this->snapshotHash('4.0'));

		$result = pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root);
		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testThirdLiveStateFailsAndRetainsApplyingJournal(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]];
		$target = ['pfblockerng' => ['config' => ['0' => ['value' => 'target']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedSnapshot('4.0', 'target-pkg', '2', $target);
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'third']]]]);
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $this->snapshotHash('3.2'), $this->snapshotHash('4.0'));

		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame('settings-applying', pfb_settings_journal_read($this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testClearRemovesOnlyOwnedAndPreservesUnrelated(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['secret' => 'clear-secret']]]];
		$this->seedSnapshot('4.0', 'source-pkg', '4.0.0', $source);
		$this->seedConfig($source, ['unrelated' => ['keep' => 'yes']]);
		$this->createJournal('clear', '4.0', 'source-pkg', '4.0.0', $this->snapshotHash('4.0'), '');

		$result = pfb_settings_transition_apply('3.2', 'target-pkg', '2', $this->root);
		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame([], $GLOBALS['config']['installedpackages']);
		$this->assertSame(['keep' => 'yes'], $GLOBALS['config']['unrelated']);
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testPreserveSameFamilyAndAppliedCompleteDoNotWrite(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedConfig($source);
		$this->createJournal(
			'preserve',
			'3.2',
			'source-pkg',
			'1',
			$this->snapshotHash('3.2'),
			$this->snapshotHash('3.2'),
			'3.2',
			'source-pkg',
			'1'
		);

		$this->assertSame('settings-applied', pfb_settings_transition_apply('3.2', 'source-pkg', '1', $this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame('settings-applied', pfb_settings_transition_apply('3.2', 'source-pkg', '1', $this->root)['phase']);
		pfb_settings_journal_advance('settings-applied', 'complete', $this->root);
		$this->assertSame('complete', pfb_settings_transition_apply('3.2', 'source-pkg', '1', $this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testWriteFailureRetainsApplyingAndSourceForRetry(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]];
		$target = ['pfblockerng' => ['config' => ['0' => ['value' => 'target']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedSnapshot('4.0', 'target-pkg', '2', $target);
		$this->seedConfig($source);
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $this->snapshotHash('3.2'), $this->snapshotHash('4.0'));

		$GLOBALS['pfb_test_write_config_failure'] = true;
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame('settings-applying', pfb_settings_journal_read($this->root)['phase']);
		$this->assertSame($source, pfb_settings_capture_owned());
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);

		$GLOBALS['pfb_test_write_config_failure'] = false;
		$this->assertSame('settings-applied', pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root)['phase']);
		$this->assertCount(2, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testActionEndpointContractsRejectContradictions(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedConfig($source);
		$sourceHash = $this->snapshotHash('3.2');
		foreach ([
			['restore', ''],
			['preserve', str_repeat('b', 64)],
			['clear', str_repeat('b', 64)],
		] as [$action, $targetHash]) {
			$this->createJournal($action, '3.2', 'source-pkg', '1', $sourceHash, $targetHash);
			$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
			$this->removeTree($this->root);
			mkdir($this->root, 0700, true);
			$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
			$sourceHash = $this->snapshotHash('3.2');
			$this->seedConfig($source);
		}
	}

	public function testApplyingPhaseRevalidatesActionContract(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedConfig($source);
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $this->snapshotHash('3.2'), '');
		pfb_settings_journal_advance('prepared', 'settings-applying', $this->root);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testSelectedRestoreHeadMustVerifyInPreparedAndApplying(): void
	{
		foreach (['prepared', 'settings-applying'] as $phase) {
			$source = ['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]];
			$target = ['pfblockerng' => ['config' => ['0' => ['value' => 'target']]]];
			$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
			$this->seedSnapshot('4.0', 'target-pkg', '2', $target);
			$this->seedConfig($target);
			$this->createJournal('restore', '3.2', 'source-pkg', '1', $this->snapshotHash('3.2'), $this->snapshotHash('4.0'));
			if ($phase === 'settings-applying') {
				pfb_settings_journal_advance('prepared', 'settings-applying', $this->root);
			}
			unlink($this->root . '/4.0/head.json');
			$this->assertThrows(Throwable::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
			$this->assertSame('settings-applying', pfb_settings_journal_read($this->root)['phase']);
			$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
			$this->removeTree($this->root);
			mkdir($this->root, 0700, true);
			$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		}
	}

	public function testIdentityAndSourceHeadContradictionsFailBeforeWrite(): void
	{
		$source = ['pfblockerng' => ['config' => ['0' => ['secret' => 'head-secret']]]];
		$this->seedSnapshot('3.2', 'source-pkg', '1', $source);
		$this->seedSnapshot('4.0', 'target-pkg', '2', $source);
		$this->seedConfig($source);
		$this->createJournal('restore', '3.2', 'source-pkg', '1', $this->snapshotHash('3.2'), $this->snapshotHash('4.0'));

		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_apply('4.0', 'wrong-pkg', '2', $this->root));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$head = $this->root . '/3.2/head.json';
		file_put_contents($head, '{}');
		chmod($head, 0600);
		$this->assertThrows(Throwable::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	private function seedSnapshot(string $family, string $package, string $version, array $owned): void
	{
		$this->seedConfig($owned);
		pfb_settings_snapshot_create($family, $package, $version, $this->root);
	}

	private function seedConfig(array $owned, array $topLevel = []): void
	{
		$config = ['installedpackages' => $owned];
		foreach ($topLevel as $key => $value) {
			$config[$key] = $value;
		}
		$GLOBALS['config'] = $config;
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
		?string $targetFamily = null,
		string $targetPackage = 'target-pkg',
		string $targetVersion = '2'
	): void {
		$hash = str_repeat('a', 64);
		pfb_settings_journal_create([
			'journal_version' => 1,
			'phase' => 'prepared',
			'action' => $action,
			'source_family' => $sourceFamily,
			'source_package_name' => $sourcePackage,
			'source_package_version' => $sourceVersion,
			'source_snapshot_sha256' => $sourceHash,
			'source_live_sha256' => $sourceHash,
			'target_family' => $targetFamily ?? ($sourceFamily === '3.2' ? '4.0' : '3.2'),
			'target_package_name' => $targetPackage,
			'target_package_version' => $targetVersion,
			'target_snapshot_sha256' => $targetHash,
			'target_artifact' => '/var/db/pfblockerng/target.pkg',
			'target_artifact_sha256' => $hash,
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:recovery-test',
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
