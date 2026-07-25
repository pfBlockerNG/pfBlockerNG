<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionPrepareRecoveryBoundaryTest extends TestCase
{
	private string $root;
	private string $artifact;
	private string $artifactHash;

	protected function setUp(): void
	{
		$this->root = realpath(sys_get_temp_dir()) . '/pfb_prepare_recovery_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$this->artifact = $this->root . '/target.pkg';
		file_put_contents($this->artifact, 'target artifact bytes');
		chmod($this->artifact, 0600);
		$this->artifactHash = hash_file('sha256', $this->artifact);
		$GLOBALS['config'] = ['installedpackages' => []];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testPreparedJournalResumesAcrossPhasesAfterLiveMarkerOrSourceContextChanges(): void
	{
		foreach (['4.0', NULL] as $marker) {
			$this->resetRootAndArtifact();
			$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]], '3.2');
			$journal = $this->prepare();
			$snapshotBytes = $this->sourceSnapshotBytes();
			$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'target']]]], $marker);
			$expectedPhase = 'prepared';
			foreach (['prepared', 'settings-applying', 'settings-applied', 'complete'] as $phase) {
				if ($phase !== 'prepared') {
					pfb_settings_journal_advance($expectedPhase, $phase, $this->root);
					$expectedPhase = $phase;
				}
				$result = $this->prepare([
					'source_package_name' => 'post-install-source',
					'source_package_version' => 'post-install-version',
				]);
				$this->assertSame($expectedPhase, $result['phase']);
				$this->assertSame($snapshotBytes, $this->sourceSnapshotBytes());
			}
		}
	}

	public function testActivatedTargetUsesCurrentHeadAndEmptySourceBaselineNeverDiverges(): void
	{
		$targetOwned = ['pfblockerng' => ['config' => ['0' => ['value' => 'saved-target']]]];
		$this->seedConfig($targetOwned, '4.0');
		$targetRecord = pfb_settings_snapshot_create('4.0', 'old-target-pkg', 'old-version', $this->root);
		$targetHash = $targetRecord['payload_sha256'];
		pfb_settings_transition_state_record_activation('4.0', str_repeat('b', 64), $this->root);
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]], '3.2');

		$result = $this->prepare();
		$this->assertSame($targetHash, $result['target_snapshot_sha256']);
		$this->assertSame(str_repeat('b', 64), pfb_settings_transition_state_read($this->root)['activations']['4.0']);
		$this->assertSame([], pfb_settings_transition_state_read($this->root)['divergences']);
	}

	public function testFirstTransitionWithEmptySourceBaselineNeverRecordsDivergence(): void
	{
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'source']]]], '3.2');
		$this->prepare();
		$this->assertSame([], pfb_settings_transition_state_read($this->root)['divergences']);
	}

	private function prepare(array $overrides = []): array
	{
		$defaults = [
			'source_package_name' => 'source-pkg',
			'source_package_version' => '1',
			'target_family' => '4.0',
			'target_package_name' => 'target-pkg',
			'target_package_version' => '2',
			'target_artifact' => $this->artifact,
			'target_artifact_sha256' => $this->artifactHash,
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:prepare-recovery-test',
			'authorization_sha256' => '',
		];
		$values = array_replace($defaults, $overrides);
		return pfb_settings_transition_prepare(
			$values['source_package_name'],
			$values['source_package_version'],
			$values['target_family'],
			$values['target_package_name'],
			$values['target_package_version'],
			$values['target_artifact'],
			$values['target_artifact_sha256'],
			$values['target_abi'],
			$values['target_source_identity'],
			$values['authorization_sha256'],
			$this->root
		);
	}

	private function seedConfig(array $owned, ?string $marker): void
	{
		if ($marker !== NULL) {
			$owned['pfblockerng']['config']['0']['pfb_schema_family'] = $marker;
		}
		$GLOBALS['config'] = ['installedpackages' => $owned];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
	}

	private function sourceSnapshotBytes(): string
	{
		$head = pfb_settings_snapshot_head('3.2', 'ignored', 'ignored', $this->root);
		$bytes = file_get_contents($head['path']);
		$this->assertIsString($bytes);
		return $bytes;
	}

	private function resetRootAndArtifact(): void
	{
		$this->removeTree($this->root);
		mkdir($this->root, 0700, TRUE);
		$this->artifact = $this->root . '/target.pkg';
		file_put_contents($this->artifact, 'target artifact bytes');
		chmod($this->artifact, 0600);
		$this->artifactHash = hash_file('sha256', $this->artifact);
		$GLOBALS['config'] = ['installedpackages' => []];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
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
