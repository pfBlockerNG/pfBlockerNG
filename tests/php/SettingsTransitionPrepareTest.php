<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionPrepareTest extends TestCase
{
	private string $root;
	private string $artifact;
	private string $artifactHash;

	protected function setUp(): void
	{
		$this->root = realpath(sys_get_temp_dir()) . '/pfb_prepare_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$this->artifact = $this->root . '/target.pkg';
		file_put_contents($this->artifact, 'target artifact bytes');
		chmod($this->artifact, 0600);
		$this->artifactHash = hash_file('sha256', $this->artifact);
		$GLOBALS['config'] = ['installedpackages' => []];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
		$this->clearSeams();
	}

	protected function tearDown(): void
	{
		$this->clearSeams();
		$this->removeTree($this->root);
	}

	public function testFreshEmptyWithoutMarkerReturnsNoArtifactsOrMutation(): void
	{
		$before = $GLOBALS['config'];
		$this->assertSame([], $this->prepare());
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
		$this->assertFileDoesNotExist($this->root . '/transition-state.json');
		$this->assertFileDoesNotExist($this->root . '/3.2/head.json');
		$this->assertFileDoesNotExist($this->root . '/4.0/head.json');
	}

	public function testOwnedSettingsWithoutMarkerFailsBeforeArtifacts(): void
	{
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'legacy']]]], NULL);
		$before = $GLOBALS['config'];
		$this->assertThrows(InvalidArgumentException::class, fn() => $this->prepare());
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertNoTransitionArtifacts();
	}

	public function testSameFamilyPreservesLiveSettingsWithoutTransitionArtifacts(): void
	{
		foreach (['3.2', '4.0'] as $family) {
			$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => $family]]]], $family);
			$before = $GLOBALS['config'];
			$this->assertSame([], $this->prepare(['target_family' => $family]));
			$this->assertSame($before, $GLOBALS['config']);
			$this->assertNoTransitionArtifacts();
			$this->resetRootAndArtifact();
		}
	}

	public function testFirstThreeTwoToFourPublishesSourceRestoreJournal(): void
	{
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'v3']]]], '3.2');
		$sourceLive = hash('sha256', serialize(pfb_settings_capture_owned()));
		$result = $this->prepare(['target_family' => '4.0']);

		$this->assertSame('prepared', $result['phase']);
		$this->assertSame('restore', $result['action']);
		$this->assertSame($result['source_snapshot_sha256'], $result['target_snapshot_sha256']);
		$this->assertSame($sourceLive, $result['source_live_sha256']);
		$this->assertSame($result, pfb_settings_journal_read($this->root));
		$this->assertSame($result['source_snapshot_sha256'], pfb_settings_snapshot_head('3.2', 'source-pkg', '1', $this->root)['payload_sha256']);
		$this->assertFileDoesNotExist($this->root . '/4.0/head.json');
	}

	public function testFirstFourToThreeRequiresExactAuthorizationAndClears(): void
	{
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'v4']]]], '4.0');
		foreach (['', str_repeat('g', 64)] as $authorization) {
			$this->assertThrows(InvalidArgumentException::class, fn() => $this->prepare([
				'target_family' => '3.2',
				'authorization_sha256' => $authorization,
			]));
			$this->assertNoTransitionArtifacts();
		}
		$result = $this->prepare([
			'target_family' => '3.2',
			'authorization_sha256' => str_repeat('b', 64),
		]);
		$this->assertSame('clear', $result['action']);
		$this->assertSame('', $result['target_snapshot_sha256']);
		$this->assertSame(str_repeat('b', 64), $result['authorization_sha256']);
		$this->assertFileExists($this->root . '/4.0/head.json');
	}

	public function testActivatedTargetHeadsDriveRestoreAcrossBothDirectionsAndProvenance(): void
	{
		foreach ([['3.2', '4.0'], ['4.0', '3.2']] as [$sourceFamily, $targetFamily]) {
			$targetOwned = ['pfblockerng' => ['config' => ['0' => ['value' => 'saved-' . $targetFamily]]]];
			$this->seedTargetHead($targetFamily, $targetOwned, 'old-target-pkg', 'old-version');
			$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'live-' . $sourceFamily]]]], $sourceFamily);
			$targetHash = pfb_settings_snapshot_head($targetFamily, 'ignored', 'ignored', $this->root)['payload_sha256'];
			$result = $this->prepare([
				'target_family' => $targetFamily,
				'authorization_sha256' => $sourceFamily === '4.0' ? str_repeat('c', 64) : '',
			]);
			$this->assertSame('restore', $result['action']);
			$this->assertSame($targetHash, $result['target_snapshot_sha256']);
			$this->assertSame($targetHash, pfb_settings_transition_state_read($this->root)['activations'][$targetFamily]);
			$this->resetRootAndArtifact();
		}
	}

	public function testActivatedTargetMissingOrWrongHeadFailsBeforeSourceSnapshot(): void
	{
		$targetOwned = ['pfblockerng' => ['config' => ['0' => ['value' => 'saved']]]];
		$this->seedTargetHead('4.0', $targetOwned);
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'live']]]], '3.2');
		unlink($this->root . '/4.0/head.json');
		$this->assertThrows(Throwable::class, fn() => $this->prepare(['target_family' => '4.0']));
		$this->assertFileDoesNotExist($this->root . '/3.2/head.json');
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	public function testUnchangedSourceHasNoDivergenceAndChangedSourceRecordsExactPair(): void
	{
		$targetOwned = ['pfblockerng' => ['config' => ['0' => ['value' => 'saved']]]];
		$this->seedTargetHead('4.0', $targetOwned);
		$sourceOwned = ['pfblockerng' => ['config' => ['0' => ['value' => 'live']]]];
		$this->seedConfig($sourceOwned, '3.2');
		$liveHash = hash('sha256', serialize(pfb_settings_capture_owned()));
		pfb_settings_transition_state_record_activation('3.2', $liveHash, $this->root);
		$result = $this->prepare(['target_family' => '4.0']);
		$this->assertSame([], pfb_settings_transition_state_read($this->root)['divergences']);
		$this->assertSame($result, $this->prepare(['target_family' => '4.0']));

		$this->resetRootAndArtifact();
		$this->seedTargetHead('4.0', $targetOwned);
		$this->seedConfig($sourceOwned, '3.2');
		$baseline = str_repeat('d', 64);
		pfb_settings_transition_state_record_activation('3.2', $baseline, $this->root);
		$result = $this->prepare(['target_family' => '4.0']);
		$state = pfb_settings_transition_state_read($this->root);
		$this->assertCount(1, $state['divergences']);
		$this->assertSame('3.2', $state['divergences'][0]['source_family']);
		$this->assertSame('4.0', $state['divergences'][0]['target_family']);
		$this->assertSame($result['source_snapshot_sha256'], $state['divergences'][0]['source_snapshot_sha256']);
		$this->assertSame($result['target_snapshot_sha256'], $state['divergences'][0]['target_snapshot_sha256']);
		pfb_settings_transition_state_acknowledge_divergence('3.2', '4.0', $result['source_snapshot_sha256'], $result['target_snapshot_sha256'], $this->root);
		$this->prepare(['target_family' => '4.0']);
		$this->assertTrue(pfb_settings_transition_state_read($this->root)['divergences'][0]['acknowledged']);
	}

	public function testDivergencePublicationFailureRetainsPreparedJournalAndRetryAddsOnlyMissingRow(): void
	{
		$this->seedTargetHead('4.0', ['pfblockerng' => ['config' => ['0' => ['value' => 'saved']]]]);
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'changed']]]], '3.2');
		pfb_settings_transition_state_record_activation('3.2', str_repeat('e', 64), $this->root);
		$GLOBALS['pfb_test_transition_state_write_failure'] = TRUE;
		$this->assertThrows(RuntimeException::class, fn() => $this->prepare(['target_family' => '4.0']));
		$journal = pfb_settings_journal_read($this->root);
		$this->assertSame('prepared', $journal['phase']);
		$this->assertSame([], pfb_settings_transition_state_read($this->root)['divergences']);
		$head = pfb_settings_snapshot_head('3.2', 'ignored', 'ignored', $this->root);
		$GLOBALS['pfb_test_transition_state_write_failure'] = FALSE;
		$retry = $this->prepare(['target_family' => '4.0']);
		$this->assertSame($journal, $retry);
		$this->assertSame($head['payload_sha256'], pfb_settings_snapshot_head('3.2', 'ignored', 'ignored', $this->root)['payload_sha256']);
		$this->assertCount(1, pfb_settings_transition_state_read($this->root)['divergences']);
	}

	public function testExistingJournalRequiresExactTargetFieldsAndResumesEveryPhase(): void
	{
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'v3']]]], '3.2');
		$journal = $this->prepare(['target_family' => '4.0']);
		foreach (['target_family', 'target_package_name', 'target_package_version', 'target_artifact', 'target_artifact_sha256', 'target_abi', 'target_source_identity', 'authorization_sha256'] as $field) {
			$overrides = ['target_family' => '4.0'];
			$overrides[$field] = $field === 'target_artifact_sha256' ? str_repeat('f', 64) : 'mismatch';
			$this->assertThrows(InvalidArgumentException::class, fn() => $this->prepare($overrides));
		}
		$this->assertSame($journal, $this->prepare(['target_family' => '4.0']));
		foreach (['settings-applying', 'settings-applied', 'complete'] as $phase) {
			$current = pfb_settings_journal_read($this->root)['phase'];
			pfb_settings_journal_advance($current, $phase, $this->root);
			$this->assertSame($phase, $this->prepare(['target_family' => '4.0'])['phase']);
		}
	}

	public function testJournalPublicationFailureLeavesConfigAndAllowsSafeSnapshot(): void
	{
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'v3']]]], '3.2');
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_journal_rename_failure'] = TRUE;
		$this->assertThrows(RuntimeException::class, fn() => $this->prepare(['target_family' => '4.0']));
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
		$this->assertFileExists($this->root . '/3.2/head.json');
		$this->assertFileDoesNotExist($this->root . '/transition-state.json');
	}

	public function testNoJournalCompletionSeedsMissingBaselineButNeverOverwritesExisting(): void
	{
		$owned = ['pfblockerng' => ['config' => ['0' => ['value' => 'owned']]]];
		$this->seedConfig($owned, '4.0');
		$liveHash = hash('sha256', serialize(pfb_settings_capture_owned()));
		$this->assertSame([], pfb_settings_transition_complete('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame($liveHash, pfb_settings_transition_state_read($this->root)['activations']['4.0']);
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'changed']]]], '4.0');
		$this->assertSame([], pfb_settings_transition_complete('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame($liveHash, pfb_settings_transition_state_read($this->root)['activations']['4.0']);
	}

	public function testNoJournalCompletionRejectsMarkerMismatchOrOwnedMissingMarker(): void
	{
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'wrong']]]], '3.2');
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_complete('4.0', 'target-pkg', '2', $this->root));
		$this->resetRootAndArtifact();
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'missing']]]], NULL);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_complete('4.0', 'target-pkg', '2', $this->root));
	}

	public function testTargetArtifactMustExistBePrivateSingleOwnedAndChecksumExact(): void
	{
		$cases = ['missing', 'symlink', 'hardlink', 'writable', 'checksum'];
		foreach ($cases as $case) {
			if ($case === 'missing') {
				unlink($this->artifact);
			} elseif ($case === 'symlink') {
				$other = $this->root . '/other.pkg';
				file_put_contents($other, 'target artifact bytes');
				chmod($other, 0600);
				unlink($this->artifact);
				symlink($other, $this->artifact);
			} elseif ($case === 'hardlink') {
				link($this->artifact, $this->root . '/target-copy.pkg');
			} elseif ($case === 'writable') {
				chmod($this->artifact, 0660);
			}
			$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'v3']]]], '3.2');
			$overrides = ['target_family' => '4.0'];
			if ($case === 'checksum') {
				$overrides['target_artifact_sha256'] = str_repeat('f', 64);
			}
			$this->assertThrows(Throwable::class, fn() => $this->prepare($overrides));
			$this->assertNoTransitionArtifacts();
			$this->resetRootAndArtifact();
		}
		$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'v3']]]], '3.2');
		chmod($this->artifact, 0644);
		$this->assertSame('prepared', $this->prepare(['target_family' => '4.0'])['phase']);
	}

	public function testTargetArtifactRejectsWrongOwnerWhenPrivilegeAllows(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0
			|| !function_exists('posix_getpwnam') || !function_exists('chown')) {
			$this->markTestSkipped('wrong-owner artifact case requires root chown capability');
		}
		$owner = posix_getpwnam('nobody');
		if (!is_array($owner) || !isset($owner['uid']) || !is_int($owner['uid'])) {
			$this->markTestSkipped('wrong-owner artifact case requires nobody account');
		}
		$originalOwner = fileowner($this->artifact);
		if ($originalOwner === FALSE || $owner['uid'] === $originalOwner || !chown($this->artifact, $owner['uid'])) {
			$this->markTestSkipped('wrong-owner artifact case unavailable');
		}
		try {
			$this->seedConfig(['pfblockerng' => ['config' => ['0' => ['value' => 'v3']]]], '3.2');
			$this->assertThrows(Throwable::class, fn() => $this->prepare(['target_family' => '4.0']));
			$this->assertNoTransitionArtifacts();
		} finally {
			chown($this->artifact, $originalOwner);
		}
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
			'target_source_identity' => 'git:prepare-test',
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

	private function seedTargetHead(string $family, array $owned, string $package = 'old-target-pkg', string $version = 'old-version'): void
	{
		$this->seedConfig($owned, $family);
		pfb_settings_snapshot_create($family, $package, $version, $this->root);
		$head = pfb_settings_snapshot_head($family, 'ignored', 'ignored', $this->root);
		pfb_settings_transition_state_record_activation($family, $head['payload_sha256'], $this->root);
	}

	private function seedConfig(array $owned, ?string $marker): void
	{
		if ($marker !== NULL) {
			$owned['pfblockerng']['config']['0']['pfb_schema_family'] = $marker;
		}
		$GLOBALS['config'] = ['installedpackages' => $owned];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
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
		$this->clearSeams();
	}

	private function assertNoTransitionArtifacts(): void
	{
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
		$this->assertFileDoesNotExist($this->root . '/transition-state.json');
		$this->assertFileDoesNotExist($this->root . '/3.2/head.json');
		$this->assertFileDoesNotExist($this->root . '/4.0/head.json');
	}

	private function clearSeams(): void
	{
		foreach (['pfb_test_journal_rename_failure', 'pfb_test_transition_state_write_failure'] as $name) {
			unset($GLOBALS[$name]);
		}
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
