<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionStateTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_state_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['marker' => 'state-secret']]],
			],
		];
		$this->clearFailureSeams();
	}

	protected function tearDown(): void
	{
		$this->clearFailureSeams();
		$this->removeTree($this->root);
	}

	public function testMissingStateIsCanonicalAndActivationOverwritesFamily(): void
	{
		$empty = pfb_settings_transition_state_read($this->root);
		$this->assertSame([
			'state_version' => 1,
			'activations' => ['3.2' => '', '4.0' => ''],
			'divergences' => [],
		], $empty);

		$first = str_repeat('a', 64);
		$second = str_repeat('b', 64);
		$this->assertSame($first, pfb_settings_transition_state_record_activation('3.2', $first, $this->root)['activations']['3.2']);
		$state = pfb_settings_transition_state_record_activation('3.2', $second, $this->root);
		$this->assertSame($second, $state['activations']['3.2']);
		$this->assertSame('', $state['activations']['4.0']);
	}

	public function testDivergenceDuplicatePreservesAcknowledgementAndNewPairIsUnacknowledged(): void
	{
		$source = str_repeat('a', 64);
		$target = str_repeat('b', 64);
		$state = pfb_settings_transition_state_record_divergence('3.2', '4.0', $source, $target, $this->root);
		$this->assertFalse($state['divergences'][0]['acknowledged']);
		$state = pfb_settings_transition_state_acknowledge_divergence('3.2', '4.0', $source, $target, $this->root);
		$this->assertTrue($state['divergences'][0]['acknowledged']);
		$state = pfb_settings_transition_state_record_divergence('3.2', '4.0', $source, $target, $this->root);
		$this->assertCount(1, $state['divergences']);
		$this->assertTrue($state['divergences'][0]['acknowledged']);
		$state = pfb_settings_transition_state_record_divergence('3.2', '4.0', $source, str_repeat('c', 64), $this->root);
		$this->assertCount(2, $state['divergences']);
		$this->assertFalse($state['divergences'][1]['acknowledged']);
	}

	public function testMalformedStateAndUnsafePathFailClosed(): void
	{
		pfb_settings_transition_state_record_activation('3.2', str_repeat('a', 64), $this->root);
		$path = $this->root . '/transition-state.json';
		$valid = file_get_contents($path);
		$this->assertIsString($valid);
		foreach ([
			'{"state_version":1,"activations":{"3.2":"","4.0":""},"divergences":[],"extra":1}',
			'{"activations":{"3.2":"","4.0":""},"state_version":1,"divergences":[]}',
			'{"state_version":1,"activations":{"3.2":"","4.0":""},"divergences":[{"source_family":"3.2","target_family":"4.0","source_snapshot_sha256":"' . str_repeat('a', 64) . '","target_snapshot_sha256":"' . str_repeat('b', 64) . '","acknowledged":false,"acknowledged":true}]}',
		] as $malformed) {
			file_put_contents($path, $malformed);
			chmod($path, 0600);
			$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_state_read($this->root));
		}
		file_put_contents($path, $valid);
		chmod($path, 0600);
		$link = $this->root . '/state-link';
		$this->assertTrue(symlink($path, $link));
		unlink($path);
		$this->assertTrue(symlink($link, $path));
		$this->assertThrows(Throwable::class, fn() => pfb_settings_transition_state_read($this->root));
	}

	public function testPublicationFailuresPreservePreviousState(): void
	{
		$first = str_repeat('a', 64);
		$second = str_repeat('b', 64);
		pfb_settings_transition_state_record_activation('3.2', $first, $this->root);
		$path = $this->root . '/transition-state.json';
		$bytes = file_get_contents($path);
		foreach ([
			'pfb_test_transition_state_write_failure',
			'pfb_test_transition_state_readback_failure',
			'pfb_test_journal_rename_failure',
			'pfb_test_transition_state_dir_sync_failure',
		] as $failure) {
			$GLOBALS[$failure] = TRUE;
			$this->assertThrows(Throwable::class, fn() => pfb_settings_transition_state_record_activation('3.2', $second, $this->root));
			$this->assertSame($bytes, file_get_contents($path));
			$this->assertSame([], glob($this->root . '/.transition-state.*.tmp') ?: []);
			$GLOBALS[$failure] = FALSE;
		}
	}

	public function testPostRenameDirectorySyncFailureRetainsPublishedState(): void
	{
		$first = str_repeat('a', 64);
		$second = str_repeat('b', 64);
		pfb_settings_transition_state_record_activation('3.2', $first, $this->root);
		$GLOBALS['pfb_test_transition_state_post_rename_dir_sync_failure'] = TRUE;
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_state_record_activation('3.2', $second, $this->root));
		$this->assertSame($second, pfb_settings_transition_state_read($this->root)['activations']['3.2']);
		$GLOBALS['pfb_test_transition_state_post_rename_dir_sync_failure'] = FALSE;
		$this->assertSame($second, pfb_settings_transition_state_record_activation('3.2', $second, $this->root)['activations']['3.2']);
	}

	public function testCompletionNoJournalIsNoOpAndAppliedRecordsActivationBeforeComplete(): void
	{
		$GLOBALS['config']['installedpackages'] = [];
		$this->assertSame([], pfb_settings_transition_complete('4.0', 'pkg', '2', $this->root));
		$this->assertFileDoesNotExist($this->root . '/transition-state.json');
		$GLOBALS['config']['installedpackages'] = [
			'pfblockerng' => ['config' => ['0' => ['marker' => 'state-secret']]],
		];
		PfbConfig::write('pfb_schema_family', '4.0');
		$owned_hash = hash('sha256', serialize(pfb_settings_capture_owned()));
		$this->createJournal('settings-applied', '4.0', 'pkg', '2');
		$result = pfb_settings_transition_complete('4.0', 'pkg', '2', $this->root);
		$this->assertSame('complete', $result['phase']);
		$this->assertSame($owned_hash, pfb_settings_transition_state_read($this->root)['activations']['4.0']);
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	public function testCompletionRejectsIdentityOrMarkerMismatchWithoutStateChange(): void
	{
		PfbConfig::write('pfb_schema_family', '3.2');
		$this->createJournal('settings-applied', '4.0', 'pkg', '2');
		$before = pfb_settings_transition_state_read($this->root);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_complete('3.2', 'pkg', '2', $this->root));
		$this->assertSame($before, pfb_settings_transition_state_read($this->root));
		$this->assertSame('settings-applied', pfb_settings_journal_read($this->root)['phase']);
	}

	public function testCompleteRecoveryRequiresActivationAndClearFailureRetainsSafeEvidence(): void
	{
		PfbConfig::write('pfb_schema_family', '4.0');
		$this->createJournal('complete', '4.0', 'pkg', '2');
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_complete('4.0', 'pkg', '2', $this->root));
		$hash = hash('sha256', serialize(pfb_settings_capture_owned()));
		pfb_settings_transition_state_record_activation('4.0', $hash, $this->root);
		$GLOBALS['pfb_test_journal_clear_unlink_failure'] = TRUE;
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_complete('4.0', 'pkg', '2', $this->root));
		$this->assertSame('complete', pfb_settings_journal_read($this->root)['phase']);
		$GLOBALS['pfb_test_journal_clear_unlink_failure'] = FALSE;
		$result = pfb_settings_transition_complete('4.0', 'pkg', '2', $this->root);
		$this->assertSame('complete', $result['phase']);
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	private function createJournal(string $phase, string $family, string $package, string $version): void
	{
		$hash = str_repeat('a', 64);
		pfb_settings_journal_create([
			'journal_version' => 1,
			'phase' => 'prepared',
			'action' => 'preserve',
			'source_family' => $family,
			'source_package_name' => $package,
			'source_package_version' => $version,
			'source_snapshot_sha256' => $hash,
			'source_live_sha256' => $hash,
			'target_family' => $family,
			'target_package_name' => $package,
			'target_package_version' => $version,
			'target_snapshot_sha256' => $hash,
			'target_artifact' => '/var/db/pfblockerng/target.pkg',
			'target_artifact_sha256' => $hash,
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:state-test',
			'authorization_sha256' => '',
		], $this->root);
		$expected = 'prepared';
		foreach (['settings-applying', 'settings-applied', 'complete'] as $next) {
			pfb_settings_journal_advance($expected, $next, $this->root);
			if ($next === $phase) {
				break;
			}
			$expected = $next;
		}
	}

	private function clearFailureSeams(): void
	{
		foreach ([
			'pfb_test_transition_state_write_failure',
			'pfb_test_transition_state_readback_failure',
			'pfb_test_journal_rename_failure',
			'pfb_test_transition_state_dir_sync_failure',
			'pfb_test_transition_state_post_rename_dir_sync_failure',
			'pfb_test_journal_clear_unlink_failure',
		] as $failure) {
			unset($GLOBALS[$failure]);
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
