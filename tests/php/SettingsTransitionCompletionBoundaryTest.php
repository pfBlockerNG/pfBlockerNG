<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionCompletionBoundaryTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = realpath(sys_get_temp_dir()) . '/pfb_completion_boundary_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['value' => 'target', 'pfb_schema_family' => '4.0']]],
			],
		];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testCompletionRejectsUnsafeJournalRootBeforeAnyPublication(): void
	{
		pfb_settings_journal_create($this->journal(), $this->root);
		pfb_settings_journal_advance('prepared', 'settings-applying', $this->root);
		pfb_settings_journal_advance('settings-applying', 'settings-applied', $this->root);
		$journalPath = $this->root . '/transition-journal.json';
		$journalBytes = file_get_contents($journalPath);
		$this->assertIsString($journalBytes);
		$this->assertFileDoesNotExist($this->root . '/transition-state.json');

		chmod($this->root, 0755);
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_complete('4.0', 'target-pkg', '2', $this->root));
		$this->assertSame($journalBytes, file_get_contents($journalPath));

		chmod($this->root, 0700);
		$this->assertFileDoesNotExist($this->root . '/transition-state.json');
		$this->assertSame('', pfb_settings_transition_state_read($this->root)['activations']['4.0']);
		$this->assertSame('settings-applied', pfb_settings_journal_read($this->root)['phase']);
	}

	public function testCompletionReadsDecisionInputsAfterExclusiveLockAcquisition(): void
	{
		$reflection = new ReflectionFunction('pfb_settings_transition_complete');
		$lines = file($reflection->getFileName());
		$this->assertIsArray($lines);
		$body = implode('', array_slice($lines, $reflection->getStartLine() - 1, $reflection->getEndLine() - $reflection->getStartLine() + 1));
		$lock = strpos($body, '$lock_key = lock(\'pfblockerng-settings-transition\', LOCK_EX);');
		$this->assertNotFalse($lock);
		foreach ([
			'$has_journal = file_exists($journal_path)',
			'$owned = pfb_settings_capture_owned()',
			'$marker = PfbConfig::read(\'pfb_schema_family\')',
		] as $decision) {
			$position = strpos($body, $decision);
			$this->assertNotFalse($position);
			$this->assertGreaterThan($lock, $position, $decision . ' must be read under the EX lock');
		}
	}

	private function journal(): array
	{
		$hash = str_repeat('a', 64);
		return [
			'journal_version' => 1,
			'phase' => 'prepared',
			'action' => 'restore',
			'source_family' => '3.2',
			'source_package_name' => 'source-pkg',
			'source_package_version' => '1',
			'source_snapshot_sha256' => $hash,
			'source_live_sha256' => $hash,
			'target_family' => '4.0',
			'target_package_name' => 'target-pkg',
			'target_package_version' => '2',
			'target_snapshot_sha256' => $hash,
			'target_artifact' => '/var/db/pfblockerng/target.pkg',
			'target_artifact_sha256' => $hash,
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:completion-boundary-test',
			'authorization_sha256' => '',
		];
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
