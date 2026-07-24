<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SettingsTransitionJournalDurabilityTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_journal_durable_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['pfb_test_journal_dir_open_failure'] = false;
		$GLOBALS['pfb_test_journal_dir_fsync_failure'] = false;
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_journal_dir_open_failure'], $GLOBALS['pfb_test_journal_dir_fsync_failure']);
		$this->removeTree($this->root);
	}

	#[DataProvider('directorySyncFailures')]
	public function testCreateRejectsDirectorySyncFailureWithoutPartialFile(string $failure): void
	{
		$GLOBALS[$failure] = true;
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_journal_create($this->journal(), $this->root));
		$this->assertSame($this->journal(), pfb_settings_journal_read($this->root));
		$this->assertSame([], glob($this->root . '/.transition-journal.*.tmp'));
	}

	public static function directorySyncFailures(): array
	{
		return [
			['pfb_test_journal_dir_open_failure'],
			['pfb_test_journal_dir_fsync_failure'],
		];
	}

	public function testAdvanceDirectorySyncFailureLeavesCompleteOldOrNewRecord(): void
	{
		pfb_settings_journal_create($this->journal(), $this->root);
		$GLOBALS['pfb_test_journal_dir_fsync_failure'] = true;
		$this->assertThrows(
			RuntimeException::class,
			fn() => pfb_settings_journal_advance('prepared', 'settings-applying', $this->root)
		);
		$this->assertContains(pfb_settings_journal_read($this->root)['phase'], ['prepared', 'settings-applying']);
		$this->assertSame([], glob($this->root . '/.transition-journal.*.tmp'));
	}

	public function testClearDirectorySyncFailureLeavesJournalAbsent(): void
	{
		pfb_settings_journal_create($this->journal(), $this->root);
		pfb_settings_journal_advance('prepared', 'settings-applying', $this->root);
		pfb_settings_journal_advance('settings-applying', 'settings-applied', $this->root);
		pfb_settings_journal_advance('settings-applied', 'complete', $this->root);
		$GLOBALS['pfb_test_journal_dir_fsync_failure'] = true;
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_journal_clear($this->root));
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	public function testMissingArtifactUnderSymlinkedParentIsRejected(): void
	{
		$parent = $this->root . '/symlink-parent';
		$this->assertTrue(symlink($this->root . '/missing-parent', $parent));
		$journal = $this->journal();
		$journal['target_artifact'] = $parent . '/missing.pkg';
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_journal_create($journal, $this->root));
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	private function journal(): array
	{
		$hash = str_repeat('a', 64);
		return [
			'journal_version' => 1,
			'phase' => 'prepared',
			'action' => 'restore',
			'source_family' => '3.2',
			'source_package_name' => 'pfSense-pkg-pfBlockerNG',
			'source_package_version' => '3.2.15',
			'source_snapshot_sha256' => $hash,
			'source_live_sha256' => $hash,
			'target_family' => '4.0',
			'target_package_name' => 'pfSense-pkg-pfBlockerNG',
			'target_package_version' => '4.0.0',
			'target_snapshot_sha256' => $hash,
			'target_artifact' => '/var/db/pfblockerng/pfSense-pkg-pfBlockerNG-4.0.0.pkg',
			'target_artifact_sha256' => $hash,
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:0123456789abcdef',
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
