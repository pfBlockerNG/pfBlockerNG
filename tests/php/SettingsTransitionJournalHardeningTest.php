<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SettingsTransitionJournalHardeningTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_journal_hardening_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	#[DataProvider('illegalPhasePairs')]
	public function testEveryIllegalDistinctPhasePairIsRejected(string $current, string $next): void
	{
		pfb_settings_journal_create($this->journal(), $this->root);
		$this->assertThrows(
			InvalidArgumentException::class,
			fn() => pfb_settings_journal_advance($current, $next, $this->root)
		);
		$this->assertSame('prepared', pfb_settings_journal_read($this->root)['phase']);
	}

	public static function illegalPhasePairs(): array
	{
		return [
			['prepared', 'settings-applied'],
			['prepared', 'complete'],
			['settings-applying', 'prepared'],
			['settings-applying', 'complete'],
			['settings-applied', 'prepared'],
			['settings-applied', 'settings-applying'],
			['complete', 'prepared'],
			['complete', 'settings-applying'],
			['complete', 'settings-applied'],
		];
	}

	public function testBrokenSymlinkArtifactIsRejected(): void
	{
		$artifact = $this->root . '/missing-target.pkg';
		$this->assertTrue(symlink($this->root . '/does-not-exist.pkg', $artifact));
		$journal = $this->journal();
		$journal['target_artifact'] = $artifact;

		$this->assertThrows(
			InvalidArgumentException::class,
			fn() => pfb_settings_journal_create($journal, $this->root)
		);
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
