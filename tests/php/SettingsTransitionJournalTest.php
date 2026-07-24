<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class SettingsTransitionJournalTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_journal_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, true);
		$GLOBALS['pfb_test_journal_write_failure'] = false;
		$GLOBALS['pfb_test_journal_readback_failure'] = false;
		$GLOBALS['pfb_test_journal_rename_failure'] = false;
	}

	protected function tearDown(): void
	{
		unset(
			$GLOBALS['pfb_test_journal_write_failure'],
			$GLOBALS['pfb_test_journal_readback_failure'],
			$GLOBALS['pfb_test_journal_rename_failure']
		);
		$this->removeTree($this->root);
	}

	public function testPreparedRoundTripUsesExactCanonicalIdentity(): void
	{
		$journal = $this->journal();
		$written = pfb_settings_journal_create($journal, $this->root);

		$this->assertSame($journal, $written);
		$this->assertSame($journal, pfb_settings_journal_read($this->root));
		$this->assertSame(
			json_encode($journal, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
			file_get_contents($this->root . '/transition-journal.json')
		);
		$this->assertSame(0600, fileperms($this->root . '/transition-journal.json') & 0777);
	}

	public function testAllLegalPhasesAndIllegalTransitions(): void
	{
		pfb_settings_journal_create($this->journal(), $this->root);
		foreach ([
			['prepared', 'settings-applying'],
			['settings-applying', 'settings-applied'],
			['settings-applied', 'complete'],
		] as [$current, $next]) {
			$record = pfb_settings_journal_advance($current, $next, $this->root);
			$this->assertSame($next, $record['phase']);
		}
		foreach ([
			['complete', 'prepared'],
			['complete', 'complete'],
			['settings-applied', 'prepared'],
			['prepared', 'settings-applied'],
			['unknown', 'complete'],
		] as [$current, $next]) {
			$this->expectException(InvalidArgumentException::class);
			pfb_settings_journal_advance($current, $next, $this->root);
		}
	}

	#[DataProvider('hostileJournalProvider')]
	public function testStrictCodecRejectsHostileJournal(Closure $mutator): void
	{
		$journal = $this->journal();
		$mutator($journal);
		$this->expectException(InvalidArgumentException::class);
		pfb_settings_journal_create($journal, $this->root);
	}

	public static function hostileJournalProvider(): array
	{
		return [
			[static function (array &$j): void { unset($j['target_abi']); }],
			[static function (array &$j): void { $j['extra'] = 'nope'; }],
			[static function (array &$j): void { $j['source_family'] = '3.3'; }],
			[static function (array &$j): void { $j['source_live_sha256'] = strtoupper($j['source_live_sha256']); }],
			[static function (array &$j): void { $j['target_artifact_sha256'] = 'abc'; }],
			[static function (array &$j): void { $j['source_snapshot_sha256'] = ''; }],
			[static function (array &$j): void { $j['target_source_identity'] = ''; }],
			[static function (array &$j): void { $j['source_package_name'] = "pkg\nname"; }],
			[static function (array &$j): void { $j['target_package_version'] = str_repeat('x', 256); }],
			[static function (array &$j): void { $j['target_artifact'] = '../target.pkg'; }],
			[static function (array &$j): void { $j['target_artifact'] = '/tmp/../target.pkg'; }],
			[static function (array &$j): void { $j['phase'] = 'done'; }],
			[static function (array &$j): void { $j['action'] = 'delete'; }],
			[static function (array &$j): void { $j['journal_version'] = '1'; }],
		];
	}

	public function testCanonicalMismatchAndDuplicateKeysAreRejected(): void
	{
		$canonical = json_encode($this->journal(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
		file_put_contents($this->root . '/transition-journal.json', " {$canonical}", LOCK_EX);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_journal_read($this->root));

		file_put_contents(
			$this->root . '/transition-journal.json',
			str_replace('"phase":"prepared"', '"phase":"prepared","phase":"complete"', $canonical),
			LOCK_EX
		);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_journal_read($this->root));
	}

	public function testPublicationFailuresPreservePreviousBytes(): void
	{
		$journal = $this->journal();
		pfb_settings_journal_create($journal, $this->root);
		$path = $this->root . '/transition-journal.json';
		$before = file_get_contents($path);

		foreach (['pfb_test_journal_write_failure', 'pfb_test_journal_readback_failure', 'pfb_test_journal_rename_failure'] as $failure) {
			$GLOBALS[$failure] = true;
			$this->assertThrows(RuntimeException::class, fn() => pfb_settings_journal_advance('prepared', 'settings-applying', $this->root));
			$GLOBALS[$failure] = false;
			$this->assertSame($before, file_get_contents($path), $failure . ' changed durable journal');
		}
	}

	public function testClearRequiresCompleteAndRemovesJournal(): void
	{
		pfb_settings_journal_create($this->journal(), $this->root);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_journal_clear($this->root));

		pfb_settings_journal_advance('prepared', 'settings-applying', $this->root);
		pfb_settings_journal_advance('settings-applying', 'settings-applied', $this->root);
		pfb_settings_journal_advance('settings-applied', 'complete', $this->root);
		pfb_settings_journal_clear($this->root);
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
