<?php

declare(strict_types=1);

require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\TestCase;

/** issue #3062/#3090/#3157: package operations serialize with real feed-pass flocks. */
final class InstallFeedPassInterlockTest extends TestCase
{
	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];

	/** @var list<resource> */
	private array $rawFps = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->dbdir = sys_get_temp_dir() . '/pfb_install_interlock_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'  => $this->dbdir,
			'log'    => "{$this->dbdir}/pfblockerng.log",
			'errlog' => "{$this->dbdir}/error.log",
		]);
	}

	protected function tearDown(): void
	{
		foreach ($this->rawFps as $fp) {
			if (is_resource($fp)) {
				@flock($fp, LOCK_UN);
				@fclose($fp);
			}
		}
		pfb_feed_pass_release();
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		$this->rrmdir($this->dbdir);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = "{$dir}/{$entry}";
			is_dir($path) ? $this->rrmdir($path) : @unlink($path);
		}
		@rmdir($dir);
	}

	private function lockPath(): string
	{
		return "{$this->dbdir}/pfb_feed_pass.lock";
	}

	private function rawProbeStillLocked(): bool
	{
		$probe = fopen($this->lockPath(), 'c');
		$this->assertIsResource($probe, 'test setup: lock probe open failed');
		$held = !flock($probe, LOCK_EX | LOCK_NB);
		if (!$held) {
			flock($probe, LOCK_UN);
		}
		fclose($probe);
		return $held;
	}

	private function logContents(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	/** @return array{PfbFlockClockFixture,string} */
	private function clockedFeedPass(?Closure $onSleep = NULL): array
	{
		$clock = new PfbFlockClockFixture();
		$clock->setOnSleep($onSleep);
		$namespace = $clock->loadChain([
			'pfb_flock_bounded',
			'pfb_feed_pass_acquire',
			'pfb_install_feed_pass_hold',
		]);
		return [$clock, $namespace];
	}

	public function testHoldTakesTheFeedPassLockWhenNoPassIsInFlight(): void
	{
		$this->assertFalse($this->rawProbeStillLocked(), 'test setup: lock must start free');
		$this->assertTrue(pfb_install_feed_pass_hold(0.1), 'install must take a free feed-pass lock');
		$this->assertTrue(is_resource($GLOBALS['pfb_feed_pass_lock'] ?? NULL),
			'install must retain the feed-pass lock');
		$this->assertTrue($this->rawProbeStillLocked(), 'another feed pass must observe the retained lock');
	}

	/** Scenario: the holder releases during the controlled wait; then the install owns the lock. */
	public function testHoldWaitsForReleaseAndRetainsTheLock(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: holder lock failed');
		$released = FALSE;
		[$clock, $namespace] = $this->clockedFeedPass(static function () use ($holder, &$released): void {
			flock($holder, LOCK_UN);
			$released = TRUE;
		});
		$hold = "{$namespace}\\pfb_install_feed_pass_hold";

		$this->assertTrue($hold(1.0), 'install must acquire after the holder releases');
		$this->assertTrue($released, 'holder must release during the controlled wait');
		$this->assertSame([20000], $clock->sleeps, 'install must retry once after release');
		$this->assertTrue(is_resource($GLOBALS['pfb_feed_pass_lock'] ?? NULL),
			'install must retain the acquired lock');
		$this->assertTrue($this->rawProbeStillLocked(), 'feed pass must observe the install hold');
	}

	/** Scenario: the holder outlives the budget; then the install logs give-up without disturbing it. */
	public function testHoldSpendsItsBudgetThenLetsTheInstallProceed(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: holder lock failed');
		[$clock, $namespace] = $this->clockedFeedPass();
		$hold = "{$namespace}\\pfb_install_feed_pass_hold";

		$this->assertFalse($hold(0.3), 'install must give up after its budget');
		$requestedSleep = array_sum($clock->sleeps);
		$this->assertGreaterThanOrEqual(300000, $requestedSleep,
			'install must poll through its virtual budget, not fail immediately');
		$this->assertLessThan(320000, $requestedSleep,
			'install must stop at its deadline, before only the poll cap remains');
		$this->assertFalse(isset($GLOBALS['pfb_feed_pass_lock']), 'failed hold must not retain a handle');
		$this->assertTrue($this->rawProbeStillLocked(), 'holder lock must remain untouched');
		$log = $this->logContents();
		$this->assertStringContainsString('Package install: waiting up to', $log);
		$this->assertStringContainsString('Package install proceeding WITHOUT the feed-pass lock', $log);
		$this->assertStringNotContainsString('Package uninstall', $log);
	}

	public function testFeedPassAcquireStaysNonBlockingByDefault(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: holder lock failed');
		[$clock, $namespace] = $this->clockedFeedPass();
		$acquire = "{$namespace}\\pfb_feed_pass_acquire";
		$contended = FALSE;

		$this->assertFalse($acquire($contended), 'contended default acquire must fail');
		$this->assertTrue($contended, 'default acquire must report contention');
		$this->assertSame([], $clock->sleeps, 'default acquire must make one non-blocking attempt');
	}

	public function testHoldIsReentrantWhenThisProcessAlreadyHoldsTheLock(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire(), 'test setup: initial acquire failed');
		$outer = $GLOBALS['pfb_feed_pass_lock'];

		$this->assertTrue(pfb_install_feed_pass_hold(0.1), 'reentrant hold must succeed');
		$this->assertSame($outer, $GLOBALS['pfb_feed_pass_lock'] ?? NULL,
			'reentrant hold must reuse the existing handle');
	}

	/** Scenario: the uninstall outlives its budget; then both log lines name the uninstall. */
	public function testHoldNamesTheUninstallWhenItGivesUp(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: holder lock failed');
		[$clock, $namespace] = $this->clockedFeedPass();
		$hold = "{$namespace}\\pfb_install_feed_pass_hold";

		$this->assertFalse($hold(0.1, 'uninstall'), 'uninstall must give up after its budget');
		$requestedSleep = array_sum($clock->sleeps);
		$this->assertGreaterThanOrEqual(100000, $requestedSleep,
			'uninstall must poll through its virtual budget, not fail immediately');
		$this->assertLessThan(120000, $requestedSleep,
			'uninstall must stop at its deadline, before only the poll cap remains');
		$this->assertFalse(isset($GLOBALS['pfb_feed_pass_lock']), 'failed hold must not retain a handle');
		$this->assertTrue($this->rawProbeStillLocked(), 'holder lock must remain untouched');
		$log = $this->logContents();
		$this->assertStringContainsString('Package uninstall: waiting up to', $log);
		$this->assertStringContainsString('Package uninstall proceeding WITHOUT the feed-pass lock', $log);
		$this->assertStringNotContainsString('Package install', $log);
	}

	public function testReleaseDropsOwnershipAndUnlocksTheFile(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire(), 'test setup: acquire failed');
		$probe = fopen($this->lockPath(), 'c');
		$wouldBlock = 0;
		$this->assertFalse(flock($probe, LOCK_EX | LOCK_NB, $wouldBlock),
			'test setup: acquired lock must block the probe');
		$this->assertSame(1, $wouldBlock, 'test setup: probe failure must be contention');

		pfb_feed_pass_release();

		$this->assertArrayNotHasKey('pfb_feed_pass_lock', $GLOBALS, 'release must clear ownership state');
		$this->assertTrue(flock($probe, LOCK_EX | LOCK_NB), 'release must unlock the real file');
		flock($probe, LOCK_UN);
		fclose($probe);
	}
}
