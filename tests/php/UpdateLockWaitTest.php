<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2122: update-lock waits reuse the non-blocking acquire once per second. */
final class UpdateLockWaitTest extends TestCase
{
	private string $dir = '';
	private array $originalPfb = [];
	private $holder = NULL;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_update_wait_' . getmypid() . '_' . uniqid('', TRUE);
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
	}

	protected function tearDown(): void
	{
		if (is_resource($this->holder)) {
			@flock($this->holder, LOCK_UN);
			@fclose($this->holder);
		}
		pfb_feed_pass_release();
		$GLOBALS['pfb'] = $this->originalPfb;
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	private function holdLock(): void
	{
		$this->holder = fopen("{$this->dir}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($this->holder);
		$this->assertTrue(flock($this->holder, LOCK_EX));
	}

	public function testDefaultTimeoutIsExactlyFortyFiveSeconds(): void
	{
		$timeout = (new ReflectionFunction('pfb_feed_pass_wait'))->getParameters()[1]->getDefaultValue();
		$this->assertSame(45.0, $timeout, 'update-lock acquire timeout must be exactly 45 seconds');
	}

	public function testManualWaitPrintsOneDotPerSecondThenAcquires(): void
	{
		$this->holdLock();
		$now = 0.0;
		$sleeps = 0;
		$clock = static function () use (&$now): float {
			return $now;
		};
		$sleep = function (int $seconds) use (&$now, &$sleeps): void {
			$this->assertSame(1, $seconds, 'wait retries must sleep exactly one second');
			$now += $seconds;
			$sleeps++;
			if ($sleeps === 2) {
				flock($this->holder, LOCK_UN);
				fclose($this->holder);
				$this->holder = NULL;
			}
		};

		ob_start();
		$acquired = pfb_feed_pass_wait(TRUE, 45.0, $clock, $sleep);
		$output = (string) ob_get_clean();

		$this->assertTrue($acquired, 'manual wait must proceed after the held lock becomes free');
		$this->assertSame(2, $sleeps, 'manual wait must retry once per elapsed second');
		$this->assertStringContainsString('Waiting', $output, 'operator must be told the run is waiting');
		$this->assertSame(2, substr_count($output, '.'), "expected one dot per waited second; output={$output}");
	}

	public function testManualWaitTimesOutWithOneDotPerSecondAndNoLock(): void
	{
		$this->holdLock();
		$now = 0.0;
		$clock = static function () use (&$now): float {
			return $now;
		};
		$sleep = static function (int $seconds) use (&$now): void {
			$now += $seconds;
		};

		ob_start();
		$acquired = pfb_feed_pass_wait(TRUE, 3.0, $clock, $sleep);
		$output = (string) ob_get_clean();

		$this->assertFalse($acquired, 'manual wait must fail closed when its budget expires');
		$this->assertSame(3, substr_count($output, '.'), "expected one dot per timeout second; output={$output}");
		$this->assertStringContainsString('Timed out waiting for the update lock', $output,
			'manual timeout must end with an explicit operator-visible outcome');
		$this->assertArrayNotHasKey('pfb_feed_pass_lock', $GLOBALS,
			'timed-out caller must not proceed under a nonexistent lock');
	}

	public function testWaitHasIndependentRetryCapWhenClockStalls(): void
	{
		$this->holdLock();
		$sleeps = 0;
		$clock = static fn (): float => 0.0;
		$sleep = static function (int $seconds) use (&$sleeps): void {
			self::assertSame(1, $seconds);
			$sleeps++;
			if ($sleeps > 3) {
				throw new RuntimeException('wait exceeded its independent retry cap');
			}
		};

		$this->assertFalse(pfb_feed_pass_wait(FALSE, 3.0, $clock, $sleep),
			'a stalled clock must not make the update-lock wait unbounded');
		$this->assertSame(3, $sleeps, 'three-second budget permits exactly three retries');
	}
}
