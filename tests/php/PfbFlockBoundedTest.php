<?php

declare(strict_types=1);

require_once __DIR__ . '/support/PfbFlockClockFixture.php';
require_once __DIR__ . '/support/FailingFlockStream.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** issue #1780/#3157: bounded flock attempts use real locks and a virtual wait clock. */
#[CoversFunction('pfb_flock_bounded')]
#[CoversFunction('pfb_unbound_py_publication_lock_timeout')]
final class PfbFlockBoundedTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_flock_bounded_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	/** @return array{PfbFlockClockFixture,string} */
	private function clockedFlockBounded(?Closure $onSleep = NULL): array
	{
		$clock = new PfbFlockClockFixture();
		$clock->setOnSleep($onSleep);
		$namespace = $clock->loadChain(['pfb_flock_bounded']);
		return [$clock, $namespace . '\\pfb_flock_bounded'];
	}

	public function testFinishedClockIsCollectedAndCannotBeReused(): void
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_flock_bounded']);
		$reference = WeakReference::create($clock);
		unset($clock);
		$this->assertNull($reference->get(), 'the registry must not retain a finished test clock');

		$this->expectException(RuntimeException::class);
		($namespace . '\\microtime')(TRUE);
	}

	/** @return array<string,array{int,string}> */
	public static function contendedOperations(): array
	{
		return [
			'LOCK_EX' => [LOCK_EX, 'exclusive'],
			'LOCK_SH' => [LOCK_SH, 'shared'],
		];
	}

	#[DataProvider('contendedOperations')]
	public function testContendedAcquireExpiresAfterPolling(int $operation, string $label): void
	{
		$path = "{$this->dir}/{$label}.lock";
		$holder = fopen($path, 'c');
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: holder lock failed');

		[$clock, $fn] = $this->clockedFlockBounded();
		$contender = fopen($path, 'c');
		$timedOut = FALSE;
		$acquired = $fn($contender, $operation, 0.2, $timedOut);

		$this->assertFalse($acquired, "contended {$label} acquire must expire");
		$this->assertTrue($timedOut, "contended {$label} expiry must report timeout");
		$requestedSleep = array_sum($clock->sleeps);
		$this->assertGreaterThanOrEqual(200000, $requestedSleep,
			"{$label} acquire must poll through its virtual budget, not fail immediately");
		$this->assertLessThan(220000, $requestedSleep,
			"{$label} acquire must stop at its deadline, before only the poll cap remains");

		fclose($contender);
		flock($holder, LOCK_UN);
		fclose($holder);
	}

	public function testContendedAcquireSucceedsAfterControlledHolderRelease(): void
	{
		$path = "{$this->dir}/released.lock";
		$holder = fopen($path, 'c');
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: holder lock failed');

		$released = FALSE;
		[$clock, $fn] = $this->clockedFlockBounded(static function () use ($holder, &$released): void {
			flock($holder, LOCK_UN);
			$released = TRUE;
		});
		$contender = fopen($path, 'c');
		$timedOut = TRUE;
		$acquired = $fn($contender, LOCK_EX, 1.0, $timedOut);

		$this->assertTrue($released, 'holder must release during the controlled wait');
		$this->assertSame([20000], $clock->sleeps, 'acquire must retry once after holder release');
		$this->assertTrue($acquired, 'acquire must succeed after holder release');
		$this->assertFalse($timedOut, 'successful retry must clear timeout');
		$probe = fopen($path, 'c');
		$wouldBlock = 0;
		$this->assertFalse(@flock($probe, LOCK_EX | LOCK_NB, $wouldBlock),
			'successful retry must retain the real lock');
		$this->assertSame(1, $wouldBlock, 'probe failure must be real contention');

		flock($contender, LOCK_UN);
		fclose($contender);
		fclose($probe);
		fclose($holder);
	}

	public function testUncontendedAcquireRetainsLockWithoutSleeping(): void
	{
		$path = "{$this->dir}/uncontended.lock";
		$lock = fopen($path, 'c');
		[$clock, $fn] = $this->clockedFlockBounded();
		$timedOut = TRUE;

		$this->assertTrue($fn($lock, LOCK_EX, 5.0, $timedOut), 'uncontended acquire must succeed');
		$this->assertFalse($timedOut, 'success must clear timeout');
		$this->assertSame([], $clock->sleeps, 'first-attempt success must not sleep');
		$probe = fopen($path, 'c');
		$wouldBlock = 0;
		$this->assertFalse(@flock($probe, LOCK_EX | LOCK_NB, $wouldBlock),
			'successful acquire must retain the real lock');
		$this->assertSame(1, $wouldBlock, 'probe failure must be real contention');

		flock($lock, LOCK_UN);
		fclose($lock);
		fclose($probe);
	}

	public function testFlockErrorClearsTimeoutWithoutSleeping(): void
	{
		$this->assertTrue(stream_wrapper_register('pfbboundederror', PfbFailingFlockStream::class));
		try {
			$stream = fopen('pfbboundederror://lock', 'c');
			$this->assertIsResource($stream, 'test setup: failing flock stream open failed');
			[$clock, $fn] = $this->clockedFlockBounded();
			$timedOut = TRUE;

			$this->assertFalse($fn($stream, LOCK_EX, 5.0, $timedOut), 'flock error must fail');
			$this->assertFalse($timedOut, 'flock error must not be reported as timeout');
			$this->assertSame([], $clock->sleeps, 'flock error must not sleep');
			fclose($stream);
		} finally {
			stream_wrapper_unregister('pfbboundederror');
		}
	}

	public function testPublicationLockDefaultTimeoutIsFiniteAndPositive(): void
	{
		$timeout = pfb_unbound_py_publication_lock_timeout();

		$this->assertIsFloat($timeout);
		$this->assertTrue(is_finite($timeout), 'default publication-lock timeout must be finite');
		$this->assertGreaterThan(0.0, $timeout, 'default publication-lock timeout must be positive');
	}

	public function testNonRepresentableBudgetRaisesNoDiagnosticAndStillAcquires(): void
	{
		foreach (['INF' => INF, 'huge' => 1e300] as $label => $budget) {
			$path = tempnam($this->dir, 'budget');
			$lock = fopen($path, 'c');
			$diagnostics = [];
			set_error_handler(static function (int $number, string $message) use (&$diagnostics): bool {
				$diagnostics[] = "[{$number}] {$message}";
				return TRUE;
			});
			try {
				$acquired = pfb_flock_bounded($lock, LOCK_EX, $budget);
			} finally {
				restore_error_handler();
			}

			$this->assertSame([], $diagnostics, "{$label} budget must not raise a diagnostic");
			$this->assertTrue($acquired, "uncontended {$label} budget must acquire");
			flock($lock, LOCK_UN);
			fclose($lock);
		}
	}
}
