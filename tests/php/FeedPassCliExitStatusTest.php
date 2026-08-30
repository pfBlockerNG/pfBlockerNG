<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Issue #2591: execute the shipped CLI dispatch and observe its process boundary. */
final class FeedPassCliExitStatusTest extends TestCase
{
	private const DISPATCHER_STDERR = "pfBlockerNG feed pass deferred: dispatcher lock is held\n";
	private const FEED_PASS_STDERR = "pfBlockerNG feed pass deferred: feed-pass lock is held\n";

	private string $dir = '';
	private $lockFp = NULL;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_cli_status_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0755, TRUE));
	}

	protected function tearDown(): void
	{
		if (is_resource($this->lockFp)) {
			flock($this->lockFp, LOCK_UN);
			fclose($this->lockFp);
		}
		$this->removeTree($this->dir);
	}

	public static function exitCodeProvider(): array
	{
		return [
			'completed pass' => [TRUE, NULL, 0],
			'real failure' => [FALSE, NULL, 1],
			'benign bool with dispatcher deferral' => [TRUE, 'dispatcher-lock', 75],
			'failure bool with feed-pass deferral' => [FALSE, 'feed-pass-lock', 75],
		];
	}

	#[DataProvider('exitCodeProvider')]
	public function testExitCodeKeepsCompletionFailureAndDeferralDistinct(
		bool $completed,
		?string $deferredBy,
		int $expected
	): void {
		$this->assertTrue(function_exists('pfb_feed_pass_exit_code'),
			'pfb_feed_pass_exit_code() must map the internal bool plus lock-deferral reason at the CLI boundary');
		$this->assertSame($expected, pfb_feed_pass_exit_code($completed, $deferredBy));
	}

	public function testLockedExitCodeIsExTempfail(): void
	{
		$this->assertTrue(defined('PFB_EXIT_LOCKED'), 'the lock-deferral status must have one named CLI constant');
		$this->assertSame(75, constant('PFB_EXIT_LOCKED'));
	}

	public static function deferralMessageProvider(): array
	{
		return [
			'dispatcher lock' => ['dispatcher-lock', 'dispatcher lock'],
			'feed-pass lock' => ['feed-pass-lock', 'feed-pass lock'],
		];
	}

	#[DataProvider('deferralMessageProvider')]
	public function testDeferralMessageNamesTheHeldLockAndEndsWithNewline(string $reason, string $identity): void
	{
		$this->assertTrue(function_exists('pfb_feed_pass_deferral_message'),
			'pfb_feed_pass_deferral_message() must make lock contention diagnosable on stderr');
		$message = pfb_feed_pass_deferral_message($reason);
		$this->assertStringContainsString($identity, $message);
		$this->assertStringEndsWith("\n", $message);
	}

	public static function contendedCliProvider(): array
	{
		return [
			'cron dispatcher' => [['cron'], 'dispatcher', self::DISPATCHER_STDERR],
			'cron feed-pass' => [['cron'], 'feed-pass', self::FEED_PASS_STDERR],
			'pfb_trigger dispatcher' => [
				['pfb_trigger', 'scope=both', 'force=false', 'trigger=cron'],
				'dispatcher',
				self::DISPATCHER_STDERR,
			],
			'pfb_trigger feed-pass' => [
				['pfb_trigger', 'scope=both', 'force=false', 'trigger=cron'],
				'feed-pass',
				self::FEED_PASS_STDERR,
			],
			'update dispatcher' => [['update'], 'dispatcher', self::DISPATCHER_STDERR],
			'update feed-pass' => [['update'], 'feed-pass', self::FEED_PASS_STDERR],
			'updateip dispatcher' => [['updateip'], 'dispatcher', self::DISPATCHER_STDERR],
			'updateip feed-pass' => [['updateip'], 'feed-pass', self::FEED_PASS_STDERR],
			'updatednsbl dispatcher' => [['updatednsbl'], 'dispatcher', self::DISPATCHER_STDERR],
			'updatednsbl feed-pass' => [['updatednsbl'], 'feed-pass', self::FEED_PASS_STDERR],
			'forcecheck dispatcher' => [['forcecheck'], 'dispatcher', self::DISPATCHER_STDERR],
			'forcecheck feed-pass' => [['forcecheck'], 'feed-pass', self::FEED_PASS_STDERR],
		];
	}

	#[DataProvider('contendedCliProvider')]
	public function testEveryFeedPassVerbReturns75AndNamesTheHeldLock(
		array $arguments,
		string $lock,
		string $expectedStderr
	): void {
		$this->holdLock($lock);

		$result = $this->runCli($arguments);

		$this->assertSame(75, $result['exit'], var_export($result, TRUE));
		$this->assertSame('', $result['stdout']);
		$this->assertSame($expectedStderr, $result['stderr']);
	}

	public function testCompletedCliPassReturnsZeroWithoutDeferralStderr(): void
	{
		$result = $this->runCli(
			['pfb_trigger', 'scope=both', 'force=false', 'trigger=manual'],
			'success'
		);

		$this->assertSame(0, $result['exit'], var_export($result, TRUE));
		$this->assertSame('', $result['stderr']);
	}

	public function testRealCliFailureReturnsOneWithoutDeferralStderr(): void
	{
		$result = $this->runCli(['cron'], 'real-failure');

		$this->assertSame(1, $result['exit'], var_export($result, TRUE));
		$this->assertSame('', $result['stderr']);
	}

	public static function acquisitionErrorProvider(): array
	{
		return [
			'dispatcher open error' => ['dispatcher-open-error'],
			'dispatcher flock error' => ['dispatcher-flock-error'],
			'feed-pass flock error' => ['feed-flock-error'],
		];
	}

	#[DataProvider('acquisitionErrorProvider')]
	public function testLockAcquisitionErrorReturnsOneWithoutDeferralStderr(string $scenario): void
	{
		$result = $this->runCli(['update'], $scenario);

		$this->assertSame(1, $result['exit'], var_export($result, TRUE));
		$this->assertSame('', $result['stdout']);
		$this->assertSame('', $result['stderr']);
	}

	private function holdLock(string $lock): void
	{
		$path = $lock === 'dispatcher'
			? "{$this->dir}/pfb_schedule_dispatch.lock"
			: "{$this->dir}/pfb_feed_pass.lock";
		$this->lockFp = fopen($path, 'c');
		$this->assertIsResource($this->lockFp, "test setup: could not open {$lock} lock");
		$this->assertTrue(flock($this->lockFp, LOCK_EX), "test setup: could not hold {$lock} lock");
	}

	/** @return array{stdout: string, stderr: string, exit: int} */
	private function runCli(array $arguments, string $scenario = 'dispatch'): array
	{
		$environment = getenv();
		$this->assertIsArray($environment);
		$environment['PFB_TEST_LOCK_DIR'] = $this->dir;
		$environment['PFB_TEST_SCENARIO'] = $scenario;
		return pfb_test_run_process(
			array_merge([PHP_BINARY, __DIR__ . '/support/FeedPassCliWorker.php'], $arguments),
			10.0,
			$environment
		);
	}

	private function removeTree(string $root): void
	{
		if (!is_dir($root)) {
			return;
		}
		foreach (scandir($root) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = "{$root}/{$entry}";
			is_dir($path) ? $this->removeTree($path) : unlink($path);
		}
		rmdir($root);
	}
}
