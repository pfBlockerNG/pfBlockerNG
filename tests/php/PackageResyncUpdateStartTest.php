<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3977 (spec section 5, coverage matrix): the package resync starts one `manual` Update through Core instead of running a PHP
 * pass. After an install or upgrade it carries `lifecycle: install` and the package operation, so the hooks fire once in that
 * Update with PFB_POST_INSTALL=1. The installer has just restarted pfb_core, whose start returns before its socket listens, so
 * a Core that is not answering yet is asked again on a short tick, a bounded number of times. A Core that never answers, or an
 * Update already running, is reported and the change is marked pending: no PHP pass runs and no hook fires another way.
 */
#[CoversFunction('pfb_resync_update_start')]
final class PackageResyncUpdateStartTest extends TestCase
{
	private string $marker;

	protected function setUp(): void
	{
		$this->marker = (string) tempnam(sys_get_temp_dir(), 'pfb_pending_');
		@unlink($this->marker);
		$GLOBALS['pfb']['pending_marker'] = $this->marker;
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb']['pending_marker']);
		@unlink($this->marker);
	}

	/**
	 * @param list<array{status: int, body: ?array, error: ?string}> $answers one per call, the last repeated
	 * @return array{0: callable, 1: ArrayObject<int, array{string, array}>}
	 */
	private static function core(array $answers): array
	{
		$calls = new ArrayObject();
		return [function (string $method, array $params) use ($answers, $calls): array {
			$calls[] = [$method, $params];
			return $answers[min(count($calls), count($answers)) - 1];
		}, $calls];
	}

	private const DOWN = ['status' => 0, 'body' => NULL, 'error' => 'the Core API is not running'];
	private const OK = ['status' => 200, 'body' => [], 'error' => NULL];

	public function testAnInstallStartsOneManualUpdateWithItsLifecycleAndOperation(): void
	{
		[$call, $calls] = self::core([self::OK]);
		$this->assertNull(pfb_resync_update_start($call, static function (): void {}, 'install', 'upgrade'));
		$this->assertCount(1, $calls);
		$this->assertSame('StartUpdate', $calls[0][0]);
		$params = $calls[0][1];
		unset($params['requestId']);
		$this->assertSame(['trigger' => 'manual', 'scope' => 'both', 'force' => 'none', 'lifecycle' => 'install', 'pkgOp' => 'upgrade'], $params);
		$this->assertFileDoesNotExist($this->marker);
	}

	public function testAResyncOutsideAnInstallCarriesNoLifecycle(): void
	{
		[$call, $calls] = self::core([self::OK]);
		$this->assertNull(pfb_resync_update_start($call, static function (): void {}, NULL, ''));
		$this->assertArrayNotHasKey('lifecycle', $calls[0][1]);
		$this->assertArrayNotHasKey('pkgOp', $calls[0][1]);
	}

	public function testACoreThatIsStillStartingIsAskedAgainOnAShortTick(): void
	{
		$sleeps = 0;
		[$call, $calls] = self::core([self::DOWN, self::DOWN, self::OK]);
		$this->assertNull(pfb_resync_update_start($call, static function () use (&$sleeps): void { $sleeps++; }, 'install', 'install'));
		$this->assertCount(3, $calls);
		$this->assertSame(2, $sleeps);
		$this->assertFileDoesNotExist($this->marker);
	}

	public function testACoreThatNeverAnswersIsReportedAndTheChangeIsPending(): void
	{
		[$call, $calls] = self::core([self::DOWN]);
		$error = pfb_resync_update_start($call, static function (): void {}, 'install', 'install');
		$this->assertStringContainsString('the Core API is not running', (string) $error);
		$this->assertCount(PFB_RESYNC_START_TRIES, $calls, 'bounded');
		$this->assertFileExists($this->marker);
	}

	public function testAnUpdateAlreadyRunningIsReportedAtOnceAndTheChangeIsPending(): void
	{
		[$call, $calls] = self::core([['status' => 409, 'body' => ['error' => ['code' => 'conflict', 'message' => 'an Update is running']], 'error' => NULL]]);
		$error = pfb_resync_update_start($call, static function (): void {}, 'install', 'upgrade');
		$this->assertStringContainsString('an Update is running', (string) $error);
		$this->assertCount(1, $calls, 'a conflict is no Core still starting: it is not asked again');
		$this->assertFileExists($this->marker);
	}

	/** The resync command: one Update through Core, its lifecycle from the installer; at boot the boot branch alone (no Update). */
	public function testTheResyncCommandStartsTheUpdateAndKeepsTheBootBranchAlone(): void
	{
		$xml = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng.xml');
		$this->assertSame(1, preg_match('~<custom_php_resync_config_command>(.*?)</custom_php_resync_config_command>~s', $xml, $m));
		$resync = $m[1];
		$this->assertStringContainsString("pfb_resync_update_start('pfb_core_call'", $resync);
		$this->assertStringContainsString('pfb_pkg_operation()', $resync);
		$this->assertMatchesRegularExpression('~if \(platform_booting\(\)\) \{[^}]*sync_package_pfblockerng\(~s', $resync,
			'the boot branch runs only at boot');
		$this->assertSame(1, substr_count($resync, 'sync_package_pfblockerng('), 'no PHP pass outside the boot branch');
	}
}
