<?php

declare(strict_types=1);

require_once __DIR__ . '/PageStatementLoader.php';

use PHPUnit\Framework\TestCase;

/**
 * The Update page's schedule-status line and the CLI verbs it no longer dispatches (issue #3941). Run Now is Core's now
 * (UpdateViewResponseTest, UpdatePageCoreTest); what stays here is the status line, which the page still computes, and
 * the exit-status contract of the verbs the Outpost and the smoke harness still run.
 */
final class UpdatePageCronStatusTest extends TestCase
{
	private string $dir;
	private array $originalPfb;
	private mixed $originalConfig;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$this->dir = sys_get_temp_dir() . '/pfb-runnow-schedule-' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	/** Core schedules the tick (issue #3996): no crontab entry exists to probe, so an enabled package is never reported as missing one. */
	private function statusVariables(PfbToggle $enable): array
	{
		$pfb = $GLOBALS['pfb'];
		$pfb['enable'] = $enable;
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$this->assertIsString($source);
		$start = strpos($source, '$pfb_tick_min = 15;');
		$end = strpos($source, "\n\$status = ", (int) $start);
		$this->assertNotFalse($start);
		$this->assertNotFalse($end);
		$scope = pfb_test_page_eval(substr($source, $start, $end - $start), ['pfb' => $pfb]);
		return ['cronreal' => $scope['cronreal'], 'nextcron' => $scope['nextcron']];
	}

	public function testAnEnabledPackageWithNoCrontabEntryShowsTheNextTickNotAMissingTask(): void
	{
		$this->assertSame([], config_get_path('cron/item', []), 'before: the crontab holds no pfBlockerNG entry');
		$this->assertFalse(pfb_cron_disabled());

		$status = $this->statusVariables(PfbToggle::On);

		$this->assertMatchesRegularExpression('/^\d\d:\d\d$/', $status['cronreal'], 'the next quarter-hour boundary');
		$this->assertMatchesRegularExpression('/^\d\d:\d\d:\d\d$/', $status['nextcron']);
	}

	public function testTheCronDisableSentinelStillOutranksAnEnabledPackage(): void
	{
		touch(pfb_cron_disable_path());

		$status = $this->statusVariables(PfbToggle::On);

		$this->assertSame(' [ Disabled by ' . pfb_cron_disable_path() . ' ]', $status['cronreal']);
		$this->assertSame('--', $status['nextcron']);
	}

	public function testADisabledPackageShowsDisabled(): void
	{
		$this->assertFalse(pfb_cron_disabled());

		$status = $this->statusVariables(PfbToggle::Off);

		$this->assertSame(' [ Disabled ]', $status['cronreal']);
		$this->assertSame('--', $status['nextcron']);
	}

	public function testThePageNoLongerProbesTheCrontab(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$this->assertStringNotContainsString('Missing cron task', $source);
		$this->assertStringNotContainsString('cron_exists', $source);
	}

	public function testDetachedCliVerbsPropagateLockedProcessFailure(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertStringContainsString('$pfb_completed = sync_package_pfblockerng(', $source);
		$this->assertStringContainsString('$pfb_completed = pfblockerng_sync_cron(', $source);
		$this->assertStringContainsString('pfb_cli_feed_pass_exit($pfb_completed, $pfb_deferred_by);', $source);
	}

	public function testForceValidatorsAreClearedOnlyInsideTheLockedChild(): void
	{
		$page = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$cron = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc');
		$this->assertStringNotContainsString('pfb_force_clear_validators(', $page, 'the page asks Core; the Update program clears the validators');
		$lock = strpos($cron, "pfb_feed_pass_begin('cron', \$pfb_feed_pass_contended)");
		$clear = strpos($cron, 'pfb_force_clear_validators(', $lock);
		$this->assertNotFalse($lock);
		$this->assertNotFalse($clear);
		$this->assertGreaterThan($lock, $clear);
	}

}
