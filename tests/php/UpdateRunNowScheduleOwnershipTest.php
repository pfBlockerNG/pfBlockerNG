<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

if (!function_exists('pfbupdate_status')) {
	function pfbupdate_status($status): void
	{
	}
}
if (!function_exists('pfb_active_task_running')) {
	function pfb_active_task_running(): bool
	{
		return FALSE;
	}
}
if (!function_exists('mwexec_bg')) {
	function mwexec_bg($command): void
	{
		$GLOBALS['pfb_test_mwexec_bg'][] = $command;
	}
}

final class UpdateRunNowScheduleOwnershipTest extends TestCase
{
	private string $dir;
	private array $originalPfb;
	private mixed $originalConfig;

	public static function setUpBeforeClass(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		if (!is_string($source)) {
			throw new RuntimeException('failed to read Update page');
		}
		$start = strpos($source, 'function pfb_runnow(');
		$end = strpos($source, "\n\n\$pgtitle", $start);
		if ($start === FALSE || $end === FALSE) {
			throw new RuntimeException('failed to locate Run Now functions');
		}
		eval(substr($source, $start, $end - $start));
	}

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$this->dir = sys_get_temp_dir() . '/pfb-runnow-schedule-' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['runlog'] = "{$this->dir}/run.log";
		$GLOBALS['pfb']['interval'] = 24;
		$GLOBALS['pfb_test_mwexec_bg'] = [];
		$this->assertTrue(pfb_due_ledger_write_entry('cron', [
			'last_run' => 100,
			'next_due' => 200,
			'jitter' => 0,
		], $this->dir));
		config_set_path('cron/item', [[
			'command' => '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick',
			'minute' => '*/15',
		]]);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		unset($GLOBALS['pfb_test_mwexec_bg']);
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testRunNowLeavesTickOwnedCacheUntouched(): void
	{
		$before = file_get_contents("{$this->dir}/pfb_due_ledger.json");
		$this->assertCount(1, config_get_path('cron/item', []));

		pfb_runnow('both', FALSE);

		$this->assertSame($before, file_get_contents("{$this->dir}/pfb_due_ledger.json"));
		$this->assertCount(1, $GLOBALS['pfb_test_mwexec_bg']);
		$this->assertCount(1, config_get_path('cron/item', []), 'Run Now must not remove the fixed recovery tick');
	}

	public function testForceCheckLeavesTickOwnedCacheUntouched(): void
	{
		$before = file_get_contents("{$this->dir}/pfb_due_ledger.json");
		$this->assertCount(1, config_get_path('cron/item', []));

		pfb_runnow_forcecheck('both');

		$this->assertSame($before, file_get_contents("{$this->dir}/pfb_due_ledger.json"));
		$this->assertCount(1, $GLOBALS['pfb_test_mwexec_bg']);
		$this->assertCount(1, config_get_path('cron/item', []), 'Force Check must not remove the fixed recovery tick');
	}

	public function testHealthyCronTickIsNotReportedMissingWithoutSuppression(): void
	{
		$pfb = $GLOBALS['pfb'];
		$pfb['enable'] = PfbToggle::On;
		$command = "/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick >> {$pfb['log']} 2>&1";
		config_set_path('cron/item', [[
			'command' => $command,
			'minute' => '*/15',
			'hour' => '*',
			'mday' => '*',
			'wday' => '*',
		]]);
		$this->assertFalse(pfb_cron_disabled());
		$this->assertTrue(pfblockerng_cron_exists($command, '*/15', '*', '*', '*'));

		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$this->assertIsString($source);
		$start = strpos($source, '$pfb_tick_min = 15;');
		$end = strpos($source, "\n\$status = 'NEXT Scheduled CRON Event", $start);
		$this->assertNotFalse($start);
		$this->assertNotFalse($end);
		eval(substr($source, $start, $end - $start));

		$this->assertStringNotContainsString('Missing cron task', $cronreal);
		$this->assertNotSame('--', $nextcron);

		config_set_path('cron/item', []);
		eval(substr($source, $start, $end - $start));
		$this->assertSame(' [ Missing cron task ]', $cronreal);
		$this->assertSame('--', $nextcron);
	}

	public function testDetachedCliVerbsPropagateLockedProcessFailure(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertStringContainsString('exit(sync_package_pfblockerng(array(', $source);
		$this->assertStringContainsString('exit(pfblockerng_sync_cron(TRUE, $pfb_fcscope, FALSE, $pfb_fchashes) ? 0 : 1);', $source);
	}

	public function testForceValidatorsAreClearedOnlyInsideTheLockedChild(): void
	{
		$page = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$cron = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc');
		$this->assertStringNotContainsString('pfb_force_clear_validators($dirs,', $page);
		$this->assertStringContainsString('hashes={$hashes_val}', $page);
		$lock = strpos($cron, "pfb_feed_pass_begin('cron')");
		$clear = strpos($cron, 'pfb_force_clear_validators(', $lock);
		$this->assertNotFalse($lock);
		$this->assertNotFalse($clear);
		$this->assertGreaterThan($lock, $clear);
	}

	public function testDurableStateWithoutTimestampsPreservesCachedLastRun(): void
	{
		$page = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$this->assertStringContainsString(
			"is_array(\$item) && (isset(\$item['last_successful_check']) || isset(\$item['last_completed_occurrence']))",
			$page
		);
		$this->assertStringNotContainsString("\$item['last_completed_occurrence']??0", $page);
	}
}
