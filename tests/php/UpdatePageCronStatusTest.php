<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The Update page's cron-status line and Core-owned CLI feed requests (issues #3941 and #3977).
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
		config_set_path('cron/item', [[
			'command' => '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick',
			'minute' => '*/15',
		]]);
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
		$end = strpos($source, "\n\$status = ", $start);
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

	public function testLegacyCliVerbsStartCoreUpdatesInsteadOfThePhpPass(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertStringContainsString('pfb_core_update_start(', $source);
		$this->assertStringNotContainsString('$pfb_completed = sync_package_pfblockerng(', $source);
		$this->assertStringNotContainsString('$pfb_completed = pfblockerng_sync_cron(', $source);
		$this->assertStringNotContainsString('pfb_cli_feed_pass_exit(', $source);
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
