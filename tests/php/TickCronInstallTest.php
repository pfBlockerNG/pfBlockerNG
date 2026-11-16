<?php

declare(strict_types=1);

require_once __DIR__ . '/PageStatementLoader.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Core owns every schedule (issue #3996): install, upgrade and every apply retire the pfBlockerNG crontab entries and install none,
 * regardless of package enablement. The hidden sentinel remains presence-only for Core's scheduled maintenance.
 */
#[CoversFunction('pfblockerng_retire_cron_jobs')]
#[CoversFunction('pfb_cron_disable_path')]
#[CoversFunction('pfb_cron_disabled')]
final class TickCronInstallTest extends TestCase
{
	private const LOG = '/var/log/pfblockerng/pfblockerng.log';

	/** @var string Per-test temp dir for the cron-disable sentinel tests. */
	private string $tmp;

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$this->tmp = sys_get_temp_dir() . '/pfb_cron_disable_' . getmypid() . '_' . uniqid();
		@mkdir($this->tmp, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmp);
	}

	private function cronCommands(): array
	{
		return array_map(
			static fn ($item) => $item['command'],
			config_get_path('cron/item', [])
		);
	}

	private function seedCronItem(int $idx, string $command, string $minute = '*/30'): void
	{
		config_set_path("cron/item/{$idx}", [
			'minute' => $minute, 'hour' => '*', 'mday' => '*', 'month' => '*',
			'wday' => '*', 'who' => 'root', 'command' => $command,
		]);
	}

	private function applyRegistration(bool $enabled): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', $enabled ? 'on' : '');
		$code = pfb_test_page_statement('src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc', '/^\tpfblockerng_retire_cron_jobs\(\);/m');
		pfb_test_page_eval($code, ['pfb' => [
			'enable' => PfbConfig::read('gen/enable_cb'),
			'log' => self::LOG,
		]]);
	}

	#[DataProvider('registrationStates')]
	public function testEveryApplyRetiresEveryPackageEntryWithoutInstallingAndKeepsSiblingJobs(bool $enabled, string $log): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', $enabled ? 'on' : '');
		config_set_path('installedpackages/pfblockerng/config/0/pfb_metrics_export', 'on');
		config_set_path('installedpackages/pfblockerngglobal/widget-clearip', 'daily');
		config_set_path('installedpackages/pfblockerngglobal/widget-cleardnsbl', 'weekly');
		$prefix = '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ';
		$retired = [];
		foreach (['cron', 'tick', 'cron-tick', 'dcc', 'ss_refresh', 'bl'] as $verb) {
			$retired[] = $prefix . $verb . ' >> ' . $log . ' 2>&1';
		}
		foreach (['clearip', 'cleardnsbl'] as $verb) {
			foreach (['', "'"] as $quote) {
				$retired[] = $prefix . $quote . $verb . $quote . ' >/dev/null 2>&1';
			}
		}
		$retired[] = '/usr/bin/timeout -s TERM -k 5 50 ' . $prefix . 'metrics >> /dev/null 2>&1';
		$kept = ['/usr/sbin/newsyslog', '/usr/local/bin/php /usr/local/www/otherpackage.php clearip-cache'];
		foreach (array_merge($retired, $kept) as $idx => $command) {
			$this->seedCronItem($idx, $command);
		}
		$this->assertSame(array_merge($retired, $kept), $this->cronCommands(), 'before: every package entry and the sibling jobs');
		$installs = [];
		$GLOBALS['pfb_test_install_cron_hook'] = static function (string $command, bool $active) use (&$installs): void {
			if ($active) {
				$installs[] = $command;
			}
		};
		try {
			$this->applyRegistration($enabled);
			$this->assertSame($kept, $this->cronCommands(), 'the first apply removes every package entry and no sibling job');
			$this->applyRegistration($enabled);
			$this->assertSame($kept, $this->cronCommands(), 'a repeat apply installs nothing');
			$this->assertSame([], $installs, 'no entry is ever installed, not even transiently');
		} finally {
			unset($GLOBALS['pfb_test_install_cron_hook']);
		}
	}

	/** The metrics lock is released inside pfb_metrics_configure_export(): the retirement (install_cron_job() can start cron, which would inherit a held lock) must come after it. */
	public function testTheApplyPassRetiresOnlyAfterTheMetricsExportIsConfigured(): void
	{
		$source = php_strip_whitespace(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$export = strpos($source, 'pfb_metrics_configure_export(');
		$retire = strpos($source, 'pfblockerng_retire_cron_jobs();');
		$this->assertNotFalse($export);
		$this->assertNotFalse($retire);
		$this->assertLessThan($retire, $export);
	}

	public static function registrationStates(): array
	{
		return [
			'enabled current commands' => [TRUE, self::LOG],
			'enabled old log commands' => [TRUE, '/var/log/old-pfblockerng.log'],
			'disabled current commands' => [FALSE, self::LOG],
			'disabled old log commands' => [FALSE, '/var/log/old-pfblockerng.log'],
		];
	}

	public function testFreshEnabledInstallRegistersNoDispatch(): void
	{
		$this->assertSame([], $this->cronCommands());
		$this->applyRegistration(TRUE);
		$this->assertSame([], $this->cronCommands());
	}

	// --- pfb_cron_disable_path() / pfb_cron_disabled() ------------------------

	public function testDisablePathBuildsFromInjectedDbdir(): void
	{
		$this->assertSame("{$this->tmp}/.pfb_cron_disable", pfb_cron_disable_path($this->tmp));
	}

	public function testDisablePathDefaultsToGlobalPfbDbdir(): void
	{
		$this->assertSame("{$GLOBALS['pfb']['dbdir']}/.pfb_cron_disable", pfb_cron_disable_path());
	}

	public function testCronNotDisabledWhenFlagAbsent(): void
	{
		$this->assertFalse(pfb_cron_disabled(pfb_cron_disable_path($this->tmp)));
	}

	public function testCronDisabledWhenFlagIsEmptyFile(): void
	{
		$path = pfb_cron_disable_path($this->tmp);
		touch($path);

		$this->assertTrue(pfb_cron_disabled($path));
	}

	/**
	 * @return array<string, array{0:string}>
	 */
	public static function arbitraryFlagContentProvider(): array
	{
		return [
			'off (content never overrides presence)' => ['off'],
			'whitespace'                              => ["  \t\n  "],
			'binary'                                  => ["\x00\x01\xff\xfe"],
			'oversized'                                => [str_repeat('x', 65536)],
		];
	}

	#[DataProvider('arbitraryFlagContentProvider')]
	public function testCronDisabledIgnoresFlagContent(string $content): void
	{
		$path = pfb_cron_disable_path($this->tmp);
		file_put_contents($path, $content);

		$this->assertTrue(pfb_cron_disabled($path));
	}

	public function testCronNotDisabledWhenPathIsADirectory(): void
	{
		$path = pfb_cron_disable_path($this->tmp);
		mkdir($path);

		$this->assertFalse(pfb_cron_disabled($path));
	}

	public function testCronDisabledWhenFlagIsASymlinkToAFile(): void
	{
		$target = "{$this->tmp}/real-file";
		touch($target);
		$path = pfb_cron_disable_path($this->tmp);
		symlink($target, $path);

		$this->assertTrue(pfb_cron_disabled($path));
	}
}
