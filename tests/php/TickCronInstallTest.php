<?php

declare(strict_types=1);

require_once __DIR__ . '/PageStatementLoader.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Core owns the quarter-hour dispatch: install, upgrade and every apply retire
 * only the old pfBlockerNG dispatch jobs, regardless of package enablement.
 * The hidden sentinel remains presence-only for Core's scheduled maintenance.
 */
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
		$code = pfb_test_page_region(
			'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc',
			"\t#\tDefine/Apply CRON Jobs",
			"\tpfb_metrics_configure_cron("
		);
		pfb_test_page_eval($code, ['pfb' => [
			'enable' => PfbConfig::read('gen/enable_cb'),
			'log' => self::LOG,
		]]);
	}

	#[DataProvider('registrationStates')]
	public function testEveryApplyRetiresDispatchWithoutInstallingAndKeepsSiblingJobs(bool $enabled, string $log): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', $enabled ? 'on' : '');
		$prefix = '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ';
		$retired = [];
		foreach (['cron', 'tick', 'cron-tick', 'dcc', 'ss_refresh', 'bl'] as $verb) {
			$retired[] = $prefix . $verb . ' >> ' . $log . ' 2>&1';
		}
		$kept = [$prefix . 'metrics', $prefix . 'clearip', $prefix . 'cleardnsbl', '/usr/sbin/newsyslog'];
		foreach (array_merge($retired, $kept) as $idx => $command) {
			$this->seedCronItem($idx, $command);
		}
		$this->assertSame(array_merge($retired, $kept), $this->cronCommands(), 'before: every obsolete dispatch and sibling job');
		$installs = [];
		$GLOBALS['pfb_test_install_cron_hook'] = static function (string $command, bool $active) use (&$installs): void {
			if ($active) {
				$installs[] = $command;
			}
		};
		try {
			$this->applyRegistration($enabled);
			$this->assertSame($kept, $this->cronCommands(), 'first apply removes dispatch but no sibling job');
			$this->applyRegistration($enabled);
			$this->assertSame($kept, $this->cronCommands(), 'repeat apply never reinstalls dispatch');
			$this->assertSame([], $installs, 'no transient competing registration is allowed');
		} finally {
			unset($GLOBALS['pfb_test_install_cron_hook']);
		}
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
