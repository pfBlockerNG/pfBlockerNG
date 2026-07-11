<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_configure_tick_cron() (issue #1204): the ADR-43 scheduled-tick cron
 * install/teardown now installs the cron-tick verb (not tick), so the crontab
 * entry is gateable by pfb_cron_disabled() without touching the direct tick verb.
 * Also covers the migration-teardown strstr regression: 'pfblockerng.php cron'
 * must NOT substring-match the just-installed 'pfblockerng.php cron-tick' entry.
 *
 * pfb_cron_disable_path()/pfb_cron_disabled(): the hidden dbdir sentinel that
 * suppresses the scheduled dispatch (house pattern: PFB_SOFTWARE_PANEL_OVERRIDE /
 * pfb_software_panel_override()). Presence-only -- content is never read; every
 * hostile-input class from CLAUDE.md's coverage matrix gets its own assertion.
 */
#[CoversFunction('pfblockerng_configure_tick_cron')]
#[CoversFunction('pfb_cron_disable_path')]
#[CoversFunction('pfb_cron_disabled')]
final class TickCronInstallTest extends TestCase
{
	private const LOG = '/var/log/pfblockerng/pfblockerng.log';
	private const CRON_TICK_CMD = '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick >> ' . self::LOG . ' 2>&1';
	private const LEGACY_TICK_CMD = '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick >> ' . self::LOG . ' 2>&1';

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
		foreach (glob("{$this->tmp}/*") ?: [] as $f) {
			is_dir($f) ? @rmdir($f) : @unlink($f);
		}
		@rmdir($this->tmp);
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

	// --- pfblockerng_configure_tick_cron() ------------------------------------

	public function testEnableInstallsCronTickCommand(): void
	{
		$this->assertSame([], $this->cronCommands());

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
	}

	public function testEnableRemovesStaleCronTickBeforeReinstall(): void
	{
		// A pre-existing cron-tick entry at a DIFFERENT interval (interval changed
		// 30 -> 15 across a settings save) must not linger alongside the fresh one.
		$this->seedCronItem(0, self::CRON_TICK_CMD, '*/30');
		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
	}

	public function testEnableUpgradesLegacyTickEntryToCronTick(): void
	{
		// Upgrade case: a pre-#1204 build left a bare 'tick' entry. It must be
		// replaced -- exactly ONE entry remains, and it is cron-tick.
		$this->seedCronItem(0, self::LEGACY_TICK_CMD, '*/15');
		$this->assertSame([self::LEGACY_TICK_CMD], $this->cronCommands());

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
	}

	public function testDisableRemovesCronTickEntry(): void
	{
		$this->seedCronItem(0, self::CRON_TICK_CMD, '*/15');

		pfblockerng_configure_tick_cron(false, 15, self::LOG);

		$this->assertSame([], $this->cronCommands());
	}

	public function testDisableRemovesLegacyTickEntry(): void
	{
		// A box that upgraded straight into 'disabled' must still lose its old tick entry.
		$this->seedCronItem(0, self::LEGACY_TICK_CMD, '*/15');

		pfblockerng_configure_tick_cron(false, 15, self::LOG);

		$this->assertSame([], $this->cronCommands());
	}

	public function testMigrationTeardownRemovesLegacyCronButSparesCronTick(): void
	{
		// strstr regression (issue #1204): the bare 'pfblockerng.php cron' needle must
		// NOT substring-match 'pfblockerng.php cron-tick' and delete the just-installed entry.
		$this->seedCronItem(0, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron >> ' . self::LOG . ' 2>&1', '0');

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
	}

	public function testMigrationTeardownRemovesLegacyDccSsRefreshBlAndCronTickSurvives(): void
	{
		$this->seedCronItem(0, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dcc >> ' . self::LOG . ' 2>&1', '0');
		$this->seedCronItem(1, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ss_refresh >> ' . self::LOG . ' 2>&1', '0');
		$this->seedCronItem(2, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bl >> ' . self::LOG . ' 2>&1', '0');
		$this->assertCount(3, $this->cronCommands());

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
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
