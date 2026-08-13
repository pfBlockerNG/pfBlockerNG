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

		pfblockerng_configure_tick_cron(TRUE, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
	}

	public function testEnableRegeneratesDisposableScheduleCache(): void
	{
		$regenerated = 0;

		pfblockerng_configure_tick_cron(TRUE, self::LOG, static function () use (&$regenerated): bool {
			$regenerated++;
			return TRUE;
		});

		$this->assertSame(1, $regenerated);
	}

	public function testSettingsSaveCanSuppressActiveCacheRegeneration(): void
	{
		$regenerated = 0;
		pfblockerng_configure_tick_cron(TRUE, self::LOG, static function () use (&$regenerated): bool {
			$regenerated++;
			return TRUE;
		}, FALSE);
		$this->assertSame(0, $regenerated);
	}

	public function testEnableRemovesStaleCronTickBeforeReinstall(): void
	{
		$this->seedCronItem(0, self::CRON_TICK_CMD, '*/30');
		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
		$this->assertSame('*/30', config_get_path('cron/item/0/minute'), 'before: the stale interval is in place');

		pfblockerng_configure_tick_cron(TRUE, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
		$this->assertSame('*/15', config_get_path('cron/item/0/minute'), 'after: the entry carries the fixed interval');
	}

	public function testEnableReplacesACronTickEntryWhoseCommandChanged(): void
	{
		// The stale-cron-tick removal earns its keep here: install_cron_job() overwrites an
		// entry its own command substring-matches, but a stored cron-tick command that DIFFERS
		// (e.g. a log path change) is not matched by the new command -- without the removal it
		// would linger beside the fresh entry.
		$stale = '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron-tick >> /var/log/old-pfblockerng.log 2>&1';
		$this->seedCronItem(0, $stale, '*/15');
		$this->assertSame([$stale], $this->cronCommands());

		pfblockerng_configure_tick_cron(TRUE, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands(), 'the stale-command entry must not linger beside the fresh one');
	}

	public function testEnableUpgradesLegacyTickEntryToCronTick(): void
	{
		// Upgrade case: a pre-#1204 build left a bare 'tick' entry. It must be
		// replaced -- exactly ONE entry remains, and it is cron-tick.
		$this->seedCronItem(0, self::LEGACY_TICK_CMD, '*/15');
		$this->assertSame([self::LEGACY_TICK_CMD], $this->cronCommands());

		pfblockerng_configure_tick_cron(TRUE, self::LOG);

		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands());
	}

	public function testDisableRemovesCronTickEntry(): void
	{
		$this->seedCronItem(0, self::CRON_TICK_CMD, '*/15');

		pfblockerng_configure_tick_cron(FALSE, self::LOG);

		$this->assertSame([], $this->cronCommands());
	}

	public function testDisableRemovesLegacyTickEntry(): void
	{
		// A box that upgraded straight into 'disabled' must still lose its old tick entry.
		$this->seedCronItem(0, self::LEGACY_TICK_CMD, '*/15');

		pfblockerng_configure_tick_cron(FALSE, self::LOG);

		$this->assertSame([], $this->cronCommands());
	}

	public function testMigrationTeardownRemovesLegacyCronButSparesCronTick(): void
	{
		// strstr regression (issue #1204): the bare 'pfblockerng.php cron' needle must NOT
		// substring-match 'pfblockerng.php cron-tick' and delete the just-installed entry.
		// The SECOND call is what discriminates: on the first pass the legacy entry absorbs
		// install_cron_job()'s first-match-wins removal, so only a steady-state resync (no
		// legacy entry left to absorb it) exposes a too-loose needle.
		$this->seedCronItem(0, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron >> ' . self::LOG . ' 2>&1', '0');

		pfblockerng_configure_tick_cron(TRUE, self::LOG);
		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands(), 'first sync: legacy cron removed, cron-tick installed');

		pfblockerng_configure_tick_cron(TRUE, self::LOG);
		$this->assertSame([self::CRON_TICK_CMD], $this->cronCommands(), 'steady-state resync: the cron-tick entry must survive the migration teardown');
	}

	public function testMigrationTeardownRemovesLegacyDccSsRefreshBlAndCronTickSurvives(): void
	{
		$this->seedCronItem(0, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dcc >> ' . self::LOG . ' 2>&1', '0');
		$this->seedCronItem(1, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ss_refresh >> ' . self::LOG . ' 2>&1', '0');
		$this->seedCronItem(2, '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bl >> ' . self::LOG . ' 2>&1', '0');
		$this->assertCount(3, $this->cronCommands());

		pfblockerng_configure_tick_cron(TRUE, self::LOG);

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
