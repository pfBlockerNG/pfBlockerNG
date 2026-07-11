<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_configure_tick_cron() (issue #1204) -- the ADR-43 scheduled-tick cron
 * install/teardown, extracted out of sync_package_pfblockerng() for testability.
 *
 * This file currently pins the PRE-#1204 behaviour (verb 'tick'; the extraction
 * itself is behaviour-preserving -- issue #1204's cron-tick verb + suppression
 * gate land in a later commit that edits these expectations forward).
 */
#[CoversFunction('pfblockerng_configure_tick_cron')]
final class TickCronInstallTest extends TestCase
{
	private const LOG = '/var/log/pfblockerng/pfblockerng.log';
	private const TICK_CMD = '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick >> ' . self::LOG . ' 2>&1';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	private function cronCommands(): array
	{
		return array_map(
			static fn ($item) => $item['command'],
			config_get_path('cron/item', [])
		);
	}

	public function testEnableInstallsTickCommand(): void
	{
		// Before: no cron/item at all.
		$this->assertSame([], $this->cronCommands());

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		$this->assertSame([self::TICK_CMD], $this->cronCommands());
	}

	public function testEnableRemovesStaleTickBeforeReinstall(): void
	{
		// A pre-existing tick entry at a DIFFERENT interval (e.g. interval changed
		// 30 -> 15 across a settings save) must not linger alongside the fresh one.
		config_set_path('cron/item/0', [
			'minute' => '*/30', 'hour' => '*', 'mday' => '*', 'month' => '*',
			'wday' => '*', 'who' => 'root', 'command' => self::TICK_CMD,
		]);
		$this->assertSame([self::TICK_CMD], $this->cronCommands());

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		// Exactly ONE entry remains, and it is the (re-added) tick command.
		$this->assertSame([self::TICK_CMD], $this->cronCommands());
	}

	public function testDisableRemovesTickEntry(): void
	{
		config_set_path('cron/item/0', [
			'minute' => '*/15', 'hour' => '*', 'mday' => '*', 'month' => '*',
			'wday' => '*', 'who' => 'root', 'command' => self::TICK_CMD,
		]);
		$this->assertSame([self::TICK_CMD], $this->cronCommands());

		pfblockerng_configure_tick_cron(false, 15, self::LOG);

		$this->assertSame([], $this->cronCommands());
	}

	public function testMigrationTeardownRemovesLegacyCronDccSsRefreshBl(): void
	{
		config_set_path('cron/item/0', ['minute' => '0', 'hour' => '0', 'mday' => '*', 'month' => '*', 'wday' => '*', 'who' => 'root', 'command' => '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron >> ' . self::LOG . ' 2>&1']);
		config_set_path('cron/item/1', ['minute' => '0', 'hour' => '0', 'mday' => '*', 'month' => '*', 'wday' => '*', 'who' => 'root', 'command' => '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dcc >> ' . self::LOG . ' 2>&1']);
		config_set_path('cron/item/2', ['minute' => '0', 'hour' => '0', 'mday' => '*', 'month' => '*', 'wday' => '*', 'who' => 'root', 'command' => '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ss_refresh >> ' . self::LOG . ' 2>&1']);
		config_set_path('cron/item/3', ['minute' => '0', 'hour' => '0', 'mday' => '*', 'month' => '*', 'wday' => '*', 'who' => 'root', 'command' => '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bl >> ' . self::LOG . ' 2>&1']);
		$this->assertCount(4, $this->cronCommands());

		pfblockerng_configure_tick_cron(true, 15, self::LOG);

		// Every legacy fleet entry is gone; only the fresh tick entry remains.
		$this->assertSame([self::TICK_CMD], $this->cronCommands());
	}
}
