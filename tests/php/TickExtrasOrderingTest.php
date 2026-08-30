<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Extras run synchronously in schedule order before the feed worker. */
final class TickExtrasOrderingTest extends TestCase
{
	private string $dir = '';
	private mixed $pfb = NULL;
	private mixed $config = NULL;
	private bool $hadG = FALSE;
	private mixed $originalG = NULL;

	protected function setUp(): void
	{
		$this->pfb = $GLOBALS['pfb'];
		$this->config = $GLOBALS['config'] ?? NULL;
		$this->hadG = array_key_exists('g', $GLOBALS);
		$this->originalG = $GLOBALS['g'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_tick_extras_' . getmypid() . '_' . uniqid();
		mkdir($this->dir . '/state', 0777, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['schedule_state_dir'] = $this->dir . '/state';
		$GLOBALS['pfb']['runlog'] = $this->dir . '/run.log';
		$GLOBALS['pfb']['extraslog'] = $this->dir . '/extras.log';
		$GLOBALS['pfb']['log'] = $this->dir . '/pfb.log';
		$GLOBALS['pfb']['logdir'] = $this->dir;
		$GLOBALS['pfb']['errlog'] = $this->dir . '/error.log';
		$GLOBALS['pfb']['ccdir'] = $this->dir . '/cc';
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['php'] = $this->recorder();
		$GLOBALS['config'] = [];
		$slot = new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get()));
		$slot = $slot->modify('-15 minutes');
		$minute = intdiv((int) $slot->format('i'), 15) * 15;
		config_set_path('installedpackages/pfblockerng/config/0', [
			'skipfeed' => '0',
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => $slot->format('N'),
			'pfb_schedule_hour' => $slot->format('G'),
			'pfb_schedule_minute' => (string) $minute,
			'pfb_quiet_hours' => '00:00-00:01',
		]);
		config_set_path('installedpackages/pfblockerngipsettings/config/0', [
			'suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
			'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => '',
		]);
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', [
			'pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443',
		]);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'schedule_override' => '',
			'row' => [['header' => 'feed', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
		]]);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		$GLOBALS['pfb']['blconfig'] = [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'work',
			'blacklist_freq' => 'Weekly', 'item' => [[
				'xml' => 'work', 'selected' => 'yes', 'title' => 'Work', 'feed' => 'https://example.test/bl',
			]],
		];
		config_set_path('installedpackages/pfblockerngblacklist', $GLOBALS['pfb']['blconfig']);
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		mkdir($this->dir . '/cc');
	}

	protected function tearDown(): void
	{
		if ($this->hadG) {
			$GLOBALS['g'] = $this->originalG;
		} else {
			unset($GLOBALS['g']);
		}
		$GLOBALS['pfb'] = $this->pfb;
		$GLOBALS['config'] = $this->config;
		$this->remove($this->dir);
	}

	public function testDueExtrasRunDccThenBlThenFeedAndIgnoreApplyWindow(): void
	{
		$order = [];
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, static function (string $job, string $argument = '') use (&$order): bool {
			$order[] = $job;
			return TRUE;
		}, static function () use (&$order): void {
			$order[] = 'feed';
		});
		$this->assertSame(['dcc', 'bl', 'feed'], $order);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
	}

	public function testExtraFailureKeepsItsPendingOccurrenceAndDoesNotBlockLaterJobs(): void
	{
		$order = [];
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, static function (string $job, string $argument = '') use (&$order): bool {
			$order[] = $job;
			return $job !== 'dcc';
		}, static function (): void {});
		$state = pfb_schedule_state_read($this->dir . '/state');
		$this->assertSame(['dcc', 'bl'], $order);
		$this->assertArrayHasKey('pending_occurrence', $state['items']['extra:dcc']);
		$this->assertSame('success', $state['items']['extra:bl']['completion_outcome']);
	}

	public function testDccChangeWithoutDueFeedsRunsOneApplyConsumer(): void
	{
		PfbConfig::writeSystem('gen/pfb_quiet_hours', '');
		PfbConfig::writeSectionRawSystem('installedpackages/pfblockernglistsv4/config', []);
		$GLOBALS['g']['pfblockerng_install'] = TRUE;
		$order = [];
		pfblockerng_tick(
			[], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static function (string $job, string $argument, bool &$changed) use (&$order): bool {
				$order[] = $job;
				$changed = $job === 'dcc';
				return TRUE;
			},
			static function () use (&$order): void { $order[] = 'feed'; },
			static function () use (&$order): bool { $order[] = 'apply'; return TRUE; }
		);
		$this->assertSame(['dcc', 'bl', 'apply'], $order);
	}

	public function testSuccessfulExtrasDoNotRepeatTheSameOccurrence(): void
	{
		$order = [];
		$runner = static function (string $job, string $argument = '') use (&$order): bool {
			$order[] = $job;
			return TRUE;
		};
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, $runner, static function (): void {});
		$this->assertSame(['dcc', 'bl'], $order);
		$order = [];
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, $runner, static function (): void {});
		$this->assertSame([], $order);
	}

	public function testFailedExtraWaitsForTheNextScheduledSlot(): void
	{
		$order = [];
		$runner = static function (string $job, string $argument = '') use (&$order): bool {
			$order[] = $job;
			return $job !== 'dcc';
		};
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, $runner, static function (): void {});
		$this->assertSame(['dcc', 'bl'], $order);
		$order = [];
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, $runner, static function (): void {});
		$this->assertSame([], $order);
	}

	public function testPendingManualApplyDoesNotSuppressSameSlotExtras(): void
	{
		PfbConfig::writeSystem('gen/pfb_quiet_hours', '');
		$this->assertTrue(pfb_due_ledger_write_entry('cron', [
			'last_run' => time() - 60, 'next_due' => time() - 1, 'jitter' => 0, 'pending_apply' => TRUE,
		], $this->dir));
		$order = [];
		pfblockerng_tick(
			[], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static function (string $job) use (&$order): bool { $order[] = $job; return TRUE; },
			static function () use (&$order): void { $order[] = 'feed'; },
			static function () use (&$order): bool { $order[] = 'manual'; return TRUE; }
		);
		$this->assertSame(['dcc', 'bl', 'manual', 'feed'], $order);
	}

	public function testFailedInterruptedGeoipRecoveryBlocksManualAndFeedConsumers(): void
	{
		PfbConfig::writeSystem('gen/pfb_quiet_hours', '');
		$this->assertTrue(pfb_due_ledger_write_entry('cron', [
			'last_run' => time() - 60, 'next_due' => time() - 1, 'jitter' => 0, 'pending_apply' => TRUE,
		], $this->dir));
		file_put_contents($this->dir . '/cc/.pfb_generation_swapping', 'interrupted');
		$order = [];

		pfblockerng_tick(
			[], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static function (string $job) use (&$order): bool {
				$order[] = $job;
				return $job !== 'dcc';
			},
			static function () use (&$order): void { $order[] = 'feed'; },
			static function () use (&$order): bool { $order[] = 'manual'; return TRUE; }
		);

		$this->assertSame(['dcc', 'bl'], $order);
		$this->assertTrue(pfb_due_ledger_read_entry('cron', $this->dir)['pending_apply']);
	}

	public function testDispatcherContentionLeavesInvalidCacheBytesUntouched(): void
	{
		$cache = $this->dir . '/pfb_due_ledger.json';
		$before = '{"stale":true}';
		file_put_contents($cache, $before);
		$lock = fopen($this->dir . '/state/pfb_schedule_dispatch.lock', 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, static fn (string $job, string $argument = ''): bool => TRUE);
		$this->assertSame($before, file_get_contents($cache));
		flock($lock, LOCK_UN);
		fclose($lock);
	}

	public function testFeedPassContentionLeavesExtrasAndFeedsUnreserved(): void
	{
		$cache = $this->dir . '/pfb_due_ledger.json';
		$before = '{"stale":true}';
		file_put_contents($cache, $before);
		$lock = fopen($this->dir . '/pfb_feed_pass.lock', 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static fn (string $job, string $argument = ''): bool => TRUE,
			static function (): void {
				self::fail('feed runner must not run while feed-pass lock is held');
			}
		);
		$this->assertSame($before, file_get_contents($cache));
		$this->assertFileDoesNotExist($this->dir . '/state/pfb_schedule_state.json');
		flock($lock, LOCK_UN);
		fclose($lock);
	}

	public function testScheduledWorkRunsSynchronouslyWhileBothLocksAreHeld(): void
	{
		$order = [];
		$lock_probe = static function (string $path): bool {
			$probe = fopen($path, 'c');
			$held = $probe !== FALSE && !flock($probe, LOCK_EX | LOCK_NB);
			if (is_resource($probe)) {
				fclose($probe);
			}
			return $held;
		};
		$extra_runner = function (string $job, string $argument = '') use (&$order, $lock_probe): bool {
			$order[] = [$job, $lock_probe($this->dir . '/state/pfb_schedule_dispatch.lock'), $lock_probe($this->dir . '/pfb_feed_pass.lock')];
			return TRUE;
		};
		$feed_runner = function () use (&$order, $lock_probe): void {
			$order[] = ['feed', $lock_probe($this->dir . '/state/pfb_schedule_dispatch.lock'), $lock_probe($this->dir . '/pfb_feed_pass.lock')];
		};
		pfblockerng_tick([], NULL, NULL, 5.0, NULL, NULL, 5.0, $extra_runner, $feed_runner);
		$this->assertSame(['dcc', 'bl', 'feed'], array_column($order, 0));
		$this->assertSame([["dcc", TRUE, TRUE], ["bl", TRUE, TRUE], ["feed", TRUE, TRUE]], $order);
		$this->assertFileDoesNotExist($this->dir . '/spawns');
		$state = pfb_schedule_state_read($this->dir . '/state');
		foreach ($state['items'] as $item) {
			$this->assertArrayNotHasKey('pending_dispatch_at', $item);
		}
	}

	private function recorder(): string
	{
		$path = $this->dir . '/php-recorder';
		$log = escapeshellarg($this->dir . '/spawns');
		file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> {$log}\n");
		chmod($path, 0755);
		return $path;
	}

	private function remove(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = $dir . '/' . $entry;
			is_dir($path) ? $this->remove($path) : @unlink($path);
		}
		@rmdir($dir);
	}
}
