<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_schedule_settings')]
final class CoreSettingsFeedsScheduleTest extends TestCase
{
	use ConfigXmlDiskTrait;

	public function testAScheduleWriteForAGroupBoundToAResolvableInterfaceIsAccepted(): void
	{
		$priorConfig = $GLOBALS['config'] ?? [];
		$priorPfb = $GLOBALS['pfb'];
		$dir = sys_get_temp_dir() . '/pfb_feeds_schedule_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$dir}/pending";
		$GLOBALS['pfb']['log'] = "{$dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$dir}/error.log";
		$GLOBALS['pfb']['metrics_lock'] = "{$dir}/metrics.lock";
		$path = 'installedpackages/pfblockernglistsv4/config/0';
		config_set_path($path, ['aliasname' => 'Bound', 'action' => 'Deny_Both', 'cron' => 'Never', 'srcint' => 'em0']);
		$this->configXmlOnDisk();
		$interfaces = static fn(): array => ['em0' => '192.0.2.1'];
		try {
			$read = pfb_core_settings_backend(['version' => 1, 'op' => 'read'], "{$dir}/metrics", $interfaces);
			$this->assertSame('192.0.2.1', $read['settings']['feeds/ipv4']['groups'][0]['bindAddress']);
			$this->assertSame('ipv4/Bound', $read['settings']['schedule']['groups'][0]['id']);
			$this->assertFalse($read['settings']['schedule']['groups'][0]['override']);
			$settings = $read['settings'];
			$settings['schedule']['groups'][0]['override'] = TRUE;
			$settings['schedule']['groups'][0]['hour'] = 7;

			$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings], "{$dir}/metrics", $interfaces);

			$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
			$this->assertSame('on', config_get_path("{$path}/schedule_override"));
			$this->assertSame('7', config_get_path("{$path}/schedule_hour"));
			$this->assertSame('em0', config_get_path("{$path}/srcint"));
		} finally {
			$GLOBALS['config'] = $priorConfig;
			$GLOBALS['pfb'] = $priorPfb;
			foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
				'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
				unset($GLOBALS["pfb_test_{$global}"]);
			}
			rmdir_recursive($dir);
		}
	}
}
