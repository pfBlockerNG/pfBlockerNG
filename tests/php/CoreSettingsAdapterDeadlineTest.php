<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3927: Core kills the settings adapter at its write deadline (go/pfb_core/settings/adapter.go `writeTimeout`), so a
 * client-IP change it asks for must end inside it: a killed adapter answers nothing, and Core reports a failure for a save that
 * may have landed. The adapter's longest path waits for the DNS config lock, then the metrics lock, then up to three passes over
 * both metrics databases (the privacy reconcile, its undo after a refused write, the read-back for the message), each bounded by
 * the SQLite busy wait the adapter gives pfb_metrics_client_save().
 */
#[CoversFunction('pfb_core_settings_backend')]
final class CoreSettingsAdapterDeadlineTest extends TestCase
{
	/** PHP start, the revision reads and write_config() itself, none of which waits on a lock this budget bounds */
	private const RESERVE_S = 3.0;

	private static function coreWriteDeadline(): float
	{
		$go = (string) file_get_contents(dirname(__DIR__, 2) . '/go/pfb_core/settings/adapter.go');
		if (preg_match('/^\s*writeTimeout\s*=\s*(\d+)\s*\*\s*time\.Second\b/m', $go, $m) !== 1) {
			throw new RuntimeException('writeTimeout not found in go/pfb_core/settings/adapter.go');
		}
		return (float) $m[1];
	}

	public function testTheAdaptersLongestClientIpChangeEndsBeforeCoreKillsIt(): void
	{
		// Without the adapter's own waits, pfb_metrics_client_save() falls back to the metrics lock's 10 s and SQLite's 5 s
		$metrics_lock_s = defined('PFB_CORE_SETTINGS_METRICS_LOCK_WAIT') ? constant('PFB_CORE_SETTINGS_METRICS_LOCK_WAIT') : 10.0;
		$sqlite_s = (defined('PFB_CORE_SETTINGS_SQLITE_WAIT_MS') ? constant('PFB_CORE_SETTINGS_SQLITE_WAIT_MS') : 5000) / 1000;

		$longest = PFB_DNS_CONFIG_LOCK_WAIT + $metrics_lock_s + 3 * 2 * $sqlite_s + self::RESERVE_S;

		$this->assertLessThan(self::coreWriteDeadline(), $longest, sprintf('DNS config lock %ds + metrics lock %.1fs + 6 x SQLite %.1fs + reserve %.1fs',
			PFB_DNS_CONFIG_LOCK_WAIT, $metrics_lock_s, $sqlite_s, self::RESERVE_S));
	}
}
