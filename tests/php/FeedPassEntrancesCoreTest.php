<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #3977: legacy and lifecycle entrypoints must delegate feed work to Core. */
final class FeedPassEntrancesCoreTest extends TestCase
{
	private const WWW = __DIR__ . '/../../src/usr/local/www/pfblockerng';

	private static function source(string $path): string
	{
		$source = file_get_contents($path);
		self::assertIsString($source);
		return $source;
	}

	private function contains(string $source, string $needle, string $message): void
	{
		$this->assertTrue(str_contains($source, $needle), $message);
	}

	private function excludes(string $source, string $needle, string $message): void
	{
		$this->assertFalse(str_contains($source, $needle), $message);
	}

	public function testUpdateStartsManualBothWithNoForce(): void
	{
		$cli = self::source(self::WWW . '/pfblockerng.php');
		$this->contains($cli, "'update' => ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']", 'update must request manual/both/none');
		$this->excludes($cli, 'sync_package_pfblockerng($argv[1]', 'update must not enter the PHP feed pass');
	}

	public function testUpdateIpStartsManualIpWithDownloadForce(): void
	{
		$cli = self::source(self::WWW . '/pfblockerng.php');
		$this->contains($cli, "'updateip' => ['trigger' => 'manual', 'scope' => 'ip', 'force' => 'download']", 'updateip must request manual/ip/download');
	}

	public function testUpdateDnsblStartsManualDnsblWithDownloadForce(): void
	{
		$cli = self::source(self::WWW . '/pfblockerng.php');
		$this->contains($cli, "'updatednsbl' => ['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'download']", 'updatednsbl must request manual/dnsbl/download');
	}

	public function testCronStartsCoreApply(): void
	{
		$cli = self::source(self::WWW . '/pfblockerng.php');
		$this->contains($cli, "'cron' => ['trigger' => 'apply']", 'cron must request apply');
		$this->excludes($cli, 'pfblockerng_sync_cron(', 'cron must not run the PHP cron feed pass');
	}

	public function testPfbTriggerPreservesManualScopeAndForce(): void
	{
		$cli = self::source(self::WWW . '/pfblockerng.php');
		$this->contains($cli, "'scope' => \$pfb_tscope", 'pfb_trigger must preserve scope');
		$this->contains($cli, "'force' => \$pfb_tforce ? 'download' : 'none'", 'pfb_trigger must preserve force');
		$this->contains($cli, "\$pfb_ttrigger === 'cron'", 'pfb_trigger cron must become apply');
	}

	public function testForcecheckPreservesScopeAndHashForce(): void
	{
		$cli = self::source(self::WWW . '/pfblockerng.php');
		$this->contains($cli, "'force' => \$pfb_fchashes ? 'both' : 'download'", 'forcecheck hashes flag must select download or both');
		$this->contains($cli, "'scope' => \$pfb_fcscope", 'forcecheck must preserve scope');
		$this->contains($cli, 'pfb_core_update_start(', 'forcecheck must use Core StartUpdate');
	}

	public function testCoreApplyRefusalLeavesSavePending(): void
	{
		$inc = self::source(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->contains($inc, "pfb_core_update_start('apply',", 'save apply must use Core');
		$this->contains($inc, 'pfb_mark_pending_changes()', 'Core refusal must preserve pending apply');
	}

	public function testGeneralSaveRunsConfigReconciliationThenRequestsApply(): void
	{
		$general = self::source(self::WWW . '/pfblockerng_general.php');
		$this->contains($general, "\$pfb['save'] = TRUE", 'General save must retain save mode');
		$this->contains($general, 'sync_package_pfblockerng()', 'General save must retain non-feed reconciliation');
		$this->contains($general, 'pfb_update_apply_after_save()', 'General save must ask Core to apply');
	}

	public function testTop1mChangeRequestsApplyAndKeepsPendingOnCoreRefusal(): void
	{
		$cli = self::source(self::WWW . '/pfblockerng.php');
		$this->contains($cli, "pfb_core_update_start('apply', \$core_call ?? 'pfb_core_call')", 'TOP1M change must request apply through Core');
		$this->contains($cli, 'pfb_mark_pending_changes()', 'TOP1M must retain apply when Core is unavailable or busy');
		$this->excludes($cli, 'pfb_trigger scope=dnsbl', 'TOP1M must not spawn the old bypass CLI');
	}

	public function testPackageResyncRetainsSaveReconciliationThenRequestsApply(): void
	{
		$package = self::source(__DIR__ . '/../../src/usr/local/pkg/pfblockerng.xml');
		$this->contains($package, "\$pfb['save'] = TRUE", 'package resync must retain save mode');
		$this->contains($package, 'sync_package_pfblockerng(', 'package resync must retain lifecycle and cron reconciliation');
		$this->contains($package, 'pfb_update_apply_after_save()', 'package resync must ask Core to apply');
	}

}
