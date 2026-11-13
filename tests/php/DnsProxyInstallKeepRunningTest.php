<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * issue #3566 -- the installer's DNS proxy block, which runs inside the package's install command, leaves a serving pfB-DNS
 * running. pfSense unlinks the proxy's rc script before the install command, so the stop that left the proxy running copied the
 * script to $pfb['dns_proxy_rc_kept'] (the rc script's own work, pinned by DnsProxyUpgradeStopTest); the installer writes the new
 * rc script and compares its text with that copy:
 *   - the same text: nothing to apply, no restart and nothing pending;
 *   - another text, or no copy to compare with: no restart either, the proxy runs the old flags until the next update restarts
 *     it once (one pending-restart marker);
 *   - the copy is removed in every case;
 *   - a proxy that does not serve is restarted as before, and with pfB-DNS off the service is written and stopped as before.
 *
 * The block is cut out of the shipped installer between its anchors and run as shipped (the same seam as
 * DnsProxyMovedResolverFixtureTrait::runInstallProxyBlock()).
 */
#[CoversNothing]
final class DnsProxyInstallKeepRunningTest extends TestCase
{
	use KeepRunningScenario;

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::krGlobals() as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_keep_running_install_' . getmypid() . '_' . bin2hex(random_bytes(4)));
	}

	protected function tearDown(): void
	{
		$this->clearProxyFiles();
		@unlink(PFB_DNS_PROXY_RCFILE);
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->krDir);
	}

	/** The installer's DNS proxy block, cut out of the shipped file between its anchors and run as shipped, its gateway binaries in the sandbox. */
	private function runInstallProxyBlock(): void
	{
		$install = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$from = strpos($install, '// Create DNS proxy service once its runtime files are staged');
		$to = strpos($install, 'if ($ufound) {', (int) $from);
		$this->assertIsInt($from, 'test bootstrap: the installer\'s proxy block lost its start anchor');
		$this->assertIsInt($to, 'test bootstrap: the installer\'s proxy block lost its end anchor');
		(static function (string $code): void {
			global $pfb;
			eval($code);
		})(str_replace('PFB_DNS_PROXY_DIR', var_export($this->krProxyDir, TRUE), substr($install, $from, $to - $from)));
	}

	/**
	 * What pfSense leaves when the old package's stop kept the proxy running: the rc script copied to the kept path and unlinked
	 * from rc.d. $keptText NULL = no copy (the old package predates the probe); '' = a copy of what the installer will write.
	 * The installer keeps on the gateway's readiness alone, so the Unbound backend stays dead here (serving FALSE) unless a row asks for it.
	 */
	private function upgradeLeavesTheProxyServing(?string $keptText, array $scenario = []): void
	{
		$this->krApply($scenario + ['serving' => FALSE]);
		$kept = $GLOBALS['pfb']['dns_proxy_rc_kept'];
		if ($keptText !== NULL) {
			pfb_dns_proxy_service();
			file_put_contents($kept, $keptText === '' ? (string) file_get_contents(PFB_DNS_PROXY_RCFILE) : $keptText);
		}
		@unlink(PFB_DNS_PROXY_RCFILE);
		$this->krCalls = [];
	}

	public function testTheBootstrapKeepsTheRcCopyInTheSameSandboxAsTheProxyPidfile(): void
	{
		$bootstrap = $this->savedGlobals['pfb'][1];
		$this->assertSame(dirname($bootstrap['dns_proxy_pidfile']) . '/pfb_dns_proxy_rc.kept',
		    $bootstrap['dns_proxy_rc_kept'], 'the installer must never unlink a real host kept-copy path');
	}

	public function testAKeptCopyEqualToTheNewRcScriptMeansNoRestartAndNothingPending(): void
	{
		// Given a serving proxy and a kept copy of the rc script the new package writes
		$this->upgradeLeavesTheProxyServing('');
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_rc_kept'], 'before: the old stop left its copy');
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'before: pfSense unlinked the rc script');

		// When the installer's proxy block runs
		$this->runInstallProxyBlock();

		// Then the rc script is back, the proxy was not restarted, nothing is pending and the copy is gone
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertNull($this->krMarker());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_rc_kept']);
		$this->assertTrue(pfb_dns_proxy_ready(), 'the proxy still serves');
	}

	public function testAKeptCopyThatDiffersFromTheNewRcScriptDefersTheRestart(): void
	{
		// Given a kept copy of an older rc script
		$this->upgradeLeavesTheProxyServing("#!/bin/sh\n# the rc script the old package wrote\n");
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_rc_kept'], 'before: the old stop left its copy');

		// When the installer's proxy block runs
		$this->runInstallProxyBlock();

		// Then the new rc script is written, nothing restarted, a pending restart says why, and the copy is gone
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertIsString($this->krMarker());
		$this->assertStringContainsString('rc script', (string) $this->krMarker());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_rc_kept']);
	}

	public function testNoKeptCopyCountsAsADifferentRcScriptAndDefersTheRestart(): void
	{
		// Given an old package that did not leave a copy
		$this->upgradeLeavesTheProxyServing(NULL);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_rc_kept'], 'before: there is no copy');

		// When the installer's proxy block runs
		$this->runInstallProxyBlock();

		// Then nothing restarted and a restart is pending
		$this->assertSame([], $this->krProxyCalls());
		$this->assertIsString($this->krMarker());
	}

	public function testAProxyThatDoesNotServeIsRestartedAsBefore(): void
	{
		// Given a proxy that is down after the upgrade, and a stale copy of the rc script
		$this->upgradeLeavesTheProxyServing('', ['proxy' => 'dead']);
		$this->assertFalse(pfb_dns_proxy_ready(), 'before: the proxy does not serve');

		// When the installer's proxy block runs
		$this->runInstallProxyBlock();

		// Then it is restarted, nothing is pending and the copy is gone too
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertNull($this->krMarker());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_rc_kept']);
	}

	public function testWithPfbDnsOffTheServiceIsWrittenAndStoppedAsBefore(): void
	{
		// Given no snapshot (pfB-DNS off) and a copy an earlier upgrade left
		$this->upgradeLeavesTheProxyServing('', ['snapshot' => FALSE, 'proxy' => 'dead']);

		// When the installer's proxy block runs
		$this->runInstallProxyBlock();

		// Then the service is written and stopped, nothing is pending, and the copy is gone
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE);
		$this->assertSame(['stop_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertNull($this->krMarker());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_rc_kept']);
	}

	/** The pending-changes marker in the sandbox, as the tick reads it: the one a settings save sets. */
	private function noPendingChanges(): void
	{
		$GLOBALS['pfb']['pending_marker'] = "{$this->krDir}/pfb_pending_changes";
		$this->assertFalse(pfb_pending_changes(), 'before: no changes are pending');
	}

	public function testAnUpgradeThatLeavesThePreviousGatewayRunningMarksThePendingChanges(): void
	{
		// Given a serving gateway that runs another binary than the one the package installed, and the same rc script (issue #3855)
		$this->upgradeLeavesTheProxyServing('', ['gateway' => 'different']);
		$this->noPendingChanges();
		$this->assertTrue(pfb_dns_proxy_gateway_changed($this->krProxyDir), 'before: the running gateway is not the installed binary');

		// When the installer's proxy block runs
		$this->runInstallProxyBlock();

		// Then the gateway keeps running and the changes are pending, as a settings save leaves them: the next schedule check applies them
		$this->assertSame([], $this->krProxyCalls());
		$this->assertTrue(pfb_pending_changes());
		$this->assertNull($this->krMarker(), 'the rc script did not change: no restart is recorded for it');
	}

	public function testAnRcScriptOnlyChangeMarksNoPendingChanges(): void
	{
		// Given a serving gateway that runs the installed binary, and an rc script the package changed
		$this->upgradeLeavesTheProxyServing("#!/bin/sh\n# the rc script the old package wrote\n");
		$this->noPendingChanges();

		// When the installer's proxy block runs
		$this->runInstallProxyBlock();

		// Then the restart waits for the next Update, as before, and no changes are pending
		$this->assertIsString($this->krMarker(), 'the restart is still recorded');
		$this->assertFalse(pfb_pending_changes());
	}

	public function testAnUpgradeThatChangesNothingMarksNoPendingChanges(): void
	{
		$this->upgradeLeavesTheProxyServing('');
		$this->noPendingChanges();

		$this->runInstallProxyBlock();

		$this->assertFalse(pfb_pending_changes());
	}

	public function testAGatewayThatDoesNotServeIsRestartedOntoTheInstalledBinaryAndMarksNoPendingChanges(): void
	{
		// Given a gateway that is down after the upgrade, whose last record names the previous binary
		$this->upgradeLeavesTheProxyServing('', ['proxy' => 'dead', 'gateway' => 'different']);
		$this->noPendingChanges();

		$this->runInstallProxyBlock();

		// Then the installer restarts it as before: nothing is left for the next schedule check
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertFalse(pfb_pending_changes());
	}

	public function testTheNextScheduleCheckAppliesThePendingChangesAndItsUpdateRestartsTheGatewayOntoTheInstalledBinary(): void
	{
		// Given the installer left the previous gateway running and the changes pending, the Unbound backend answering
		$this->upgradeLeavesTheProxyServing('', ['gateway' => 'different', 'serving' => TRUE]);
		$this->noPendingChanges();
		$this->runInstallProxyBlock();
		pfb_dns_proxy_service($this->krProxyDir);	// the installer's rc script, naming the sandbox's dns_proxy directory as the update pass does
		$this->assertTrue(pfb_pending_changes(), 'before: the installer marked the changes pending');

		// When the next schedule check runs, outside the package operation; the Update it asks Core for is the pass's own gateway check
		// (pfb_dns_proxy_ensure_running()) and its settle of the version it saw, as sync_package_pfblockerng() makes them
		$dispatched = 0;
		$ready = FALSE;
		$this->krTick([], function (string $method, array $params = []) use (&$dispatched, &$ready): array {
			if ($method === 'StartUpdate') {
				$dispatched++;
				$seen = pfb_pending_changes_token();
				$ready = $this->krEnsure();
				pfb_settle_pending_changes($seen);
				return ['status' => 200, 'body' => [], 'error' => NULL];
			}
			return ['status' => 200, 'body' => ['running' => FALSE], 'error' => NULL];
		});

		// Then the tick asked for the Update once, which restarted the gateway once, and nothing is pending any more
		$this->assertSame(1, $dispatched, 'the tick dispatches the pending apply');
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertStringContainsString('the package installed another gateway', $this->krLog());
		$this->assertTrue($ready, 'the restarted gateway is ready');
		$this->assertFalse(pfb_pending_changes());
	}
}
