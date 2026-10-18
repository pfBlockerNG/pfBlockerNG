<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- an apply that finds nothing to reload restarts nothing, so a DNS proxy whose supervisor died since
 * the last reload would stay down until the next reload or boot, with the Resolver on loopback and no DNS on
 * port 53. That branch of the apply calls pfb_dns_proxy_ensure_running(): in proxy mode it regenerates the rc
 * script and starts a proxy that is not running, and restarts a live one whose script changed (it bakes in the
 * addresses the proxy listens on, so an interface that got a new address is only served after a restart); a live
 * proxy whose script is unchanged is left alone, and in every other state nothing happens. The reload branch does
 * not call it: pfb_reload_unbound() has just restarted the proxy itself.
 *
 * A proxy-mode row is a Resolver whose saved snapshot exists (pfb_dns_proxy_saved() !== NULL); "running" is the
 * proxy's child pidfile naming a live process.
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
final class DnsProxyApplyStartTest extends TestCase
{
	private const PROXY_PIDFILE = '/var/run/pfb_dns_proxy.pid';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_service_hook', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles',
		'pfb_test_valid_pids', 'pfb_test_rcfile_dir', 'pfb_test_interface_ip', 'pfb_test_interface_info',
	];

	private string $dir;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_proxy_apply_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->dir,
			'log'    => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->dir);
	}

	/** config.xml as a proxy-On apply leaves it: a valid Resolver snapshot of a Resolver that listened on lan. */
	private function setProxyMode(string $lanAddress = '192.0.2.1'): void
	{
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => $lanAddress];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
	}

	public function testProxyModeWithTheProxyDownRegeneratesItsScriptThenStartsItOnce(): void
	{
		// Given proxy mode and a proxy that is not running
		$this->setProxyMode();
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn, string $service) use (&$seen): void {
			$seen[] = [[$fn, $service], $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0];
		};

		// When the apply finds nothing to reload
		pfb_dns_proxy_ensure_running();

		// Then the proxy is started exactly once, and not restarted, after its rc script was written
		$this->assertSame([[['start_service', 'pfb_dns_proxy'], 1]], $seen);
	}

	public function testProxyModeWithALiveProxyAndAnUnchangedScriptRestartsNothing(): void
	{
		// Given proxy mode, the script a start would run already on disk, and the proxy running
		$this->setProxyMode();
		pfb_dns_proxy_service();
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = TRUE;

		// When the apply finds nothing to reload
		pfb_dns_proxy_ensure_running();

		// Then the proxy is neither started nor restarted
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
	}

	public function testProxyModeWithALiveProxyWhoseListenAddressesChangedRestartsItWithTheNewScript(): void
	{
		// Given a live proxy started from a script naming the LAN's old address ...
		$this->setProxyMode('192.0.2.1');
		pfb_dns_proxy_service();
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = TRUE;
		$this->assertStringContainsString("'192.0.2.1'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the old address');
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn, string $service) use (&$seen): void {
			$seen[] = [[$fn, $service], (string) file_get_contents(PFB_DNS_PROXY_RCFILE)];
		};

		// When the LAN gets a new address and the apply finds nothing to reload
		$this->setProxyMode('192.0.2.77');
		pfb_dns_proxy_ensure_running();

		// Then the proxy is restarted once, and the script it restarts from names the new address only
		$this->assertCount(1, $seen, 'exactly one service call');
		$this->assertSame(['restart_service', 'pfb_dns_proxy'], $seen[0][0]);
		$this->assertStringContainsString("'192.0.2.77'", $seen[0][1]);
		$this->assertStringNotContainsString("'192.0.2.1'", $seen[0][1]);
	}

	public function testWithoutProxyModeTheProxyIsNeverStartedEvenThoughItIsNotRunning(): void
	{
		// Given the toggle is off: no snapshot, and the proxy is of course not running (same state as the first test)
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertFalse(pfb_dns_proxy_running());

		pfb_dns_proxy_ensure_running();

		$this->assertSame([], $GLOBALS['pfb_test_service_calls'], 'toggle off: not one call about the proxy');
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'nor its rc script');
	}

	public function testTheApplyCallsItAfterTheReloadBranchWhateverTheDnsblMode(): void
	{
		$source = (string) file_get_contents(self::APPLY);

		$this->assertSame(1, substr_count($source, 'pfb_dns_proxy_ensure_running('), 'one call site');
		$this->assertMatchesRegularExpression(
			"/\\n\\t\\t\\tpfb_dnsbl_cache\\('save'\\);\\n\\t\\t}\\n\\t}\\n(?:\\n?\\t\\/\\/[^\\n]*\\n)*\\tpfb_dns_proxy_ensure_running\\(\\);\\n/",
			$source,
			'a statement of its own after the reload branch has closed: pfB-DNS runs with DNSBL off, where the mode is not enabled'
		);
		$this->assertDoesNotMatchRegularExpression(
			"/\\{\\s*pfb_dns_proxy_ensure_running\\(\\);\\s*\\}/",
			$source,
			'not inside a branch of the DNSBL mode'
		);
	}
}
