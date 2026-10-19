<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- an apply that finds nothing to reload restarts nothing, so a DNS proxy whose supervisor died since
 * the last reload would stay down until the next reload or boot, with the Resolver on loopback and no DNS on
 * port 53. The apply therefore calls pfb_dns_proxy_ensure_running() after its reload decision, whichever branch ran:
 * in proxy mode it regenerates the rc script and starts a proxy that is not running, and restarts a live one whose
 * script changed (it bakes in the addresses the proxy listens on, so an interface that got a new address is only
 * served after a restart); a live proxy whose script is unchanged is left alone, and in every other state nothing
 * happens.
 *
 * issue #3513 -- the script also carries the DoH/DoQ settings, so a changed setting restarts a running proxy the
 * same way. After a reload the script is already current (pfb_reload_unbound() restarted the proxy itself), so the
 * call is then a no-op; after a zero-downtime swap, which restarts nothing, it is what applies a changed setting.
 *
 * A proxy-mode row is a Resolver whose saved snapshot exists (pfb_dns_proxy_saved() !== NULL); "running" is the
 * proxy's child pidfile naming a live process.
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
final class DnsProxyApplyStartTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_service_hook', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles',
		'pfb_test_valid_pids', 'pfb_test_rcfile_dir', 'pfb_test_interface_ip', 'pfb_test_interface_info',
		'pfb_test_configured_ipv6', 'pfb_test_configured_ip_addresses',
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
		$this->clearProxyFiles();
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
		$this->clearProxyFiles();
		$this->savedGlobals = [];
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->dir);
	}

	/** config.xml as a proxy-On apply leaves it: a valid Resolver snapshot of a Resolver that listened on $interfaces. */
	private function setProxyMode(string $lanAddress = '192.0.2.1', string $interfaces = 'lan'): void
	{
		$keys = [];
		foreach (['active_interface' => $interfaces, 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => $lanAddress];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
	}

	/**
	 * A proxy-mode box with two addressed interfaces, a package that ships pfb-dns and a running proxy.
	 *
	 * @return string the package's dns_proxy directory
	 */
	private function runningGatewayBox(): string
	{
		$gateway = "{$this->dir}/dns_proxy";
		mkdir("{$gateway}/bin/freebsd-amd64", 0777, TRUE);
		file_put_contents("{$gateway}/bin/freebsd-amd64/pfb-dns", "#!/bin/sh\n");
		chmod("{$gateway}/bin/freebsd-amd64/pfb-dns", 0555);
		$this->setProxyMode('192.0.2.1', 'lan,opt1');
		$up = ['status' => 'up', 'enable' => TRUE];
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => $up, 'opt1' => $up];
		$this->proxyServes();
		return $gateway;
	}

	/** @param array<string,string> $settings */
	private function configure(array $settings): void
	{
		foreach ($settings as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
	}

	public function testProxyModeWithTheProxyDownRegeneratesItsScriptThenStartsItOnce(): void
	{
		// Given proxy mode and a proxy that is not running
		$this->setProxyMode();
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen): void {
			$seen[] = [[$fn, $service], $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0];
			$this->proxyServes();
		};

		// When the apply finds nothing to reload
		$ready = pfb_dns_proxy_ensure_running();

		// Then the proxy is started exactly once, and not restarted, after its rc script was written, and it is ready
		$this->assertSame([[['start_service', 'pfb_dns_proxy'], 1]], $seen);
		$this->assertTrue($ready);
	}

	public function testProxyModeWithALiveProxyAndAnUnchangedScriptRestartsNothing(): void
	{
		// Given proxy mode, the script a start would run already on disk, and the proxy running
		$this->setProxyMode();
		pfb_dns_proxy_service();
		$this->proxyServes();

		// When the apply finds nothing to reload
		$ready = pfb_dns_proxy_ensure_running();

		// Then the proxy is neither started nor restarted
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
		$this->assertTrue($ready);
	}

	public function testProxyModeWithALiveProxyWhoseListenAddressesChangedRestartsItWithTheNewScript(): void
	{
		// Given a live proxy started from a script naming the LAN's old address ...
		$this->setProxyMode('192.0.2.1');
		pfb_dns_proxy_service();
		$this->proxyServes();
		$this->assertStringContainsString("'192.0.2.1'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the old address');
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen): void {
			$seen[] = [[$fn, $service], (string) file_get_contents(PFB_DNS_PROXY_RCFILE)];
			$this->proxyServes();
		};

		// When the LAN gets a new address and the apply runs
		$this->setProxyMode('192.0.2.77');
		pfb_dns_proxy_ensure_running();

		// Then the proxy is restarted once, and the script it restarts from names the new address only
		$this->assertCount(1, $seen, 'exactly one service call');
		$this->assertSame(['restart_service', 'pfb_dns_proxy'], $seen[0][0]);
		$this->assertStringContainsString("'192.0.2.77'", $seen[0][1]);
		$this->assertStringNotContainsString("'192.0.2.1'", $seen[0][1]);
	}

	public function testProxyModeWithALiveProxyWhoseDnsReplyLoggingPreferenceChangedRestartsItWithTheNewScript(): void
	{
		// Given DNSBL off with DNS Reply Logging off, and a live proxy started from that script (no --reply-log)
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_py_reply'] = PfbToggle::Off;
		$this->setProxyMode();
		pfb_dns_proxy_service();
		$this->proxyServes();
		$this->assertStringNotContainsString('--reply-log', (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: not logging');
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen): void {
			$seen[] = [[$fn, $service], (string) file_get_contents(PFB_DNS_PROXY_RCFILE)];
			$this->proxyServes();
		};

		// When the preference is switched on and the apply finds nothing to reload
		$GLOBALS['pfb']['dnsbl_py_reply'] = PfbToggle::On;
		pfb_dns_proxy_ensure_running();

		// Then the proxy restarts once, from a script that launches it with --reply-log (a running proxy reads its flags only at start)
		$this->assertCount(1, $seen, 'exactly one service call');
		$this->assertSame(['restart_service', 'pfb_dns_proxy'], $seen[0][0]);
		$this->assertStringContainsString(' --no-module --reply-log', $seen[0][1]);
	}

	/** @return array<string,array{array<string,string>,array<string,string>}> settings already saved, the setting that changes */
	public static function listenerSettingChanges(): array
	{
		$doh = ['pfb_dns_doh' => 'on'];
		$doq = ['pfb_dns_doq' => 'on'];
		return [
			'DoH turned on'  => [[], $doh],
			'DoH port'       => [$doh, ['pfb_dns_doh_port' => '8443']],
			'DoH interfaces' => [$doh, ['pfb_dns_doh_interface' => 'opt1']],
			'DoH trusted'    => [$doh, ['pfb_dns_doh_trusted' => '192.0.2.10']],
			'DoQ turned on'  => [[], $doq],
			'DoQ port'       => [$doq, ['pfb_dns_doq_port' => '8853']],
			'DoQ interfaces' => [$doq, ['pfb_dns_doq_interface' => 'opt1']],
		];
	}

	/**
	 * @param array<string,string> $saved
	 * @param array<string,string> $change
	 */
	#[DataProvider('listenerSettingChanges')]
	public function testAChangedDohOrDoqSettingRewritesTheScriptThenRestartsTheRunningProxy(array $saved, array $change): void
	{
		// Given a running proxy started from the script these settings generate
		$gateway = $this->runningGatewayBox();
		$this->configure($saved);
		pfb_dns_proxy_service($gateway);
		$script = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);
		pfb_dns_proxy_ensure_running($gateway);
		$writes = $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'];
		$this->assertSame([], $GLOBALS['pfb_test_service_calls'], 'before: unchanged settings leave the running proxy alone');

		// When one setting changes and the next apply runs
		$this->configure($change);
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use (&$seen): void {
			$seen[] = [[$fn, $service], $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0];
			$this->proxyServes();
		};
		pfb_dns_proxy_ensure_running($gateway);

		// Then the script was rewritten first and the running proxy was restarted: not started, not left on the old script
		$this->assertSame([[['restart_service', 'pfb_dns_proxy'], $writes + 1]], $seen);
		$this->assertNotSame($script, (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'the script on disk carries the change');
	}

	public function testAChangedSettingWithTheProxyDownOnlyStartsIt(): void
	{
		$gateway = $this->runningGatewayBox();
		pfb_dns_proxy_service($gateway);
		$this->clearProxyFiles();
		$GLOBALS['pfb_test_service_hook'] = function (): void {
			$this->proxyServes();
		};
		$this->configure(['pfb_dns_doh' => 'on']);

		pfb_dns_proxy_ensure_running($gateway);

		$this->assertSame([['start_service', 'pfb_dns_proxy']], $GLOBALS['pfb_test_service_calls']);
	}

	public function testASettingTheScriptIgnoresRestartsNothing(): void
	{
		// Given no gateway binary: the Python listener serves no DoH/DoQ, so those settings do not change the script
		$absent = "{$this->dir}/no_such_gateway";
		$this->runningGatewayBox();
		pfb_dns_proxy_service($absent);

		$this->configure(['pfb_dns_doh' => 'on', 'pfb_dns_doq' => 'on']);
		pfb_dns_proxy_ensure_running($absent);

		$this->assertSame([], $GLOBALS['pfb_test_service_calls'], 'an unchanged script is no reason to restart');
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
			"/\\n\\t\\t\\tpfb_dnsbl_cache\\('save'\\);\\n\\t\\t}\\n\\t}\\n(?:\\n?\\t\\/\\/[^\\n]*\\n)*\\tif \\(!pfb_dns_proxy_ensure_running\\(\\)\\) \\{\\n/",
			$source,
			'a statement of its own after the reload branch has closed, whose result is read: pfB-DNS runs with DNSBL off, where the mode is not enabled'
		);
		$this->assertDoesNotMatchRegularExpression(
			"/\\{\\s*if \\(!pfb_dns_proxy_ensure_running\\(\\)\\)/",
			$source,
			'not inside a branch of the DNSBL mode'
		);
	}

	/** @return array<string,array{?string}> the marker as stored: lost, or a value that is no snapshot */
	public static function orphanedMarkers(): array
	{
		return ['marker lost' => [NULL], 'marker not a snapshot' => ['!!!not-a-snapshot!!!']];
	}

	/**
	 * With our block and no snapshot the apply's check fails: nothing is started or restarted and no rc script is written with
	 * listen addresses that cannot be known, so no TRUE is reported for an activation that did not happen.
	 */
	#[DataProvider('orphanedMarkers')]
	public function testAnOrphanedResolverIsNeverStartedAndTheApplyCheckFails(?string $marker): void
	{
		// Given our block is in the Resolver and no snapshot says what it was moved from
		$GLOBALS['config']['unbound'] = [
			'active_interface' => 'lo0',
			'custom_options'   => base64_encode("server:\n# pfBlockerNG DNS proxy\nport: 5354\n# end pfBlockerNG DNS proxy"),
		];
		if ($marker !== NULL) {
			config_set_path(self::SAVED, $marker);
		}

		// When the apply checks the proxy
		$ready = pfb_dns_proxy_ensure_running();

		// Then the activation fails, and nothing is started, restarted or written
		$this->assertFalse($ready, 'nothing serves the Resolver: the activation failed');
		$this->assertSame([], $GLOBALS['pfb_test_service_calls'], 'no start, no restart');
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'no rc script with invented listen addresses');
	}
}
