<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- an apply that finds nothing to reload restarts nothing, so a DNS proxy whose supervisor died since
 * the last reload would stay down until the next reload or boot, with the Resolver on loopback 5353 and no DNS on
 * port 53. That branch of the apply calls pfb_dns_proxy_ensure_running(): in proxy mode with the proxy not running it
 * regenerates the rc script and starts the proxy; in every other state it does nothing. The reload branch does not
 * call it: pfb_reload_unbound() has just restarted the proxy itself.
 *
 * A proxy-mode row is a Resolver whose saved snapshot exists (pfb_dns_proxy_saved() !== NULL); "running" is the
 * proxy's child pidfile naming a live process.
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
final class DnsProxyApplyStartTest extends TestCase
{
	private const PROXY_PIDFILE = '/var/run/pfb_dns_proxy.pid';
	private const SAVED = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dns_proxy_saved';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_service_hook', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles',
		'pfb_test_valid_pids',
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
		rmdir_recursive($this->dir);
	}

	/** config.xml as a proxy-On apply leaves it: a valid Resolver snapshot. */
	private function setProxyMode(): void
	{
		$keys = [];
		foreach (['port' => '53', 'active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
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

	public function testProxyModeWithTheProxyRunningTouchesNothing(): void
	{
		$this->setProxyMode();
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = TRUE;

		pfb_dns_proxy_ensure_running();

		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
		$this->assertArrayNotHasKey('pfb_dns_proxy.sh', $GLOBALS['pfb_test_rcfile_writes'] ?? [], 'nor its rc script');
	}

	public function testWithoutProxyModeTheProxyIsNeverStartedEvenThoughItIsNotRunning(): void
	{
		// Given the toggle is off: no snapshot, and the proxy is of course not running (same state as the first test)
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertFalse(pfb_dns_proxy_running());

		pfb_dns_proxy_ensure_running();

		$this->assertSame([], $GLOBALS['pfb_test_service_calls'], 'toggle off: not one call about the proxy');
		$this->assertArrayNotHasKey('pfb_dns_proxy.sh', $GLOBALS['pfb_test_rcfile_writes'] ?? [], 'nor its rc script');
	}

	public function testTheApplyCallsItOnlyFromTheBranchThatDoesNotReload(): void
	{
		$source = (string) file_get_contents(self::APPLY);

		$this->assertSame(1, substr_count($source, 'pfb_dns_proxy_ensure_running('), 'one call site');
		$this->assertStringContainsString(
			"\t\t\tpfb_dnsbl_cache('save');\n\t\t}\n\t}\n\telseif (\$mode === 'enabled') {\n\t\tpfb_dns_proxy_ensure_running();\n\t}\n",
			$source,
			'it is the else of the reload predicate, after the reload branch (which restarted the proxy) has closed'
		);
	}
}
