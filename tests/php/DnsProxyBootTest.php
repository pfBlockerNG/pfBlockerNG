<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- pfB-DNS must be answering before the rest of boot needs DNS.
 *
 * pfSense starts Unbound inside rc.bootup (services_unbound_configure()), long before rc.start_packages runs the
 * package's own services; with pfB-DNS on, Unbound has left the client-facing port, so nothing answers there until the
 * proxy does. services_unbound_configure() require_once's /var/unbound/<python_script>_include.inc right after it
 * stopped Unbound, whenever Unbound has a python script, so pfB-DNS keeps Unbound's python keys naming the observer and
 * ships pfb_upstream_observer_include.inc to start the proxy from there. On a RAM-disk /var the include must also be
 * staged back at boot by the DNSBL cache's earlyshellcmd, which therefore follows pfB-DNS as well as DNSBL.
 */
final class DnsProxyBootTest extends TestCase
{
	private const HOOK = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/dns_proxy/pfb_upstream_observer_include.inc';
	private const EARLY = '/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache restore';

	private string $dir = '';
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_write_config_calls'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_proxy_boot_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir'       => $this->dir,
			'log'          => "{$this->dir}/pfb.log",
			'errlog'       => "{$this->dir}/pfb.err",
			'dnsblarchive' => "{$this->dir}/pfb_dnsbl_cache.tar",
			'enable'       => PfbToggle::On,
			'dnsbl'        => PfbToggle::Off,
			'pfb_dns'      => PfbToggle::Off,
			'unbound_state' => PfbToggle::On,
		]);
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

	/**
	 * Run the hook as services_unbound_configure() does -- require_once inside a function, in a process where nothing
	 * of pfBlockerNG is loaded (the non-verbose boot path) and only these two core functions exist.
	 *
	 * @param list<string> $livePidfiles pidfiles isvalidpid() answers TRUE for
	 * @return array{calls: list<string>, leaked: list<string>}
	 */
	private function runHook(array $livePidfiles, ?int $rcMode): array
	{
		$rc = "{$this->dir}/pfb_dns_proxy.sh";
		if ($rcMode !== NULL) {
			file_put_contents($rc, "#!/bin/sh\n");
			chmod($rc, $rcMode);
		}
		$driver = <<<'PHP'
			<?php
			$calls = [];
			function isvalidpid($pidfile) { return in_array($pidfile, json_decode((string) getenv('LIVE'), TRUE), TRUE); }
			function mwexec_bg($command, $clearsigmask = false) { global $calls; $calls[] = $command; }
			define('PFB_DNS_PROXY_RCFILE', (string) getenv('RC'));
			$leaked = (function () {
				$before = array_keys(get_defined_vars());
				require_once getenv('HOOK');
				return array_values(array_diff(array_keys(get_defined_vars()), $before, ['before']));
			})();
			echo json_encode(['calls' => $calls, 'leaked' => $leaked]);
			PHP;
		$run = pfb_test_run_process(
			[PHP_BINARY, '-d', 'display_errors=stderr', '-r', substr($driver, strlen("<?php\n"))],
			10.0,
			['LIVE' => json_encode($livePidfiles), 'RC' => $rc, 'HOOK' => self::HOOK]
		);
		$out = $run['stdout'];
		$err = $run['stderr'];
		$status = $run['exit'];
		$this->assertSame(0, $status, "the hook must run with core functions only: {$err}{$out}");
		$this->assertSame('', $err, 'no warning or notice');
		$result = json_decode($out, TRUE);
		$this->assertIsArray($result, "driver output: {$out}");
		return $result;
	}

	public function testTheHookExists(): void
	{
		$this->assertFileExists(self::HOOK, 'pfSense looks for /var/unbound/pfb_upstream_observer_include.inc, the staged copy of this');
	}

	public function testItStartsTheProxyInTheBackgroundWhenNothingServes(): void
	{
		$result = $this->runHook([], 0755);

		$this->assertSame(["{$this->dir}/pfb_dns_proxy.sh start"], $result['calls'], 'one backgrounded start, never a blocking one');
		$this->assertSame([], $result['leaked'], 'it is included inside pfSense\'s function: no variable of its own may survive');
	}

	/** @return array<string,array{list<string>}> */
	public static function servingRows(): array
	{
		return [
			'the proxy process is alive'      => [[PFB_DNS_PROXY_PIDFILE]],
			'only its supervisor is alive (between two restarts)' => [[PFB_DNS_PROXY_DAEMON_PIDFILE]],
		];
	}

	/** @param list<string> $live */
	#[DataProvider('servingRows')]
	public function testItStartsNothingWhileTheProxyIsServing(array $live): void
	{
		$this->assertSame([], $this->runHook($live, 0755)['calls'], 'a Resolver restart from the GUI must not bounce the proxy');
	}

	public function testItStartsNothingWithoutAnExecutableRcScript(): void
	{
		$this->assertSame([], $this->runHook([], NULL)['calls'], 'no rc script: pfB-DNS was never set up, or is gone');
		$this->assertSame([], $this->runHook([], 0644)['calls'], 'not executable');
	}

	public function testItUsesTheSamePidfilesAsThePackage(): void
	{
		// The hook names no constant of the package (they are not loaded at boot), so its literals are pinned here
		$source = (string) file_get_contents(self::HOOK);
		$this->assertStringContainsString("'" . PFB_DNS_PROXY_PIDFILE . "'", $source);
		$this->assertStringContainsString("'" . PFB_DNS_PROXY_DAEMON_PIDFILE . "'", $source);
		$this->assertStringContainsString("'/usr/local/etc/rc.d/pfb_dns_proxy.sh'", $source, 'the appliance default of PFB_DNS_PROXY_RCFILE');
	}

	// -----------------------------------------------------------------------
	// The RAM-disk /var restore follows pfB-DNS as well as DNSBL
	// -----------------------------------------------------------------------

	private function earlyshellcmds(): array
	{
		return array_values((array) config_get_path('system/earlyshellcmd', []));
	}

	/** @return array<string,array{bool,bool,bool,bool}> pfB-DNS on, DNSBL on, RAM-disk /var, registered */
	public static function conditionRows(): array
	{
		return [
			'pfB-DNS only, RAM-disk /var'   => [TRUE, FALSE, TRUE, TRUE],
			'DNSBL only, RAM-disk /var'     => [FALSE, TRUE, TRUE, TRUE],
			'both off, RAM-disk /var'       => [FALSE, FALSE, TRUE, FALSE],
			'pfB-DNS only, disk /var'       => [TRUE, FALSE, FALSE, FALSE],
		];
	}

	#[DataProvider('conditionRows')]
	public function testTheRestoreIsRegisteredWhilePfbDnsOrDnsblIsOnAndVarIsARamDisk(bool $pfbDns, bool $dnsbl, bool $ram, bool $registered): void
	{
		$GLOBALS['pfb']['pfb_dns'] = $pfbDns ? PfbToggle::On : PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl'] = $dnsbl ? PfbToggle::On : PfbToggle::Off;
		if ($ram) {
			config_set_path('system/use_mfs_tmpvar', '');
		}
		// An earlier registration (DNSBL was on before) that the conf pass must drop when nothing needs it
		config_set_path('system/earlyshellcmd', ['/usr/local/bin/other', self::EARLY]);

		pfb_dnsbl_cache('conf');

		$this->assertSame($registered, in_array(self::EARLY, $this->earlyshellcmds(), TRUE));
		$this->assertContains('/usr/local/bin/other', $this->earlyshellcmds(), 'the admin\'s own commands are never touched');
	}

	public function testTheRestoreIsNotRegisteredForPfbDnsWhenTheResolverOrPfBlockerNgIsOff(): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$GLOBALS['pfb']['unbound_state'] = PfbToggle::Off;
		config_set_path('system/use_mfs_tmpvar', '');
		config_set_path('system/earlyshellcmd', ['/usr/local/bin/other']);

		pfb_dnsbl_cache('conf');

		$this->assertNotContains(self::EARLY, $this->earlyshellcmds(), 'pfB-DNS is not wanted with the Resolver disabled');
	}
}
