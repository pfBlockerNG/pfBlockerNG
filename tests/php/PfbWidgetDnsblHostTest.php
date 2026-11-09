<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3770 -- the dashboard widget's DNSBL row says Active only while the module has a host, and the only host is the DNS proxy
 * while pfB-DNS owns the Resolver: an Unbound that runs and still names pfb_unbound.py in its unbound.conf is not one. Like
 * PfbWidgetOracleTest this eval-extracts the shipped icon-decision block (the page itself cannot be required off-appliance).
 */
final class PfbWidgetDnsblHostTest extends TestCase
{
	private const ICON_GREEN = 'fa-solid fa-check-circle text-success';
	private const ICON_RED = 'fa-solid fa-times-circle text-danger';
	private const PROXY_PIDFILE = '/var/run/pfb_dns_proxy.pid';

	private string $dir;
	private array $savedGlobals = [];

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_widget_oracle_status')) {
			return;
		}
		$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php');
		$start = $src === FALSE ? FALSE : strpos($src, "\tif (\$pfb['enable'] === PfbToggle::On) {");
		$end = $start === FALSE ? FALSE : strpos($src, "\t\$stats = array();", $start);
		if ($start === FALSE || $end === FALSE || $end <= $start) {
			throw new RuntimeException('test bootstrap: icon-status block not found in widget source');
		}
		eval(
			'function pfb_widget_oracle_status(array $pfb): array { ' . substr($src, $start, $end - $start)
			. ' return [$pfb_status, $pfb_msg, $dnsbl_status, $dnsbl_msg]; }'
		);
	}

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_process_running', 'pfb_test_valid_pids'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_widget_dnsbl_host_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [self::PROXY_PIDFILE => FALSE];
		// A legacy box: Unbound runs and its unbound.conf names pfb_unbound.py
		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
		file_put_contents("{$this->dir}/unbound.conf", "python:\n\tpython-script: pfb_unbound.py\n");
		$GLOBALS['pfb']['dnsbldir'] = $this->dir;
		$GLOBALS['pfb']['enable'] = $GLOBALS['pfb']['pfb_dns'] = $GLOBALS['pfb']['dnsbl'] = PfbToggle::On;
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

	/** @return array<string,mixed> */
	private function pfb(): array
	{
		return ['enable' => PfbToggle::On, 'pfb_dns' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'unbound_state' => PfbToggle::On, 'dbdir' => $this->dir, 'dnsbldir' => $this->dir,
			'dnsbl_vip_demand' => FALSE, 'config' => []];
	}

	/** config.xml as a pfB-DNS-On apply leaves it: a Resolver snapshot, and the proxy's pid file state. */
	private function pfbDnsOwnsTheResolver(bool $proxyUp): void
	{
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = $proxyUp;
	}

	public function testARunningUnboundWiredToThePythonModuleIsNotAnActiveDnsblWhenPfbDnsDoesNotOwnTheResolver(): void
	{
		[, , $status, $msg] = pfb_widget_oracle_status($this->pfb());

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('DNSBL is Disabled.', $msg);
	}

	public function testAProxyThatOwnsTheResolverButIsDownIsNotAnActiveDnsblEvenWithAWiredUnbound(): void
	{
		$this->pfbDnsOwnsTheResolver(FALSE);

		[, , $status] = pfb_widget_oracle_status($this->pfb());

		$this->assertSame(self::ICON_RED, $status);
	}

	public function testARunningProxyThatOwnsTheResolverIsAnActiveDnsblWhateverUnbound(): void
	{
		// Given the proxy hosting the module, an Unbound that is down and a conf without it
		$this->pfbDnsOwnsTheResolver(TRUE);
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;
		file_put_contents("{$this->dir}/unbound.conf", "# no python module\n");

		[, , $status, $msg] = pfb_widget_oracle_status($this->pfb());

		$this->assertSame(self::ICON_GREEN, $status);
		$this->assertSame('DNSBL is Active.', $msg);
	}
}
