<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the pfB-DNS tab's status panel: whether the proxy runs, which mode the box is in, where it
 * listens and whether it serves DNS over TLS. Everything derives from the Resolver snapshot (the box is moved
 * or it is not), the toggle (what the admin asked for) and DNSBL (whether the proxy makes DNSBL decisions);
 * a toggle that is on while nothing is moved is said to be unapplied, never to run.
 */
#[CoversFunction('pfb_dns_status')]
final class PfbDnsStatusTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const PROXY_PIDFILE = '/var/run/pfb_dns_proxy.pid';

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_valid_pids'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$GLOBALS['pfb'] = ['enable' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'pfb_dns' => PfbToggle::Off];
		$GLOBALS['config'] = [];
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
	}

	/** The Resolver as pfB-DNS leaves it: the saved one listened on `lan` (192.0.2.1), with or without DoT. */
	private function moved(bool $dot, bool $up = TRUE): void
	{
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => $dot, 'value' => $dot ? '' : NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = $up;
	}

	public function testAnOffToggleWithNothingMovedIsNotInUse(): void
	{
		$this->assertSame([
			'service' => 'Not in use',
			'mode'    => 'Off: the DNS Resolver serves clients itself',
			'listen'  => '-',
			'dot'     => '-',
		], pfb_dns_status());
	}

	public function testAnOnToggleWithNothingMovedIsSaidToBeUnappliedNotRunning(): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;

		$status = pfb_dns_status();

		$this->assertSame('Not in use', $status['service']);
		$this->assertSame('On, not applied yet: run an Update, and check the notices if this stays', $status['mode']);
		$this->assertSame('-', $status['listen']);
	}

	public function testAMovedBoxWithDnsblOnNamesTheAddressesTheTlsPortAndTheRunningService(): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$this->moved(TRUE);
		config_set_path('unbound/tlsport', '8853');

		$this->assertSame([
			'service' => 'Running',
			'mode'    => 'On, with DNSBL: the proxy answers DNSBL blocks and forwards everything else',
			'listen'  => '192.0.2.1:53, 127.0.0.1:53, [::1]:53',
			'dot'     => 'On, port 8853',
		], pfb_dns_status());
	}

	public function testAMovedBoxWithDnsblOffAndAStoppedProxyOnAnotherPort(): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$this->moved(FALSE, FALSE);
		config_set_path('unbound/port', '5300');

		$this->assertSame([
			'service' => 'Stopped',
			'mode'    => 'On, without DNSBL: the proxy forwards every query',
			'listen'  => '192.0.2.1:5300, 127.0.0.1:5300, [::1]:5300',
			'dot'     => 'Off',
		], pfb_dns_status());
	}

	public function testAMovedBoxWhoseToggleIsOffIsSaidToBeTurningOff(): void
	{
		$this->moved(FALSE);

		$this->assertSame('Turning off: the Resolver restore is pending, see the notices', pfb_dns_status()['mode']);
	}

	public function testPfBlockerNgDisabledCountsAsNoDnsbl(): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->moved(FALSE);

		$this->assertSame('On, without DNSBL: the proxy forwards every query', pfb_dns_status()['mode']);
	}
}
