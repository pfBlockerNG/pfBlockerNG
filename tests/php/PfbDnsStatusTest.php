<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the pfB-DNS tab's status panel: whether the proxy is running, starting or stopped, which mode the box is in, where it
 * listens and whether it serves DNS over TLS. Everything derives from the Resolver snapshot (the box is moved
 * or it is not), the toggle (what the admin asked for) and DNSBL (whether the proxy makes DNSBL decisions);
 * a toggle that is on while nothing is moved is said not to be active, with the reason (pfBlockerNG or the Resolver
 * disabled, or the Resolver not moved), never to run.
 */
#[CoversFunction('pfb_dns_status')]
final class PfbDnsStatusTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private string $dir;

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_valid_pids'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_status_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = [
			'enable' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'pfb_dns' => PfbToggle::Off,
			'dns_proxy_pidfile' => "{$this->dir}/pfb_dns_proxy.pid", 'dns_proxy_ready' => "{$this->dir}/pfb_dns_ready",
		];
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
		rmdir_recursive($this->dir);
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
		$this->seedProxy('4242', "4242\n", $up);
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

	/** @return array<string,array{PfbToggle,PfbToggle,string}> pfBlockerNG, Resolver and the status the toggle-on-but-nothing-moved box shows */
	public static function notActiveReasons(): array
	{
		return [
			'pfBlockerNG disabled' => [PfbToggle::Off, PfbToggle::On, 'On, but not active: pfBlockerNG is disabled'],
			'the Resolver disabled' => [PfbToggle::On, PfbToggle::Off, 'On, but not active: the DNS Resolver is disabled'],
			'the Resolver not moved yet, or the move refused' => [PfbToggle::On, PfbToggle::On,
				'On, not active: the DNS Resolver has not been moved to the proxy (run an Update; if this stays, see the notices). '
				. 'It serves clients itself, with DNSBL if that is on'],
		];
	}

	#[DataProvider('notActiveReasons')]
	public function testAnOnToggleWithNothingMovedIsSaidNotToBeActiveAndWhy(PfbToggle $enable, PfbToggle $resolver, string $mode): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$GLOBALS['pfb']['enable'] = $enable;
		$GLOBALS['pfb']['unbound_state'] = $resolver;

		$status = pfb_dns_status();

		$this->assertSame('Not in use', $status['service']);
		$this->assertSame($mode, $status['mode']);
		$this->assertSame('-', $status['listen']);
	}

	public function testAMovedBoxWithThePackageDisabledSaysTheRestoreIsPendingNotThatTheProxyIsOn(): void
	{
		// Given a moved Resolver, pfB-DNS still on in config.xml, and pfBlockerNG disabled: no apply runs the proxy's mode
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->moved(TRUE);

		// When the status is read
		$mode = pfb_dns_status()['mode'];

		// Then it does not claim the proxy is on: the Resolver restore is pending and the notices say what to do
		$this->assertSame('Off: pfBlockerNG is disabled, and the DNS Resolver restore is pending: see the notices', $mode);
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

	/** @return array<string,array{?string}> the marker a live proxy child has not published: none yet, or one an earlier proxy left */
	public static function unpublishedMarkers(): array
	{
		return [
			'no marker yet' => [NULL],
			'a marker naming another process' => ["4343\n"],
		];
	}

	#[DataProvider('unpublishedMarkers')]
	public function testALiveProxyThatIsNotReadyIsStartingNotRunning(?string $marker): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$this->moved(TRUE);
		$this->seedProxy('4242', $marker);

		$this->assertSame('Starting', pfb_dns_status()['service']);
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

		$this->assertSame('Off: pfBlockerNG is disabled, and the DNS Resolver restore is pending: see the notices', pfb_dns_status()['mode']);
	}

	/** @return array<string,array{PfbToggle,bool,string}> the pfB-DNS toggle, whether the proxy serves, the service the status shows */
	public static function orphanedStatuses(): array
	{
		return [
			'toggle on, proxy serving'  => [PfbToggle::On, TRUE, 'Running'],
			'toggle off, proxy serving' => [PfbToggle::Off, TRUE, 'Running'],
			'toggle on, proxy down'     => [PfbToggle::On, FALSE, 'Stopped'],
		];
	}

	/**
	 * Our block with no snapshot is a Resolver that cannot be put back: the status says so whatever the toggle, and the service
	 * is what the proxy really does (a serving proxy is not "Not in use").
	 */
	#[DataProvider('orphanedStatuses')]
	public function testAnOrphanedResolverIsRecoveryRequiredAndTheServiceIsWhatTheProxyDoes(PfbToggle $toggle, bool $serving, string $service): void
	{
		// Given our block is in the Resolver and its snapshot is gone
		$GLOBALS['config']['unbound'] = [
			'active_interface' => 'lo0',
			'custom_options'   => base64_encode("server:\n# pfBlockerNG DNS proxy\nport: 5354\n# end pfBlockerNG DNS proxy"),
		];
		config_set_path(self::SAVED, '');
		$GLOBALS['pfb']['pfb_dns'] = $toggle;
		$this->seedProxy('4242', "4242\n", $serving);

		// When the status is read
		$status = pfb_dns_status();

		// Then it says recovery is required, not that the Resolver is unchanged or not moved, and claims no listen address
		$this->assertSame($service, $status['service']);
		$this->assertStringStartsWith('Recovery required', $status['mode']);
		foreach (['not been moved', 'serves clients itself', 'unchanged', 'Off:'] as $wrong) {
			$this->assertStringNotContainsString($wrong, $status['mode']);
		}
		$this->assertSame(['-', '-'], [$status['listen'], $status['dot']]);
	}

	/** @return array<string,array{string}> a stored marker that is no snapshot, on a Resolver that carries no block of ours */
	public static function unconfirmedMarkers(): array
	{
		return [
			'the single character 0'           => ['0'],
			'the text of an interrupted write' => ['!!!truncated-snapshot!!!'],
			'base64 of text that is not JSON'  => [base64_encode('not json')],
		];
	}

	#[DataProvider('unconfirmedMarkers')]
	public function testAMarkerThatIsNoSnapshotIsRecoveryRequiredAndSaysItCannotBeConfirmed(string $marker): void
	{
		// Given a stored marker that is no snapshot and no block of ours in a Resolver on loopback
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode("do-ip6: no")];
		config_set_path(self::SAVED, $marker);
		// (reading a marker that is no snapshot logs it once: the log paths are this test's)
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], ['logdir' => $this->dir, 'log' => "{$this->dir}/pfb.log", 'errlog' => "{$this->dir}/pfb.err"]);
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$this->seedProxy('4242', "4242\n", FALSE);

		// When the status is read
		$status = pfb_dns_status();

		// Then it asks for a manual repair and says the saved state cannot be confirmed; it never says the Resolver is moved,
		// unchanged or not moved yet, and claims no listen address
		$this->assertStringStartsWith('Recovery required', $status['mode']);
		$this->assertStringContainsString('cannot be confirmed', $status['mode']);
		$this->assertStringContainsString('manual repair', $status['mode']);
		foreach (['still carries', 'not been moved', 'serves clients itself', 'unchanged', 'Off:'] as $wrong) {
			$this->assertStringNotContainsString($wrong, $status['mode']);
		}
		$this->assertSame(['-', '-'], [$status['listen'], $status['dot']]);
	}

	public function testALoopbackOnlyResolverWithAnEmptyMarkerIsNotRecoveryRequired(): void
	{
		// Given the same Resolver and an empty marker, with the toggle on
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode("do-ip6: no")];
		config_set_path(self::SAVED, '');
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$GLOBALS['pfb']['unbound_state'] = PfbToggle::On;

		// Then the status is the ordinary "not moved yet" one
		$this->assertStringNotContainsString('Recovery required', pfb_dns_status()['mode']);
	}
}
