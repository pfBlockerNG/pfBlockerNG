<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';
require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694 -- DoH on port 443 on the running gateway.
 *
 * An automatically created Resolver VIP serves DoH on 443 beside the configured DoH port: the rc script's command carries
 * `--doh-listen-443 'VIP'` for it, and pfb_dns_proxy_command_listeners() names that listener as `doh <VIP>:443`, so that the update pass
 * adds it live (a bind the box refuses is reported by the startup check) and removes it live, and a script that differs only in those
 * arguments is never a restart. The addresses DDR advertises on 443 are `--ddr-doh-443 'ADDR'` arguments, masked the same way and sent to the
 * running gateway with the name answers as one table (lines `ddr-doh-443 ADDR` and `dns-name-answer LOCAL=ADDR[,ADDR]`, in the command's
 * order).
 *
 * The VIP of these rows is 172.16.53.53, an address this box does not hold: its bind fails as EADDRNOTAVAIL, which the sync leaves for a later
 * pass with nothing sent or logged, as root and as any other user (so that no row needs the right to bind port 443).
 */
#[CoversFunction('pfb_dns_proxy_command_listeners')]
#[CoversFunction('pfb_dns_proxy_listeners_sync')]
#[CoversFunction('pfb_dns_proxy_command_name_answers')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
final class DnsProxyDoh443LiveTest extends TestCase
{
	use KeepRunningScenario;
	use LiveListenerStandIn;

	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	private const SHARED = 'installedpackages/pfblockerngdnssettings/config/0/';
	private const NAME = 'fw.example.lan';
	private const VIP = '172.16.53.53';
	private const VIP6 = 'fd00:53:53:53:53:53:53:1';
	private const TABLE = 'fffffffb';
	private const STARTUP = 'pfBlockerNG DNS Proxy startup';

	private array $savedGlobals = [];
	private int $port = 0;
	private int $dohPort = 0;
	private string $socket = '';

	protected function setUp(): void
	{
		foreach (self::krGlobals() as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_doh443_' . getmypid() . '_' . bin2hex(random_bytes(4)));
		[$this->port, $this->dohPort] = self::freePorts(2);
		$this->socket = "{$this->krDir}/ctl.sock";
	}

	protected function tearDown(): void
	{
		$this->standInsStop();
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

	/** The Resolver VIP the package created for one family. */
	private function autoVip(int $family = 4): void
	{
		$address = ($family === 6) ? self::VIP6 : self::VIP;
		$rows = array_values(array_filter((array) config_get_path('virtualip/vip', []), static fn (array $row): bool => ($row['uniqid'] ?? '') !== "auto{$family}"));
		$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address, 'subnet_bits' => ($family === 6) ? '128' : '32',
			'descr' => "pfB_DNS_LISTEN_VIP_v{$family}", 'uniqid' => "auto{$family}"];
		config_set_path('virtualip/vip', $rows);
		config_set_path(PFB_SECTIONS['gen'] . '/pfb_dns_listen_vip', 'on');
		config_set_path(PFB_SECTIONS['gen'] . "/pfb_dns_listen_vip{$family}", 'auto');
		config_set_path(PFB_SECTIONS['gen'] . "/pfb_dns_listen_auto{$family}", $address);
	}

	private function noVip(): void
	{
		config_set_path('virtualip/vip', []);
	}

	/** DoH on lan at its own free port, and these other settings; then a ready proxy whose script is written from all of it. */
	private function ready(array $settings = [], array $scenario = []): void
	{
		foreach ($settings + [
			self::SETTINGS . 'pfb_dns_interface' => 'lan', self::SHARED . 'pfb_dns_doh' => 'on', self::SHARED . 'pfb_dns_doh_port' => (string) $this->dohPort,
			self::SETTINGS . 'pfb_dns_doh_interface' => 'lan',
		] as $path => $value) {
			config_set_path($path, $value);
		}
		$this->krApply($scenario + ['port' => (string) $this->port]);
	}

	/** @return array<string,string> the settings that make the command carry the DNS Name, DDR and the 443 selection */
	private static function ddrOn(string $selection = ''): array
	{
		return [self::SETTINGS . 'pfb_dns_name' => self::NAME, self::SHARED . 'pfb_dns_ddr' => 'on', self::SETTINGS . 'pfb_dns_ddr_doh_443_interfaces' => $selection];
	}

	/**
	 * What a gateway serves that started with the command: plain DNS and DoH on lan and loopback, DoH also on each of $dohHosts at the DoH port
	 * and on 443 where $vips are given, as it lists them.
	 *
	 * @param list<string> $vips hosts as the gateway spells them (IPv6 bracketed)
	 * @return list<string> `<kind> <host:port>`
	 */
	private function served(array $vips = []): array
	{
		$served = [];
		foreach (['192.0.2.1', '127.0.0.1', '[::1]'] as $host) {
			$served[] = "udp+tcp {$host}:{$this->port}";
		}
		foreach (['192.0.2.1', ...$vips, '127.0.0.1', '[::1]'] as $host) {
			$served[] = "doh {$host}:{$this->dohPort}";
		}
		foreach ($vips as $host) {
			$served[] = "doh {$host}:443";
		}
		return $served;
	}

	private function gateway(array $listening, array $refused = []): string
	{
		return $this->standIn($this->socket, [], ['listening' => $listening, 'refused' => $refused]);
	}

	/** @return list<string> each frame that changes the gateway, as "<head> <body>" */
	private static function sent(string $record): array
	{
		return array_map(static fn (array $frame): string => "{$frame['head']} {$frame['body']}", self::changeFrames($record));
	}

	private function rc(): string
	{
		return (string) file_get_contents(PFB_DNS_PROXY_RCFILE);
	}

	// -----------------------------------------------------------------------
	// what the command asks the gateway to listen on
	// -----------------------------------------------------------------------

	public function testTheCommandNamesTheVipOnPort443AsADohListenerBesideItsConfiguredPort(): void
	{
		// Given DoH on lan, no VIP
		$this->ready();
		$before = pfb_dns_proxy_command_listeners()['doh'] ?? [];
		$this->assertSame(["192.0.2.1:{$this->dohPort}", "127.0.0.1:{$this->dohPort}", "[::1]:{$this->dohPort}"], $before, 'before: the configured port only');

		// When the package's VIP exists when the script is written (row D3)
		$this->autoVip();
		pfb_dns_proxy_service($this->krProxyDir);

		// Then the command carries the extra listener, and names it as a DoH listener of port 443 after the configured ones
		$this->assertStringContainsString(" --doh-listen-443 '" . self::VIP . "'", $this->rc());
		$this->assertSame(
			["192.0.2.1:{$this->dohPort}", self::VIP . ":{$this->dohPort}", "127.0.0.1:{$this->dohPort}", "[::1]:{$this->dohPort}", self::VIP . ':443'],
			pfb_dns_proxy_command_listeners()['doh'] ?? []
		);
	}

	public function testBothVipsAreNamedAndAnIpv6OneIsSpelledAsTheGatewayPrintsIt(): void
	{
		$this->autoVip(4);
		$this->autoVip(6);
		$this->ready();

		$doh = pfb_dns_proxy_command_listeners()['doh'] ?? [];

		$this->assertSame([self::VIP . ':443', '[' . self::VIP6 . ']:443'], array_slice($doh, -2));
		$this->assertCount(2, array_filter($doh, static fn (string $at): bool => str_ends_with($at, ':443')), 'no other 443 listener');
	}

	public function testAFamilyWhoseDohPortIs443AlreadyIsNamedOnceNotTwice(): void
	{
		// Given DoH on 443 for both families and the created VIP: DoH already listens on the VIP at 443 (row D7)
		$this->autoVip();
		$this->ready([self::SHARED . 'pfb_dns_doh_port' => '443']);

		$this->assertStringNotContainsString('--doh-listen-443', $this->rc());
		$doh = pfb_dns_proxy_command_listeners()['doh'] ?? [];
		$this->assertSame(array_values(array_unique($doh)), $doh, 'no listener twice');
		$this->assertContains(self::VIP . ':443', $doh);
	}

	// -----------------------------------------------------------------------
	// the update pass: a VIP that appears or goes is live
	// -----------------------------------------------------------------------

	public function testAVipThatAppearsIsReconciledLiveAndRestartsNothing(): void
	{
		// Given a ready proxy that started with no VIP, and the package's VIP created by the time the update pass runs (row D8)
		$this->ready();
		$record = $this->gateway($this->served());
		$this->assertStringNotContainsString('--doh-listen-443', $this->rc(), 'before: the running script has no VIP');
		$this->autoVip();

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then the script now names the VIP's two DoH listeners, and nothing was restarted: those arguments are masked like the addresses
		$this->assertTrue($ready);
		$this->assertStringContainsString(" --doh-listen-443 '" . self::VIP . "'", $this->rc());
		$this->assertSame([], $this->krProxyCalls(), 'no restart');
		$this->assertSame([], self::sent($record), 'the box cannot assign the VIP yet: nothing is sent, and the next pass tries again');
	}

	public function testAVipThatGoesIsRemovedLiveFromBothOfItsDohListenersAndRestartsNothing(): void
	{
		// Given a ready proxy that serves the VIP at the DoH port and on 443, and the VIP removed by the time the update pass runs
		$this->autoVip();
		$this->ready();
		$record = $this->gateway($this->served([self::VIP]));
		$this->assertStringContainsString(" --doh-listen-443 '" . self::VIP . "'", $this->rc(), 'before: the running script serves the VIP on 443');
		$this->noVip();

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then both of its DoH listeners are removed, in frames of their own, and nothing restarted
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls(), 'no restart');
		$removed = array_map(
			static fn (string $verb): string => substr($verb, strlen('fffffffd doh ')),
			array_filter(self::sent($record), static fn (string $verb): bool => str_starts_with($verb, 'fffffffd doh '))
		);
		$this->assertEqualsCanonicalizing([self::VIP . ":{$this->dohPort}", self::VIP . ':443'], $removed, 'one remove each for the VIP\'s two DoH listeners');
		$this->assertStringNotContainsString('--doh-listen-443', $this->rc());
	}

	public function testTheStartupCheckNamesTheVipListenerOn443TheGatewayRefused(): void
	{
		// Given a ready proxy whose command names the VIP on 443, and a gateway that refused that bind at its start (row D4)
		$this->autoVip();
		$this->ready();
		$served = array_values(array_diff($this->served([self::VIP]), ['doh ' . self::VIP . ':443']));
		$this->gateway($served, ['doh ' . self::VIP . ':443' => 'bind: address already in use']);

		// When the update pass runs
		$this->assertTrue($this->krEnsure());

		// Then the startup check says DoH is not served there, with the gateway's reason, and says nothing of the listeners that are served
		$notices = implode(' ', array_column(array_filter($GLOBALS['pfb_test_file_notices'], static fn (array $notice): bool => $notice['id'] === self::STARTUP), 'notice'));
		$this->assertStringContainsString('DoH is not served on ' . self::VIP . ':443: bind: address already in use', $notices);
		$this->assertStringNotContainsString('DoH is not served on ' . self::VIP . ":{$this->dohPort}", $notices);
		$this->assertSame([], $this->krProxyCalls(), 'a refused extra listener restarts nothing');
	}

	// -----------------------------------------------------------------------
	// the table: the 443 set and the name answers go together
	// -----------------------------------------------------------------------

	public function testTheSyncSendsTheAdvertisedAddressesWithTheNameAnswersInTheCommandsOrder(): void
	{
		// Given lan selected for DoH on 443, DDR on with the name
		$this->ready(self::ddrOn('lan'));
		$record = $this->gateway($this->served());
		$this->assertStringContainsString(" --ddr --ddr-doh-443 '192.0.2.1' --dns-name-answer '192.0.2.1=192.0.2.1'", $this->rc(), 'before: the command carries both');

		// When the sync runs
		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));

		// Then one frame carries both kinds of line, the command's order, joined by newlines
		$this->assertSame([self::TABLE . " ddr-doh-443 192.0.2.1\ndns-name-answer 192.0.2.1=192.0.2.1"], self::sent($record));
	}

	public function testASelectionThatChangesAloneIsReconciledLiveWithTheWholeTableAndRestartsNothing(): void
	{
		// Given lan selected, and the selection emptied by the time the update pass runs: the script differs only in --ddr-doh-443
		$this->ready(self::ddrOn('lan'));
		$record = $this->gateway($this->served());
		$this->assertStringContainsString("--ddr-doh-443 '192.0.2.1'", $this->rc(), 'before: the running script advertises lan');
		config_set_path(self::SETTINGS . 'pfb_dns_ddr_doh_443_interfaces', '');

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then the table without the 443 address was sent, and nothing restarted
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls(), 'no restart');
		$this->assertStringNotContainsString('--ddr-doh-443', $this->rc());
		$this->assertSame([self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1'], self::sent($record));
	}

	public function testNoAddressLineIsSentWithoutDdrOrASelection(): void
	{
		// Given DDR on and nothing selected: the table is the name answers alone
		$this->ready(self::ddrOn());
		$record = $this->gateway($this->served());
		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));
		$this->assertSame([self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1'], self::sent($record), 'before: no 443 line');

		// When lan is selected but DDR is turned off, the script has no --ddr and so no 443 argument
		config_set_path(self::SETTINGS . 'pfb_dns_ddr_doh_443_interfaces', 'lan');
		config_set_path(self::SHARED . 'pfb_dns_ddr', '');
		pfb_dns_proxy_service($this->krProxyDir);
		$this->assertStringNotContainsString('--ddr-doh-443', $this->rc());
		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));

		// Then the second table is still the name answers alone
		$this->assertSame(
			[self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1', self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1'],
			self::sent($record)
		);
	}
}
