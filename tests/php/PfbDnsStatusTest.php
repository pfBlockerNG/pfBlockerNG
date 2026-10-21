<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issues #3515, #3548, #3555 -- the pfB-DNS tab's status data: whether the proxy is running, starting or stopped, which mode the box is
 * in, and for each transport (plain DNS, DoT, DoH, DoQ) either a whole-transport state (`off`, or `no_listener`) or the rows of its
 * table: one per interface and outcome, with the addresses it covers. Service and mode derive from the Resolver snapshot (the box is
 * moved or it is not), the toggle (what the admin asked for) and DNSBL (whether the proxy makes DNSBL decisions); a toggle that is on
 * while nothing is moved is said not to be active, with the reason (pfBlockerNG or the Resolver disabled, or the Resolver not moved),
 * never to run, and shows no transport at all.
 *
 * A transport is `off` when its toggle is off and there are no active listeners. Otherwise, with the proxy running, its rows are what
 * the gateway's current start reported `listening <kind>` in its log (state `listening`), then every address the rc script's command
 * names that the start did not bind (`not_listening`, with the `cannot listen on` reason when the log has one); with the proxy not
 * running its rows are the command's addresses (`configured_not_bound`), and with no log record that matches the running PID the same
 * addresses are `configured_unconfirmed`. An address sits under the pfSense description of the interface that carries it. The startup
 * check reads the same parsed start, so the panel and the notice never disagree. The rc script is the real generator's output
 * (pfb_dns_proxy_service()), the log a real file in the gateway's shape.
 */
#[CoversFunction('pfb_dns_status')]
#[CoversFunction('pfb_dns_proxy_listeners')]
#[CoversFunction('pfb_dns_proxy_command_listeners')]
#[CoversFunction('pfb_dns_status_rows')]
#[CoversFunction('pfb_dns_proxy_address_interfaces')]
#[CoversFunction('pfb_dns_status_panel')]
final class PfbDnsStatusTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private const DOT_ON = ['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '853'];
	private const DOH_ON = ['pfb_dns_doh' => 'on', 'pfb_dns_doh_interface' => 'lan', 'pfb_dns_doh_port' => '443'];
	private const DOQ_ON = ['pfb_dns_doq' => 'on', 'pfb_dns_doq_interface' => 'lan', 'pfb_dns_doq_port' => '8853'];

	private const PLAIN = ['listening udp+tcp 192.0.2.1:53', 'listening udp+tcp 127.0.0.1:53', 'listening udp+tcp [::1]:53'];
	private const DOT = ['listening dot 192.0.2.1:853', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853'];
	private const DOH = ['listening doh 192.0.2.1:443', 'listening doh 127.0.0.1:443', 'listening doh [::1]:443'];
	private const DOQ = ['listening doq 192.0.2.1:8853', 'listening doq 127.0.0.1:8853', 'listening doq [::1]:8853'];
	private const READY = 'ready upstream 127.0.0.1:5353 pid 4242';
	private const OFF = ['state' => 'off'];
	private const NO_LISTENER = ['state' => 'no_listener', 'notice' => 'On, but the service has no listener for it: see the notices, or run an Update'];

	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_file_notices', 'pfb_test_valid_pids', 'pfb_test_rcfile_dir', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles',
		'pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_configured_ipv6', 'pfb_test_configured_ip_addresses',
		'pfb_test_interfaces',
	];

	private string $dir;

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_status_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'enable' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'pfb_dns' => PfbToggle::Off,
			'dns_proxy_pidfile' => "{$this->dir}/pfb_dns_proxy.pid", 'dns_proxy_ready' => "{$this->dir}/pfb_dns_ready",
			'logdir' => $this->dir, 'log' => "{$this->dir}/pfb.log", 'errlog' => "{$this->dir}/pfb.err",
			'dns_proxy_log' => "{$this->dir}/dns_proxy.log",
			'dns_proxy_cert' => "{$this->dir}/etc/pfb_dns/tls.pem",
			'dns_proxy_cert_legacy' => "{$this->dir}/chroot/pfb_dns_cert.pem",
			'dns_proxy_ctl' => "{$this->dir}/ctl.sock",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
	}

	protected function tearDown(): void
	{
		$this->clearProxyFiles();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		@unlink(PFB_DNS_PROXY_RCFILE);
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
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$this->seedProxy('4242', "4242\n", $up);
	}

	/**
	 * A moved box with pfB-DNS on and these settings of its own (plain DNS on lan; the interface stored is the sign of a seeded box, so
	 * the saved Resolver supplies nothing), and the rc script the generator writes for them: every transport that is on listens on lan
	 * (192.0.2.1) and loopback. $up: the proxy serves, else it is stopped.
	 *
	 * @param array<string,string> $settings
	 */
	private function box(array $settings = [], bool $up = TRUE): void
	{
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$this->moved(FALSE, $up);
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::shared())];
		foreach ($settings + ['pfb_dns_interface' => 'lan', 'pfb_dns_sslcertref' => 'cert1'] as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
		pfb_dns_proxy_service();
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE, 'the generator wrote the rc script the status reads');
	}

	/**
	 * The gateway's log: these lines, each ended by a newline. An argument is one line, or a list of them.
	 *
	 * @param string|list<string> ...$lines
	 */
	private function log(string|array ...$lines): void
	{
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], implode("\n", array_merge(...array_map(static fn (string|array $part): array => (array) $part, $lines))) . "\n");
	}

	/** @return array<string,array<string,mixed>> the four transports of the status; none while the status claims none */
	private function transports(): array
	{
		return (array) pfb_dns_status()['transports'];
	}

	/**
	 * One expected row of a transport's table.
	 *
	 * @param list<string> $addresses
	 * @return array{interface:string,addresses:list<string>,state:string,reason:string}
	 */
	private static function row(string $interface, array $addresses, string $state, string $reason = ''): array
	{
		return ['interface' => $interface, 'addresses' => $addresses, 'state' => $state, 'reason' => $reason];
	}

	/**
	 * A transport whose addresses, loopback and the one `lan` address, are all in one $state at $port: the rows a box seeded by box() shows.
	 *
	 * @return array{state:string,rows:list<array<string,mixed>>}
	 */
	private static function served(string $port, string $state = 'listening', string $lan = '192.0.2.1'): array
	{
		return ['state' => 'rows', 'rows' => [
			self::row('Localhost', ["127.0.0.1:{$port}", "[::1]:{$port}"], $state),
			self::row('LAN', ["{$lan}:{$port}"], $state),
		]];
	}

	/**
	 * A transport whose loopback is bound and whose `lan` address is not, for $reason.
	 *
	 * @return array{state:string,rows:list<array<string,mixed>>}
	 */
	private static function lanRefused(string $port, string $reason): array
	{
		return ['state' => 'rows', 'rows' => [
			self::row('Localhost', ["127.0.0.1:{$port}", "[::1]:{$port}"], 'listening'),
			self::row('LAN', ["192.0.2.1:{$port}"], 'not_listening', $reason),
		]];
	}

	/** @return array{address:string,state:string,reason:string} one address as pfb_dns_status() hands it to the grouping */
	private static function entry(string $address, string $state = 'listening', string $reason = ''): array
	{
		return ['address' => $address, 'state' => $state, 'reason' => $reason];
	}

	public function testAnOffToggleWithNothingMovedIsNotInUse(): void
	{
		$this->assertSame([
			'service'    => 'Not in use',
			'mode'       => 'Off: the DNS Resolver serves clients itself',
			'transports' => NULL,
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
		$this->assertArrayHasKey('transports', $status);
		$this->assertNull($status['transports'], 'no transport is claimed while nothing is moved');
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

	public function testARunningProxyListsForEachTransportTheAddressesItsCurrentStartBound(): void
	{
		// Given a running proxy with DoT, DoH and DoQ on, and a log whose older start bound DoT on another address
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->log(
			self::PLAIN, 'listening dot 198.51.100.9:853', self::READY,
			self::PLAIN, self::DOT, self::DOH, self::DOQ, 'control socket /var/run/pfb_dns/ctl.sock', self::READY,
			'pfb_dns_proxy warning: no reply from Unbound for 1.2.0.192.in-addr.arpa. PTR'
		);

		// When the status is read
		$status = pfb_dns_status();

		// Then each of the four tables lists what the current start bound, loopback first; the older start's DoT is gone
		$this->assertSame([
			'service'    => 'Running',
			'mode'       => 'On, with DNSBL: the proxy answers DNSBL blocks and forwards everything else',
			'transports' => [
				'plain' => self::served('53'),
				'dot'   => self::served('853'),
				'doh'   => self::served('443'),
				'doq'   => self::served('8853'),
			],
		], $status);
	}

	public function testATransportWithNoActiveListenersAndItsToggleOffIsOff(): void
	{
		// Given DoT on, DoH and DoQ off, and a current start that serves only plain DNS and DoT
		$this->box(self::DOT_ON + ['pfb_dns_doh' => '', 'pfb_dns_doq' => '']);
		$this->log(self::PLAIN, self::DOT, self::READY);

		// Then DoT lists its listeners and the two that are off are off
		$this->assertSame([
			'plain' => self::served('53'),
			'dot'   => self::served('853'),
			'doh'   => self::OFF,
			'doq'   => self::OFF,
		], $this->transports());
	}

	/** @return array<string,array{string,string}> */
	public static function encryptedTransports(): array
	{
		return ['DoT' => ['dot', '853'], 'DoH' => ['doh', '443'], 'DoQ' => ['doq', '8853']];
	}

	#[DataProvider('encryptedTransports')]
	public function testSavingATransportToggleDoesNotChangeWhatTheRunningStartServes(string $kind, string $port): void
	{
		$this->box();
		$this->log(self::PLAIN, self::READY);
		$this->assertSame(self::OFF, $this->transports()[$kind], 'before: no active transport');

		foreach (["pfb_dns_{$kind}" => 'on', "pfb_dns_{$kind}_interface" => 'lan', "pfb_dns_{$kind}_port" => $port] as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
		$this->assertSame(self::NO_LISTENER, $this->transports()[$kind], 'enable saved but not applied');

		pfb_dns_proxy_service();
		$this->log(self::PLAIN, "listening {$kind} 192.0.2.1:{$port}", "listening {$kind} 127.0.0.1:{$port}", "listening {$kind} [::1]:{$port}", self::READY);
		$active = self::served($port);
		$this->assertSame($active, $this->transports()[$kind], 'enable applied: every listener bound');

		config_set_path(self::SETTINGS . "pfb_dns_{$kind}", '');
		$this->assertSame($active, $this->transports()[$kind], 'disable saved: gateway still serves its existing listeners');

		$this->log(self::PLAIN, "listening {$kind} 127.0.0.1:{$port}");
		$this->assertSame(self::served($port, 'configured_unconfirmed'), $this->transports()[$kind], 'missing readiness lines cannot prove a pending disable has stopped the configured service');

		$this->log(self::PLAIN, "cannot listen on 192.0.2.1:{$port}: bind failed", "listening {$kind} 127.0.0.1:{$port}", "listening {$kind} [::1]:{$port}", self::READY);
		$this->assertSame(self::lanRefused($port, 'bind failed'), $this->transports()[$kind], 'pending disable must not hide a failed listener either');

		pfb_dns_proxy_service();
		$this->log(self::PLAIN, self::READY);
		$this->assertSame(self::OFF, $this->transports()[$kind], 'disable applied: no listeners remain');
	}

	#[DataProvider('encryptedTransports')]
	public function testTheCurrentStartStillShowsItsBoundListenersWhenTheServiceScriptIsMissing(string $kind, string $port): void
	{
		$this->box(["pfb_dns_{$kind}" => 'on', "pfb_dns_{$kind}_interface" => 'lan', "pfb_dns_{$kind}_port" => $port]);
		$this->log(self::PLAIN, "listening {$kind} 127.0.0.1:{$port}", self::READY);
		unlink(PFB_DNS_PROXY_RCFILE);

		$only = ['state' => 'rows', 'rows' => [self::row('Localhost', ["127.0.0.1:{$port}"], 'listening')]];
		$this->assertSame($only, $this->transports()[$kind], 'a missing command cannot erase a listener confirmed by the running start');
		config_set_path(self::SETTINGS . "pfb_dns_{$kind}", '');
		$this->assertSame($only, $this->transports()[$kind], 'a pending disable cannot hide log-confirmed listeners when the command is missing');
	}

	/** @return array<string,array{string,string,string}> */
	public static function allTransports(): array
	{
		return ['Plain DNS' => ['plain', 'udp+tcp', '53'], 'DoT' => ['dot', 'dot', '853'], 'DoH' => ['doh', 'doh', '443'], 'DoQ' => ['doq', 'doq', '8853']];
	}

	#[DataProvider('allTransports')]
	public function testPendingAddressAndPortChangesDoNotReplaceTheRunningStart(string $row, string $kind, string $port): void
	{
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ, self::READY);
		$active = self::served($port);
		$this->assertSame($active, $this->transports()[$row], 'before: old listeners are active');

		$GLOBALS['pfb_test_interface_ip']['opt1'] = '198.51.100.1';
		$GLOBALS['pfb_test_interface_info']['opt1'] = ['status' => 'up', 'enable' => TRUE];
		$GLOBALS['pfb_test_interfaces']['opt1'] = 'OPT1';
		$key = ($row === 'plain') ? 'pfb_dns_interface' : "pfb_dns_{$row}_interface";
		config_set_path(self::SETTINGS . $key, 'opt1');
		config_set_path(($row === 'plain') ? 'unbound/port' : self::SETTINGS . "pfb_dns_{$row}_port", '5553');
		$this->assertSame($active, $this->transports()[$row], 'save alone does not change the active addresses or port');

		pfb_dns_proxy_service();
		$this->log("listening {$kind} 198.51.100.1:5553", "listening {$kind} 127.0.0.1:5553", "listening {$kind} [::1]:5553", self::READY);
		$this->assertSame(['state' => 'rows', 'rows' => [
			self::row('Localhost', ['127.0.0.1:5553', '[::1]:5553'], 'listening'),
			self::row('OPT1', ['198.51.100.1:5553'], 'listening'),
		]], $this->transports()[$row], 'after apply: the new start, not the pending settings, confirms the listeners');
	}

	public function testDotIsPfbDnsOwnToggleAndPortWhateverTheResolversTlsPort(): void
	{
		// Given a Resolver with a TLS port of its own, and pfB-DNS's own DoT on at 8853, stopped
		config_set_path('unbound/tlsport', '9999');
		$this->box(['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '8853'], FALSE);

		$this->assertSame(self::served('8853', 'configured_not_bound'), $this->transports()['dot']);
	}

	public function testAnAddressTheCommandNamesThatTheStartDidNotBindIsNotListeningWithItsReasonWhenLogged(): void
	{
		// Given DoT and DoH on lan + loopback, and a current start that lacks both on lan: DoT with a logged reason, DoH without one
		$this->box(self::DOT_ON + self::DOH_ON);
		$this->log(
			self::PLAIN,
			'cannot listen on 192.0.2.1:853: listen tcp 192.0.2.1:853: bind: address already in use',
			'listening dot 127.0.0.1:853', 'listening dot [::1]:853',
			'listening doh 127.0.0.1:443', 'listening doh [::1]:443',
			self::READY
		);

		// Then each table lists what was bound, then the address it missed, with the gateway's reason or that it was not reported
		$this->assertSame([
			'plain' => self::served('53'),
			'dot'   => self::lanRefused('853', 'listen tcp 192.0.2.1:853: bind: address already in use'),
			'doh'   => self::lanRefused('443', 'the gateway did not report it'),
			'doq'   => self::OFF,
		], $this->transports());
	}

	public function testAGatewayReasonIsReturnedVerbatimForThePageToEscape(): void
	{
		// Given a reason carrying markup and the rows' own separator
		$this->box(self::DOT_ON);
		$this->log(self::PLAIN, 'cannot listen on 192.0.2.1:853: <b>bind</b> & "x", y', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853', self::READY);

		// Then the status carries it as the gateway wrote it; only the panel escapes (PfbDnsStatusPanelTest)
		$this->assertSame(self::lanRefused('853', '<b>bind</b> & "x", y'), $this->transports()['dot']);
	}

	public function testAStoppedProxyShowsTheConfiguredAddressesOfEachTransportThatIsOnNotTheLogsOldListeners(): void
	{
		// Given a stopped proxy with DoT, DoH and DoQ on, and a log from when it last ran in which DoT on lan had failed
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON, FALSE);
		$this->log(self::PLAIN, 'listening dot 127.0.0.1:853', self::DOH, self::DOQ, self::READY);

		$status = pfb_dns_status();

		// Then every transport names the command's addresses and port, as configured and not bound, never as bound
		$this->assertSame('Stopped', $status['service']);
		$this->assertSame([
			'plain' => self::served('53', 'configured_not_bound'),
			'dot'   => self::served('853', 'configured_not_bound'),
			'doh'   => self::served('443', 'configured_not_bound'),
			'doq'   => self::served('8853', 'configured_not_bound'),
		], $this->transports());
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
	public function testALiveProxyThatIsNotReadyIsStartingAndShowsItsConfiguredAddresses(?string $marker): void
	{
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->seedProxy('4242', $marker);
		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ, self::READY);

		$status = pfb_dns_status();

		// Then a start not ready yet bound nothing that counts
		$this->assertSame('Starting', $status['service']);
		$this->assertSame([
			'plain' => self::served('53', 'configured_not_bound'),
			'dot'   => self::served('853', 'configured_not_bound'),
			'doh'   => self::served('443', 'configured_not_bound'),
			'doq'   => self::served('8853', 'configured_not_bound'),
		], $this->transports());
	}

	public function testARunningProxyWhoseLogHoldsNoStartShowsItsConfiguredAddressesAsNotConfirmed(): void
	{
		// Given a running proxy whose log was rotated: listening lines, but no `ready upstream` line
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ);

		// Then nothing is claimed bound: the configured addresses, said not to be confirmed by the log
		$this->assertSame([
			'plain' => self::served('53', 'configured_unconfirmed'),
			'dot'   => self::served('853', 'configured_unconfirmed'),
			'doh'   => self::served('443', 'configured_unconfirmed'),
			'doq'   => self::served('8853', 'configured_unconfirmed'),
		], $this->transports());
	}

	/** @return array<string,array{string,list<string>,bool}> */
	public static function logsWithoutCurrentPidReadiness(): array
	{
		return [
			'old PID, zero current bytes' => ['ready upstream 127.0.0.1:5353 pid 4241', [], FALSE],
			'old PID, partial current listeners' => ['ready upstream 127.0.0.1:5353 pid 4241',
				['listening udp+tcp 198.51.100.1:53', 'listening dot 198.51.100.1:853'], FALSE],
			'legacy record without PID' => ['ready upstream 127.0.0.1:5353', [], FALSE],
			'PID suffix must match exactly' => ['ready upstream 127.0.0.1:5353 pid 42420', [], FALSE],
			'malformed PID suffix' => ['ready upstream 127.0.0.1:5353 pid 4242x', [], FALSE],
			'never search backward for a matching PID' => ['ready upstream 127.0.0.1:5353 pid 4241', [], TRUE],
		];
	}

	/** @param list<string> $partial */
	#[DataProvider('logsWithoutCurrentPidReadiness')]
	public function testPreviousStartBindingsStayUnconfirmedUntilTheCurrentPidLogsReadiness(string $ready, array $partial, bool $olderMatch): void
	{
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$GLOBALS['pfb_test_interface_ip']['lan'] = '198.51.100.1';
		pfb_dns_proxy_service();
		$older = $olderMatch ? [...self::PLAIN, ...self::DOT, ...self::DOH, ...self::DOQ, self::READY] : [];
		$this->log($older, self::PLAIN, self::DOT, self::DOH, self::DOQ, $ready, $partial);

		$this->assertSame('Running', pfb_dns_status()['service'], 'the current child already published its PID marker');
		$this->assertSame([
			'plain' => self::served('53', 'configured_unconfirmed', '198.51.100.1'),
			'dot'   => self::served('853', 'configured_unconfirmed', '198.51.100.1'),
			'doh'   => self::served('443', 'configured_unconfirmed', '198.51.100.1'),
			'doq'   => self::served('8853', 'configured_unconfirmed', '198.51.100.1'),
		], $this->transports(), 'neither the old bindings nor partial new output confirms the current start');
		$this->assertNull(pfb_dns_proxy_listeners(NULL, '4242'));
	}

	public function testSupervisorRespawnOnTheSameAddressesNeedsItsOwnPidReadinessRecord(): void
	{
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ, self::READY);
		$bound = ['plain' => self::served('53'), 'dot' => self::served('853'), 'doh' => self::served('443'), 'doq' => self::served('8853')];
		$this->assertSame($bound, $this->transports(), 'before: the complete record belongs to PID 4242');

		// daemon -r changes the child PID without re-running the rc script or changing its addresses
		$this->seedProxy('4243', "4243\n");
		$unknown = [
			'plain' => self::served('53', 'configured_unconfirmed'),
			'dot'   => self::served('853', 'configured_unconfirmed'),
			'doh'   => self::served('443', 'configured_unconfirmed'),
			'doq'   => self::served('8853', 'configured_unconfirmed'),
		];
		$this->assertSame($unknown, $this->transports(), 'new ready marker, zero new log bytes');
		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ, self::READY, self::PLAIN, self::DOT);
		$this->assertSame($unknown, $this->transports(), 'same-address partial startup is still not its complete readiness record');

		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ, self::READY,
			self::PLAIN, self::DOT, self::DOH, self::DOQ, 'ready upstream 127.0.0.1:5353 pid 4243');
		$this->assertSame($bound, $this->transports(), 'only the new PID record confirms its same-address listeners');
		$this->assertSame([
			'udp+tcp' => array_fill_keys(['192.0.2.1:53', '127.0.0.1:53', '[::1]:53'], TRUE),
			'dot' => array_fill_keys(['192.0.2.1:853', '127.0.0.1:853', '[::1]:853'], TRUE),
			'doh' => array_fill_keys(['192.0.2.1:443', '127.0.0.1:443', '[::1]:443'], TRUE),
			'doq' => array_fill_keys(['192.0.2.1:8853', '127.0.0.1:8853', '[::1]:8853'], TRUE),
		], pfb_dns_proxy_listeners(NULL, '4243')['listening']);
	}

	public function testATransportThatIsOnButHasNoListenerInTheCommandSaysSo(): void
	{
		// Given DoT on with a stored port that is no port: the generator leaves DoT out of the command
		$this->box(['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => 'abc']);
		$this->assertStringNotContainsString('--dot-', (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the command has no DoT');
		$this->log(self::PLAIN, self::READY);

		$this->assertSame(self::NO_LISTENER, $this->transports()['dot']);
	}

	public function testPlainDnsIsPfbDnsOwnInterfaceListNotTheSavedResolversInterfaces(): void
	{
		// Given a saved Resolver that listened on opt1, and pfB-DNS's own list: lan
		$this->box([], FALSE);
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => 'opt1'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE], 'opt1' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'OPT1'];
		pfb_dns_proxy_service();

		$this->assertSame(self::served('53', 'configured_not_bound'), $this->transports()['plain']);
	}

	public function testAMovedBoxWithDnsblOffAndAStoppedProxyOnAnotherPort(): void
	{
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		config_set_path('unbound/port', '5300');
		$this->box([], FALSE);

		$this->assertSame([
			'service'    => 'Stopped',
			'mode'       => 'On, without DNSBL: the proxy forwards every query',
			'transports' => [
				'plain' => self::served('5300', 'configured_not_bound'),
				'dot'   => self::OFF,
				'doh'   => self::OFF,
				'doq'   => self::OFF,
			],
		], pfb_dns_status());
	}

	/** @return array<string,array{list<string>,list<string>}> logs of one start with DoT, DoH and DoQ on lan + loopback, and the listeners it missed */
	public static function startLogs(): array
	{
		return [
			'everything bound' => [[...self::PLAIN, ...self::DOT, ...self::DOH, ...self::DOQ, self::READY], []],
			'loopback only, one reason' => [[
				'listening udp+tcp 127.0.0.1:53', 'listening udp+tcp [::1]:53', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853',
				'listening doh 127.0.0.1:443', 'listening doh [::1]:443', 'listening doq 127.0.0.1:8853', 'listening doq [::1]:8853',
				'cannot listen on 192.0.2.1:53: listen tcp 192.0.2.1:53: bind: address already in use', self::READY,
			], ['plain 192.0.2.1:53', 'dot 192.0.2.1:853', 'doh 192.0.2.1:443', 'doq 192.0.2.1:8853']],
			'an older start that missed DoQ, a current one that missed DoT' => [[
				...self::PLAIN, ...self::DOT, ...self::DOH, 'listening doq 127.0.0.1:8853', self::READY,
				...self::PLAIN, 'listening dot garbage', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853', ...self::DOH, ...self::DOQ, self::READY,
			], ['dot 192.0.2.1:853']],
		];
	}

	/**
	 * @param list<string> $lines
	 * @param list<string> $missed
	 */
	#[DataProvider('startLogs')]
	public function testTheStatusAndTheStartupCheckJudgeTheSameStart(array $lines, array $missed): void
	{
		// Given a running proxy with every transport on and a log of its start
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->log($lines);

		// When the startup check judges it and the status is read
		pfb_dns_proxy_startup_check(TRUE);
		$notice = implode(' ', array_column($GLOBALS['pfb_test_file_notices'], 'notice'));
		preg_match_all('/(Plain DNS|DoT|DoH|DoQ) is not served on (\S+?): /', $notice, $named, PREG_SET_ORDER);
		$byLabel = ['Plain DNS' => 'plain', 'DoT' => 'dot', 'DoH' => 'doh', 'DoQ' => 'doq'];
		$fromNotice = array_map(static fn (array $match): string => "{$byLabel[$match[1]]} {$match[2]}", $named);
		$fromStatus = [];
		foreach ($this->transports() as $kind => $transport) {
			foreach ($transport['rows'] ?? [] as $row) {
				if ($row['state'] === 'not_listening') {
					foreach ($row['addresses'] as $address) {
						$fromStatus[] = "{$kind} {$address}";
					}
				}
			}
		}

		// Then the addresses the notice names are exactly those the panel shows not listening
		$this->assertSame($missed, $fromNotice, 'the notice names what the start missed');
		$this->assertSame($fromNotice, $fromStatus, 'the panel shows not listening exactly what the notice names');
	}

	public function testTheLogHasOneParserThatTheStatusAndTheStartupCheckBothCall(): void
	{
		$inc = (string) file_get_contents(self::INC);
		$this->assertSame(1, substr_count($inc, "'/^listening (udp\\+tcp|dot|doh|doq) "), 'one parser of the listening lines');
		$this->assertSame(1, substr_count($inc, "'/^cannot listen on "), 'one parser of the cannot-listen lines');
		foreach (['pfb_dns_status', 'pfb_dns_proxy_startup_check'] as $function) {
			$reflection = new ReflectionFunction($function);
			$body = implode('', array_slice((array) file(self::INC), $reflection->getStartLine() - 1, $reflection->getEndLine() - $reflection->getStartLine() + 1));
			$this->assertStringContainsString('pfb_dns_proxy_listeners(', $body, "{$function}() reads the parsed start");
			$this->assertStringContainsString('pfb_dns_proxy_command_listeners(', $body, "{$function}() reads the command's listeners");
		}
	}

	public function testAMovedBoxWhoseToggleIsOffIsSaidToBeTurningOff(): void
	{
		$this->moved(FALSE);

		$this->assertSame('Turning off: pfB-DNS is off, and the DNS Resolver restore is pending: see the notices', pfb_dns_status()['mode']);
	}

	public function testAMovedBoxWithPfbDnsOffNamesPfbDnsWhateverPfBlockerNgSays(): void
	{
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->moved(FALSE);

		$mode = pfb_dns_status()['mode'];
		$this->assertStringContainsString('pfB-DNS is off', $mode);
		$this->assertStringNotContainsString('pfBlockerNG is disabled', $mode);
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

		// Then it says recovery is required, not that the Resolver is unchanged or not moved, and claims no transport
		$this->assertSame($service, $status['service']);
		$this->assertStringStartsWith('Recovery required', $status['mode']);
		foreach (['not been moved', 'serves clients itself', 'unchanged', 'Off:'] as $wrong) {
			$this->assertStringNotContainsString($wrong, $status['mode']);
		}
		$this->assertArrayHasKey('transports', $status);
		$this->assertNull($status['transports']);
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
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
		$this->seedProxy('4242', "4242\n", FALSE);

		// When the status is read
		$status = pfb_dns_status();

		// Then it asks for a manual repair and says the saved state cannot be confirmed; it never says the Resolver is moved,
		// unchanged or not moved yet, and claims no transport
		$this->assertStringStartsWith('Recovery required', $status['mode']);
		$this->assertStringContainsString('cannot be confirmed', $status['mode']);
		$this->assertStringContainsString('manual repair', $status['mode']);
		foreach (['still carries', 'not been moved', 'serves clients itself', 'unchanged', 'Off:'] as $wrong) {
			$this->assertStringNotContainsString($wrong, $status['mode']);
		}
		$this->assertArrayHasKey('transports', $status);
		$this->assertNull($status['transports']);
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

	/** pfSense's interfaces as the grouping reads them: the description, the IPv4 and the IPv6 address of each, by name. */
	private function interfaces(array $descriptions, array $ipv4 = [], array $ipv6 = []): void
	{
		$GLOBALS['pfb_test_interfaces'] = $descriptions;
		$GLOBALS['pfb_test_interface_ip'] = $ipv4;
		$GLOBALS['pfb_test_configured_ipv6'] = $ipv6;
	}

	public function testEachAddressOfAnInterfaceIsLabelledWithItsDescriptionAndLoopbackIsLocalhost(): void
	{
		// Given lan with an IPv4 and an IPv6 address, another interface with an IPv4 one, and wan with none
		$this->interfaces(['wan' => 'WAN', 'lan' => 'LAN', 'opt1' => 'GUEST'], ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'], ['lan' => '2001:db8::1']);

		// Then loopback is Localhost and first, the others follow in pfSense's interface order, and wan, with no address, labels none
		$this->assertSame([
			'127.0.0.1'    => 'Localhost',
			'::1'          => 'Localhost',
			'192.0.2.1'    => 'LAN',
			'2001:db8::1'  => 'LAN',
			'198.51.100.1' => 'GUEST',
		], pfb_dns_proxy_address_interfaces());
	}

	public function testAnAddressOnTwoInterfacesBelongsToTheFirstAndAnythingThatIsNoAddressLabelsNothing(): void
	{
		// Given one IPv4 address on lan and on opt1, an IPv6 address spelled out in full, and "dhcp" where an address should be
		$this->interfaces(
			['lan' => 'LAN', 'opt1' => 'GUEST', 'opt2' => 'DSL'],
			['lan' => '192.0.2.1', 'opt1' => '192.0.2.1', 'opt2' => 'dhcp'],
			['opt1' => '2001:DB8:0:0:0:0:0:1']
		);

		// Then the shared address is the first interface's, the IPv6 one is keyed as the gateway spells it, and dhcp labels nothing
		$this->assertSame([
			'127.0.0.1'   => 'Localhost',
			'::1'         => 'Localhost',
			'192.0.2.1'   => 'LAN',
			'2001:db8::1' => 'GUEST',
		], pfb_dns_proxy_address_interfaces());
	}

	public function testWithNoAssignedInterfaceOnlyLoopbackIsLabelled(): void
	{
		$this->interfaces([]);

		$this->assertSame(['127.0.0.1' => 'Localhost', '::1' => 'Localhost'], pfb_dns_proxy_address_interfaces());
	}

	public function testRowsAreOrderedLocalhostThenTheInterfacesInPfSensesOrderThenAddressesOfNoInterface(): void
	{
		// Given the interfaces wan (no address), lan and a guest one, and two addresses on none of them
		$this->interfaces(['wan' => 'WAN', 'lan' => 'LAN', 'opt1' => 'GUEST'], ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'], ['opt1' => '2001:db8:1::1']);

		// When the addresses, in the order the gateway logged them, are grouped
		$rows = pfb_dns_status_rows([
			self::entry('203.0.113.99:853'),
			self::entry('[2001:db8:1::1]:853'),
			self::entry('192.0.2.1:853'),
			self::entry('[::1]:853'),
			self::entry('[2001:db8:ffff::9]:853'),
			self::entry('198.51.100.1:853'),
			self::entry('127.0.0.1:853'),
		], pfb_dns_proxy_address_interfaces());

		// Then Localhost is first, then lan and the guest interface (wan has no address, so no row), then each address of no interface
		// on a row of its own, labelled with the bare address and still bracketed in the address column when it is IPv6
		$this->assertSame([
			self::row('Localhost', ['[::1]:853', '127.0.0.1:853'], 'listening'),
			self::row('LAN', ['192.0.2.1:853'], 'listening'),
			self::row('GUEST', ['[2001:db8:1::1]:853', '198.51.100.1:853'], 'listening'),
			self::row('203.0.113.99', ['203.0.113.99:853'], 'listening'),
			self::row('2001:db8:ffff::9', ['[2001:db8:ffff::9]:853'], 'listening'),
		], $rows);
	}

	public function testAddressesOfOneInterfaceShareARowOnlyWhenTheirStateAndReasonAreTheSame(): void
	{
		$this->interfaces(['lan' => 'LAN'], ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);

		// Given loopback with one address bound and one not, and lan with both addresses refused for the same reason
		$same = pfb_dns_status_rows([
			self::entry('127.0.0.1:853'),
			self::entry('[::1]:853', 'not_listening', 'address already in use'),
			self::entry('192.0.2.1:853', 'not_listening', 'address already in use'),
			self::entry('[2001:db8::1]:853', 'not_listening', 'address already in use'),
		], pfb_dns_proxy_address_interfaces());

		// Then the outcomes of loopback are two rows and the same refusal on lan is one
		$this->assertSame([
			self::row('Localhost', ['127.0.0.1:853'], 'listening'),
			self::row('Localhost', ['[::1]:853'], 'not_listening', 'address already in use'),
			self::row('LAN', ['192.0.2.1:853', '[2001:db8::1]:853'], 'not_listening', 'address already in use'),
		], $same);

		// And lan's two addresses refused for different reasons are two rows
		$this->assertSame([
			self::row('LAN', ['192.0.2.1:853'], 'not_listening', 'address already in use'),
			self::row('LAN', ['[2001:db8::1]:853'], 'not_listening', 'permission denied'),
		], pfb_dns_status_rows([
			self::entry('192.0.2.1:853', 'not_listening', 'address already in use'),
			self::entry('[2001:db8::1]:853', 'not_listening', 'permission denied'),
		], pfb_dns_proxy_address_interfaces()));
	}

	public function testAnAddressOfNoInterfaceIsNeverDropped(): void
	{
		$this->interfaces([]);

		$this->assertSame([self::row('2001:db8::7', ['[2001:db8::7]:853'], 'listening')], pfb_dns_status_rows([self::entry('[2001:db8::7]:853')], pfb_dns_proxy_address_interfaces()));
		$this->assertSame([], pfb_dns_status_rows([], pfb_dns_proxy_address_interfaces()), 'no address, no row');
	}

	public function testAnInterfaceWhoseAddressesDifferInOutcomeGetsOneRowPerOutcome(): void
	{
		// Given DoT on lan, which has an IPv4 and an IPv6 address; the start bound the IPv4 one and could not bind the IPv6 one
		$this->box(self::DOT_ON);
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		pfb_dns_proxy_service();
		$this->log(
			self::PLAIN,
			'cannot listen on [2001:db8::1]:853: listen tcp [2001:db8::1]:853: bind: address already in use',
			'listening dot 192.0.2.1:853', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853',
			self::READY
		);

		// Then lan has a row for what listens and a row of its own for what failed, with the logged reason
		$this->assertSame(['state' => 'rows', 'rows' => [
			self::row('Localhost', ['127.0.0.1:853', '[::1]:853'], 'listening'),
			self::row('LAN', ['192.0.2.1:853'], 'listening'),
			self::row('LAN', ['[2001:db8::1]:853'], 'not_listening', 'listen tcp [2001:db8::1]:853: bind: address already in use'),
		]], $this->transports()['dot']);
	}

	public function testAnAddressWhoseInterfacePfSenseNoLongerListsIsStillShownLabelledWithTheAddress(): void
	{
		// Given a stopped proxy whose command names lan's address, and an interface list that no longer has lan
		$this->box([], FALSE);
		$GLOBALS['pfb_test_interfaces'] = [];

		// Then plain DNS still lists the address, on a row labelled with it, after loopback
		$this->assertSame(['state' => 'rows', 'rows' => [
			self::row('Localhost', ['127.0.0.1:53', '[::1]:53'], 'configured_not_bound'),
			self::row('192.0.2.1', ['192.0.2.1:53'], 'configured_not_bound'),
		]], $this->transports()['plain']);
	}

	#[DataProvider('allTransports')]
	public function testEveryTransportListsItsListenersAndOnlyTheEncryptedOnesCanBeOff(string $row, string $kind, string $port): void
	{
		// Given every transport on and served by the current start
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ, self::READY);
		$this->assertSame(self::served($port), $this->transports()[$row], 'before: the transport lists its listeners');

		if ($row === 'plain') {
			// When plain DNS has no listener left (it has no toggle to turn off)
			unlink(PFB_DNS_PROXY_RCFILE);
			$this->log(self::DOT, self::DOH, self::DOQ, self::READY);

			// Then it is a fault to report, never Off
			$this->assertSame(self::NO_LISTENER, $this->transports()['plain']);
			return;
		}

		// When its toggle is turned off and applied, and the next start does not serve it
		config_set_path(self::SETTINGS . "pfb_dns_{$row}", '');
		pfb_dns_proxy_service();
		$others = array_diff_key(['dot' => self::DOT, 'doh' => self::DOH, 'doq' => self::DOQ], [$row => TRUE]);
		$this->log(self::PLAIN, array_merge(...array_values($others)), self::READY);

		// Then it is Off
		$this->assertSame(self::OFF, $this->transports()[$row]);
	}

	public function testThePanelShowsWhatTheStatusReturnedForAnAddressTheStartDidNotBind(): void
	{
		// Given DoT on lan, the start bound loopback only and logged why it could not bind lan
		$this->box(self::DOT_ON);
		$this->log(self::PLAIN, 'cannot listen on 192.0.2.1:853: bind failed', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853', self::READY);

		// When the panel is rendered from that status
		$html = pfb_dns_status_panel(pfb_dns_status());

		// Then lan's row names its address, says it is not listening and gives the logged reason
		$this->assertMatchesRegularExpression('~<td>LAN</td><td>192\.0\.2\.1:853</td><td><i [^>]*title="Not listening"[^>]*></i><span class="sr-only">Not listening</span> bind failed</td>~', $html);
	}
}
