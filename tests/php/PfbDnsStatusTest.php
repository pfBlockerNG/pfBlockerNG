<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issues #3515, #3548 -- the pfB-DNS tab's status panel: whether the proxy is running, starting or stopped, which mode the box is
 * in, and one row per transport (plain DNS, DoT, DoH, DoQ) with the addresses it serves on. Service and mode derive from the
 * Resolver snapshot (the box is moved or it is not), the toggle (what the admin asked for) and DNSBL (whether the proxy makes
 * DNSBL decisions); a toggle that is on while nothing is moved is said not to be active, with the reason (pfBlockerNG or the
 * Resolver disabled, or the Resolver not moved), never to run.
 *
 * A transport row is `Off` when its toggle is off and there are no active listeners. Otherwise, with the proxy running, it lists what the gateway's current start
 * reported `listening <kind>` in its log, then every address the rc script's command names that the start did not bind, as not
 * listening with the `cannot listen on` reason when the log has one; with the proxy not running it lists the command's
 * addresses, labelled configured and not bound. The startup check reads the same parsed start, so the panel and the notice never
 * disagree. The rc script is the real generator's output (pfb_dns_proxy_service()), the log a real file in the gateway's shape.
 */
#[CoversFunction('pfb_dns_status')]
#[CoversFunction('pfb_dns_proxy_listeners')]
#[CoversFunction('pfb_dns_proxy_command_listeners')]
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
	private const READY = 'ready upstream 127.0.0.1:5353';
	private const NO_TRANSPORT = ['plain' => '-', 'dot' => '-', 'doh' => '-', 'doq' => '-'];

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
		$GLOBALS['pfb_test_interfaces'] = ['lan' => ''];
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

	/** @return array{plain:string,dot:string,doh:string,doq:string} the four transport rows of the status */
	private function transports(): array
	{
		return array_intersect_key(pfb_dns_status(), self::NO_TRANSPORT);
	}

	public function testAnOffToggleWithNothingMovedIsNotInUse(): void
	{
		$this->assertSame([
			'service' => 'Not in use',
			'mode'    => 'Off: the DNS Resolver serves clients itself',
		] + self::NO_TRANSPORT, pfb_dns_status());
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
		$this->assertSame(self::NO_TRANSPORT, $this->transports(), 'no transport is claimed while nothing is moved');
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

		// Then each of the four rows lists what the current start bound, in the order it logged them; the older start's DoT is gone
		$this->assertSame([
			'service' => 'Running',
			'mode'    => 'On, with DNSBL: the proxy answers DNSBL blocks and forwards everything else',
			'plain'   => '192.0.2.1:53, 127.0.0.1:53, [::1]:53',
			'dot'     => '192.0.2.1:853, 127.0.0.1:853, [::1]:853',
			'doh'     => '192.0.2.1:443, 127.0.0.1:443, [::1]:443',
			'doq'     => '192.0.2.1:8853, 127.0.0.1:8853, [::1]:8853',
		], $status);
	}

	public function testATransportWithNoActiveListenersAndItsToggleOffIsOff(): void
	{
		// Given DoT on, DoH and DoQ off, and a current start that serves only plain DNS and DoT
		$this->box(self::DOT_ON + ['pfb_dns_doh' => '', 'pfb_dns_doq' => '']);
		$this->log(self::PLAIN, self::DOT, self::READY);

		// Then DoT lists its listeners and the two that are off say Off
		$this->assertSame([
			'plain' => '192.0.2.1:53, 127.0.0.1:53, [::1]:53',
			'dot'   => '192.0.2.1:853, 127.0.0.1:853, [::1]:853',
			'doh'   => 'Off',
			'doq'   => 'Off',
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
		$this->assertSame('Off', $this->transports()[$kind], 'before: no active transport');

		foreach (["pfb_dns_{$kind}" => 'on', "pfb_dns_{$kind}_interface" => 'lan', "pfb_dns_{$kind}_port" => $port] as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
		$this->assertSame('On, but the service has no listener for it: see the notices, or run an Update', $this->transports()[$kind], 'enable saved but not applied');

		pfb_dns_proxy_service();
		$this->log(self::PLAIN, "listening {$kind} 192.0.2.1:{$port}", "listening {$kind} 127.0.0.1:{$port}", "listening {$kind} [::1]:{$port}", self::READY);
		$active = "192.0.2.1:{$port}, 127.0.0.1:{$port}, [::1]:{$port}";
		$this->assertSame($active, $this->transports()[$kind], 'enable applied: every listener bound');

		config_set_path(self::SETTINGS . "pfb_dns_{$kind}", '');
		$this->assertSame($active, $this->transports()[$kind], 'disable saved: gateway still serves its existing listeners');

		$this->log(self::PLAIN, "listening {$kind} 127.0.0.1:{$port}");
		$this->assertSame("Configured (not confirmed by the log): {$active}", $this->transports()[$kind], 'missing readiness lines cannot prove a pending disable has stopped the configured service');

		$this->log(self::PLAIN, "cannot listen on 192.0.2.1:{$port}: bind failed", "listening {$kind} 127.0.0.1:{$port}", "listening {$kind} [::1]:{$port}", self::READY);
		$this->assertSame("127.0.0.1:{$port}, [::1]:{$port}, 192.0.2.1:{$port}: not listening (bind failed)", $this->transports()[$kind], 'pending disable must not hide a failed listener either');

		pfb_dns_proxy_service();
		$this->log(self::PLAIN, self::READY);
		$this->assertSame('Off', $this->transports()[$kind], 'disable applied: no listeners remain');
	}

	#[DataProvider('encryptedTransports')]
	public function testTheCurrentStartStillShowsItsBoundListenersWhenTheServiceScriptIsMissing(string $kind, string $port): void
	{
		$this->box(["pfb_dns_{$kind}" => 'on', "pfb_dns_{$kind}_interface" => 'lan', "pfb_dns_{$kind}_port" => $port]);
		$this->log(self::PLAIN, "listening {$kind} 127.0.0.1:{$port}", self::READY);
		unlink(PFB_DNS_PROXY_RCFILE);

		$this->assertSame("127.0.0.1:{$port}", $this->transports()[$kind], 'a missing command cannot erase a listener confirmed by the running start');
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
		$active = "192.0.2.1:{$port}, 127.0.0.1:{$port}, [::1]:{$port}";
		$this->assertSame($active, $this->transports()[$row], 'before: old listeners are active');

		$GLOBALS['pfb_test_interface_ip']['opt1'] = '198.51.100.1';
		$GLOBALS['pfb_test_interface_info']['opt1'] = ['status' => 'up', 'enable' => TRUE];
		$GLOBALS['pfb_test_interfaces']['opt1'] = '';
		$key = ($row === 'plain') ? 'pfb_dns_interface' : "pfb_dns_{$row}_interface";
		config_set_path(self::SETTINGS . $key, 'opt1');
		config_set_path(($row === 'plain') ? 'unbound/port' : self::SETTINGS . "pfb_dns_{$row}_port", '5553');
		$this->assertSame($active, $this->transports()[$row], 'save alone does not change the active addresses or port');

		pfb_dns_proxy_service();
		$this->log("listening {$kind} 198.51.100.1:5553", "listening {$kind} 127.0.0.1:5553", "listening {$kind} [::1]:5553", self::READY);
		$this->assertSame('198.51.100.1:5553, 127.0.0.1:5553, [::1]:5553', $this->transports()[$row], 'after apply: the new start, not the pending settings, confirms the listeners');
	}

	public function testDotIsPfbDnsOwnToggleAndPortWhateverTheResolversTlsPort(): void
	{
		// Given a Resolver with a TLS port of its own, and pfB-DNS's own DoT on at 8853, stopped
		config_set_path('unbound/tlsport', '9999');
		$this->box(['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '8853'], FALSE);

		$this->assertSame('Configured (not bound): 192.0.2.1:8853, 127.0.0.1:8853, [::1]:8853', $this->transports()['dot']);
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

		// Then each row lists what was bound, then the address it missed, with the gateway's reason or that it was not reported
		$this->assertSame([
			'plain' => '192.0.2.1:53, 127.0.0.1:53, [::1]:53',
			'dot'   => '127.0.0.1:853, [::1]:853, 192.0.2.1:853: not listening (listen tcp 192.0.2.1:853: bind: address already in use)',
			'doh'   => '127.0.0.1:443, [::1]:443, 192.0.2.1:443: not listening (the gateway did not report it)',
			'doq'   => 'Off',
		], $this->transports());
	}

	public function testAGatewayReasonIsReturnedVerbatimForThePageToEscape(): void
	{
		// Given a reason carrying markup and the rows' own separator
		$this->box(self::DOT_ON);
		$this->log(self::PLAIN, 'cannot listen on 192.0.2.1:853: <b>bind</b> & "x", y', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853', self::READY);

		// Then the status carries it as the gateway wrote it; only the page escapes (htmlspecialchars, PfbDnsPageWiringTest)
		$this->assertSame('127.0.0.1:853, [::1]:853, 192.0.2.1:853: not listening (<b>bind</b> & "x", y)', $this->transports()['dot']);
	}

	public function testAStoppedProxyShowsTheConfiguredAddressesOfEachTransportThatIsOnNotTheLogsOldListeners(): void
	{
		// Given a stopped proxy with DoT, DoH and DoQ on, and a log from when it last ran in which DoT on lan had failed
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON, FALSE);
		$this->log(self::PLAIN, 'listening dot 127.0.0.1:853', self::DOH, self::DOQ, self::READY);

		$status = pfb_dns_status();

		// Then every transport names the command's addresses and port, labelled as configured, never as bound
		$this->assertSame('Stopped', $status['service']);
		$this->assertSame([
			'plain' => 'Configured (not bound): 192.0.2.1:53, 127.0.0.1:53, [::1]:53',
			'dot'   => 'Configured (not bound): 192.0.2.1:853, 127.0.0.1:853, [::1]:853',
			'doh'   => 'Configured (not bound): 192.0.2.1:443, 127.0.0.1:443, [::1]:443',
			'doq'   => 'Configured (not bound): 192.0.2.1:8853, 127.0.0.1:8853, [::1]:8853',
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
			'plain' => 'Configured (not bound): 192.0.2.1:53, 127.0.0.1:53, [::1]:53',
			'dot'   => 'Configured (not bound): 192.0.2.1:853, 127.0.0.1:853, [::1]:853',
			'doh'   => 'Configured (not bound): 192.0.2.1:443, 127.0.0.1:443, [::1]:443',
			'doq'   => 'Configured (not bound): 192.0.2.1:8853, 127.0.0.1:8853, [::1]:8853',
		], $this->transports());
	}

	public function testARunningProxyWhoseLogHoldsNoStartShowsItsConfiguredAddressesAsNotConfirmed(): void
	{
		// Given a running proxy whose log was rotated: listening lines, but no `ready upstream` line
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->log(self::PLAIN, self::DOT, self::DOH, self::DOQ);

		// Then nothing is claimed bound: the configured addresses, said not to be confirmed by the log
		$this->assertSame([
			'plain' => 'Configured (not confirmed by the log): 192.0.2.1:53, 127.0.0.1:53, [::1]:53',
			'dot'   => 'Configured (not confirmed by the log): 192.0.2.1:853, 127.0.0.1:853, [::1]:853',
			'doh'   => 'Configured (not confirmed by the log): 192.0.2.1:443, 127.0.0.1:443, [::1]:443',
			'doq'   => 'Configured (not confirmed by the log): 192.0.2.1:8853, 127.0.0.1:8853, [::1]:8853',
		], $this->transports());
	}

	public function testATransportThatIsOnButHasNoListenerInTheCommandSaysSo(): void
	{
		// Given DoT on with a stored port that is no port: the generator leaves DoT out of the command
		$this->box(['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => 'abc']);
		$this->assertStringNotContainsString('--dot-', (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the command has no DoT');
		$this->log(self::PLAIN, self::READY);

		$this->assertSame('On, but the service has no listener for it: see the notices, or run an Update', $this->transports()['dot']);
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
		$GLOBALS['pfb_test_interfaces'] = ['lan' => '', 'opt1' => ''];
		pfb_dns_proxy_service();

		$this->assertSame('Configured (not bound): 192.0.2.1:53, 127.0.0.1:53, [::1]:53', $this->transports()['plain']);
	}

	public function testAMovedBoxWithDnsblOffAndAStoppedProxyOnAnotherPort(): void
	{
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		config_set_path('unbound/port', '5300');
		$this->box([], FALSE);

		$this->assertSame([
			'service' => 'Stopped',
			'mode'    => 'On, without DNSBL: the proxy forwards every query',
			'plain'   => 'Configured (not bound): 192.0.2.1:5300, 127.0.0.1:5300, [::1]:5300',
			'dot'     => 'Off',
			'doh'     => 'Off',
			'doq'     => 'Off',
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
		foreach ($this->transports() as $kind => $row) {
			foreach (explode(', ', $row) as $entry) {
				if (preg_match('/^(\S+): not listening /', $entry, $found) === 1) {
					$fromStatus[] = "{$kind} {$found[1]}";
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

		// Then it says recovery is required, not that the Resolver is unchanged or not moved, and claims no transport
		$this->assertSame($service, $status['service']);
		$this->assertStringStartsWith('Recovery required', $status['mode']);
		foreach (['not been moved', 'serves clients itself', 'unchanged', 'Off:'] as $wrong) {
			$this->assertStringNotContainsString($wrong, $status['mode']);
		}
		$this->assertSame(self::NO_TRANSPORT, $this->transports());
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
		$this->assertSame(self::NO_TRANSPORT, $this->transports());
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
