<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- pfB-DNS never fails to start, so the status says exactly what is lost. The Service line is `Running` only while the
 * gateway's applied status is readable and its Unbound backend is owned by the live Unbound; with the gateway ready and that backend not,
 * it says why (the Resolver is disabled, another process holds Unbound's port, or Unbound does not answer); a gateway that is running and
 * not ready says the error its latest start ended with, else `Starting`; a gateway that is not running is `Stopped`. Every part the
 * gateway reports `degraded` is a row of the panel under Service and a line of the widget's hover; DNSBL not blocking changes the mode;
 * no usable certificate turns every listening DoT, DoH and DoQ row into not served.
 *
 * The rc script is the real generator's output (pfb_dns_proxy_service()); the gateway is a stand-in on a real Unix socket answering the
 * applied status as the real one does (support/ListenerControlServer.php); Unbound's sockets are the sockstat double.
 */
#[CoversFunction('pfb_dns_status')]
#[CoversFunction('pfb_dns_status_panel')]
#[CoversFunction('pfb_dns_proxy_backend_problem')]
#[CoversFunction('pfb_dns_proxy_start_error')]
final class PfbDnsStatusDegradedTest extends TestCase
{
	use DnsProxyReadySeedTrait;
	use LiveListenerStandIn;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';

	private const ALL_ON = [
		'pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '853',
		'pfb_dns_doh' => 'on', 'pfb_dns_doh_interface' => 'lan', 'pfb_dns_doh_port' => '443',
		'pfb_dns_doq' => 'on', 'pfb_dns_doq_interface' => 'lan', 'pfb_dns_doq_port' => '8853',
	];

	private const PLAIN = ['udp+tcp 192.0.2.1:53', 'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53'];
	private const DOT = ['dot 192.0.2.1:853', 'dot 127.0.0.1:853', 'dot [::1]:853'];
	private const DOH = ['doh 192.0.2.1:443', 'doh 127.0.0.1:443', 'doh [::1]:443'];
	private const DOQ = ['doq 192.0.2.1:8853', 'doq 127.0.0.1:8853', 'doq [::1]:8853'];

	private const MODE_WITH_DNSBL = 'On, with DNSBL: the proxy answers DNSBL blocks and forwards everything else';

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
		$this->dir = sys_get_temp_dir() . '/pfb_dns_status_degraded_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'enable' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'pfb_dns' => PfbToggle::On,
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
		$this->setUpUpstreamFixture();
	}

	protected function tearDown(): void
	{
		$this->standInsStop();
		$this->tearDownUpstreamFixture();
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

	/**
	 * A moved box with pfB-DNS and DNSBL on, the Resolver enabled and these settings of its own (plain DNS on lan; the rc script the
	 * generator writes for them). $up: the gateway is ready and Unbound serves it; else the gateway is not running.
	 *
	 * @param array<string,string> $settings
	 */
	private function box(array $settings = [], bool $up = TRUE): void
	{
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		config_set_path('unbound/enable', '');
		PfbConfig::write('dns/pfb_dns_name', 'fw.example.lan');
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::shared())];
		foreach ($settings + ['pfb_dns_interface' => 'lan', 'pfb_dns_sslcertref' => 'cert1'] as $key => $value) {
			config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key($key), 2)[0]] . '/' . $key, $value);
		}
		pfb_dns_proxy_service();
		$this->seedProxy('4242', "4242\n", $up);
		$this->seedRunningGateway('4242');
	}

	/** Unbound is gone: its pidfile names a dead process, and the Resolver is enabled or not. */
	private function unboundDead(bool $resolverEnabled = TRUE): void
	{
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = FALSE;
		if (!$resolverEnabled) {
			config_del_path('unbound/enable');
		}
	}

	/** Another process holds Unbound's PROXYv2 port while Unbound lives; the Resolver is enabled or not. */
	private function foreignHolder(bool $resolverEnabled = TRUE): void
	{
		if (!$resolverEnabled) {
			config_del_path('unbound/enable');
		}
		file_put_contents($GLOBALS['pfb_test_sockstat_output'],
			"USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n"
			. "root dnsmasq 777 5 tcp4 127.0.0.1:5353 *:*\n"
			. "root dnsmasq 777 6 udp4 127.0.0.1:5353 *:*\n");
	}

	/** @param list<string> $lines the gateway's log, one line each */
	private function log(array $lines): void
	{
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], implode("\n", $lines) . "\n");
	}

	/** The gateway reports these parts degraded. @param list<array{part:string,reason:string}> $degraded */
	private function degrade(array $degraded): void
	{
		$this->gatewayStatus(['degraded' => $degraded]);
	}

	private function panel(?array $status = NULL): DOMXPath
	{
		$document = new DOMDocument();
		$previous = libxml_use_internal_errors(TRUE);
		$loaded = $document->loadXML('<root>' . pfb_dns_status_panel($status ?? pfb_dns_status()) . '</root>');
		$errors = array_map(static fn (LibXMLError $error): string => trim($error->message), libxml_get_errors());
		libxml_clear_errors();
		libxml_use_internal_errors($previous);
		$this->assertTrue($loaded, 'the panel is well-formed markup: ' . implode('; ', $errors));

		return new DOMXPath($document);
	}

	/**
	 * @return array{state:string,rows:list<array<string,mixed>>} a transport on loopback and lan, every row in $state for $reason
	 */
	private static function served(string $port, string $state = 'listening', string $reason = ''): array
	{
		return ['state' => 'rows', 'rows' => [
			['interface' => 'Localhost', 'addresses' => ["127.0.0.1:{$port}", "[::1]:{$port}"], 'state' => $state, 'reason' => $reason],
			['interface' => 'LAN', 'addresses' => ["192.0.2.1:{$port}"], 'state' => $state, 'reason' => $reason],
		]];
	}

	// -----------------------------------------------------------------------
	// Service
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> how the backend is lost, and what the Service line says of it */
	public static function lostBackends(): array
	{
		return [
			'the Resolver is disabled' => ['disabled', 'Resolver backend not answering: the DNS Resolver is disabled'],
			'another process holds Unbound\'s port' => ['foreign', 'Resolver backend not answering: dnsmasq (pid 777) holds Unbound\'s port 5353'],
			'Unbound does not answer' => ['dead', 'Resolver backend not answering: Unbound does not answer on 127.0.0.1:5353'],
			'the Resolver is disabled and another process holds the port' => ['disabled and foreign', 'Resolver backend not answering: the DNS Resolver is disabled'],
		];
	}

	#[DataProvider('lostBackends')]
	public function testAReadyGatewayWhoseBackendIsLostSaysWhyInsteadOfStartingOrRunning(string $loss, string $service): void
	{
		// Given a ready gateway, and Unbound serving it
		$this->box();
		$this->assertSame('Running', pfb_dns_status()['service'], 'before: the gateway and Unbound serve');

		// When the backend is lost
		match ($loss) {
			'disabled' => $this->unboundDead(FALSE),
			'foreign' => $this->foreignHolder(),
			'dead' => $this->unboundDead(),
			'disabled and foreign' => $this->foreignHolder(FALSE),
		};
		$status = pfb_dns_status();

		// Then the gateway is still ready, the Service line names the loss, and the panel and the widget's title say the same
		$this->assertTrue(pfb_dns_proxy_ready(), 'the gateway is ready');
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the backend is not');
		$this->assertSame($service, $status['service']);
		$this->assertSame($service, $this->panel($status)->evaluate("string(//tr[@id='pfb-dns-status-service']/td)"));
		$this->assertStringStartsWith("{$service}: ", pfb_dns_widget_status($status)[0]['title']);
	}

	public function testAGatewayThatIsReadyButGivesNoStatusIsStartingNotABackendLoss(): void
	{
		// Given a ready gateway whose control socket does not answer, and Unbound dead: nothing says where it forwards to
		$this->box();
		$this->standInsStop();
		$this->unboundDead();

		// Then the Service line does not blame a backend it cannot name
		$this->assertTrue(pfb_dns_proxy_ready());
		$this->assertSame('Starting', pfb_dns_status()['service']);
	}

	/** @return array<string,array{list<string>,string}> the gateway's log while it is running and not ready, and the Service line */
	public static function logsOfAGatewayThatIsNotReady(): array
	{
		return [
			'the latest start ended with a fatal error' => [
				['starting pid 4100', 'pfb_dns_gateway: old failure', 'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'pfb_dns_gateway: decider: python_enable is off'],
				'Not serving: decider: python_enable is off',
			],
			'the fatal error is followed by supervisor lines' => [
				['starting pid 4242', 'pfb_dns_gateway: cannot start: boom', 'pfb_dns_proxy: restarting in 5 s'],
				'Not serving: cannot start: boom',
			],
			'the last of several fatal lines of the latest start' => [
				['starting pid 4242', 'pfb_dns_gateway: first', 'pfb_dns_gateway: second'],
				'Not serving: second',
			],
			'the latest start has logged no fatal error yet' => [
				['starting pid 4242', 'listening udp+tcp 127.0.0.1:53'],
				'Starting',
			],
			'a fatal error only of an earlier start' => [
				['starting pid 4100', 'pfb_dns_gateway: old failure', 'starting pid 4242'],
				'Starting',
			],
			'a fatal error with no start line before it' => [
				['pfb_dns_gateway: ancient failure'],
				'Starting',
			],
			'no log' => [[], 'Starting'],
		];
	}

	/** @param list<string> $lines */
	#[DataProvider('logsOfAGatewayThatIsNotReady')]
	public function testARunningGatewayThatIsNotReadySaysTheErrorItsLatestStartEndedWithElseStarting(array $lines, string $service): void
	{
		// Given a gateway that lives and never publishes its marker, and its log
		$this->box();
		$this->seedProxy('4242', NULL);
		if ($lines !== []) {
			$this->log($lines);
		}

		// Then the Service line is what the latest start says
		$this->assertTrue(pfb_dns_proxy_running(), 'the gateway lives');
		$this->assertFalse(pfb_dns_proxy_ready(), 'and is not ready');
		$this->assertSame($service, pfb_dns_status()['service']);
	}

	public function testAGatewayThatIsNotRunningIsStoppedWhateverItsLogSays(): void
	{
		// Given a gateway that is not running, and a log whose latest start ended with a fatal error
		$this->box([], FALSE);
		$this->log(['starting pid 4242', 'pfb_dns_gateway: cannot start: boom']);

		// Then it is Stopped, not Not serving
		$this->assertFalse(pfb_dns_proxy_running());
		$this->assertSame('Stopped', pfb_dns_status()['service']);
	}

	public function testTheFatalErrorOfTheLatestStartIsEscapedOnceInThePanel(): void
	{
		$this->box();
		$this->seedProxy('4242', NULL);
		$this->log(['starting pid 4242', 'pfb_dns_gateway: <b>boom</b> & "quoted"']);

		$panel = $this->panel();

		$this->assertSame('Not serving: <b>boom</b> & "quoted"', $panel->evaluate("string(//tr[@id='pfb-dns-status-service']/td)"));
		$this->assertSame(0, $panel->query("//tr[@id='pfb-dns-status-service']//b")->length, 'the error is text, never markup');
	}

	// -----------------------------------------------------------------------
	// degraded
	// -----------------------------------------------------------------------

	public function testAGatewayThatReportsNoDegradedFieldHasNothingDegraded(): void
	{
		// Given a gateway older than the field
		$this->box();

		$status = pfb_dns_status();

		// Then nothing is degraded, the panel has no degraded row, and the mode is the healthy one
		$this->assertSame([], $status['degraded']);
		$this->assertSame(self::MODE_WITH_DNSBL, $status['mode']);
		$this->assertSame(0, $this->panel($status)->query("//tr[starts-with(@id, 'pfb-dns-status-degraded-')]")->length);
	}

	/** @return array<string,array{string,string}> every part the gateway can report, and the one line the panel and the notice say of it */
	public static function degradedParts(): array
	{
		return [
			'dnsbl' => ['dnsbl', 'DNSBL is not blocking: boot timeout'],
			'dnsbl_settings' => ['dnsbl_settings', 'DNSBL settings are only partly read: boot timeout'],
			'dns_name' => ['dns_name', 'DNS Name answers are not served: boot timeout'],
			'ddr' => ['ddr', 'DDR is off: boot timeout'],
			'tls_certificate' => ['tls_certificate', 'DoT, DoH and DoQ are not served: no usable certificate: boot timeout'],
			'acl' => ['acl', 'Client access control is not applied, so every client is forwarded: boot timeout'],
			'statistics' => ['statistics', 'DNSBL statistics are not recorded: boot timeout'],
			'observer' => ['observer', 'The upstream observer is not running: boot timeout'],
		];
	}

	#[DataProvider('degradedParts')]
	public function testEachDegradedPartIsARowOfThePanelUnderServiceAndStaysRunning(string $part, string $text): void
	{
		// Given a healthy box with a gateway that serves everything
		$this->box();
		$this->assertSame([], pfb_dns_status()['degraded'], 'before: nothing is degraded');

		// When the gateway reports the part degraded
		$this->degrade([['part' => $part, 'reason' => 'boot timeout']]);
		$status = pfb_dns_status();
		$panel = $this->panel($status);

		// Then the service still runs, the status lists the part, and the panel has its row right under Service
		$this->assertSame('Running', $status['service']);
		$this->assertSame([['part' => $part, 'reason' => 'boot timeout']], $status['degraded']);
		$this->assertSame("pfb-dns-status-degraded-{$part}", $panel->evaluate("string(//tr[@id='pfb-dns-status-service']/following-sibling::tr[1]/@id)"));
		$this->assertSame('Degraded', $panel->evaluate("string(//tr[@id='pfb-dns-status-degraded-{$part}']/th)"));
		$this->assertSame($text, $panel->evaluate("string(//tr[@id='pfb-dns-status-degraded-{$part}']/td)"));
		$this->assertSame(1, $panel->query("//tr[starts-with(@id, 'pfb-dns-status-degraded-')]")->length, 'one row for one part');
	}

	/** issue #3870: the decider's reason for a missing pfb_unbound.ini passes the status check and is the panel's dnsbl row. */
	public function testAMissingIniIsTheDnsblRowWithTheDecidersReason(): void
	{
		$this->box();
		$this->degrade([['part' => 'dnsbl', 'reason' => 'Failed to load ini configuration. Ini file missing.']]);

		$this->assertSame(
			'DNSBL is not blocking: Failed to load ini configuration. Ini file missing.',
			$this->panel(pfb_dns_status())->evaluate("string(//tr[@id='pfb-dns-status-degraded-dnsbl']/td)")
		);
	}

	public function testSeveralDegradedPartsAreRowsInTheOrderTheGatewayGaveThem(): void
	{
		$this->box();
		$this->degrade([['part' => 'dnsbl', 'reason' => 'a'], ['part' => 'ddr', 'reason' => 'b'], ['part' => 'observer', 'reason' => 'c']]);

		$ids = [];
		foreach ($this->panel()->query("//tr[starts-with(@id, 'pfb-dns-status-degraded-')]") as $row) {
			$ids[] = $row->getAttribute('id');
		}

		$this->assertSame(['pfb-dns-status-degraded-dnsbl', 'pfb-dns-status-degraded-ddr', 'pfb-dns-status-degraded-observer'], $ids);
	}

	public function testADegradedReasonIsEscapedOnceAndNeverMarkup(): void
	{
		$this->box();
		$this->degrade([['part' => 'acl', 'reason' => '<b>x</b> & "q"']]);

		$panel = $this->panel();

		$this->assertSame(
			'Client access control is not applied, so every client is forwarded: <b>x</b> & "q"',
			$panel->evaluate("string(//tr[@id='pfb-dns-status-degraded-acl']/td)")
		);
		$this->assertSame(0, $panel->query("//tr[@id='pfb-dns-status-degraded-acl']//b")->length);
	}

	public function testDnsblNotBlockingChangesTheModeAndNoOtherPartDoes(): void
	{
		// Given a healthy box: the mode says the proxy answers DNSBL blocks
		$this->box();
		$this->assertSame(self::MODE_WITH_DNSBL, pfb_dns_status()['mode']);

		// When another part is degraded, the mode is unchanged
		$this->degrade([['part' => 'ddr', 'reason' => 'no usable name']]);
		$this->assertSame(self::MODE_WITH_DNSBL, pfb_dns_status()['mode']);

		// When DNSBL is degraded, the mode says it does not block, and why, and that the proxy only forwards
		$this->degrade([['part' => 'dnsbl', 'reason' => 'the module did not boot in time']]);
		$this->assertSame(
			'On, with DNSBL: DNSBL is not blocking: the module did not boot in time; the proxy forwards every query',
			pfb_dns_status()['mode']
		);
	}

	public function testNoUsableCertificateMakesEveryListeningEncryptedRowNotServedAndPlainDnsStaysListening(): void
	{
		// Given every transport serving, and plain DNS and every encrypted listener listed as listening
		$this->box(self::ALL_ON);
		$this->gatewayServes([...self::PLAIN, ...self::DOT, ...self::DOH, ...self::DOQ]);
		$this->assertSame(
			['plain' => self::served('53'), 'dot' => self::served('853'), 'doh' => self::served('443'), 'doq' => self::served('8853')],
			pfb_dns_status()['transports'],
			'before: every transport listens'
		);

		// When the gateway reports that it has no usable certificate
		$this->degrade([['part' => 'tls_certificate', 'reason' => 'the PEM holds no private key']]);
		$status = pfb_dns_status();
		$panel = $this->panel($status);

		// Then plain DNS still listens, and every DoT, DoH and DoQ row is not served, for that reason
		$reason = 'no usable certificate: the PEM holds no private key';
		$this->assertSame([
			'plain' => self::served('53'),
			'dot'   => self::served('853', 'not_served', $reason),
			'doh'   => self::served('443', 'not_served', $reason),
			'doq'   => self::served('8853', 'not_served', $reason),
		], $status['transports']);
		foreach (['dot', 'doh', 'doq'] as $transport) {
			$cell = "//div[@id='pfb-dns-status-{$transport}']//tbody/tr[1]/td[3]";
			$this->assertSame('Not served', $panel->evaluate("string({$cell}/span[@class='sr-only'])"), "{$transport}: what a screen reader hears");
			$this->assertSame('Not served', $panel->evaluate("string({$cell}/i/@title)"), "{$transport}: the icon's hover title");
			$this->assertStringContainsString($reason, $panel->evaluate("string({$cell})"), "{$transport}: the reason is shown");
		}
		$this->assertSame('Listening', $panel->evaluate("string(//div[@id='pfb-dns-status-plain']//tbody/tr[1]/td[3]/span[@class='sr-only'])"));
	}

	public function testNoUsableCertificateLeavesARefusedRowAndAnOffTransportAsTheyAre(): void
	{
		// Given DoT refused on lan and listening on loopback, and DoH off
		$this->box(['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '853']);
		$this->gatewayServes([...self::PLAIN, 'dot 127.0.0.1:853', 'dot [::1]:853'], ['dot 192.0.2.1:853' => 'address already in use']);

		// When the gateway has no usable certificate
		$this->degrade([['part' => 'tls_certificate', 'reason' => 'expired']]);
		$transports = pfb_dns_status()['transports'];

		// Then the refusal keeps its own reason, the loopback rows are not served, and DoH stays off
		$this->assertSame([
			['interface' => 'Localhost', 'addresses' => ['127.0.0.1:853', '[::1]:853'], 'state' => 'not_served', 'reason' => 'no usable certificate: expired'],
			['interface' => 'LAN', 'addresses' => ['192.0.2.1:853'], 'state' => 'not_listening', 'reason' => 'address already in use'],
		], $transports['dot']['rows']);
		$this->assertSame(['state' => 'off'], $transports['doh']);
	}

	public function testANonCertificatePartLeavesEveryTransportRowListening(): void
	{
		$this->box(self::ALL_ON);
		$this->gatewayServes([...self::PLAIN, ...self::DOT, ...self::DOH, ...self::DOQ]);
		$this->degrade([['part' => 'dnsbl', 'reason' => 'x'], ['part' => 'acl', 'reason' => 'y']]);

		$this->assertSame(
			['plain' => self::served('53'), 'dot' => self::served('853'), 'doh' => self::served('443'), 'doq' => self::served('8853')],
			pfb_dns_status()['transports']
		);
	}

	public function testAStatusThatClaimsNoGatewayCarriesNoDegradedPart(): void
	{
		// Given a moved box whose gateway reports DNSBL degraded
		$this->box();
		$this->degrade([['part' => 'dnsbl', 'reason' => 'boot timeout']]);
		$GLOBALS['pfb']['unbound_state'] = PfbToggle::On;
		$this->assertSame([['part' => 'dnsbl', 'reason' => 'boot timeout']], pfb_dns_status()['degraded'], 'before: the row is listed');
		$this->assertSame(1, $this->panel()->query("//tr[starts-with(@id, 'pfb-dns-status-degraded-')]")->length, 'before: the panel has the row');

		// When the Resolver snapshot is gone: pfB-DNS is on with nothing moved, so no gateway is claimed
		config_del_path(self::SAVED);
		$status = pfb_dns_status();

		// Then the gateway's degraded rows are not carried over: no degraded part and no row
		$this->assertNull($status['transports']);
		$this->assertSame([], $status['degraded'] ?? [], 'a status that claims no gateway lists no degraded part');
		$this->assertSame(0, $this->panel($status)->query("//tr[starts-with(@id, 'pfb-dns-status-degraded-')]")->length);
	}
}
