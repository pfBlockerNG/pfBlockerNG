<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- the one startup notice (id `pfBlockerNG DNS Proxy startup`) names what pfB-DNS runs without. With the gateway ready and
 * its applied status readable, every part the gateway reports `degraded` is a problem of the notice in the panel's wording, and so is a
 * Resolver backend that does not answer (the Resolver is disabled, another process holds Unbound's port, or Unbound does not answer on
 * the gateway's upstream), in the panel's own words for the cause. A ready gateway whose backend is lost after the activation wait ran
 * out is checked the same way: it files the backend problem and never closes the notice. A gateway that gives no status cannot be
 * judged: it files nothing and closes nothing.
 *
 * The rc script is the real generator's output (pfb_dns_proxy_service()); the gateway is a stand-in on a real Unix socket answering the
 * applied status as the real one does; the activation wait runs on a virtual clock.
 */
#[CoversFunction('pfb_dns_proxy_startup_check')]
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
#[CoversFunction('pfb_dns_proxy_backend_problem')]
final class DnsProxyStartupCheckDegradedTest extends TestCase
{
	use DnsProxyReadySeedTrait;
	use LiveListenerStandIn;

	private const ID = 'pfBlockerNG DNS Proxy startup';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const HEAD = 'pfB-DNS started with problems: ';
	private const TAIL = ' Correct the settings on "DNS" > "General" or the cause named, then use "Run Now" on "Update".';

	private const DOT_ON = ['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '853'];
	private const PLAIN = ['udp+tcp 192.0.2.1:53', 'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53'];
	private const DOT_LOOPBACK = ['dot 127.0.0.1:853', 'dot [::1]:853'];

	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_file_notices', 'pfb_test_valid_pids', 'pfb_test_rcfile_dir', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles',
		'pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_configured_ipv6', 'pfb_test_configured_ip_addresses',
		'pfb_test_interfaces', 'pfb_test_try_lock_fail', 'pfb_test_lock_held', 'pfb_test_lock_events', 'pfb_test_service_calls',
	];

	private string $dir = '';
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_startup_degraded_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->dir,
			'log' => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
			'dns_proxy_log' => "{$this->dir}/dns_proxy.log",
			'dns_proxy_cert' => "{$this->dir}/etc/pfb_dns/tls.pem",
			'dns_proxy_cert_legacy' => "{$this->dir}/chroot/pfb_dns_cert.pem",
			'dns_proxy_ctl' => "{$this->dir}/ctl.sock",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
		$this->clearProxyFiles();
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
		$this->savedGlobals = [];
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->dir);
	}

	/**
	 * A moved box with the Resolver enabled and a ready gateway that serves every listener its rc script names; Unbound serves it.
	 *
	 * @param array<string,string> $settings
	 * @param array<string,?string> $v4 interface => address (NULL: configured, no address)
	 */
	private function box(array $settings = [], array $v4 = ['lan' => '192.0.2.1']): void
	{
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		config_set_path('unbound/enable', '');
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::shared())];
		foreach ($settings + ['pfb_dns_interface' => 'lan', 'pfb_dns_sslcertref' => 'cert1', 'pfb_dns_name' => 'fw.example.lan'] as $key => $value) {
			config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key($key), 2)[0]] . '/' . $key, $value);
		}
		$names = array_keys($v4);
		$GLOBALS['pfb_test_interface_ip'] = $v4;
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_info'] = [];
		foreach ($names as $name) {
			$GLOBALS['pfb_test_interface_info'][$name] = ['status' => 'up', 'enable' => TRUE];
		}
		$GLOBALS['pfb_test_interfaces'] = array_fill_keys($names, '');
		pfb_dns_proxy_service();
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE, 'the generator wrote the rc script the check reads');
		$this->proxyServes();
		$this->seedRunningGateway();
	}

	/** @return list<string> the text of every standing notice of the startup id */
	private function startupTexts(): array
	{
		return array_values(array_map(
			static fn (array $notice): string => $notice['notice'],
			array_filter($GLOBALS['pfb_test_file_notices'], static fn (array $notice): bool => $notice['id'] === self::ID)
		));
	}

	private function problemText(string ...$sentences): string
	{
		return self::HEAD . implode(' ', $sentences) . self::TAIL;
	}

	/** @param list<array{part:string,reason:string}> $degraded */
	private function degrade(array $degraded): void
	{
		$this->gatewayStatus(['degraded' => $degraded]);
	}

	/** @return array{PfbFlockClockFixture,string} the virtual clock, and the confirmation's name in the namespace it was loaded into */
	private function clockedConfirm(): array
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_dns_proxy_confirm_ready', 'pfb_dns_proxy_await_ready'], ['PFB_DNS_PROXY_START_WAIT' => 1]);

		return [$clock, $namespace . '\\pfb_dns_proxy_confirm_ready'];
	}

	/** Unbound is lost in one of the ways the status names; what the notice and the status both say of it. */
	private function loseTheBackend(string $loss): void
	{
		if ($loss === 'foreign') {
			file_put_contents($GLOBALS['pfb_test_sockstat_output'],
				"USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\nroot dnsmasq 777 5 tcp4 127.0.0.1:5353 *:*\nroot dnsmasq 777 6 udp4 127.0.0.1:5353 *:*\n");
			return;
		}
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = FALSE;
		if ($loss === 'disabled') {
			config_del_path('unbound/enable');
		}
	}

	/** @return array<string,array{string,string}> how the backend is lost, and the cause the notice names */
	public static function lostBackends(): array
	{
		return [
			'the Resolver is disabled' => ['disabled', 'the DNS Resolver is disabled'],
			'another process holds Unbound\'s port' => ['foreign', 'dnsmasq (pid 777) holds Unbound\'s port 5353'],
			'Unbound does not answer' => ['dead', 'Unbound does not answer on 127.0.0.1:5353'],
		];
	}

	// -----------------------------------------------------------------------
	// degraded rows
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> every part the gateway can report, and the one sentence the panel and the notice say of it */
	public static function degradedParts(): array
	{
		return [
			'dnsbl' => ['dnsbl', 'DNSBL is not blocking: boot timeout.'],
			'dnsbl_settings' => ['dnsbl_settings', 'DNSBL settings are only partly read: boot timeout.'],
			'dns_name' => ['dns_name', 'DNS Name answers are not served: boot timeout.'],
			'ddr' => ['ddr', 'DDR is off: boot timeout.'],
			'tls_certificate' => ['tls_certificate', 'DoT, DoH and DoQ are not served: no usable certificate: boot timeout.'],
			'acl' => ['acl', 'Client access control is not applied, so every client is forwarded: boot timeout.'],
			'statistics' => ['statistics', 'DNSBL statistics are not recorded: boot timeout.'],
			'observer' => ['observer', 'The upstream observer is not running: boot timeout.'],
		];
	}

	#[DataProvider('degradedParts')]
	public function testEachDegradedPartOfAReadyGatewayIsAProblemOfTheNotice(string $part, string $sentence): void
	{
		// Given a ready gateway that serves everything, and a standing notice of an earlier problem
		$this->box();
		file_notice(self::ID, 'pfB-DNS started with problems: an earlier problem.', 'pfBlockerNG', '/pfblockerng/pfblockerng_dns_general.php', 2);
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertSame([], $this->startupTexts(), 'before: a gateway with nothing degraded closes the notice');

		// When the gateway reports the part degraded
		$this->degrade([['part' => $part, 'reason' => 'boot timeout']]);
		pfb_dns_proxy_startup_check(TRUE);

		// Then one notice names it, in the panel's words
		$this->assertSame([$this->problemText($sentence)], $this->startupTexts());
	}

	public function testSeveralDegradedPartsAreOneNoticeInTheOrderTheGatewayGaveThem(): void
	{
		$this->box();
		$this->degrade([['part' => 'tls_certificate', 'reason' => 'expired'], ['part' => 'dnsbl', 'reason' => 'no build']]);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame(
			[$this->problemText('DoT, DoH and DoQ are not served: no usable certificate: expired.', 'DNSBL is not blocking: no build.')],
			$this->startupTexts()
		);
	}

	public function testAGatewayThatReportsNoDegradedFieldAddsNoProblem(): void
	{
		$this->box();

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([], $this->startupTexts());
	}

	// -----------------------------------------------------------------------
	// the Resolver backend
	// -----------------------------------------------------------------------

	#[DataProvider('lostBackends')]
	public function testAReadyGatewayWhoseBackendIsLostAfterTheActivationWaitIsFiledAndNeverClosesTheNotice(string $loss, string $cause): void
	{
		// Given a ready gateway with Unbound serving it, and a standing notice that an earlier check filed
		$this->box();
		[$clock, $confirm] = $this->clockedConfirm();
		$this->assertTrue($confirm(), 'before: the gateway and Unbound serve');
		file_notice(self::ID, 'pfB-DNS started with problems: an earlier problem.', 'pfBlockerNG', '/pfblockerng/pfblockerng_dns_general.php', 2);

		// When the backend is lost and the activation wait runs out
		$this->loseTheBackend($loss);
		[$clock, $confirm] = $this->clockedConfirm();
		$ready = $confirm();

		// Then the wait ran out, the gateway is ready, and the notice names the backend; the standing notice was not closed
		$this->assertFalse($ready, 'the proxy does not serve');
		$this->assertTrue(pfb_dns_proxy_ready(), 'the gateway is ready');
		$this->assertSame(array_fill(0, 10, 100000), $clock->sleeps, 'the wait ran its whole budget');
		$texts = $this->startupTexts();
		$this->assertSame($this->problemText("the DNS Resolver backend does not answer: {$cause}."), end($texts), 'the newest row names the backend');
		$this->assertContains('pfB-DNS started with problems: an earlier problem.', $texts, 'the standing row is not closed');
	}

	#[DataProvider('lostBackends')]
	public function testALostBackendIsAProblemOfAStartupCheckOfAReadyGateway(string $loss, string $cause): void
	{
		$this->box();
		$this->loseTheBackend($loss);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([$this->problemText("the DNS Resolver backend does not answer: {$cause}.")], $this->startupTexts());
	}

	public function testAGatewayThatGivesNoStatusIsNotBlamedForABackendItCannotNameAndNothingIsClosed(): void
	{
		// Given a ready gateway whose control socket answers nothing, Unbound dead, and a standing notice
		$this->box();
		$this->standInsStop();
		$this->loseTheBackend('dead');
		file_notice(self::ID, 'pfB-DNS started with problems: an earlier problem.', 'pfBlockerNG', '/pfblockerng/pfblockerng_dns_general.php', 2);

		// When the check runs
		pfb_dns_proxy_startup_check(TRUE);

		// Then it neither names a backend nor closes what stands
		$this->assertSame(['pfB-DNS started with problems: an earlier problem.'], $this->startupTexts());
	}

	public function testProblemsAreNamedBackendThenListenersThenDegradedPartsThenWarnings(): void
	{
		// Given DoT missing on lan, a selected interface with no address, a degraded DNSBL, and a dead backend
		$this->box(self::DOT_ON + ['pfb_dns_interface' => 'lan,opt1'], ['lan' => '192.0.2.1', 'opt1' => NULL]);
		$this->gatewayServes([...self::PLAIN, ...self::DOT_LOOPBACK]);
		$this->degrade([['part' => 'dnsbl', 'reason' => 'no build']]);
		$this->loseTheBackend('dead');

		pfb_dns_proxy_startup_check(TRUE);

		// Then one notice, in that order
		$this->assertSame([$this->problemText(
			'the DNS Resolver backend does not answer: Unbound does not answer on 127.0.0.1:5353.',
			'DoT is not served on 192.0.2.1:853: the gateway did not report it listening.',
			'DNSBL is not blocking: no build.',
			'plain DNS interface opt1 has no usable address; it adds no listener.'
		)], $this->startupTexts());
	}

	public function testANotReadyGatewayKeepsItsOwnSentenceAndNamesNoBackend(): void
	{
		// Given a gateway that lives and never became ready, and Unbound dead
		$this->box();
		$this->proxyLivesButNeverServes();
		$this->loseTheBackend('dead');

		pfb_dns_proxy_startup_check(FALSE);

		$this->assertSame(
			[$this->problemText('pfB-DNS is not serving: the DNS proxy did not become ready within ' . PFB_DNS_PROXY_START_WAIT . ' s.')],
			$this->startupTexts()
		);
	}
}
