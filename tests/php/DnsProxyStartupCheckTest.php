<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3538 -- pfB-DNS startup problems become one GUI notice.
 *
 * After every start (an apply, the boot start) and on the cron tick while the proxy is meant to serve,
 * pfb_dns_proxy_startup_check() raises ONE notice, id `pfBlockerNG DNS Proxy startup`, naming every problem, and a check that
 * finds none closes the standing notice of that id. Three kinds of problem, in this order: the proxy never became ready (with the
 * gateway's last error from its log); a listener the rc script's command names that the running gateway does not serve, as the
 * gateway itself lists them on its control socket (issue #3625), with the reason it refused that listener when it did; and a setting
 * skipped, or an interface that adds no listener, while the command line was built. A gateway that gives no list judges nothing: no
 * listener problem, and nothing closed. The notices `pfBlockerNG DNS Proxy` (rollback) and `pfBlockerNG DNS Proxy certificate` are
 * never closed or replaced by it.
 *
 * pfSense's close_notice($id) removes ONE row per call (the one keyed $id, else the oldest row of that id), and file_notice()
 * appends a row for every changed text, so "closed" here means every row of the id, which the double mirrors.
 *
 * The rc script is the real generator's output (pfb_dns_proxy_service()); the gateway is a stand-in process on a real Unix socket
 * that answers the listener list as the real one does (support/ListenerControlServer.php); the log is a real file in the shape the
 * gateway writes, read only for the error of a start that never became ready; readiness is a seeded marker; no test waits: an
 * explicit $ready, or the production wait on the virtual clock.
 */
#[CoversFunction('pfb_dns_proxy_startup_check')]
#[CoversFunction('pfb_dns_proxy_plain_listen')]
#[CoversFunction('pfb_dns_proxy_log_lines')]
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
final class DnsProxyStartupCheckTest extends TestCase
{
	use DnsProxyReadySeedTrait;
	use LiveListenerStandIn;

	private const ID = 'pfBlockerNG DNS Proxy startup';
	private const URL = '/pfblockerng/pfblockerng_dns.php';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';

	private const HEAD = 'pfB-DNS started with problems: ';
	private const TAIL = ' Correct the settings on the pfB-DNS page or the cause named, then run an Update.';

	private const DOT_ON = ['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '853'];
	private const DOH_ON = ['pfb_dns_doh' => 'on', 'pfb_dns_doh_interface' => 'lan', 'pfb_dns_doh_port' => '443'];
	private const DOQ_ON = ['pfb_dns_doq' => 'on', 'pfb_dns_doq_interface' => 'lan', 'pfb_dns_doq_port' => '8853'];

	private const PLAIN = ['udp+tcp 192.0.2.1:53', 'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53'];
	private const DOT = ['dot 192.0.2.1:853', 'dot 127.0.0.1:853', 'dot [::1]:853'];
	private const DOT_LOOPBACK = ['dot 127.0.0.1:853', 'dot [::1]:853'];
	private const DOQ_ON_853 = ['pfb_dns_doq' => 'on', 'pfb_dns_doq_interface' => 'lan', 'pfb_dns_doq_port' => '853'];

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
		$this->dir = sys_get_temp_dir() . '/pfb_dns_startup_' . bin2hex(random_bytes(6));
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

	// -----------------------------------------------------------------------
	// fixtures
	// -----------------------------------------------------------------------

	/**
	 * A moved box whose rc script is generated from these pfB-DNS settings (interface list `lan` unless given): lan has
	 * 192.0.2.1, and what the caller adds. Plain DNS is on lan and loopback, port 53; each transport that is on is on lan and loopback.
	 *
	 * @param array<string,string> $settings
	 * @param array<string,?string> $v4 interface => address (NULL: configured, no address)
	 * @param array<string,string> $v6
	 * @param list<string> $down interfaces that are configured and down
	 */
	private function box(array $settings = [], array $v4 = ['lan' => '192.0.2.1'], array $v6 = [], array $down = []): void
	{
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::shared())];
		foreach ($settings + ['pfb_dns_interface' => 'lan', 'pfb_dns_sslcertref' => 'cert1'] as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
		$names = array_keys($v4 + $v6);
		$GLOBALS['pfb_test_interface_ip'] = $v4;
		$GLOBALS['pfb_test_configured_ipv6'] = $v6;
		$GLOBALS['pfb_test_interface_info'] = [];
		foreach ($names as $name) {
			$GLOBALS['pfb_test_interface_info'][$name] = ['status' => in_array($name, $down, TRUE) ? 'down' : 'up', 'enable' => TRUE];
		}
		$GLOBALS['pfb_test_interfaces'] = array_fill_keys($names, '');
		pfb_dns_proxy_service();
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE, 'the generator wrote the rc script the check reads');
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

	/** The gateway lists every listener of the default box with DoT on: plain DNS and DoT, on lan and loopback. */
	private function gatewayServesEverything(): void
	{
		$this->gatewayServes([...self::PLAIN, ...self::DOT]);
	}

	/** The gateway serves DoT on loopback only: DoT on lan is neither listed nor refused. */
	private function gatewayLacksDotOnLan(): void
	{
		$this->gatewayServes([...self::PLAIN, ...self::DOT_LOOPBACK]);
	}

	/** @return list<array{string,string}> the (id, text) of each notice standing, in queue order */
	private function standing(): array
	{
		return array_values(array_map(
			static fn (array $notice): array => [$notice['id'], $notice['notice']],
			$GLOBALS['pfb_test_file_notices']
		));
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

	private function fileOther(string $id, string $text): void
	{
		file_notice($id, $text, 'pfBlockerNG', self::URL, 2);
	}

	// -----------------------------------------------------------------------
	// Row 1 -- the proxy never became ready
	// -----------------------------------------------------------------------

	public function testAStartThatNeverBecameReadyIsFiledWithTheLastGatewayErrorOfTheLog(): void
	{
		// Given a moved box and a log with two gateway errors
		$this->box();
		$this->log('pfb_dns_gateway: first error', 'cannot listen on 192.0.2.1:53: bind: address already in use', 'pfb_dns_gateway: cannot start: second error');

		// When the check runs after a start that never became ready
		pfb_dns_proxy_startup_check(FALSE);

		// Then one notice names the failure and quotes the LAST gateway error only
		$this->assertSame([self::ID], array_column($GLOBALS['pfb_test_file_notices'], 'id'));
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertSame(
			$this->problemText('pfB-DNS is not serving: the DNS proxy did not become ready within ' . PFB_DNS_PROXY_START_WAIT . ' s (last gateway error: pfb_dns_gateway: cannot start: second error).'),
			$notice['notice']
		);
		$this->assertSame(self::URL, $notice['url']);
		$this->assertSame('pfBlockerNG', $notice['category']);
		$this->assertSame(2, $notice['priority']);
	}

	/** @return array<string,array{?string}> a log that says nothing about a gateway error: none, empty, unreadable (a directory), or only other lines */
	public static function logsWithoutAGatewayError(): array
	{
		return [
			'no log file' => [NULL],
			'an empty log' => [''],
			'a log that is a directory' => ['<dir>'],
			'only other lines' => ["cannot listen on 192.0.2.1:53: bind: address already in use\nlistening udp+tcp 127.0.0.1:53\n"],
		];
	}

	#[DataProvider('logsWithoutAGatewayError')]
	public function testANotReadyStartWithNoGatewayErrorInTheLogQuotesNone(?string $content): void
	{
		$this->box();
		$path = $GLOBALS['pfb']['dns_proxy_log'];
		if ($content === '<dir>') {
			mkdir($path);
		} elseif ($content !== NULL) {
			file_put_contents($path, $content);
		}

		pfb_dns_proxy_startup_check(FALSE);

		$this->assertSame(
			[$this->problemText('pfB-DNS is not serving: the DNS proxy did not become ready within ' . PFB_DNS_PROXY_START_WAIT . ' s.')],
			$this->startupTexts()
		);
	}

	public function testANotReadyStartDoesNotCompareListenersButStillReportsTheWarnings(): void
	{
		// Given a gateway that serves nothing (a probe of it would name every listener), a last log error, and a selected interface that is down
		$this->box(['pfb_dns_interface' => 'lan,opt1'], ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'], [], ['opt1']);
		$this->gatewayServes([]);
		$this->log('pfb_dns_gateway: gone');

		pfb_dns_proxy_startup_check(FALSE);

		// Then the not-ready sentence, then the warning; no "is not served on" (nothing to compare)
		$this->assertSame(
			[$this->problemText(
				'pfB-DNS is not serving: the DNS proxy did not become ready within ' . PFB_DNS_PROXY_START_WAIT . ' s (last gateway error: pfb_dns_gateway: gone).',
				'plain DNS interface opt1 is down or disabled; it adds no listener.'
			)],
			$this->startupTexts()
		);
	}

	public function testANotReadyStartWithNoSnapshotStillNamesTheFailure(): void
	{
		// Given no snapshot (nothing stored: the rollback of this very start may already have consumed it)
		$this->log('pfb_dns_gateway: bind failed');

		pfb_dns_proxy_startup_check(FALSE);

		$this->assertSame(
			[$this->problemText('pfB-DNS is not serving: the DNS proxy did not become ready within ' . PFB_DNS_PROXY_START_WAIT . ' s (last gateway error: pfb_dns_gateway: bind failed).')],
			$this->startupTexts()
		);
	}

	public function testAHostileGatewayErrorIsQuotedVerbatimAndRaisesNothing(): void
	{
		$this->box();
		$this->log('pfb_dns_gateway: <script>alert(1)</script>');

		pfb_dns_proxy_startup_check(FALSE);

		$this->assertStringContainsString('(last gateway error: pfb_dns_gateway: <script>alert(1)</script>).', $this->startupTexts()[0], 'file_notice() encodes it itself: never pre-escape');
	}

	/** @return array<string,array{list<string>,list<string>,?int,string}> log before the size is taken, lines appended after it, how far past the log's end the size is (NULL: no size is taken), and the error quoted */
	public static function logWindowsOfANotReadyStart(): array
	{
		// 70,000 bytes of another writer's lines: more than the 64 KiB the log is read within
		$chatter = array_fill(0, 700, str_repeat('f', 99));
		return [
			'an error older than the last 64 KiB of the log' => [['pfb_dns_gateway: too old', ...$chatter], [], NULL, ''],
			'an error inside the last 64 KiB of the log' => [[...$chatter, 'pfb_dns_gateway: recent'], [], NULL, 'pfb_dns_gateway: recent'],
			'an error of the start, after the size taken before it' => [['pfb_dns_gateway: before the start'], ['pfb_dns_gateway: of the start'], 0, 'pfb_dns_gateway: of the start'],
			'a log rotated to less than the size taken before the start' => [['pfb_dns_gateway: rotated'], [], 4096, 'pfb_dns_gateway: rotated'],
		];
	}

	/**
	 * @param list<string> $before
	 * @param list<string> $after
	 */
	#[DataProvider('logWindowsOfANotReadyStart')]
	public function testANotReadyStartQuotesOnlyAGatewayErrorInsideTheWindowItIsJudgedBy(array $before, array $after, ?int $past, string $quote): void
	{
		// Given a moved box, a log of $before, and the size taken after it by the caller that made the start (none: a tick that made no start)
		$this->box();
		$this->log($before);
		$since = ($past === NULL) ? NULL : pfb_dns_proxy_log_size() + $past;
		if ($after !== []) {
			file_put_contents($GLOBALS['pfb']['dns_proxy_log'], implode("\n", $after) . "\n", FILE_APPEND);
		}

		// When the check judges the start as not ready
		pfb_dns_proxy_startup_check(FALSE, $since);

		// Then only an error inside the last 64 KiB, and after the size when one was taken, is quoted
		$this->assertSame(
			[$this->problemText('pfB-DNS is not serving: the DNS proxy did not become ready within ' . PFB_DNS_PROXY_START_WAIT . ' s' . ($quote === '' ? '' : " (last gateway error: {$quote})") . '.')],
			$this->startupTexts()
		);
	}

	// -----------------------------------------------------------------------
	// Rows 2, 3 -- a listener the command names that the gateway does not serve
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string,string}> the kind the gateway refused, the kind it serves on the same host:port, and the refused one's label */
	public static function kindsOnOneAddress(): array
	{
		return [
			'DoT refused, DoQ served on the same address' => ['dot', 'doq', 'DoT'],
			'DoQ refused, DoT served on the same address' => ['doq', 'dot', 'DoQ'],
		];
	}

	#[DataProvider('kindsOnOneAddress')]
	public function testAListenerTheGatewayRefusedIsNamedWithItsReasonAndNotTheOtherKindOnTheSameAddress(string $refused, string $served, string $label): void
	{
		// Given DoT and DoQ both on port 853 of lan + loopback, one kind refused on lan with its reason and the other served there
		$this->box(self::DOT_ON + self::DOQ_ON_853);
		$this->gatewayServes(
			[...self::PLAIN, "{$refused} 127.0.0.1:853", "{$refused} [::1]:853", "{$served} 192.0.2.1:853", "{$served} 127.0.0.1:853", "{$served} [::1]:853"],
			["{$refused} 192.0.2.1:853" => "bind: can't assign requested address"]
		);

		pfb_dns_proxy_startup_check(TRUE);

		// Then one sentence names the refused kind with its reason, and nothing is said about the other
		$this->assertSame(
			[$this->problemText("{$label} is not served on 192.0.2.1:853: bind: can't assign requested address.")],
			$this->startupTexts()
		);
		$this->assertSame(self::URL, $GLOBALS['pfb_test_file_notices'][0]['url']);
	}

	public function testADohListenerTheGatewayNeverReportedIsNamedWithoutAReason(): void
	{
		$this->box(self::DOH_ON);
		$this->gatewayServes([...self::PLAIN, 'doh 127.0.0.1:443', 'doh [::1]:443']);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame(
			[$this->problemText('DoH is not served on 192.0.2.1:443: the gateway did not report it listening.')],
			$this->startupTexts()
		);
	}

	public function testARefusalOfAnotherKindOnTheSameAddressIsNeverBorrowed(): void
	{
		// Given DoT and DoQ on port 853, DoQ refused on lan, and DoT on lan neither listed nor refused
		$this->box(self::DOT_ON + self::DOQ_ON_853);
		$this->gatewayServes([...self::PLAIN, ...self::DOT_LOOPBACK, 'doq 127.0.0.1:853', 'doq [::1]:853'], ['doq 192.0.2.1:853' => 'bind: address already in use']);

		pfb_dns_proxy_startup_check(TRUE);

		// Then DoT on lan is not said to be refused for DoQ's reason, and DoQ keeps its own
		$this->assertSame(
			[$this->problemText(
				'DoT is not served on 192.0.2.1:853: the gateway did not report it listening.',
				'DoQ is not served on 192.0.2.1:853: bind: address already in use.'
			)],
			$this->startupTexts()
		);
	}

	public function testEveryTransportIsNamedByItsLabelAndEveryMissingListenerAlone(): void
	{
		// Given plain DNS, DoT, DoH and DoQ on lan + loopback, and a gateway that lists only loopback, refusing plain DNS on lan
		$this->box(self::DOT_ON + self::DOH_ON + self::DOQ_ON);
		$this->gatewayServes(
			[
				'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53', 'dot 127.0.0.1:853', 'dot [::1]:853',
				'doh 127.0.0.1:443', 'doh [::1]:443', 'doq 127.0.0.1:8853', 'doq [::1]:8853',
			],
			['udp+tcp 192.0.2.1:53' => 'listen tcp 192.0.2.1:53: bind: address already in use']
		);

		pfb_dns_proxy_startup_check(TRUE);

		// Then one sentence for each address that is missing, in the order plain, DoT, DoH, DoQ; the ones served are not named
		$this->assertSame(
			[$this->problemText(
				'Plain DNS is not served on 192.0.2.1:53: listen tcp 192.0.2.1:53: bind: address already in use.',
				'DoT is not served on 192.0.2.1:853: the gateway did not report it listening.',
				'DoH is not served on 192.0.2.1:443: the gateway did not report it listening.',
				'DoQ is not served on 192.0.2.1:8853: the gateway did not report it listening.'
			)],
			$this->startupTexts()
		);
	}

	// -----------------------------------------------------------------------
	// Row 4 -- a gateway that serves every listener closes the standing notice
	// -----------------------------------------------------------------------

	public function testAGatewayThatServesEveryListenerClosesTheStandingStartupNotice(): void
	{
		// Given a standing startup notice from an earlier start
		$this->box(self::DOT_ON);
		$this->fileOther(self::ID, 'pfB-DNS started with problems: DoT is not served on 192.0.2.1:853: old.');
		$this->assertCount(1, $this->startupTexts(), 'before: the notice stands');
		$this->gatewayServesEverything();

		// When the check asks the gateway, which lists every listener of the command
		pfb_dns_proxy_startup_check(TRUE);

		// Then the notice is gone
		$this->assertSame([], $this->standing());
	}

	// -----------------------------------------------------------------------
	// Row 5 -- a healthy start closes its own notice and nothing else
	// -----------------------------------------------------------------------

	public function testAHealthyStartClosesTheStartupNoticeAndLeavesTheOtherTwoByteIdentical(): void
	{
		// Given three standing notices
		$this->box(self::DOT_ON);
		$this->fileOther(self::ID, 'pfB-DNS started with problems: DoT is not served on 192.0.2.1:853: old.');
		$this->fileOther('pfBlockerNG DNS Proxy', 'pfB-DNS: the DNS proxy did not become ready; <rolled back> & "restored".');
		$this->fileOther('pfBlockerNG DNS Proxy certificate', 'pfB-DNS: DoT, DoH and DoQ got no new certificate: no certificate is selected.');
		$before = get_notices();
		$this->assertCount(3, $before, 'before: all three stand');
		$this->assertSame([self::ID, 'pfBlockerNG DNS Proxy', 'pfBlockerNG DNS Proxy certificate'], array_column(array_values($before), 'id'));
		$this->gatewayServesEverything();

		// When the next start is healthy
		pfb_dns_proxy_startup_check(TRUE);

		// Then the startup notice is gone and the other two are the very rows that stood
		$after = get_notices();
		$this->assertIsArray($after);
		$this->assertSame(['pfBlockerNG DNS Proxy', 'pfBlockerNG DNS Proxy certificate'], array_column(array_values($after), 'id'));
		unset($before[array_key_first($before)]);
		$this->assertSame(json_encode($before), json_encode($after));
	}

	public function testAHealthyStartWithNothingStandingWritesNothing(): void
	{
		$this->box(self::DOT_ON);
		$this->gatewayServesEverything();

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
		$this->assertFalse(is_file("{$this->dir}/pfb.err") && str_contains((string) file_get_contents("{$this->dir}/pfb.err"), 'started with problems'), 'and no problem was logged');
	}

	// -----------------------------------------------------------------------
	// Rows 6, 7 -- what building the command line warned about
	// -----------------------------------------------------------------------

	/** @return array<string,array{array<string,?string>,list<string>,string}> */
	public static function interfaceThatAddsNoListener(): array
	{
		$v4 = ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'];
		return [
			'down' => [$v4, ['opt1'], 'plain DNS interface opt1 is down or disabled; it adds no listener.'],
			'no address' => [['lan' => '192.0.2.1', 'opt1' => NULL], [], 'plain DNS interface opt1 has no usable address; it adds no listener.'],
		];
	}

	/**
	 * @param array<string,?string> $v4
	 * @param list<string> $down
	 */
	#[DataProvider('interfaceThatAddsNoListener')]
	public function testASelectedInterfaceThatAddsNoListenerIsNamedBesideAHealthyStart(array $v4, array $down, string $sentence): void
	{
		// Given every listener of the command serves, and one selected interface added none
		$this->box(['pfb_dns_interface' => 'lan,opt1'] + self::DOT_ON, $v4, [], $down);
		$this->gatewayServesEverything();

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([$this->problemText($sentence)], $this->startupTexts());
	}

	public function testAnUnknownSelectedInterfaceIsNamedAsStored(): void
	{
		$this->box(['pfb_dns_interface' => 'lan,wan9'] + self::DOT_ON);
		$this->gatewayServesEverything();

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([$this->problemText('plain DNS interface "wan9" is not a configured interface; it is skipped.')], $this->startupTexts());
	}

	public function testAStoredDotPortTheGatewayCouldNotParseIsNamed(): void
	{
		// Given DoT on with a stored port that is no port: the command has no DoT at all
		$this->box(['pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => 'abc']);
		$this->gatewayServes(self::PLAIN);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame(
			[$this->problemText('the stored DoT port is not a whole number from 1 to 65535; DoT is not served.')],
			$this->startupTexts()
		);
	}

	public function testAPlainListThatNamesNoInterfaceSaysPlainDnsIsServedOnLoopbackOnly(): void
	{
		// Given a stored plain list of separators only: loopback still serves, and the sentence says so
		$this->box(['pfb_dns_interface' => ',']);
		$this->gatewayServes(['udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53']);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame(
			[$this->problemText('the stored plain DNS interface list names no interface; plain DNS is served on loopback only.')],
			$this->startupTexts()
		);
	}

	public function testTheListenersComeBeforeTheWarningsInTheNotice(): void
	{
		$this->box(['pfb_dns_interface' => 'lan,opt1'] + self::DOT_ON, ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'], [], ['opt1']);
		$this->gatewayLacksDotOnLan();

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame(
			[$this->problemText(
				'DoT is not served on 192.0.2.1:853: the gateway did not report it listening.',
				'plain DNS interface opt1 is down or disabled; it adds no listener.'
			)],
			$this->startupTexts()
		);
	}

	// -----------------------------------------------------------------------
	// Row 8 -- an IPv6 address is matched in the form the gateway prints
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> how the rc script may spell the address pfSense reported */
	public static function ipv6Spellings(): array
	{
		return ['compressed' => ['2001:db8::1'], 'zero padded' => ['2001:0db8::0001'], 'upper case, expanded' => ['2001:DB8:0:0:0:0:0:1']];
	}

	#[DataProvider('ipv6Spellings')]
	public function testAnIpv6ListenerIsMatchedAgainstTheBracketedCompressedFormTheGatewayPrints(string $spelling): void
	{
		$this->box(self::DOT_ON, ['lan' => '192.0.2.1'], ['lan' => $spelling]);
		$this->assertStringContainsString("--dot-listen '{$spelling}'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the command names it as given');
		$this->gatewayServes([
			'udp+tcp 192.0.2.1:53', 'udp+tcp [2001:db8::1]:53', 'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53',
			'dot 192.0.2.1:853', 'dot [2001:db8::1]:853', 'dot 127.0.0.1:853', 'dot [::1]:853',
		]);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([], $this->startupTexts(), 'no problem: the same listener, spelled the other way');
	}

	public function testTheReasonOfAnIpv6ListenerIsFoundByItsBracketedCompressedForm(): void
	{
		// Given the rc script spells the address in full, and the gateway lists and refuses it in the form it prints
		$this->box(self::DOT_ON, ['lan' => '192.0.2.1'], ['lan' => '2001:0db8::0001']);
		$this->gatewayServes(
			[
				'udp+tcp 192.0.2.1:53', 'udp+tcp [2001:db8::1]:53', 'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53',
				'dot 192.0.2.1:853', 'dot 127.0.0.1:853', 'dot [::1]:853',
			],
			['dot [2001:db8::1]:853' => 'bind: cannot assign requested address']
		);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame(
			[$this->problemText('DoT is not served on [2001:db8::1]:853: bind: cannot assign requested address.')],
			$this->startupTexts()
		);
	}

	// -----------------------------------------------------------------------
	// Rows 9, 10 -- a gateway that gives no list judges nothing; the log is not what a listener is judged by
	// -----------------------------------------------------------------------

	/** @return array<string,array{bool,?string}> whether a gateway listens, and what it answers a list request with (NULL: it hangs up) */
	public static function unknownListenerLists(): array
	{
		return [
			'no gateway socket' => [FALSE, NULL],
			'an older gateway answers a bad message length' => [TRUE, "error: a message of 4294967292 bytes is not between 1 and 65536\n"],
			'a gateway that hangs up' => [TRUE, NULL],
			'a malformed reply' => [TRUE, "listening dot garbage\nok\n"],
		];
	}

	#[DataProvider('unknownListenerLists')]
	public function testAListThatIsNotKnownFilesNothingAndClosesNothing(bool $gateway, ?string $reply): void
	{
		// Given no warning, a startup notice from an earlier start, and a gateway that gives no list
		$this->box(self::DOT_ON);
		$this->fileOther(self::ID, 'pfB-DNS started with problems: DoT is not served on 192.0.2.1:853: old.');
		$before = $this->standing();
		if ($gateway) {
			$this->gatewayAnswers($reply);
		}

		pfb_dns_proxy_startup_check(TRUE);

		// Then nothing was judged: the old notice stays (not closed) and none is added
		$this->assertSame($before, $this->standing());
		$this->assertCount(1, $this->startupTexts(), 'the old notice still stands, alone');
	}

	#[DataProvider('unknownListenerLists')]
	public function testAListThatIsNotKnownStillReportsAWarning(bool $gateway, ?string $reply): void
	{
		$this->box(['pfb_dns_interface' => 'lan,opt1'], ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'], [], ['opt1']);
		if ($gateway) {
			$this->gatewayAnswers($reply);
		}

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([$this->problemText('plain DNS interface opt1 is down or disabled; it adds no listener.')], $this->startupTexts());
	}

	/** @return array<string,array{bool}> issue #3550: a start the log's last 64 KiB cannot hold whole */
	public static function startsTheLogWindowCannotHold(): array
	{
		return ['a start more than 64 KiB back' => [FALSE], 'a window that cuts inside the start' => [TRUE]];
	}

	#[DataProvider('startsTheLogWindowCannotHold')]
	public function testAGatewayThatListsEveryListenerIsNotJudgedByWhatTheLogHoldsOfItsStart(bool $cutsInside): void
	{
		// Given a standing notice, a log of a start that its last 64 KiB cannot hold whole (more than 64 KiB of chatter after it,
		// or in the middle of it), and a gateway that lists every listener
		$this->box(self::DOT_ON);
		$this->fileOther(self::ID, 'pfB-DNS started with problems: DoT is not served on 192.0.2.1:853: old.');
		$start = ['starting pid 4242', ...array_map(static fn (string $at): string => "listening {$at}", [...self::PLAIN, ...self::DOT]), 'ready upstream 127.0.0.1:5353 pid 4242'];
		$chatter = array_fill(0, 900, 'pfb_dns_proxy warning: no reply from Unbound for 1.2.0.192.in-addr.arpa. PTR');
		$this->log($cutsInside ? [...array_slice($start, 0, 3), ...$chatter, ...array_slice($start, 3)] : [...$start, ...$chatter]);
		$window = pfb_dns_proxy_log_lines();
		$this->assertGreaterThan(65536, pfb_dns_proxy_log_size(), 'before: the log is longer than its window');
		$this->assertNotContains('starting pid 4242', $window, 'before: the start\'s first line is outside the window');
		$this->assertSame($cutsInside, in_array(end($start), $window, TRUE), 'before: the ready line is inside the window only when the cut is inside the start');
		$this->gatewayServesEverything();

		// When the cron tick checks it (no start was made: no size)
		pfb_dns_proxy_startup_check(TRUE);

		// Then no problem is filed and the standing notice is closed
		$this->assertSame([], $this->standing());
	}

	public function testAMissingRcScriptNamesNoMissingListener(): void
	{
		// Given a moved box whose rc script is gone, and a start that reports only loopback
		$this->box(self::DOT_ON);
		unlink(PFB_DNS_PROXY_RCFILE);
		$this->gatewayServes(['udp+tcp 127.0.0.1:53']);

		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([], $this->startupTexts(), 'nothing is expected, so nothing is missing');
	}

	// -----------------------------------------------------------------------
	// Rows 10, 13 -- the notice follows the starts
	// -----------------------------------------------------------------------

	public function testAHealthyStartAfterAFailedOneClosesTheNoticeTheFailedOneFiled(): void
	{
		$this->box(self::DOT_ON);
		$this->gatewayServes([...self::PLAIN, ...self::DOT_LOOPBACK], ['dot 192.0.2.1:853' => 'bind: address already in use']);

		pfb_dns_proxy_startup_check(TRUE);
		$this->assertCount(1, $this->startupTexts(), 'the failed start filed one notice');

		$this->gatewayServesEverything();
		pfb_dns_proxy_startup_check(TRUE);

		$this->assertSame([], $this->standing(), 'the healthy start closed it');
	}

	public function testTheSameProblemTwiceIsOneNotice(): void
	{
		$this->box(self::DOT_ON);
		$this->gatewayLacksDotOnLan();

		pfb_dns_proxy_startup_check(TRUE);
		pfb_dns_proxy_startup_check(TRUE);

		$this->assertCount(1, $this->startupTexts());
	}

	public function testAChangedProblemFilesAgainAndTheHealthyStartClosesEveryRowOfTheId(): void
	{
		// Given two starts that failed differently: pfb_dns_proxy_notify() files a row for each text
		$this->box(self::DOT_ON);
		$this->fileOther('pfBlockerNG DNS Proxy', 'rollback text');
		$this->gatewayLacksDotOnLan();
		pfb_dns_proxy_startup_check(TRUE);
		$this->gatewayServes([...self::PLAIN, 'dot [::1]:853']);
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertCount(2, $this->startupTexts(), 'before: two rows of the startup id stand');

		// When a start is healthy
		$this->gatewayServesEverything();
		pfb_dns_proxy_startup_check(TRUE);

		// Then no row of the id is left (close_notice() removes one row per call), and the rollback row is untouched
		$this->assertSame([['pfBlockerNG DNS Proxy', 'rollback text']], $this->standing());
	}

	// -----------------------------------------------------------------------
	// Row 11 -- nothing is meant to serve
	// -----------------------------------------------------------------------

	/** @return array<string,array{bool}> */
	public static function readyWhileNothingIsMeantToServe(): array
	{
		return ['ready' => [TRUE]];
	}

	#[DataProvider('readyWhileNothingIsMeantToServe')]
	public function testWithNoSnapshotAndNoFailureNothingIsFiledOrClosed(bool $ready): void
	{
		// Given no snapshot, a standing notice and a healthy log: only the early return keeps the notice (a check that went on would close it)
		$this->fileOther(self::ID, 'pfB-DNS started with problems: old.');
		$before = $this->standing();
		$this->gatewayServesEverything();

		pfb_dns_proxy_startup_check($ready);

		$this->assertSame($before, $this->standing());
	}

	/** @return array{PfbFlockClockFixture,string} the virtual clock, and the check's name in the namespace it was loaded into together with the production wait */
	private function clockedCheck(): array
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_dns_proxy_startup_check', 'pfb_dns_proxy_await_ready'], ['PFB_DNS_PROXY_START_WAIT' => 1]);
		return [$clock, $namespace . '\\pfb_dns_proxy_startup_check'];
	}

	public function testNothingMeantToServeNeverWaits(): void
	{
		[$clock, $check] = $this->clockedCheck();

		$check(TRUE);

		$this->assertSame([], $clock->sleeps, 'no snapshot: the bounded wait is not even started');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testANotReadyStartIsReportedAtOnceWithoutAnyWaitInTheCheck(): void
	{
		// Given a moved box whose proxy never became ready (the caller waited for it, and gave up)
		$this->box();
		[$clock, $check] = $this->clockedCheck();

		// When the check is told the proxy is not ready
		$check(FALSE);

		// Then it spent no wait of its own, and reports the one problem
		$this->assertSame([], $clock->sleeps, 'the readiness wait belongs to the caller, never to the check');
		$this->assertSame(
			[$this->problemText('pfB-DNS is not serving: the DNS proxy did not become ready within 1 s.')],
			$this->startupTexts()
		);
	}

	public function testAReadyStartIsJudgedOnTheGatewaysListWithoutAnyTick(): void
	{
		$this->box(self::DOT_ON);
		$this->proxyServes();
		$this->gatewayLacksDotOnLan();
		[$clock, $check] = $this->clockedCheck();

		$check(TRUE);

		$this->assertSame([], $clock->sleeps, 'already ready: no tick');
		$this->assertSame(
			[$this->problemText('DoT is not served on 192.0.2.1:853: the gateway did not report it listening.')],
			$this->startupTexts()
		);
	}

	// -----------------------------------------------------------------------
	// Row 12 -- pfb_dns_proxy_confirm_ready() runs the check
	// -----------------------------------------------------------------------

	/** @return array{PfbFlockClockFixture,string} */
	private function clockedConfirm(): array
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_dns_proxy_confirm_ready', 'pfb_dns_proxy_await_ready'], ['PFB_DNS_PROXY_START_WAIT' => 1]);
		return [$clock, $namespace . '\\pfb_dns_proxy_confirm_ready'];
	}

	public function testAReadyProxyIsCheckedOnTheGatewaysListByTheConfirmation(): void
	{
		// Given a proxy that is ready and a start that lacks DoT on lan
		$this->box(self::DOT_ON);
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->gatewayLacksDotOnLan();
		[$clock, $confirm] = $this->clockedConfirm();

		// When the activation confirms it
		$ready = $confirm();

		// Then it is ready, and the check ran: the missing listener is a notice
		$this->assertTrue($ready);
		$this->assertSame([], $clock->sleeps, 'already ready: the confirmation waited for nothing');
		$this->assertSame(
			[$this->problemText('DoT is not served on 192.0.2.1:853: the gateway did not report it listening.')],
			$this->startupTexts()
		);
	}

	public function testAProxyThatNeverBecameReadyWhileConfigXmlIsLockedIsNotDiagnosedAsAStartupFailure(): void
	{
		// Given a moved box whose proxy never becomes ready, and a rollback that cannot turn pfB-DNS off (the config lock stays
		// taken): ownership is not validated, so nothing about this start is diagnosed from this process's copy
		$this->box();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$this->log('pfb_dns_gateway: cannot start: boom');
		[$clock, $confirm] = $this->clockedConfirm();

		// When the activation confirms it
		$ready = $confirm();

		// Then the wait ran out, and the only notice is the rollback's recovery failure: no startup diagnosis is filed
		$this->assertFalse($ready);
		$this->assertSame(array_fill(0, 10, 100000), $clock->sleeps);
		$this->assertSame(['pfBlockerNG DNS Proxy'], array_column($GLOBALS['pfb_test_file_notices'], 'id'), 'the recovery failure only');
		$this->assertStringNotContainsString('boom', implode("\n", array_column($GLOBALS['pfb_test_file_notices'], 'notice')));
	}

}
