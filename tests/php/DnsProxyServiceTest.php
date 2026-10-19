<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyRcSandboxTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNS proxy runs as the supervised rc service pfb_dns_proxy.
 *
 * Function under test: pfb_dns_proxy_service() -- writes /usr/local/etc/rc.d/pfb_dns_proxy.sh from the SAVED
 * Resolver (listen addresses, DoT). Intent pinned here:
 *   - the rc script launches pfb-dns, the Go gateway, only through pfb_dns.sh (the shipped Python proxy is its decider, run
 *     through pfb_python.sh), on exactly the saved addresses, as the unprivileged `unbound` user, with every value
 *     shell-quoted and stdio detached (DnsProxyGatewayOnlyTest: whatever the package ships);
 *   - it starts while the moved-Resolver snapshot is set, whatever the proxy toggle and DNSBL say (a restore that
 *     was abandoned leaves the Resolver moved, and the proxy must keep serving it until a retry succeeds), and never
 *     launches over a survivor; the proxy listens on the saved Resolver's non-loopback addresses plus loopback, so a
 *     Resolver saved on Localhost only, or on an interface with no address, still gets a proxy;
 *   - a start over a proxy whose supervisor and child both serve keeps it: nothing is signalled or launched, so the
 *     package start after the boot hook does not bounce it; a restart always stops first, and starts only when that stop succeeded;
 *   - it stops by TERM, KILL at 5 s, giving up (status 1) at 7 s, signalling only live processes that its
 *     own pidfiles name AND whose command line is the proxy's, so a stale pidfile whose pid was reused can
 *     never get an unrelated process killed;
 *   - it is written on every call, like the other pfBlockerNG rc services.
 *
 * The real generator's output is written through the write_rcfile() double (wrapped as pfSense wraps it) and
 * executed under dash. Every absolute executable path is redirected to a sandbox command double (a path with
 * no double fails the test instead of running a host binary); `sleep 1` is one tick of a controlled clock, so
 * the 5 s / 7 s deadlines are counted in ticks, never measured.
 */
#[CoversFunction('pfb_dns_proxy_service')]
final class DnsProxyServiceTest extends TestCase
{
	use DnsProxyRcSandboxTrait;

	protected function setUp(): void
	{
		$this->sandboxUp();
	}

	protected function tearDown(): void
	{
		$this->sandboxDown();
	}

	private function generate(): void
	{
		pfb_dns_proxy_service();
	}

	/** @return list<string> the addresses the daemon double was told to --listen on, in order */
	private function daemonListen(): array
	{
		$argv = $this->daemonArgv();
		$listen = [];
		foreach ($argv as $i => $arg) {
			if ($arg === '--listen') {
				$listen[] = $argv[$i + 1];
			}
		}
		return $listen;
	}


	// -----------------------------------------------------------------------
	// S2 -- what the generated script says
	// -----------------------------------------------------------------------

	public function testScriptLaunchesTheGatewayThroughTheWrapperOnTheSavedAddressesAndLoopbackAsUnbound(): void
	{
		// Given a Resolver that was saved listening on lan (IPv4 and IPv6), without DoT
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);

		// When the rc service is generated and started under dash
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the daemon is launched with exactly this argument vector
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame($this->gatewayArgv(PFB_DNS_PROXY_DIR, ['192.0.2.1', '2001:db8::1']), $this->daemonArgv());
		$this->assertSame(['launch'], $this->events());
	}

	public function testTheProxyAlsoServesLoopbackSoTheFirewallsOwnLookupsAreFilteredWhateverTheSavedInterfaces(): void
	{
		// Given a Resolver saved on one IPv4-only interface: loopback is not among its addresses, and Unbound has
		// moved to its own loopback ports, so loopback on the Listen Port is free for the proxy
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$GLOBALS['config']['unbound']['port'] = '5300';

		// When the rc service is generated and started
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the proxy listens on the interface address first, then on both loopback addresses, all on that port:
		// the firewall's resolv.conf (127.0.0.1, ::1) reaches the proxy, not Unbound
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$listen = [];
		foreach ($argv as $i => $arg) {
			if ($arg === '--listen') {
				$listen[] = $argv[$i + 1];
			}
		}
		$this->assertSame(['192.0.2.1', '127.0.0.1', '::1'], $listen);
		$this->assertSame('5300', $argv[(int) array_search('--port', $argv, TRUE) + 1]);
	}

	public function testScriptNamesNoInterpreterPathAndQuotesEveryListenValue(): void
	{
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);
		$this->generate();
		$text = $this->rcText();

		$this->assertDoesNotMatchRegularExpression('~\bpython|/bin/php|\bphp\b~i', $text,
			'the proxy is launched through pfb_python.sh only: no interpreter path may appear in the script');
		$this->assertStringContainsString("--listen '192.0.2.1' --listen '2001:db8::1' --listen '127.0.0.1' --listen '::1'", $text, 'every listen value is shell-quoted');
		$this->assertStringContainsString('</dev/null >/dev/null 2>&1', $text, 'stdio is detached (#662)');
		$this->assertStringContainsString("rc_stop || return 1\n", $text, 'never launch over a survivor');
	}

	public function testGeneratedScriptIsValidPosixShell(): void
	{
		$this->moveResolver(TRUE);
		$this->generate();

		$proc = proc_open([$this->shell, '-n', "{$this->dir}/rc/" . self::RC], [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
		$this->assertIsResource($proc);
		$output = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		$this->assertSame(0, proc_close($proc), "sh -n rejected the generated script: {$output}");
	}

	/** @return array<string,array{bool}> */
	public static function dotRows(): array
	{
		return ['saved Resolver had DoT' => [TRUE], 'saved Resolver had no DoT' => [FALSE]];
	}

	#[DataProvider('dotRows')]
	public function testDotIsPassedExactlyWhenTheSavedResolverHadIt(bool $dot): void
	{
		$this->moveResolver($dot);
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$this->assertSame($dot, in_array('--dot', $argv, TRUE), '--dot iff the saved Resolver had enablessl');
		$this->assertContains('--tls-pem', $argv, 'the gateway is always told where the certificate file is: it reads it only for a TLS transport');
		$this->assertContains('--ctl-socket', $argv, 'and where root pushes a renewed certificate: it makes the socket only for a TLS transport');
		$this->assertNotContains('--pfsense-config', $argv, 'the gateway no longer reads config.xml');
		if ($dot) {
			$at = array_search('--dot', $argv, TRUE);
			$this->assertSame(['--dot', '--dot-port', '853', '--tls-pem', $this->certFile(), '--ctl-socket', $this->ctlSocket()], array_slice($argv, (int) $at, 7));
		} else {
			$this->assertNotContains('--dot-port', $argv, 'a DoT port with DoT off would restart the proxy for nothing');
		}
	}

	/** @return array<string,array{?string,string}> the Resolver's `tlsport` as config.xml holds it => the DoT port the gateway is told */
	public static function tlsPortRows(): array
	{
		return [
			'a port' => ['8530', '8530'],
			'absent' => [NULL, '853'],
			'empty' => ['', '853'],
			'zero' => ['0', '853'],
			'above 65535' => ['70000', '853'],
			'padded' => ['0853', '853'],
			'not a number: the text never reaches the script' => ['853; reboot', '853'],
		];
	}

	#[DataProvider('tlsPortRows')]
	public function testTheDoTPortIsTheResolversTlsportWhenItIsAPortAnd853Otherwise(?string $tlsport, string $expected): void
	{
		// Given a Resolver saved with DoT and this tlsport (the gateway no longer reads config.xml, so the script says it)
		$this->moveResolver(TRUE);
		if ($tlsport !== NULL) {
			$GLOBALS['config']['unbound']['tlsport'] = $tlsport;
		}

		// When the script is generated and started
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the gateway is given exactly that port, and nothing else of the text
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$this->assertSame($expected, $argv[(int) array_search('--dot-port', $argv, TRUE) + 1]);
		$this->assertStringNotContainsString('reboot', $this->rcText());
	}

	public function testTheCertificateFileIsWrittenByTheApplyBeforeTheProxyStartsAndTheStartFindsIt(): void
	{
		// Given DoT wanted and no file yet
		$this->moveResolver(TRUE);
		$this->assertFileDoesNotExist($this->certFile());

		// When the script is generated (an apply) and later started
		$this->generate();
		$this->assertFileExists($this->certFile(), 'the apply writes the Resolver\'s certificate for the gateway');
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the start launches at once: it does not run PHP for a file that is there
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
	}

	public function testAStartThatFindsNoCertificateFileHasPhpWriteItBeforeTheProxyLaunches(): void
	{
		// Given DoT wanted and a /var that came up empty: the script exists, the certificate file does not
		$this->moveResolver(TRUE);
		$this->generate();
		unlink($this->certFile());

		// When the proxy starts
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then PHP is asked for the file (the pfblockerng.inc dns_cert verb) before the launch
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['export', 'launch'], $this->events());
		$this->assertFileExists($this->certFile());
	}

	public function testAFailedCertificateWriteIsLoggedAndTheProxyStillStarts(): void
	{
		// Given the same start, and PHP that cannot write the file
		$this->moveResolver(TRUE);
		$this->generate();
		unlink($this->certFile());
		$this->arrange(['EXPORT_FAIL' => '1']);

		// When the proxy starts
		[$status, $output] = $this->rc('start');

		// Then plain DNS is served: the start goes on, and says what it could not do
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['export', 'log', 'launch', 'log'], $this->events(TRUE), 'the warning, the launch, then the usual "started" line');
		$this->assertStringContainsString('certificate could not be written', (string) file_get_contents("{$this->dir}/state/logger"));
	}

	public function testNoCertificateIsInvolvedWhenNoEncryptedTransportIsWanted(): void
	{
		// Given a saved Resolver without DoT, DoH and DoQ off, and a certificate file left by an earlier configuration
		$this->moveResolver(FALSE);
		file_put_contents($this->certFile(), 'stale');

		// When the script is generated and started
		$this->generate();
		$this->arrange();
		[$status] = $this->rc('start');

		// Then the key is gone from the disk and the script never mentions PHP or the file's content
		$this->assertSame(0, $status);
		$this->assertFileDoesNotExist($this->certFile());
		$this->assertSame(['launch'], $this->events());
		$this->assertStringNotContainsString('pfblockerng.inc dns_cert', $this->rcText());
	}

	/** @return array<string,array{?string,string}> the Resolver's `port` as config.xml holds it => the port the proxy is told to bind */
	public static function listenPortRows(): array
	{
		return [
			'Listen Port absent (the default)' => [NULL, '53'],
			'Listen Port 53'                   => ['53', '53'],
			'Listen Port 5300'                 => ['5300', '5300'],
			'Listen Port 65535'                => ['65535', '65535'],
			'Listen Port empty'                => ['', '53'],
			'Listen Port a service name'       => ['domain', '53'],
			'Listen Port 0'                    => ['0', '53'],
			'Listen Port above 65535'          => ['65536', '53'],
			'Listen Port with a shell payload' => ['5300; reboot', '53'],
		];
	}

	#[DataProvider('listenPortRows')]
	public function testTheProxyBindsTheResolversListenPortAndFallsBackToTheDefaultWhenItIsNotAPort(?string $configured, string $expected): void
	{
		// Given a moved Resolver whose Listen Port is $configured (Unbound keeps it on loopback; the proxy takes it on the LAN)
		$this->moveResolver();
		if ($configured !== NULL) {
			$GLOBALS['config']['unbound']['port'] = $configured;
		}

		// When the rc service is generated and started under dash
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the proxy is launched with exactly one --port, the Resolver's port or 53, and nothing else of the value reaches the script
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$this->assertSame(1, count(array_keys($argv, '--port', TRUE)), 'exactly one --port');
		$this->assertSame($expected, $argv[(int) array_search('--port', $argv, TRUE) + 1]);
		$this->assertStringNotContainsString('reboot', $this->rcText());
	}

	// -----------------------------------------------------------------------
	// S2/S4 -- the start gate
	// -----------------------------------------------------------------------

	public function testStartDoesNothingAndLeavesARunningProxyAloneWithoutAMovedResolver(): void
	{
		// Given a proxy that is running and a generated script whose gate finds no moved-Resolver snapshot
		$this->moveResolver();
		$this->generate();
		$this->arrange(['GATE_SAVED' => ''], '2', '1', TRUE);

		// When it is started (boot)
		[$status, $output] = $this->rc('start');

		// Then it neither stops nor launches anything
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE), 'a closed gate means no daemon, no signal, no log');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	/** @return array<string,array{array<string,string>}> */
	public static function toggleAndDnsblRows(): array
	{
		return [
			'DNS proxy toggle off' => [['GATE_PROXY' => '']],
			'DNSBL off'            => [['GATE_DNSBL' => '']],
			'both off'             => [['GATE_PROXY' => '', 'GATE_DNSBL' => '']],
		];
	}

	/** @param array<string,string> $gates */
	#[DataProvider('toggleAndDnsblRows')]
	public function testStartLaunchesWhileTheSnapshotRemainsWhateverTheToggleAndDnsblSay(array $gates): void
	{
		// Given a restore that was abandoned (config locked, or the proxy outlived its stop): the toggle or DNSBL is
		// already off, but the Resolver is still moved and its snapshot kept
		$this->moveResolver();
		$this->generate();
		$this->arrange($gates);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the proxy is launched: nothing else serves the moved Resolver's port until a retry restores it
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
	}

	/** @return array<string,array{string,array<string,string>,array<string,string>,list<string>}> */
	public static function loopbackRows(): array
	{
		return [
			'Resolver saved on Localhost only'   => ['lo0', ['lo0' => '127.0.0.1'], ['lo0' => '::1'], ['127.0.0.1', '::1']],
			'Resolver saved on Localhost and LAN' => ['lo0,lan', ['lo0' => '127.0.0.1', 'lan' => '192.0.2.1'], ['lo0' => '::1'], ['192.0.2.1', '127.0.0.1', '::1']],
			'Resolver saved on an interface with no address' => ['opt9', [], [], ['127.0.0.1', '::1']],
		];
	}

	/**
	 * @param array<string,string> $v4
	 * @param array<string,string> $v6
	 * @param list<string> $expected
	 */
	#[DataProvider('loopbackRows')]
	public function testTheProxyStartsOnLoopbackPlusWhateverAddressesTheSavedInterfacesHave(string $interfaces, array $v4, array $v6, array $expected): void
	{
		// Given a Resolver saved on these interfaces: the firewall's own lookups reach the proxy on loopback however
		// few client-facing addresses there are
		$this->moveResolver(FALSE, $interfaces, $v4, $v6);
		$this->generate();
		$this->arrange();

		// When the service is started
		[$status, $output] = $this->rc('start');

		// Then the proxy is launched on the saved interfaces' addresses and on loopback, each once
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertSame($expected, $this->daemonListen());
	}

	/** @return array<string,array{bool,bool,string}> DNSBL on, Resolver forwarding, the one module flag expected ('' = none) */
	public static function moduleFlagRows(): array
	{
		return [
			'DNSBL off: there is no module to host'          => [FALSE, FALSE, '--no-module'],
			'DNSBL off, Resolver forwarding'                 => [FALSE, TRUE, '--no-module'],
			'DNSBL on, Resolver recursing: no upstream to observe' => [TRUE, FALSE, ''],
			'DNSBL on, Resolver forwarding: upstream blocks are reported' => [TRUE, TRUE, '--observer'],
		];
	}

	#[DataProvider('moduleFlagRows')]
	public function testTheProxyBootsTheModuleOnlyWithDnsblAndListensForTheObserverOnlyWhileForwarding(bool $dnsbl, bool $forwarding, string $flag): void
	{
		// Given pfBlockerNG enabled, DNSBL on or off, and the Resolver forwarding or not
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = $dnsbl ? PfbToggle::On : PfbToggle::Off;
		if ($forwarding) {
			config_set_path('unbound/forwarding', '');
		}
		$this->moveResolver();

		// When the service is generated and started
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the daemon is launched with exactly the module flag that mode needs
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$this->assertSame($flag === '--no-module', in_array('--no-module', $argv, TRUE), '--no-module iff DNSBL is off');
		$this->assertSame($flag === '--observer', in_array('--observer', $argv, TRUE), '--observer iff DNSBL is on and the Resolver forwards');
	}

	/** @return array<string,array{bool,?PfbToggle,list<string>}> DNSBL on, the DNS Reply Logging preference ($pfb['dnsbl_py_reply'], NULL = unread), the module flags expected in order */
	public static function replyLogFlagRows(): array
	{
		return [
			'DNSBL off, DNS Reply Logging on: the proxy logs the replies it forwards' => [FALSE, PfbToggle::On, ['--no-module', '--reply-log']],
			'DNSBL off, DNS Reply Logging off: nothing is logged'                    => [FALSE, PfbToggle::Off, ['--no-module']],
			'DNSBL off, preference never read: nothing is logged'                    => [FALSE, NULL, ['--no-module']],
			'DNSBL on, DNS Reply Logging on: the module has its own log'             => [TRUE, PfbToggle::On, []],
			'DNSBL on, DNS Reply Logging off'                                        => [TRUE, PfbToggle::Off, []],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('replyLogFlagRows')]
	public function testTheProxyLogsRepliesOnlyWithoutTheModuleAndOnlyWhileTheSharedPreferenceIsOn(bool $dnsbl, ?PfbToggle $preference, array $expected): void
	{
		// Given pfBlockerNG enabled, DNSBL on or off, and the DNS Reply Logging preference (the DNSBL module's own switch) set or not
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = $dnsbl ? PfbToggle::On : PfbToggle::Off;
		if ($preference !== NULL) {
			$GLOBALS['pfb']['dnsbl_py_reply'] = $preference;
		}
		$this->moveResolver();

		// When the service is generated and started
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the daemon is launched with --reply-log iff it hosts no module and the preference is on
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame($expected, array_values(array_intersect($this->daemonArgv(), ['--no-module', '--reply-log', '--observer'])));
	}

	/** @return array<string,array{bool,bool,?PfbToggle,list<string>}> DNSBL on, Resolver forwarding, the DNS Reply Logging preference, the gateway's mode flags */
	public static function gatewayModeRows(): array
	{
		return [
			'DNSBL off, preference on: no module, the replies are logged' => [FALSE, FALSE, PfbToggle::On, ['--no-module', '--reply-log']],
			'DNSBL off, preference off: no module, nothing is logged'     => [FALSE, FALSE, PfbToggle::Off, ['--no-module']],
			'DNSBL off, Resolver forwarding: still no observer'           => [FALSE, TRUE, PfbToggle::Off, ['--no-module']],
			'DNSBL on, Resolver recursing: the decider hosts the module'  => [TRUE, FALSE, PfbToggle::On, []],
			'DNSBL on, Resolver forwarding: upstream blocks are reported' => [TRUE, TRUE, PfbToggle::On, ['--observer']],
		];
	}

	/** @param list<string> $flags */
	#[DataProvider('gatewayModeRows')]
	public function testTheGatewayLineCarriesThePfbDnsModeFlagsAsItsOwnAndTheDeciderIsLeftAlone(bool $dnsbl, bool $forwarding, ?PfbToggle $preference, array $flags): void
	{
		// Given the gateway binary, a saved Resolver, and pfB-DNS in the mode DNSBL, forwarding and the logging preference make
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = $dnsbl ? PfbToggle::On : PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_py_reply'] = $preference;
		if ($forwarding) {
			config_set_path('unbound/forwarding', '');
		}
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);

		// When the rc service is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then the gateway has exactly that mode's flags, before `--`, and the Python decider's own argv is the one it always had
		$this->assertSame($this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [], '53', $flags), $argv);
		$decider = array_slice($argv, (int) array_search('--', $argv, TRUE));
		$this->assertSame(self::DECIDER, $decider, 'the decider is told nothing the gateway does not pass on itself');
	}

	public function testDohAndDoqAreServedByTheGatewayWithDnsblOffToo(): void
	{
		// Given pfB-DNS alone (DNSBL off), DoH and DoQ on, and the gateway binary
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_py_reply'] = PfbToggle::Off;
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doq', 'on');
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);

		// When the rc service is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then the gateway serves both next to the plain listeners, and boots no DNSBL module for them
		$this->assertContains('--no-module', $argv);
		$this->assertContains('--doh-port', $argv, 'DoH is served with DNSBL off');
		$this->assertContains('--doq-port', $argv, 'DoQ is served with DNSBL off');
		$this->assertSame(['launch'], $this->events());
	}

	public function testAMarkerThatIsNotAValidSnapshotLaunchesNothingAndFailsLoudly(): void
	{
		// Given a stored marker that is non-empty but no valid Resolver snapshot (hand-edited, truncated): the PHP side
		// sees no snapshot while a gate that only asks "non-empty?" would start a proxy on loopback alone
		config_set_path(self::SAVED, 'not-a-snapshot');
		$this->generate();
		$this->arrange();

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then it logs one error and exits 1, without launching or stopping anything
		$this->assertSame(1, $status, "rc start must fail: {$output}");
		$this->assertSame(['log'], $this->events(TRUE), 'one error line, no daemon, no signal');
		$this->assertStringContainsString('not a valid', (string) file_get_contents("{$this->dir}/state/logger"));
	}

	public function testAMarkerThatChangedSinceTheScriptWasWrittenLaunchesNothing(): void
	{
		// Given a script written for one snapshot, and a different one stored now (restored and moved again since)
		$this->moveResolver();
		$this->generate();
		$this->arrange(['GATE_SAVED' => base64_encode('{"another":"snapshot"}')]);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the stale script does nothing: the next apply regenerates it for the stored snapshot
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
	}

	public function testLauncherStdFdsAreDetachedToDevNull(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->arrange();

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['0 1 2'], array_map('trim', file("{$this->dir}/state/fds", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []),
			'the daemon sees stdin, stdout and stderr on /dev/null (#662)');
	}

	// -----------------------------------------------------------------------
	// S4 -- stop and restart
	// -----------------------------------------------------------------------

	public function testStopWaitsForBothProcessesToExitAfterTerm(): void
	{
		// Given a proxy that exits two ticks after TERM
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->assertSame(['1001', '1002'], $this->livePids(), 'precondition: proxy alive');

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then stop returns only after both exited, with no KILL, and nothing stale is left behind
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep'], $this->events());
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy_daemon.pid'));
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'));
	}

	public function testAProcessIgnoringTermIsKilledAfterFiveTicksAndItsStalePidfilesAreRemoved(): void
	{
		// Given a proxy that ignores TERM and dies one tick after KILL
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', '1', TRUE);

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then TERM is waited on for exactly 5 ticks, the escalation is logged and sent, the exit is
		// observed, and the pidfile a KILLed supervisor could not remove is cleaned up
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep'], $this->events());
		$all = $this->events(TRUE);
		$kill = array_search('kill', $all, TRUE);
		$this->assertSame('log', $all[$kill - 1] ?? NULL, 'the KILL escalation is logged before it is sent');
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy_daemon.pid'));
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'));
	}

	public static function survivorVerbs(): array
	{
		$cycle = ['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep', 'sleep'];
		return [
			'stop'    => ['stop', $cycle],
			// rc_restart stops, then starts only when that stop succeeded: a survivor fails the restart after one stop
			'restart' => ['restart', $cycle],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('survivorVerbs')]
	public function testAProcessSurvivingKillGivesUpAtSevenTicksAndNeverLaunchesAReplacement(string $verb, array $expected): void
	{
		// Given a proxy that survives both TERM and KILL
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', 'never', TRUE);

		// When the service is stopped / started / restarted
		[$status, $output] = $this->rc($verb);

		// Then 7 ticks are spent, the command fails on its own (not by harness timeout), no replacement is
		// launched over the survivor, and its pidfiles are left in place
		$this->assertNotContains($status, [0, 124, 137], "rc {$verb} must fail on its own: {$output}");
		$this->assertSame($expected, $this->events(), "rc {$verb} command events");
		$this->assertSame(['1001', '1002'], $this->livePids());
		$this->assertFileExists($this->pidfile('pfb_dns_proxy.pid'));
	}

	public function testAStartThatCannotStopASupervisorWhoseChildDiedFailsAndNeverLaunches(): void
	{
		// Given a supervisor that survives TERM and KILL, and a child that is already gone
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', 'never', TRUE);
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "4242\n");
		file_put_contents("{$this->dir}/state/procs", "1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[4242] (daemon)\n");

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the pair is not healthy, so the stop runs to its bound (7 ticks) and the start fails on its own, with no launch
		$this->assertNotContains($status, [0, 124, 137], "rc start must fail on its own: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep', 'sleep'], $this->events());
		$this->assertSame(['1001'], $this->livePids());
	}

	public function testRestartReplacesARunningProxyOnlyAfterItExited(): void
	{
		// Given a serving proxy
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);

		// When it is restarted explicitly: the proxy must take a new process
		[$status, $output] = $this->rc('restart');

		// Then it is stopped once and launched once, and the launch comes only after the old pair exited
		$this->assertSame(0, $status, "rc restart failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events(), 'one stop, then one launch after the old pair exited');
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	/** @return array<string,array{?string,string}> pidfile content (NULL = absent), process table lines */
	public static function nothingToStop(): array
	{
		return [
			'pidfile absent'                 => [NULL, ''],
			'pidfile names a dead pid'       => ["4242\n", ''],
			'pidfile is garbage'             => ["1001; touch @DIR@/pwned\n", "1001|X|||pfb_dns_proxy.py\n"],
			'pidfile is empty'               => ['', ''],
			'pid reused by an unrelated process' => ["1001\n", "1001|X|||/usr/sbin/sshd -D\n"],
		];
	}

	#[DataProvider('nothingToStop')]
	public function testStopSignalsNothingWhenNoLiveProxyProcessIsNamedByItsPidfiles(?string $pidfile, string $procs): void
	{
		// Given a stale or hostile pidfile
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		if ($pidfile !== NULL) {
			file_put_contents($this->pidfile('pfb_dns_proxy.pid'), str_replace('@DIR@', $this->dir, $pidfile));
		}
		file_put_contents("{$this->dir}/state/procs", $procs);

		// When the service is stopped
		[$status, $output] = $this->rc('stop');

		// Then it returns at once and signals nothing: a recycled pid is never killed
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->events(), 'no signal, no wait');
		$this->assertSame($procs === '' ? [] : ['1001'], $this->livePids());
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'), 'the stale pidfile is removed');
		$this->assertFileDoesNotExist("{$this->dir}/pwned", 'a hostile pidfile value is never interpreted');
	}

	public function testStartLaunchesEvenWhenAStalePidfileNamesAnUnrelatedLiveProcess(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "1001\n");
		file_put_contents("{$this->dir}/state/procs", "1001|X|||/usr/sbin/sshd -D\n");

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'the unrelated process is neither waited on nor signalled');
	}

	/** @return array<string,array{string,string,string,string}> supervisor pid, child pid, process table ('@DIR@' = the sandbox), the reused pid */
	public static function reusedPidRows(): array
	{
		return [
			'the supervisor pidfile names a pid reused by sshd' => ['1003', '1002',
				"1003|@DIR@/run/pfb_dns_proxy_daemon.pid|||/usr/sbin/sshd -D\n"
				. "1002|@DIR@/run/pfb_dns_proxy.pid|||python3.11 -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py\n", '1003'],
			'the child pidfile names a pid reused by sshd' => ['1001', '1002',
				"1001|@DIR@/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
				. "1002|@DIR@/run/pfb_dns_proxy.pid|||/usr/sbin/sshd -D\n", '1002'],
		];
	}

	public function testSecondStartWhileBothProcessesServeKeepsThemAndLaunchesNothing(): void
	{
		// Given a proxy the first start launched: its supervisor and child are both live and named by their pidfiles
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'precondition: the first start launched the proxy');

		// When the package start runs again after the boot hook already started the proxy
		[$status, $output] = $this->rc('start');

		// Then the serving pair is kept: no stop, no signal, and no second daemon launch
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'a second start neither stops nor relaunches a serving proxy');
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testSecondStartWhileTheGatewayAndItsSupervisorServeKeepsThemAndLaunchesNothing(): void
	{
		// Given the gateway the boot hook's start launched (DNSBL off, so nothing but the rc script and Unbound's config is needed)
		$gateway = $this->gateway();
		$this->moveResolver();
		$this->generateWith($gateway);
		$this->arrange();
		[$status, $output] = $this->rc('start');
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'precondition: the first start launched the gateway');

		// When the package start runs the same script again
		[$status, $output] = $this->rc('start');

		// Then the serving pair is kept: no stop, no signal, and no second launch
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'a second start neither stops nor relaunches a serving gateway');
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testStartWithAChildThatDiedStopsTheSurvivingSupervisorAndLaunchesOnce(): void
	{
		// Given a supervisor still alive whose child is gone: the child pidfile names a pid that is no longer running
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "4242\n");
		file_put_contents("{$this->dir}/state/procs", "1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[4242] (daemon)\n");

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the bounded recovery runs: the supervisor gets TERM, both pidfiles are cleared, and the proxy launches once
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events());
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testAStaleMarkerLeavesEvenAServingProxyAlone(): void
	{
		// Given a serving proxy, and a script written for a snapshot that has since changed
		$this->moveResolver();
		$this->generate();
		$this->arrange(['GATE_SAVED' => base64_encode('{"another":"snapshot"}')], '2', '1', TRUE);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the stale script does nothing at all, the health check included: the next apply regenerates it
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	#[DataProvider('reusedPidRows')]
	public function testAStartNeverCountsAReusedPidAsHealthyAndNeverSignalsIt(string $supervisor, string $child, string $procs, string $reused): void
	{
		// Given a pidfile that names a pid now reused by an unrelated process (sshd), beside a live proxy process
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '1', '1');
		file_put_contents($this->pidfile('pfb_dns_proxy_daemon.pid'), "{$supervisor}\n");
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "{$child}\n");
		file_put_contents("{$this->dir}/state/procs", str_replace('@DIR@', $this->dir, $procs));

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the pair is not taken for healthy: the proxy's own process is stopped and relaunched, and the unrelated
		// process is neither signalled nor waited on
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['term', 'sleep', 'launch'], $this->events());
		$this->assertContains($reused, $this->livePids(), 'the reused pid was never signalled');
	}

	// -----------------------------------------------------------------------
	// S3 -- written on every call, like the sibling services
	// -----------------------------------------------------------------------

	public function testTheScriptIsWrittenOnEveryCallEvenWhenTheFileOnDiskIsAlreadyCurrent(): void
	{
		// Given the double writes where production looks (the appliance's rc.d), so a rewrite-only-on-change
		// check would find an identical file there on the second call
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
		$this->moveResolver();

		// When the script is generated twice with the same inputs
		pfb_dns_proxy_service();
		$first = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);
		pfb_dns_proxy_service();

		// Then write_rcfile() ran both times, as for pfb_filter.sh and pfb_dnsbl.sh, with the same content
		$this->assertSame(2, $GLOBALS['pfb_test_rcfile_writes'][self::RC]);
		$this->assertSame($first, (string) file_get_contents(PFB_DNS_PROXY_RCFILE));
		@unlink(PFB_DNS_PROXY_RCFILE);
	}

	public function testAnInterfaceAddressThatChangedIsInTheNextScript(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->assertStringContainsString("'192.0.2.1'", $this->rcText());

		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.77']);
		$this->generate();

		$this->assertStringContainsString("'192.0.2.77'", $this->rcText());
		$this->assertStringNotContainsString("'192.0.2.1'", $this->rcText());
	}

	public function testWithNoMovedResolverTheScriptStillExistsAndNeverLaunchesAnything(): void
	{
		// Given no snapshot (not in proxy mode): stop_service() can only reach a script that exists
		$this->generate();
		$this->arrange(['GATE_SAVED' => '']);

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
	}

	// -----------------------------------------------------------------------
	// S6 -- the listener-ready marker: written by the proxy itself, cleared by the rc script only around a fresh start
	// -----------------------------------------------------------------------

	private function seedMarker(string $pid): void
	{
		file_put_contents($this->readyFile(), "{$pid}\n");
	}

	/** @return list<string> what each launched proxy found at the marker's path when it started */
	private function markerAtLaunch(): array
	{
		return file("{$this->dir}/state/launch.marker", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	/** @return list<string> the descriptors above stdio each launched proxy inherited */
	private function inheritedFds(): array
	{
		return file("{$this->dir}/state/launch.fds", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	public function testTheLaunchedProxyInheritsNoDescriptorFromTheStartLock(): void
	{
		// Given a start under lockf: FreeBSD's lockf closes its lock descriptor before the command runs, but this double's flock(1)
		// passes it on, so the rc script's closes of descriptors 3-9 at launch are what keep the proxy from holding the lock
		$this->moveResolver();
		$this->generate();
		$this->arrange();

		// When it launches the proxy
		[$status, $output] = $this->rc('start');

		// Then the proxy has no descriptor above stdio: one that held the lock would keep it for as long as the proxy runs,
		// and every later start would wait its 10 s and fail
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertSame([], $this->inheritedFds());
	}

	public function testAFreshStartRemovesThePreviousMarkerBeforeTheNewProxyIsLaunched(): void
	{
		// Given the marker an earlier proxy left behind (a killed proxy cannot remove its own)
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		$this->seedMarker('999');

		// When a fresh start launches the proxy
		[$status, $output] = $this->rc('start');

		// Then the old marker was gone before the daemon was launched: nothing can mistake it for the new proxy's
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertSame(['absent'], $this->markerAtLaunch());
		$this->assertFileDoesNotExist($this->readyFile());
	}

	public function testAHealthyRepeatedStartKeepsTheMarkerOfTheServingProxy(): void
	{
		// Given a serving proxy (supervisor 1001, child 1002) whose marker names its child
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->seedMarker('1002');

		// When the package start runs again after the boot hook (or an earlier apply) started it
		[$status, $output] = $this->rc('start');

		// Then nothing is stopped, launched or removed: the marker still names the serving child
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
		$this->assertSame("1002\n", (string) file_get_contents($this->readyFile()));
		$this->assertSame(['1001', '1002'], $this->livePids());
		$this->assertSame([], $this->markerAtLaunch(), 'no new proxy was launched');
	}

	public function testAStopRemovesTheMarkerOfTheProxyItStopped(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->seedMarker('1002');

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->readyFile(), 'the marker names a process that was stopped here');
	}

	public function testAStopLeavesAMarkerThatNamesAProcessItDidNotStop(): void
	{
		// Given a marker published by another proxy process (a start that finished while this stop ran), not the one stopped
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->seedMarker('7777');

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->livePids());
		$this->assertSame("7777\n", (string) file_get_contents($this->readyFile()), 'another process\'s marker is never removed');
	}

	public function testAProxyKilledAfterIgnoringTermHasItsMarkerRemovedByTheStop(): void
	{
		// Given a proxy that ignores TERM and is KILLed: it could not remove its own marker
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', '1', TRUE);
		$this->seedMarker('1002');

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertFileDoesNotExist($this->readyFile());
	}

	public function testAProxyThatSurvivesItsStopKeepsItsMarker(): void
	{
		// Given a proxy that survives TERM and KILL: it still serves, so its marker is still true
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', 'never', TRUE);
		$this->seedMarker('1002');

		[$status] = $this->rc('stop');

		$this->assertNotSame(0, $status);
		$this->assertSame("1002\n", (string) file_get_contents($this->readyFile()));
	}

	// -----------------------------------------------------------------------
	// S7 -- starts are serialized: the boot hook's background start and an apply's start_service() must not both launch
	// -----------------------------------------------------------------------

	/** @return array{0: resource, 1: resource} the running verb and its output pipe */
	private function startVerb(string $verb): array
	{
		$proc = proc_open(
			[$GLOBALS['pfb']['timeout'], '-k', '2', '30', $this->shell, "{$this->dir}/run.sh", $verb],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
			$pipes
		);
		$this->assertIsResource($proc, 'proc_open failed');
		fclose($pipes[0]);
		return [$proc, $pipes[1]];
	}

	/** @param array{0: resource, 1: resource} $started @return array{0: int, 1: string} */
	private function finishVerb(array $started): array
	{
		$output = (string) stream_get_contents($started[1]);
		fclose($started[1]);
		return [proc_close($started[0]), $output];
	}

	private function launchCount(): int
	{
		return count(array_keys($this->events(), 'launch', TRUE));
	}

	/** @return list<string> */
	private function lockfCalls(): array
	{
		return file("{$this->dir}/state/lockf.calls", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	/** The watchdog only salvages a stuck run: it fails the test, and the caller's finally block reaps what it started. */
	private function waitUntil(callable $condition, string $what): void
	{
		$deadline = hrtime(TRUE) + 15 * 1000000000;
		while (!$condition()) {
			if (hrtime(TRUE) >= $deadline) {
				$this->fail("STUCK/ENVIRONMENT: {$what}");
			}
			usleep(20000);
		}
	}

	public function testEveryStartRunsUnderTheKeptLockWithATenSecondWaitAndTheStopDoesNot(): void
	{
		// Given a generated script
		$this->moveResolver();
		$this->generate();
		$this->arrange();

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the start ran under one lockf (kept lock file, 10 s wait: the double rejects any other form), however many
		// times the script runs itself inside the lock
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(["{$this->dir}/run/pfb_dns_proxy.lock"], $this->lockfCalls());
		$this->assertSame(['launch'], $this->events());

		// And a stop takes no lock: it must be able to run while a start waits
		[$status, $output] = $this->rc('stop');
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertCount(1, $this->lockfCalls(), 'stop is not serialized with start');
	}

	public function testTwoStartsRacingAtTheDaemonLaunchLaunchExactlyOneProxy(): void
	{
		// Given the daemon launch held open (the proxy's pidfiles are written when it returns), and a first start inside it
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		touch("{$this->dir}/state/barrier");
		$first = $second = NULL;

		try {
			$first = $this->startVerb('start');
			$this->waitUntil(fn (): bool => $this->launchCount() >= 1, 'the first start never reached the daemon launch');

			// When a second start (the boot hook's background start, or an apply's start_service()) arrives while it is held:
			// without a lock it passes the same "already serving?" check and launches too; with one it waits behind the first
			$second = $this->startVerb('start');
			$this->waitUntil(
				fn (): bool => $this->launchCount() >= 2 || count($this->lockfCalls()) >= 2,
				'the second start neither reached the daemon launch nor the lock'
			);
		} catch (Throwable $e) {
			foreach ([$first, $second] as $started) {
				if ($started !== NULL) {
					proc_terminate($started[0]);
				}
			}
			throw $e;
		} finally {
			@unlink("{$this->dir}/state/barrier");
		}

		[$firstStatus, $firstOutput] = $this->finishVerb($first);
		[$secondStatus, $secondOutput] = $this->finishVerb($second);

		// Then both succeed and exactly one proxy was launched: the second found the first's serving pair and kept it
		$this->assertSame(0, $firstStatus, "first start failed: {$firstOutput}");
		$this->assertSame(0, $secondStatus, "second start failed: {$secondOutput}");
		$this->assertSame(['launch'], $this->events(), 'one daemon launch for two concurrent starts');
		$this->assertSame(['3001', '3002'], $this->livePids(), 'one supervisor and one child');
	}

	public function testAStartThatCannotTakeTheLockWithinItsWaitFailsLoudlyAndLaunchesNothing(): void
	{
		// Given another start that holds the lock for longer than the wait
		$this->moveResolver();
		$this->generate();
		$this->arrange(['LOCKF_BUSY' => '1']);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then it gives up with lockf's own "try again" status (75), one error line, and no launch or signal
		$this->assertSame(75, $status, "rc start must fail with EX_TEMPFAIL: {$output}");
		$this->assertSame(['log'], $this->events(TRUE), 'one error line, no daemon, no signal');
		$this->assertStringContainsString('lock', (string) file_get_contents("{$this->dir}/state/logger"));
	}

	// -----------------------------------------------------------------------
	// issues #3513, #3517 -- pfb-dns, the Go gateway, is the only front end: the Python proxy is its decider
	// -----------------------------------------------------------------------

	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	private const DECIDER = [
		'--', '/usr/local/pkg/pfblockerng/pfb_python.sh', '-u', '/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py',
		'--decision-fd', '3', '--module-dir', '/var/unbound', '--user', 'unbound',
	];

	/**
	 * The dns_proxy directory of a package that ships pfb-dns: one stand-in per target the generator only has to find,
	 * never run (the wrapper beside them is the one thing the script launches).
	 *
	 * @param list<string> $targets the bin/<target>/ directories that get a pfb-dns
	 */
	private function gateway(int $mode = 0555, array $targets = ['freebsd-amd64', 'freebsd-arm64']): string
	{
		$dir = "{$this->dir}/dns_proxy";
		foreach ($targets as $target) {
			$this->assertTrue(is_dir("{$dir}/bin/{$target}") || mkdir("{$dir}/bin/{$target}", 0777, TRUE), "payload mkdir failed: {$target}");
			file_put_contents("{$dir}/bin/{$target}/pfb-dns", "#!/bin/sh\n");
			chmod("{$dir}/bin/{$target}/pfb-dns", $mode);
		}
		return $dir;
	}

	private function generateWith(string $gateway): void
	{
		pfb_dns_proxy_service($gateway);
	}

	private function setting(string $key, string $value): void
	{
		config_set_path(self::SETTINGS . $key, $value);
	}

	/** The Resolver of a box with two interfaces: lan (192.0.2.1, 2001:db8::1) and opt1 (198.51.100.1, 2001:db8:1::1). */
	private function moveTwoInterfaceResolver(bool $dot = FALSE): void
	{
		$this->moveResolver(
			$dot,
			'lan,opt1',
			['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'],
			['lan' => '2001:db8::1', 'opt1' => '2001:db8:1::1']
		);
	}

	/**
	 * The daemon argv the gateway rc script must launch.
	 *
	 * @param list<string> $listen plain DNS addresses the Resolver's interfaces give; the loopback pair is appended
	 * @param list<string> $tls the --doh-* / --doq-* arguments, in order
	 * @param string $port the Resolver's Listen Port the gateway binds for plain DNS
	 * @param list<string> $module the pfB-DNS mode flags, which are the gateway's own: no DNSBL (the state of these tests) is --no-module
	 * @return list<string>
	 */
	private function gatewayArgv(string $gateway, array $listen, bool $dot = FALSE, array $tls = [], string $port = '53', array $module = ['--no-module'], string $dotPort = '853'): array
	{
		$addresses = [];
		foreach ([...$listen, '127.0.0.1', '::1'] as $address) {
			array_push($addresses, '--listen', $address);
		}
		return [
			'-r', '-R', '5', '-t', 'pfb_dns_proxy',
			'-P', $this->pidfile('pfb_dns_proxy_daemon.pid'), '-p', $this->pidfile('pfb_dns_proxy.pid'),
			'-o', "{$this->dir}/log/dns_proxy.log",
			'/bin/sh', "{$gateway}/pfb_dns.sh", ...$addresses,
			'--port', $port, '--upstream', '127.0.0.1:5353', ...($dot ? ['--dot', '--dot-port', $dotPort] : []),
			'--tls-pem', $this->certFile(), '--ctl-socket', $this->ctlSocket(), ...$tls, ...$module,
			'--unbound-conf', '/var/unbound/unbound.conf', '--user', 'unbound', '--ready-file', $this->readyFile(), ...self::DECIDER,
		];
	}

	public function testTheGatewayIsAskedToPublishItsPidBeforeTheDeciderSeparatorAndNothingElseIs(): void
	{
		// Given a package that ships pfb-dns
		$this->moveResolver(TRUE, 'lan', ['lan' => '192.0.2.1']);
		$gateway = $this->gateway();

		// When the rc service is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then the gateway gets exactly one --ready-file, ahead of `--`, and the decider is handed none
		$separator = (int) array_search('--', $argv, TRUE);
		$this->assertSame(1, count(array_keys($argv, '--ready-file', TRUE)), 'exactly one --ready-file');
		$flag = (int) array_search('--ready-file', $argv, TRUE);
		$this->assertLessThan($separator, $flag, '--ready-file belongs to the gateway, so it comes before the separator');
		$this->assertSame($this->readyFile(), $argv[$flag + 1]);
		$this->assertNotContains('--ready-file', array_slice($argv, $separator), 'the decider never publishes the pid: it is not the gateway');
	}

	/** @return list<string> the daemon argv after the rc script started under dash */
	private function startAndReadArgv(string $gateway): array
	{
		$this->generateWith($gateway);
		$this->arrange();
		[$status, $output] = $this->rc('start');
		$this->assertSame(0, $status, "rc start failed: {$output}");
		return $this->daemonArgv();
	}

	/** @return list<string> pfBlockerNG error-log lines that name the gateway binary */

	/** @return array<string,array{bool}> */
	public static function gatewayDotRows(): array
	{
		return ['DoT off' => [FALSE], 'DoT on' => [TRUE]];
	}

	#[DataProvider('gatewayDotRows')]
	public function testWithTheGatewayInstalledTheScriptRunsItWithTheDeciderAfterTheSeparatorAndDotOnlyWhenSaved(bool $dot): void
	{
		// Given the gateway binary and a saved Resolver that listened on lan (both families), DoH/DoQ off
		$gateway = $this->gateway();
		$this->moveResolver($dot, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);

		// When the rc service is generated and started under dash
		$argv = $this->startAndReadArgv($gateway);

		// Then the daemon runs the gateway with the plain addresses, Unbound's PROXY port, Unbound's config (where it
		// reads the ACL) and the unprivileged user, and hands the Python decider's argv over after `--`
		$this->assertSame($this->gatewayArgv($gateway, ['192.0.2.1', '2001:db8::1'], $dot), $argv);
		$this->assertSame(['launch'], $this->events());
	}

	public function testTheGatewayScriptQuotesEveryValueAndStaysPosixShell(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(TRUE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);
		$this->generateWith($gateway);
		$text = $this->rcText();

		$this->assertStringContainsString("--listen '192.0.2.1' --listen '2001:db8::1'", $text);
		$this->assertStringContainsString(escapeshellarg("{$gateway}/pfb_dns.sh"), $text, 'the wrapper path is quoted too');
		$this->assertStringContainsString('</dev/null >/dev/null 2>&1', $text, 'stdio is detached (#662)');
		$this->assertStringContainsString("rc_stop || return 1\n", $text, 'never launch over a survivor');
		$proc = proc_open([$this->shell, '-n', "{$this->dir}/rc/" . self::RC], [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
		$this->assertIsResource($proc);
		$output = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		$this->assertSame(0, proc_close($proc), "sh -n rejected the generated script: {$output}");
	}

	/** @return list<string> the loopback pair DoH and DoQ always listen on, next to the interfaces they are given */
	private static function loopbackListen(string $kind): array
	{
		return ["--{$kind}-listen", '127.0.0.1', "--{$kind}-listen", '::1'];
	}

	/** @return array<string,array{string,string,list<string>}> DoH interface setting, trusted setting, the --doh-* arguments */
	public static function dohRows(): array
	{
		$loopback = self::loopbackListen('doh');
		return [
			'no interface and no trusted entry: the plain addresses and loopback' => [
				'', '',
				['--doh-listen', '192.0.2.1', '--doh-listen', '2001:db8::1', '--doh-listen', '198.51.100.1',
					'--doh-listen', '2001:db8:1::1', ...$loopback, '--doh-port', '8443'],
			],
			'opt1 only, two trusted entries' => [
				'opt1', '192.0.2.10 2001:db8::/32',
				['--doh-listen', '198.51.100.1', '--doh-listen', '2001:db8:1::1', ...$loopback, '--doh-port', '8443',
					'--doh-trusted', '192.0.2.10/32', '--doh-trusted', '2001:db8::/32'],
			],
			'repeated interface, comma and space separators' => [
				'opt1,opt1,', "10.0.0.0/8,\t 192.0.2.10",
				['--doh-listen', '198.51.100.1', '--doh-listen', '2001:db8:1::1', ...$loopback, '--doh-port', '8443',
					'--doh-trusted', '10.0.0.0/8', '--doh-trusted', '192.0.2.10/32'],
			],
		];
	}

	/**
	 * @param list<string> $expected
	 */
	#[DataProvider('dohRows')]
	public function testDohOnAddsItsListenersPortAndTrustedFrontEndsToTheGatewayLine(string $interfaces, string $trusted, array $expected): void
	{
		// Given DoH on at port 8443 with this interface and trusted setting
		$gateway = $this->gateway();
		$this->moveTwoInterfaceResolver();
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_port', '8443');
		$this->setting('pfb_dns_doh_interface', $interfaces);
		$this->setting('pfb_dns_doh_trusted', $trusted);

		// When the script starts
		$argv = $this->startAndReadArgv($gateway);

		// Then the DoH group sits between --tls-pem and --unbound-conf, loopback after its interfaces' addresses;
		// the plain DNS addresses are untouched
		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1', '2001:db8::1', '198.51.100.1', '2001:db8:1::1'], FALSE, $expected),
			$argv
		);
	}

	/** @return array<string,array{string,list<string>}> DoQ interface setting, the --doq-* arguments */
	public static function doqRows(): array
	{
		$loopback = self::loopbackListen('doq');
		return [
			'no interface: the plain addresses and loopback' => [
				'', ['--doq-listen', '192.0.2.1', '--doq-listen', '2001:db8::1', '--doq-listen', '198.51.100.1',
					'--doq-listen', '2001:db8:1::1', ...$loopback, '--doq-port', '8853'],
			],
			'lan only' => ['lan', ['--doq-listen', '192.0.2.1', '--doq-listen', '2001:db8::1', ...$loopback, '--doq-port', '8853']],
		];
	}

	/**
	 * @param list<string> $expected
	 */
	#[DataProvider('doqRows')]
	public function testDoqOnAddsItsListenersAndPortAndNoTrustedFrontEnds(string $interfaces, array $expected): void
	{
		$gateway = $this->gateway();
		$this->moveTwoInterfaceResolver();
		$this->setting('pfb_dns_doq', 'on');
		$this->setting('pfb_dns_doq_port', '8853');
		$this->setting('pfb_dns_doq_interface', $interfaces);
		$this->setting('pfb_dns_doh_trusted', '192.0.2.10');

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1', '2001:db8::1', '198.51.100.1', '2001:db8:1::1'], FALSE, $expected),
			$argv,
			'DoQ has no trusted front ends, and DoH (off) leaves nothing behind'
		);
	}

	public function testDohAndDoqTogetherListDohFirst(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doq', 'on');

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doh-listen', '192.0.2.1', ...self::loopbackListen('doh'), '--doh-port', '4443',
				'--doq-listen', '192.0.2.1', ...self::loopbackListen('doq'), '--doq-port', '853',
			]),
			$this->startAndReadArgv($gateway)
		);
	}

	#[DataProvider('listenPortRows')]
	public function testTheGatewayBindsTheResolversListenPortAndFallsBackToTheDefaultWhenItIsNotAPort(?string $configured, string $expected): void
	{
		// Given the gateway binary and a moved Resolver whose Listen Port is $configured
		$gateway = $this->gateway();
		$this->moveResolver();
		if ($configured !== NULL) {
			$GLOBALS['config']['unbound']['port'] = $configured;
		}

		// When the rc service is generated and started under dash
		$argv = $this->startAndReadArgv($gateway);

		// Then the gateway gets exactly one --port (--doh-port and --doq-port are other flags), the Resolver's or 53
		$this->assertSame(1, count(array_keys($argv, '--port', TRUE)), 'exactly one --port');
		$this->assertSame($expected, $argv[(int) array_search('--port', $argv, TRUE) + 1]);
		$this->assertStringNotContainsString('reboot', $this->rcText());
	}

	public function testTheGatewayServesLoopbackOnTheListenPortWhileDohAndDoqKeepTheirOwnListeners(): void
	{
		// Given a Resolver saved on one IPv4-only interface, Listen Port 5300, DoH and DoQ on their own ports
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$GLOBALS['config']['unbound']['port'] = '5300';
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doq', 'on');

		// When the rc service is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then plain DNS is served on the interface address and on both loopback addresses at 5300, so the firewall's
		// resolv.conf (127.0.0.1, ::1) reaches the gateway; DoH and DoQ keep their own ports and also listen on loopback
		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doh-listen', '192.0.2.1', ...self::loopbackListen('doh'), '--doh-port', '4443',
				'--doq-listen', '192.0.2.1', ...self::loopbackListen('doq'), '--doq-port', '853',
			], '5300'),
			$argv
		);
	}

	public function testTlsSettingsWhileTheirToggleIsOffAddNothing(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', '');
		$this->setting('pfb_dns_doh_port', '8443');
		$this->setting('pfb_dns_doh_trusted', '192.0.2.10');
		$this->setting('pfb_dns_doq_port', '8853');

		$this->assertSame($this->gatewayArgv($gateway, ['192.0.2.1']), $this->startAndReadArgv($gateway));
	}

	public function testATlsListenerWhoseInterfacesHaveNoAddressStillListensOnLoopbackAlone(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_interface', 'opt9');
		$this->setting('pfb_dns_doh_trusted', '192.0.2.10');

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				...self::loopbackListen('doh'), '--doh-port', '4443', '--doh-trusted', '192.0.2.10/32',
			]),
			$this->startAndReadArgv($gateway),
			'the loopback backend for a local HAProxy is there whatever the interfaces came to'
		);
	}

	public function testAHandEditedTrustedEntryThatIsNotAnAddressNeverReachesTheScript(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_trusted', "192.0.2.10 evil;touch {$this->dir}/pwned fe80::1%em0 \$(id) 10.0.0.0/33");

		$this->generateWith($gateway);
		$text = $this->rcText();

		$this->assertSame(1, substr_count($text, '--doh-trusted'), 'only the real address survives');
		$this->assertStringContainsString("--doh-trusted '192.0.2.10/32'", $text);
		foreach (['evil', 'pwned', 'fe80', '$(id)', '/33'] as $junk) {
			$this->assertStringNotContainsString($junk, $text, "{$junk} must not reach the script");
		}
	}

	public function testThreeHundredTrustedEntriesAreEachQuotedAndLaunched(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$entries = [];
		for ($i = 0; $i < 300; $i++) {
			$entries[] = '10.' . intdiv($i, 250) . '.' . ($i % 250) . '.0/24';
		}
		$this->setting('pfb_dns_doh_trusted', implode(' ', $entries));

		$argv = $this->startAndReadArgv($gateway);

		$trusted = [];
		foreach ($argv as $i => $arg) {
			if ($arg === '--doh-trusted') {
				$trusted[] = $argv[$i + 1];
			}
		}
		$this->assertSame($entries, $trusted);
		$this->assertSame(300, substr_count($this->rcText(), " --doh-trusted '"), 'each entry is its own quoted word');
	}

	/** @return array<string,array{list<string>,int}> the bin/<target>/ directories that hold a pfb-dns, and its mode */
	public static function payloads(): array
	{
		return [
			'both architectures'                       => [['freebsd-amd64', 'freebsd-arm64'], 0555],
			'amd64 alone: an arm64 box fails in the wrapper' => [['freebsd-amd64'], 0555],
			'arm64 alone: an amd64 box fails in the wrapper' => [['freebsd-arm64'], 0555],
			'a target no wrapper selects'              => [['freebsd-riscv64'], 0555],
			'both, but not executable'                 => [['freebsd-amd64', 'freebsd-arm64'], 0644],
		];
	}

	/** @param list<string> $targets */
	#[DataProvider('payloads')]
	public function testAnyPfbDnsFileMakesTheScriptRunTheWrapperAndNeverTheStandalonePythonListener(array $targets, int $mode): void
	{
		// Given a saved Resolver and a package that ships pfb-dns for $targets only
		$gateway = $this->gateway($mode, $targets);
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);

		// When the rc service is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then the daemon runs the wrapper under /bin/sh, which alone decides whether this machine has a usable binary
		$this->assertSame($this->gatewayArgv($gateway, ['192.0.2.1']), $argv);
		$this->assertStringNotContainsString('pfb_dns_proxy.py --listen', $this->rcText(), 'no standalone Python listener to fall back to when the wrapper refuses');
	}

	/** @return array<string,array{array<string,string>,int}> settings, expected number of warnings */

	/** @param array<string,string> $settings */

	public function testStopSignalsTheGatewayItStartedAndWaitsForItAndItsSupervisor(): void
	{
		// Given the gateway script was started: the supervisor and the gateway child are live in the sandbox
		$gateway = $this->gateway();
		$this->moveResolver();
		$this->startAndReadArgv($gateway);
		$this->assertStringContainsString("{$gateway}/pfb_dns.sh", (string) file_get_contents("{$this->dir}/state/procs"), 'precondition: the child is the wrapper');
		$this->assertSame(['3001', '3002'], $this->livePids(), 'precondition: supervisor and gateway alive');

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then both get TERM and are waited for, with no KILL
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['launch', 'term', 'sleep', 'sleep'], $this->events());
		$this->assertSame([], $this->livePids());
	}

	/** @return array<string,array{string}> the gateway child's command line as ps shows it, in each form it takes */
	public static function gatewayChildLines(): array
	{
		$dir = '/usr/local/pkg/pfblockerng/dns_proxy';
		return [
			'the binary the wrapper exec`d, with the decider argv after the separator' => [
				"{$dir}/bin/freebsd-amd64/pfb-dns --listen 192.0.2.1 --port 53 -- "
				. '/usr/local/pkg/pfblockerng/pfb_python.sh -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py --decision-fd 3',
			],
			'the amd64 binary by its own name alone' => ["{$dir}/bin/freebsd-amd64/pfb-dns --listen 192.0.2.1"],
			'the arm64 binary by its own name alone' => ["{$dir}/bin/freebsd-arm64/pfb-dns --listen 192.0.2.1"],
			'the wrapper before it execs' => [
				"/bin/sh {$dir}/pfb_dns.sh --listen 192.0.2.1 --port 53 -- "
				. '/usr/local/pkg/pfblockerng/pfb_python.sh -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py --decision-fd 3',
			],
		];
	}

	#[DataProvider('gatewayChildLines')]
	public function testStopRecognisesAGatewayChildByItsCommandLine(string $childArgs): void
	{
		// Given a live supervisor and a child whose command line is the gateway's
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		file_put_contents("{$this->dir}/state/procs",
			"1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
			. "1002|{$this->dir}/run/pfb_dns_proxy.pid|||{$childArgs}\n");

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->livePids(), 'the gateway child was signalled and exited with its supervisor');
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'));
	}

	/** @return array<string,array{string}> the command line a pid the gateway once had can come to carry, none of them ours */
	public static function foreignChildLines(): array
	{
		return [
			'the retired single-binary name' => ['/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_gateway --listen 192.0.2.1'],
			'another install of a pfb-dns' => ['/opt/pfb-dns/bin/freebsd-amd64/pfb-dns --listen 192.0.2.1'],
			'an editor on a file of that name' => ['vi /var/log/pfb-dns.log'],
			'a pfb-dns outside the package directory' => ['/usr/local/pkg/pfblockerng/other/bin/freebsd-amd64/pfb-dns --listen 192.0.2.1'],
		];
	}

	#[DataProvider('foreignChildLines')]
	public function testStopNeverSignalsAPidWhoseCommandLineIsNotTheProxys(string $childArgs): void
	{
		// Given a live supervisor and a pidfile child whose pid was reused by another command
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		file_put_contents("{$this->dir}/state/procs",
			"1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
			. "1002|{$this->dir}/run/pfb_dns_proxy.pid|||{$childArgs}\n");

		[$status, $output] = $this->rc('stop');

		// Then only the supervisor is signalled and waited for: the stranger lives on and gets no KILL
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['1002'], $this->livePids(), 'the unrelated process was left alone');
		$this->assertSame(['term', 'sleep', 'sleep'], $this->events());
	}

	public function testStartKeepsAServingGatewayWhosePidfileChildIsNamedByItsBinaryAlone(): void
	{
		// Given a supervisor and a child that pfb-dns replaced the wrapper in: its command line has no pfb_dns_proxy in it
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		file_put_contents("{$this->dir}/state/procs",
			"1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
			. "1002|{$this->dir}/run/pfb_dns_proxy.pid|||/usr/local/pkg/pfblockerng/dns_proxy/bin/freebsd-amd64/pfb-dns --listen 192.0.2.1\n");

		// When the package start runs the script
		[$status, $output] = $this->rc('start');

		// Then both are recognised as serving: nothing is signalled and nothing is launched
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events());
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	public function testAGatewayThatIgnoresTermIsKilledAtFiveTicksAndGivenUpOnAtSeven(): void
	{
		// Given a gateway that survives both signals
		$gateway = $this->gateway();
		$this->moveResolver();
		$this->generateWith($gateway);
		$this->arrange([], 'never', 'never', TRUE);
		file_put_contents("{$this->dir}/state/procs",
			"1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
			. "1002|{$this->dir}/run/pfb_dns_proxy.pid|||{$gateway}/bin/freebsd-amd64/pfb-dns --listen 192.0.2.1\n");

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then the wait is bounded: TERM, KILL after 5 ticks, give up after 7
		$this->assertNotContains($status, [0, 124, 137], "rc stop must fail on its own: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep', 'sleep'], $this->events());
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	// -----------------------------------------------------------------------
	// issue #3513 gate fixes -- what the gateway is handed must be what it can parse and nothing wider
	// -----------------------------------------------------------------------

	/** @return list<string> the values of every `$flag` argument the daemon double was launched with */
	private function flagValues(array $argv, string $flag): array
	{
		$values = [];
		foreach ($argv as $i => $arg) {
			if ($arg === $flag) {
				$values[] = $argv[$i + 1];
			}
		}
		return $values;
	}

	/** @return list<string> error-log lines about a stored DoH/DoQ port the gateway could not parse */
	private function portWarnings(): array
	{
		$lines = explode("\n", (string) @file_get_contents("{$this->dir}/pfb.err"));
		return array_values(array_filter($lines, static fn (string $line): bool => str_contains($line, 'is not a whole number')));
	}

	/** @return array<string,array{string,list<string>}> trusted setting, the --doh-trusted values the gateway gets */
	public static function trustedHostPrefixes(): array
	{
		return [
			'bare v4 is a /32'            => ['192.0.2.10', ['192.0.2.10/32']],
			'bare v6 is a /128'           => ['2001:db8::1', ['2001:db8::1/128']],
			'bare v4-mapped v6 is a /128' => ['::ffff:192.0.2.10', ['::ffff:192.0.2.10/128']],
			'prefixes pass through'       => ['10.0.0.0/8 2001:db8::/32', ['10.0.0.0/8', '2001:db8::/32']],
			'mixed, in order'             => ['192.0.2.10, 2001:db8::1 10.0.0.0/8', ['192.0.2.10/32', '2001:db8::1/128', '10.0.0.0/8']],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('trustedHostPrefixes')]
	public function testABareTrustedAddressBecomesAHostPrefixOfItsOwnFamilyNeverAWiderOne(string $trusted, array $expected): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_trusted', $trusted);

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame($expected, $this->flagValues($argv, '--doh-trusted'));
		$this->assertStringContainsString(
			implode(' ', array_map(static fn (string $c): string => '--doh-trusted ' . escapeshellarg($c), $expected)),
			$this->rcText(),
			'each prefix is its own quoted word, in order'
		);
	}

	public function testEveryListenAddressPortAndTrustedValueOfTheTlsGroupsIsShellQuoted(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_port', '8443');
		$this->setting('pfb_dns_doh_trusted', '192.0.2.10');
		$this->setting('pfb_dns_doq', 'on');
		$this->setting('pfb_dns_doq_port', '8853');
		$this->generateWith($gateway);
		$text = $this->rcText();

		foreach ([
			"--doh-listen '192.0.2.1'", "--doh-listen '2001:db8::1'", "--doh-listen '127.0.0.1'", "--doh-listen '::1'",
			"--doh-port '8443'", "--doh-trusted '192.0.2.10/32'",
			"--doq-listen '192.0.2.1'", "--doq-listen '2001:db8::1'", "--doq-listen '127.0.0.1'", "--doq-listen '::1'",
			"--doq-port '8853'",
		] as $quoted) {
			$this->assertStringContainsString($quoted, $text, "{$quoted} must be a quoted word of the daemon line");
		}
	}

	/** @return array<string,array{string}> */
	public static function unparsablePorts(): array
	{
		return [
			'shell text'         => ["4443'; touch PWNED #"],
			'command substitution' => ['$(touch PWNED)'],
			'a word'             => ['abc'],
			'zero'               => ['0'],
			'one past the top'   => ['65536'],
			'overflowing int'    => ['99999999999999999999'],
			'negative'           => ['-1'],
			'padded'             => [' 443'],
		];
	}

	#[DataProvider('unparsablePorts')]
	public function testAStoredPortTheGatewayCouldNotParseOmitsItsGroupAndWarnsOnce(string $port): void
	{
		// Given DoH and DoQ on, each with a hand-edited port, and a trusted front end
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		foreach (['doh', 'doq'] as $kind) {
			$this->setting("pfb_dns_{$kind}", 'on');
		}
		$this->setting('pfb_dns_doh_trusted', '192.0.2.10');
		$this->setting('pfb_dns_doh_port', $port);
		$this->setting('pfb_dns_doq_port', '8853');

		// When the script is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then the DoH group is left out whole, the DoQ group is intact, the bad value is nowhere in the script,
		// and one warning says so
		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doq-listen', '192.0.2.1', ...self::loopbackListen('doq'), '--doq-port', '8853',
			]),
			$argv
		);
		$this->assertStringNotContainsString('PWNED', $this->rcText());
		$this->assertCount(1, $this->portWarnings(), 'one warning: ' . json_encode($this->portWarnings()));
		$this->assertStringContainsString('DoH', $this->portWarnings()[0]);
		$this->assertFileDoesNotExist("{$this->dir}/PWNED");
	}

	public function testABadDoqPortOmitsOnlyTheDoqGroup(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doq', 'on');
		$this->setting('pfb_dns_doq_port', 'abc');

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doh-listen', '192.0.2.1', ...self::loopbackListen('doh'), '--doh-port', '4443',
			]),
			$this->startAndReadArgv($gateway)
		);
		$this->assertCount(1, $this->portWarnings());
		$this->assertStringContainsString('DoQ', $this->portWarnings()[0]);
	}

	/** @return array<string,array{string,string}> stored port, the one the gateway gets */
	public static function paddedPorts(): array
	{
		return [
			'one leading zero' => ['0443', '443'], 'octal-looking' => ['010', '10'], 'zero padded to five' => ['00080', '80'],
			'plain' => ['8443', '8443'], 'cleared: the registered default' => ['', '4443'],
		];
	}

	#[DataProvider('paddedPorts')]
	public function testAStoredPortWithLeadingZerosIsHandedOverWithoutThemSoNoParserReadsItAsOctal(string $stored, string $expected): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_port', $stored);

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame([$expected], $this->flagValues($argv, '--doh-port'));
		$this->assertSame([], $this->portWarnings(), 'a port that parses is not a warning');
	}

	/** @return array<string,array{string}> */
	public static function untrustworthyPrefixes(): array
	{
		return [
			'leading zero'        => ['10.0.0.0/08'],
			'two leading zeros'   => ['10.0.0.0/008'],
			'host prefix padded'  => ['192.0.2.10/032'],
			'v6 leading zero'     => ['2001:db8::/064'],
			'v4 with a v6 prefix' => ['192.0.2.1/64'],
			'zone'                => ['fe80::1%em0'],
		];
	}

	#[DataProvider('untrustworthyPrefixes')]
	public function testAHandEditedTrustedPrefixTheGatewayWouldRejectNeverReachesTheScript(string $bad): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_trusted', "{$bad} 198.51.100.7");

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame(['198.51.100.7/32'], $this->flagValues($argv, '--doh-trusted'),
			"{$bad} is dropped, the valid neighbour stays");
	}

	/** The double writes where pfb_dns_proxy_service() reads the previous script from, so an unchanged one can be told. */
	private function writeRcWhereProductionReadsIt(): void
	{
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
	}

	public function testTheBadPortWarningIsLoggedWhenTheScriptChangesNotOnEveryApply(): void
	{
		$gateway = $this->gateway();
		$this->writeRcWhereProductionReadsIt();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_doh', 'on');
		$this->setting('pfb_dns_doh_port', 'abc');
		$this->generateWith($gateway);
		$this->assertCount(1, $this->portWarnings(), 'before: the generation that wrote the script warned once');

		$this->generateWith($gateway);

		$this->assertCount(1, $this->portWarnings(), 'warnings: ' . json_encode($this->portWarnings()));
	}
}
