<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';
require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNS proxy is READY when its listener can handle queries, which is not the same as ALIVE.
 *
 * The proxy writes its own PID to the --ready-file marker only once its sockets are bound, its privileges dropped and its
 * matcher initialised. PHP therefore calls it ready only when (a) its child pidfile names a live process and (b) the marker
 * holds that same decimal PID. A live process that never published the marker (a listener that failed to bind or to
 * initialise, restarted by its supervisor every few seconds), a marker left by an earlier incarnation, a live supervisor
 * with no child, and a marker with no live child are all NOT ready. Liveness (pfb_dns_proxy_running(), pidfile only) stays
 * what it was: it answers "is the module host up?", readiness answers "did the activation work?".
 *
 * The marker and the pidfile are real files; only process liveness is the isvalidpid() double. The await is the production
 * wait, loaded onto a virtual clock (clockedAwait()): it spends its budget in ticks, and never sleeps for real.
 */
#[CoversFunction('pfb_dns_proxy_ready')]
#[CoversFunction('pfb_dns_proxy_await_ready')]
final class DnsProxyReadinessTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	/** The wait's budget in seconds: the suite's former real one, which is now ten 100 ms ticks of the virtual clock. */
	private const BUDGET_S = 1;

	private array $savedValidPids = [];
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_interface_ip', 'pfb_test_rcfile_dir', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['pfb_test_interface_ip'] = ['lo0' => '127.0.0.1'];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		$this->savedValidPids = $GLOBALS['pfb_test_valid_pids'] ?? [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$this->clearProxyFiles();
		$this->setUpUpstreamFixture();
	}

	protected function tearDown(): void
	{
		$this->tearDownUpstreamFixture();
		$this->clearProxyFiles();
		$GLOBALS['pfb_test_valid_pids'] = $this->savedValidPids;
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
	}

	public function testTheMarkerNamingTheLiveChildIsReady(): void
	{
		$this->proxyServes('4242');

		$this->assertSame(TRUE, pfb_dns_proxy_ready(), 'the marker names the live child');
	}

	public function testAProcessThatLivesButNeverPublishedTheMarkerIsAliveAndNotReady(): void
	{
		// Given a child that lives (the supervisor keeps restarting a listener that cannot bind) and no marker
		$this->proxyLivesButNeverServes('4242');

		// Then it is alive by the pidfile, and not ready
		$this->assertSame(TRUE, pfb_dns_proxy_running(), 'alive: the module-host predicate is pidfile-based and unchanged');
		$this->assertSame(FALSE, pfb_dns_proxy_ready(), 'a live pid without the marker is not a serving listener');
	}

	public function testAMarkerLeftByAnEarlierIncarnationIsNotReady(): void
	{
		// Given the supervisor restarted the child as 4243, and 4242's marker is still on disk
		$this->seedProxy('4243', "4242\n");

		$this->assertSame(FALSE, pfb_dns_proxy_ready(), 'the marker names another pid than the current child');
	}

	public function testALiveSupervisorAloneIsNotReady(): void
	{
		// Given the supervisor lives (its pid is in the marker's place by mistake) and the child pidfile is gone
		file_put_contents($this->proxyMarker(), "1001\n");
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;

		$this->assertSame(FALSE, pfb_dns_proxy_ready(), 'a live supervisor with no child is not readiness');
	}

	public function testAMarkerWithoutALiveChildIsNotReady(): void
	{
		// Given a marker and a child pidfile that agree, and a child that has exited
		$this->seedProxy('4242', "4242\n", FALSE);

		$this->assertSame(FALSE, pfb_dns_proxy_ready(), 'a marker alone is not readiness');
	}

	/** @return array<string,array{string}> */
	public static function malformedMarkers(): array
	{
		return [
			'empty'                   => [''],
			'only a newline'          => ["\n"],
			'not a number'            => ["abc\n"],
			'the pid with trailing text' => ["4242 listening\n"],
			'the pid with a prefix'   => ["pid=4242\n"],
			'zero'                    => ["0\n"],
			'a leading zero'          => ["04242\n"],
			'negative'                => ["-4242\n"],
			'two lines'               => ["4242\n4242\n"],
			'surrounding spaces'      => [" 4242 \n"],
			'hex'                     => ["0x1092\n"],
		];
	}

	#[DataProvider('malformedMarkers')]
	public function testAMalformedMarkerIsNotReadyEvenWhenTheChildLives(string $marker): void
	{
		$this->seedProxy('4242', $marker);

		$this->assertSame(FALSE, pfb_dns_proxy_ready(), 'a malformed marker is not readiness, even with a live child');
	}

	public function testAMalformedChildPidfileIsNotReady(): void
	{
		file_put_contents($this->proxyPidfile(), "4242 garbage\n");
		file_put_contents($this->proxyMarker(), "4242\n");
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = TRUE;

		$this->assertSame(FALSE, pfb_dns_proxy_ready(), 'a malformed child pidfile is not readiness');
	}

	/** @return array<string,array{string}> a malformed pid that BOTH files can carry, so the two agreeing proves nothing */
	public static function malformedPidsBothFilesCarry(): array
	{
		return [
			'zero'                     => ['0'],
			'a leading zero'           => ['04242'],
			'the pid with trailing text' => ['4242 listening'],
			'hex'                      => ['0x1092'],
			'negative'                 => ['-4242'],
		];
	}

	#[DataProvider('malformedPidsBothFilesCarry')]
	public function testAMalformedPidIsNotReadyEvenWhenThePidfileAndTheMarkerAgreeOnIt(string $pid): void
	{
		$this->seedProxy($pid, "{$pid}\n");

		$this->assertSame(FALSE, pfb_dns_proxy_ready(), 'a malformed pid that both files agree on is not readiness');
	}

	public function testTheMarkerWithoutATrailingNewlineIsStillTheSamePid(): void
	{
		$this->seedProxy('4242', '4242');

		$this->assertSame(TRUE, pfb_dns_proxy_ready(), 'a decimal pid is a decimal pid, with or without its newline');
	}

	/** @return array<string,array{string,string,bool}> */
	public static function upstreamRows(): array
	{
		$tcp = "unbound unbound 5151 3 tcp4 127.0.0.1:5353 *:*\n";
		$udp = "unbound unbound 5151 4 udp4 127.0.0.1:5353 *:*\n";
		$v6tcp = "unbound unbound 5151 3 tcp6 ::1:5353 *:*\n";
		$v6udp = "unbound unbound 5151 4 udp6 [::1]:5353 *:*\n";
		return [
			'IPv4 TCP and UDP' => ['127.0.0.1:5353', $tcp . $udp, TRUE],
			'actual command port' => ['127.0.0.1:5355', str_replace(':5353', ':5355', $tcp . $udp), TRUE],
			'only TCP' => ['127.0.0.1:5353', $tcp, FALSE],
			'only UDP' => ['127.0.0.1:5353', $udp, FALSE],
			'no listener' => ['127.0.0.1:5353', '', FALSE],
			'foreign command' => ['127.0.0.1:5353', str_replace('unbound unbound', 'root nc', $tcp . $udp), FALSE],
			'lookalike command' => ['127.0.0.1:5353', str_replace('unbound unbound', 'unbound unbound-lookalike', $tcp . $udp), FALSE],
			'foreign PID' => ['127.0.0.1:5353', str_replace('5151', '6161', $tcp . $udp), FALSE],
			'foreign holder with Unbound elsewhere' => ['127.0.0.1:5353',
				str_replace('unbound unbound 5151', 'root nc 6161', $tcp . $udp) . str_replace(':5353', ':5354', $tcp . $udp), FALSE],
			'wrong port' => ['127.0.0.1:5353', str_replace(':5353', ':5354', $tcp . $udp), FALSE],
			'wrong address' => ['127.0.0.1:5353', str_replace('127.0.0.1', '127.0.0.2', $tcp . $udp), FALSE],
			'wrong family' => ['127.0.0.1:5353', $v6tcp . $v6udp, FALSE],
			'IPv6 legacy and bracketed' => ['[::1]:5353', $v6tcp . $v6udp, TRUE],
			'IPv6 long spelling' => ['[::1]:5353', str_replace(['::1:5353', '[::1]:5353'], ['0:0:0:0:0:0:0:1:5353', '[0:0:0:0:0:0:0:1]:5353'], $v6tcp . $v6udp), TRUE],
			'whitespace and header' => ['127.0.0.1:5353', "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n"
				. str_replace(' ', "\t  ", $tcp . $udp), TRUE],
			'truncated UDP' => ['127.0.0.1:5353', $tcp . "unbound unbound 5151 4 udp4\n", FALSE],
			'wrong transport' => ['127.0.0.1:5353', $tcp . str_replace('udp4', 'sctp4', $udp), FALSE],
			'header only' => ['127.0.0.1:5353', "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n", FALSE],
		];
	}

	/** The running gateway's command line for child 4242: its --upstream is $upstream (NULL: none). The rc script is not consulted. */
	private function runningUpstream(?string $upstream = '127.0.0.1:5353'): void
	{
		$this->seedRunningGateway('4242', $upstream);
	}

	/** A gateway that serves: child live and marked, its command line forwards to the healthy IPv4 endpoint that Unbound owns. */
	private function servingGateway(): void
	{
		$this->proxyServes();
		$this->runningUpstream();
	}

	#[DataProvider('upstreamRows')]
	public function testReadinessRequiresBothTransportsOwnedByTheLiveUnboundPid(string $endpoint, string $rows, bool $expected): void
	{
		$this->proxyServes();
		$this->runningUpstream($endpoint);
		file_put_contents($GLOBALS['pfb_test_sockstat_output'], $rows);

		$this->assertSame($expected, pfb_dns_proxy_serving_ready(), "upstream={$endpoint}; sockstat:\n{$rows}");
	}

	public function testADeadUnboundCannotBeServedByTheGatewayMarkerOrItsOldSockets(): void
	{
		$this->servingGateway();
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = FALSE;

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the gateway is up but its Unbound backend has exited, so it does not serve');
	}

	public function testTheGatewayIsReadyWhileItsUnboundBackendIsDead(): void
	{
		$this->servingGateway();
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = FALSE;

		$this->assertTrue(pfb_dns_proxy_ready(), 'readiness is the gateway alone: its child pidfile and ready marker, as #3566 keeps it');
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'serving also needs the Unbound backend');
	}

	/** @return array<string,array{?string}> */
	public static function unusableUnboundPids(): array
	{
		return ['missing' => [NULL], 'empty' => [''], 'zero' => ["0\n"], 'leading zero' => ["05151\n"],
			'trailing text' => ["5151 unbound\n"], 'wrong PID' => ["6161\n"]];
	}

	#[DataProvider('unusableUnboundPids')]
	public function testUnboundNeedsItsOwnMatchingDecimalPidfile(?string $pid): void
	{
		$this->servingGateway();
		if ($pid === NULL) {
			unlink($this->unboundPidfile());
		} else {
			file_put_contents($this->unboundPidfile(), $pid);
		}

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'unusable Unbound pidfile: ' . var_export($pid, TRUE));
	}

	public function testAnUnavailableSockstatExecutableFailsClosed(): void
	{
		$this->servingGateway();
		chmod(PFB_DNS_PROXY_SOCKSTAT, 0644);
		try {
			$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the listener inventory command cannot be executed');
		} finally {
			chmod(PFB_DNS_PROXY_SOCKSTAT, 0755);
		}
	}

	/** @return array<string,array{?string}> */
	public static function malformedUpstreams(): array
	{
		return [
			'missing flag' => [NULL], 'empty value' => [''], 'malformed IP' => ['127.0.0.999:5353'],
			'zero port' => ['127.0.0.1:0'], 'oversized port' => ['127.0.0.1:65536'],
			'port text' => ['127.0.0.1:5353;false'], 'missing port' => ['127.0.0.1'],
			'broken IPv6 brackets' => ['[::1:5353'],
		];
	}

	#[DataProvider('malformedUpstreams')]
	public function testAnUnusableUpstreamCommandFailsClosed(?string $endpoint): void
	{
		$this->proxyServes();
		$this->runningUpstream($endpoint);

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'unusable --upstream: ' . var_export($endpoint, TRUE));
	}

	public function testAMissingOrForeignRunningCommandFailsClosed(): void
	{
		$this->servingGateway();
		foreach (['', "4242 /usr/bin/someone-else --upstream 127.0.0.1:5353"] as $row) {
			file_put_contents($GLOBALS['pfb_test_ps_output'], $row === '' ? '' : "{$row}\n");
			$this->assertFalse(pfb_dns_proxy_serving_ready(), 'no running gateway command: ' . var_export($row, TRUE));
		}
	}

	public function testSockstatFailureFailsClosedEvenIfItsStdoutNamesHealthySockets(): void
	{
		$this->servingGateway();
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'sockstat exited nonzero with otherwise healthy stdout');
	}

	public function testReadinessUsesTheRunningGatewayEndpointRatherThanCurrentInterfaceAvailability(): void
	{
		$this->servingGateway();
		$GLOBALS['pfb_test_interface_ip']['lo0'] = NULL;
		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'the running gateway forwards to healthy IPv4, whatever the interface holds now');
		$this->runningUpstream('[::1]:5353');
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the running gateway forwards to absent IPv6, not healthy IPv4');
	}

	public function testTheAwaitReturnsOnTheTickTheBackendStartsServing(): void
	{
		$this->servingGateway();
		file_put_contents($GLOBALS['pfb_test_sockstat_output'], '');
		[$clock, $await] = $this->clockedAwait();
		$clock->setOnSleep(function () use ($clock): void {
			if (count($clock->sleeps) === 3) {
				$this->seedUnbound();
			}
		});

		$this->assertTrue($await(), 'Unbound publishes its listeners on tick three');
		$this->assertSame([100000, 100000, 100000], $clock->sleeps, 'gateway readiness alone must not finish the wait');
	}

	public function testTheAwaitSpendsItsFullControlledBudgetWhenTheBackendNeverServes(): void
	{
		$this->servingGateway();
		file_put_contents($GLOBALS['pfb_test_sockstat_output'], '');
		[$clock, $await] = $this->clockedAwait();

		$this->assertFalse($await(), 'a live gateway is not success without the backend');
		$this->assertSame(self::fullBudget(), $clock->sleeps, 'the backend gets the existing full startup budget');
	}

	/** @return array{PfbFlockClockFixture,string} the virtual clock the wait sleeps on, and the wait's name in the namespace it was loaded into */
	private function clockedAwait(): array
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_dns_proxy_await_ready'], ['PFB_DNS_PROXY_START_WAIT' => self::BUDGET_S]);
		return [$clock, $namespace . '\\pfb_dns_proxy_await_ready'];
	}

	/** The sleeps of a wait that spent its whole budget: one 100 ms tick per poll, as the production loop sleeps. */
	private static function fullBudget(): array
	{
		return array_fill(0, self::BUDGET_S * 10, 100000);
	}

	public function testTheAwaitReturnsAsSoonAsTheMarkerAppears(): void
	{
		// Given a proxy whose marker appears on the third probe of its liveness
		$probes = 0;
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = function () use (&$probes): bool {
			if (++$probes === 3) {
				file_put_contents($this->proxyMarker(), "4242\n");
			}
			return TRUE;
		};
		file_put_contents($this->proxyPidfile(), "4242\n");
		$this->runningUpstream();
		[$clock, $await] = $this->clockedAwait();

		// When the activation waits for it
		$ready = $await();

		// Then it returns ready on the probe that found the marker, two 100 ms ticks in, not after the whole budget
		$this->assertSame(TRUE, $ready, 'the wait ends ready once the marker is there');
		$this->assertSame(3, $probes, 'one probe per tick, stopping at the probe that found the marker');
		$this->assertSame([100000, 100000], $clock->sleeps, 'the wait slept two ticks of 100 ms, then returned');
	}

	public function testTheAwaitGivesUpWhenOnlyTheSupervisorLives(): void
	{
		// Given a child that never lives past its pidfile, and a supervisor that does
		file_put_contents($this->proxyPidfile(), "4242\n");
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		[$clock, $await] = $this->clockedAwait();

		// When the activation waits for it
		$ready = $await();

		// Then the wait gives up once its whole budget has passed on the virtual clock: a live supervisor is not readiness
		$this->assertSame(FALSE, $ready, 'a live supervisor is not readiness');
		$this->assertSame(self::fullBudget(), $clock->sleeps, 'the wait gave up after its whole budget, tick by tick');
	}

	public function testTheAwaitGivesUpOnAProcessThatLivesButNeverServes(): void
	{
		// Given a process that lives and never publishes its marker
		$this->proxyLivesButNeverServes('4242');
		[$clock, $await] = $this->clockedAwait();

		// When the activation waits for it
		$ready = $await();

		// Then the wait gives up once its whole budget has passed on the virtual clock
		$this->assertSame(FALSE, $ready, 'a listener that never publishes its marker is not ready');
		$this->assertSame(self::fullBudget(), $clock->sleeps, 'the wait gave up after its whole budget, tick by tick');
	}

	public function testTheAwaitFollowsTheProcessTheSupervisorRestartedAsNewChild(): void
	{
		// Given child 4241 with the marker of an earlier incarnation (4242), a supervisor that replaces the child by 4243
		// while PHP waits, and the new child's marker landing two probes later
		$this->seedProxy('4241', "4242\n");
		$this->seedRunningGateway('4243');
		$probes = 0;
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = function () use (&$probes): bool {
			$probes++;
			if ($probes === 2) {
				file_put_contents($this->proxyPidfile(), "4243\n");
			}
			if ($probes === 4) {
				file_put_contents($this->proxyMarker(), "4243\n");
			}
			return TRUE;
		};
		[$clock, $await] = $this->clockedAwait();

		// Then the wait ends only once the marker names the child the pidfile names at that moment
		$this->assertSame(TRUE, $await(), 'the marker of the new child ends the wait');
		$this->assertSame(4, $probes, 'the marker of the earlier incarnation did not end the wait');
		$this->assertSame([100000, 100000, 100000], $clock->sleeps, 'three ticks of 100 ms, then ready');
	}

	public function testTheDefaultBudgetIsTheNativeUnboundStartupBudgetAndTheDefaultsPointAtTheRealFiles(): void
	{
		$source = (string) file_get_contents(self::INC);

		$this->assertMatchesRegularExpression(
			"/if \\(!defined\\('PFB_DNS_PROXY_START_WAIT'\\)\\) \\{\\n\\tdefine\\('PFB_DNS_PROXY_START_WAIT', PFB_UNBOUND_START_WAIT\\);\\n\\}/",
			$source,
			'the wait for a proxy is the Unbound startup budget (30 s), with no setting of its own'
		);
		$this->assertMatchesRegularExpression("/define\\('PFB_UNBOUND_START_WAIT', 30\\);/", $source);
		$this->assertMatchesRegularExpression("/\\\$pfb\\['dns_proxy_ready'\\]\\s*=\\s*'\\/var\\/unbound\\/pfb_dns_ready';/", $source,
			'the marker lives in the Unbound chroot directory, where the proxy already writes as `unbound`');
		$this->assertMatchesRegularExpression("/\\\$pfb\\['dns_proxy_pidfile'\\]\\s*=\\s*PFB_DNS_PROXY_PIDFILE;/", $source,
			'the readiness check reads the child pidfile the rc script writes');
	}

	public function testThePidfileOnlyAwaitIsReplacedEverywhere(): void
	{
		$this->assertSame(FALSE, function_exists('pfb_dns_proxy_await_running'), 'no alias is kept for the pidfile-only wait');

		$root = dirname(__DIR__, 2);
		$files = (string) shell_exec('grep -rl "pfb_dns_proxy_await_running" ' . escapeshellarg("{$root}/src") . ' ' . escapeshellarg("{$root}/docs") . ' 2>/dev/null');
		$this->assertSame('', trim($files), 'every caller and document names the readiness wait');
	}
}
