<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

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
 * The marker and the pidfile are real files; only process liveness is the isvalidpid() double. The wait is the existing
 * startup budget (PFB_UNBOUND_START_WAIT, 30 s), which the bootstrap shortens for the suite (PFB_DNS_PROXY_START_WAIT).
 */
#[CoversFunction('pfb_dns_proxy_ready')]
#[CoversFunction('pfb_dns_proxy_await_ready')]
final class DnsProxyReadinessTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private array $savedValidPids = [];

	protected function setUp(): void
	{
		$this->savedValidPids = $GLOBALS['pfb_test_valid_pids'] ?? [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$this->clearProxyFiles();
	}

	protected function tearDown(): void
	{
		$this->clearProxyFiles();
		$GLOBALS['pfb_test_valid_pids'] = $this->savedValidPids;
	}

	public function testTheMarkerNamingTheLiveChildIsReady(): void
	{
		$this->proxyServes('4242');

		$this->assertTrue(pfb_dns_proxy_ready());
	}

	public function testAProcessThatLivesButNeverPublishedTheMarkerIsAliveAndNotReady(): void
	{
		// Given a child that lives (the supervisor keeps restarting a listener that cannot bind) and no marker
		$this->proxyLivesButNeverServes('4242');

		// Then it is alive by the pidfile, and not ready
		$this->assertTrue(pfb_dns_proxy_running(), 'alive: the module-host predicate is pidfile-based and unchanged');
		$this->assertFalse(pfb_dns_proxy_ready(), 'a live pid without the marker is not a serving listener');
	}

	public function testAMarkerLeftByAnEarlierIncarnationIsNotReady(): void
	{
		// Given the supervisor restarted the child as 4243, and 4242's marker is still on disk
		$this->seedProxy('4243', "4242\n");

		$this->assertFalse(pfb_dns_proxy_ready(), 'the marker names another pid than the current child');
	}

	public function testALiveSupervisorAloneIsNotReady(): void
	{
		// Given the supervisor lives (its pid is in the marker's place by mistake) and the child pidfile is gone
		file_put_contents($this->proxyMarker(), "1001\n");
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;

		$this->assertFalse(pfb_dns_proxy_ready());
	}

	public function testAMarkerWithoutALiveChildIsNotReady(): void
	{
		// Given a marker and a child pidfile that agree, and a child that has exited
		$this->seedProxy('4242', "4242\n", FALSE);

		$this->assertFalse(pfb_dns_proxy_ready(), 'a marker alone is not readiness');
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

		$this->assertFalse(pfb_dns_proxy_ready());
	}

	public function testAMalformedChildPidfileIsNotReady(): void
	{
		file_put_contents($this->proxyPidfile(), "4242 garbage\n");
		file_put_contents($this->proxyMarker(), "4242\n");
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = TRUE;

		$this->assertFalse(pfb_dns_proxy_ready());
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

		$this->assertFalse(pfb_dns_proxy_ready());
	}

	public function testTheMarkerWithoutATrailingNewlineIsStillTheSamePid(): void
	{
		$this->seedProxy('4242', '4242');

		$this->assertTrue(pfb_dns_proxy_ready(), 'a decimal pid is a decimal pid, with or without its newline');
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

		// When the activation waits for it
		$ready = pfb_dns_proxy_await_ready();

		// Then it returns ready, having looked at least until the marker was there
		$this->assertTrue($ready);
		$this->assertGreaterThanOrEqual(3, $probes);
	}

	public function testTheAwaitGivesUpWhenOnlyTheSupervisorLives(): void
	{
		// Given a child that never lives past its pidfile, and a supervisor that does
		file_put_contents($this->proxyPidfile(), "4242\n");
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;

		$this->assertFalse(pfb_dns_proxy_await_ready(), 'a live supervisor is not readiness');
	}

	public function testTheAwaitGivesUpOnAProcessThatLivesButNeverServes(): void
	{
		$this->proxyLivesButNeverServes('4242');

		$this->assertFalse(pfb_dns_proxy_await_ready());
	}

	public function testTheAwaitFollowsTheProcessTheSupervisorRestartedAsNewChild(): void
	{
		// Given child 4241 with the marker of an earlier incarnation (4242), a supervisor that replaces the child by 4243
		// while PHP waits, and the new child's marker landing two probes later
		$this->seedProxy('4241', "4242\n");
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

		// Then the wait ends only once the marker names the child the pidfile names at that moment
		$this->assertTrue(pfb_dns_proxy_await_ready());
		$this->assertGreaterThanOrEqual(4, $probes);
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
		$this->assertFalse(function_exists('pfb_dns_proxy_await_running'), 'no alias is kept for the pidfile-only wait');

		$root = dirname(__DIR__, 2);
		$files = (string) shell_exec('grep -rl "pfb_dns_proxy_await_running" ' . escapeshellarg("{$root}/src") . ' ' . escapeshellarg("{$root}/docs") . ' 2>/dev/null');
		$this->assertSame('', trim($files), 'every caller and document names the readiness wait');
	}
}
