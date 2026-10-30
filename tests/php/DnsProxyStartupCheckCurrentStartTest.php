<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3538 -- the startup check judges only the CURRENT start, never an older one.
 *
 * The gateway logs `listening ...` lines and then `ready upstream ...` once it serves, and publishes its ready marker BEFORE it logs
 * either (go/pfb_dns_gateway/main.go), which daemon(8) then relays to the log asynchronously: a check that sees the marker can read a
 * log whose last `ready upstream` is the PREVIOUS start's. A caller that starts or restarts the proxy therefore passes the log's size
 * from before the start ($since): only the bytes after it are the start's, the check waits (bounded, PFB_DNS_PROXY_LOG_WAIT) for the
 * `ready upstream` line among them, and a start whose line never comes cannot be judged: no problem is filed and nothing is closed.
 * With no $since (the cron tick, an apply that restarted nothing) the latest segment of the log's last 64 KiB is judged, as before.
 *
 * Every wait here is the production loop on the virtual clock (PfbFlockClockFixture): no test sleeps.
 */
#[CoversFunction('pfb_dns_proxy_startup_check')]
#[CoversFunction('pfb_dns_proxy_log_size')]
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
#[CoversFunction('pfb_dns_proxy_restart')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
final class DnsProxyStartupCheckCurrentStartTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const ID = 'pfBlockerNG DNS Proxy startup';
	private const URL = '/pfblockerng/pfblockerng_dns.php';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private const PLAIN = ['listening udp+tcp 192.0.2.1:53', 'listening udp+tcp 127.0.0.1:53', 'listening udp+tcp [::1]:53'];
	private const DOT = ['listening dot 192.0.2.1:853', 'listening dot 127.0.0.1:853', 'listening dot [::1]:853'];
	private const DOT_LOOPBACK = ['listening dot 127.0.0.1:853', 'listening dot [::1]:853'];
	private const READY = 'ready upstream 127.0.0.1:5353';
	private const DOT_MISSING = 'DoT is not served on 192.0.2.1:853: the gateway did not report it listening.';

	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_file_notices', 'pfb_test_valid_pids', 'pfb_test_rcfile_dir', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles',
		'pfb_test_interface_ip', 'pfb_test_interface_info', 'pfb_test_configured_ipv6', 'pfb_test_configured_ip_addresses',
		'pfb_test_interfaces', 'pfb_test_try_lock_fail', 'pfb_test_lock_held', 'pfb_test_lock_events', 'pfb_test_service_calls',
		'pfb_test_service_hook',
	];

	private string $dir = '';
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_current_start_' . bin2hex(random_bytes(6));
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

	/** A moved box whose rc script is generated from DoT on lan (192.0.2.1) and loopback: the command names plain DNS and DoT on both. */
	private function box(): void
	{
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::shared())];
		$settings = [
			'pfb_dns_interface' => 'lan', 'pfb_dns_sslcertref' => 'cert1',
			'pfb_dns_dot' => 'on', 'pfb_dns_dot_interface' => 'lan', 'pfb_dns_dot_port' => '853',
		];
		foreach ($settings as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => ''];
		pfb_dns_proxy_service();
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE, 'the generator wrote the rc script the check reads');
	}

	/** One complete start of the box, as the gateway logs it. */
	private function healthyStart(): array
	{
		return [...self::PLAIN, ...self::DOT, 'control socket /var/run/pfb_dns/ctl.sock', self::READY];
	}

	/** @param string|list<string> ...$lines */
	private function lines(string|array ...$lines): string
	{
		return implode("\n", array_merge(...array_map(static fn (string|array $part): array => (array) $part, $lines))) . "\n";
	}

	/** @param string|list<string> ...$lines */
	private function log(string|array ...$lines): void
	{
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], $this->lines(...$lines));
	}

	/** @param string|list<string> ...$lines */
	private function appendLog(string|array ...$lines): void
	{
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], $this->lines(...$lines), FILE_APPEND);
	}

	/** The log's size now: what a caller takes before it starts the proxy. */
	private function logSize(): int
	{
		clearstatcache();
		return (int) filesize($GLOBALS['pfb']['dns_proxy_log']);
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
		return 'pfB-DNS started with problems: ' . implode(' ', $sentences) .
			' Correct the settings on the pfB-DNS page or the cause named, then run an Update.';
	}

	private function fileStandingNotice(): void
	{
		file_notice(self::ID, 'pfB-DNS started with problems: DoT is not served on 192.0.2.1:853: old.', 'pfBlockerNG', self::URL, 2);
	}

	/**
	 * The production functions on a virtual clock, with the budgets set to one second each: 100 ms ticks, so a wait that runs out is ten.
	 *
	 * @param list<string> $entries the entry points, loaded together with the wait and the check they reach
	 * @return array{PfbFlockClockFixture,string} the clock, and the namespace the functions were loaded into
	 */
	private function onVirtualClock(array $entries): array
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(
			array_values(array_unique([...$entries, 'pfb_dns_proxy_confirm_ready', 'pfb_dns_proxy_await_ready', 'pfb_dns_proxy_startup_check'])),
			['PFB_DNS_PROXY_START_WAIT' => 1, 'PFB_DNS_PROXY_LOG_WAIT' => 1]
		);

		return [$clock, $namespace];
	}

	// -----------------------------------------------------------------------
	// An older start is never judged
	// -----------------------------------------------------------------------

	public function testAnOlderCompleteStartFollowedByALatestStartThatLacksAListenerIsReported(): void
	{
		// Given the restart-after-a-settings-change log: a complete start, then a latest start that lacks DoT on lan
		$this->box();
		$this->log($this->healthyStart(), self::PLAIN, self::DOT_LOOPBACK, self::READY);

		// When the check judges the latest start
		pfb_dns_proxy_startup_check(TRUE);

		// Then the DoT listener the older start had is not credited to it
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	public function testBytesBeforeTheSizeTakenBeforeTheStartAreNeverJudged(): void
	{
		// Given a complete start, then what an aborted run left (its DoT line for lan, no ready line): all of it before $since
		$this->box();
		$this->log($this->healthyStart(), 'listening dot 192.0.2.1:853', 'pfb_dns_gateway: aborted');
		$since = $this->logSize();
		// and, after it, the new start, which lacks DoT on lan
		$this->appendLog(self::PLAIN, self::DOT_LOOPBACK, self::READY);

		pfb_dns_proxy_startup_check(TRUE, $since);

		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts(), 'the aborted run\'s line is not the new start\'s');
	}

	public function testALogShorterThanTheSizeWasRotatedAndIsJudgedFromItsStart(): void
	{
		// Given a log that was rotated since the size was taken: shorter than it, holding only the new start, which lacks DoT on lan
		$this->box();
		$this->log(self::PLAIN, self::DOT_LOOPBACK, self::READY);
		$since = $this->logSize() + 4096;
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_startup_check']);

		// When the check judges it
		($namespace . '\\pfb_dns_proxy_startup_check')(TRUE, $since);

		// Then all of it is the start's: judged at once, with nothing waited for
		$this->assertSame([], $clock->sleeps);
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	public function testAListenerAddedLiveAfterTheStartIsServedAndTheStandingNoticeIsClosed(): void
	{
		// Given a start that lacks DoT on lan, its problem standing, and the gateway logging the DoT listener it took live afterwards (issue #3599)
		$this->box();
		$this->log(self::PLAIN, self::DOT_LOOPBACK, self::READY);
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts(), 'before: the start lacks DoT on lan');
		$this->appendLog('listening dot 192.0.2.1:853');

		// When the check judges the log again
		pfb_dns_proxy_startup_check(TRUE);

		// Then the added listener counts as served: no problem, and the notice is closed
		$this->assertSame([], $this->startupTexts());
	}

	public function testAListenerRemovedLiveAfterTheStartIsNoLongerServed(): void
	{
		// Given a start that served DoT on lan (nothing wrong), and the gateway logging that it stopped listening there
		$this->box();
		$this->log($this->healthyStart());
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertSame([], $this->startupTexts(), 'before: the start served every listener');
		$this->appendLog('stopped listening dot 192.0.2.1:853');

		// When the check judges the log again
		pfb_dns_proxy_startup_check(TRUE);

		// Then the command still names it, and it is reported as not served
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	public function testTheLast64KiBLimitHoldsWhenTheStartIsKnown(): void
	{
		// Given a standing notice and a log whose only ready line is out of its last 64 KiB, the size taken before it all
		$this->box();
		$this->fileStandingNotice();
		$before = $this->standing();
		$this->log($this->healthyStart());
		$this->appendLog(array_fill(0, 720, str_repeat('f', 99)));
		$this->assertGreaterThan(65536 + 1024, $this->logSize(), 'before: the fixture is longer than the tail');

		pfb_dns_proxy_startup_check(TRUE, 0);

		// Then nothing was found to judge by: had it read from the size, it would have closed the notice
		$this->assertSame($before, $this->standing());
	}

	public function testTheLineTheTailCutsInsideOfIsNeverJudged(): void
	{
		// Given a log of 64 KiB and 2 bytes whose first line is a DoT line for lan with one byte in front of it: the tail starts at byte 2,
		// and what it reads of that line from byte 1 on is a complete-looking `listening dot 192.0.2.1:853`
		$this->box();
		$first = "Xlistening dot 192.0.2.1:853\n";
		$last = $this->lines(self::PLAIN, self::DOT_LOOPBACK, self::READY);
		$filler = str_repeat('f', 65538 - strlen($first) - strlen($last) - 1) . "\n";
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], $first . $filler . $last);
		$this->assertSame(65538, $this->logSize(), 'before: the fixture is the length that cuts the first line');

		pfb_dns_proxy_startup_check(TRUE);

		// Then the cut line is not the start's: DoT on lan was never reported
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	// -----------------------------------------------------------------------
	// The race: the ready marker comes before the log lines
	// -----------------------------------------------------------------------

	public function testAStartWhoseLinesAreNotLoggedYetIsWaitedForWithinTheBoundAndThenNotJudged(): void
	{
		// Given a standing notice, and a log that still ends with the OLDER start, which was complete
		$this->box();
		$this->fileStandingNotice();
		$this->log($this->healthyStart());
		$since = $this->logSize();
		$before = $this->standing();
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_startup_check']);

		// When the check judges a start whose lines never come
		($namespace . '\\pfb_dns_proxy_startup_check')(TRUE, $since);

		// Then it polled the log every 100 ms for the whole budget, and judged nothing: no problem filed, the standing notice kept
		$this->assertSame(array_fill(0, 10, 100000), $clock->sleeps);
		$this->assertSame($before, $this->standing());
	}

	public function testAStartWhoseLinesAreLoggedWhileTheCheckWaitsIsJudgedOnAllOfThem(): void
	{
		// Given a log that ends with the older start, complete
		$this->box();
		$this->log($this->healthyStart());
		$since = $this->logSize();
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_startup_check']);
		// and the new start, which lacks DoT on lan, logged in two parts: its first lines at once, the rest in the third tick
		$this->appendLog(self::PLAIN);
		$clock->setOnSleep(function () use ($clock): void {
			if (count($clock->sleeps) === 3) {
				$this->appendLog(self::DOT_LOOPBACK, self::READY);
			}
		});

		// When the check judges it
		($namespace . '\\pfb_dns_proxy_startup_check')(TRUE, $since);

		// Then it stopped waiting the moment the ready line came, and judged the lines of both parts
		$this->assertSame(array_fill(0, 3, 100000), $clock->sleeps);
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	public function testWithNoSizeTheLatestSegmentIsJudgedAtOnceAndNothingIsWaitedFor(): void
	{
		// Given no start was made (the cron tick, an apply that restarted nothing) and a log that cannot be judged
		$this->box();
		$this->fileStandingNotice();
		$this->log(self::PLAIN);
		$before = $this->standing();
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_startup_check']);

		($namespace . '\\pfb_dns_proxy_startup_check')(TRUE);

		$this->assertSame([], $clock->sleeps);
		$this->assertSame($before, $this->standing());
	}

	/** @return array<string,array{list<string>,list<string>,int,string}> log before $since, appended after it, how far past the log's end $since is, the quote */
	public static function notReadyStarts(): array
	{
		return [
			'an old error and nothing from this start' => [['pfb_dns_gateway: old error'], [], 0, ''],
			'an old error, then this start\'s own' => [['pfb_dns_gateway: old error'], ['pfb_dns_gateway: this start'], 0, ' (last gateway error: pfb_dns_gateway: this start)'],
			'an old error, then lines of this start that are no error' => [['pfb_dns_gateway: old error'], self::PLAIN, 0, ''],
			'a log rotated since the size was taken' => [['pfb_dns_gateway: rotated'], [], 4096, ' (last gateway error: pfb_dns_gateway: rotated)'],
		];
	}

	/**
	 * @param list<string> $before
	 * @param list<string> $after
	 */
	#[DataProvider('notReadyStarts')]
	public function testAStartThatNeverBecameReadyQuotesOnlyTheGatewayErrorTheCurrentStartLogged(array $before, array $after, int $past, string $quote): void
	{
		// Given an error logged before the size was taken, and what the start itself logged after it (a rotation: shorter than the size)
		$this->box();
		$this->log($before);
		$since = $this->logSize() + $past;
		if ($after !== []) {
			$this->appendLog($after);
		}

		// When the check judges that start as not ready (a wait here would be a defect: nothing is started)
		pfb_dns_proxy_startup_check(FALSE, $since);

		// Then an error of an older start is not blamed on this one
		$this->assertSame(
			[$this->problemText('pfB-DNS is not serving: the DNS proxy did not become ready within ' . PFB_DNS_PROXY_START_WAIT . ' s' . $quote . '.')],
			$this->startupTexts()
		);
	}

	// -----------------------------------------------------------------------
	// Wiring: the size is taken before the start, and passed on
	// -----------------------------------------------------------------------

	public function testTheLogSizeIsTheBytesTheLogHoldsNowAndZeroWithoutALog(): void
	{
		$path = $GLOBALS['pfb']['dns_proxy_log'];
		$this->assertSame(0, pfb_dns_proxy_log_size(), 'no log yet');
		$this->log('abc');
		$this->assertSame(4, pfb_dns_proxy_log_size());
		exec('printf de >> ' . escapeshellarg($path)); // another process, as daemon(8) is
		$this->assertSame(6, pfb_dns_proxy_log_size(), 'the size now, not the one read before');
	}

	public function testTheConfirmationPassesTheSizeToTheCheck(): void
	{
		// Given a proxy that is ready, an older start in the log, and a start whose lines are not logged yet
		$this->box();
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->log($this->healthyStart());
		$since = $this->logSize();
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_confirm_ready']);
		$this->appendLog(self::PLAIN);
		$clock->setOnSleep(function () use ($clock): void {
			if (count($clock->sleeps) === 2) {
				$this->appendLog(self::DOT_LOOPBACK, self::READY);
			}
		});

		$ready = ($namespace . '\\pfb_dns_proxy_confirm_ready')($since);

		$this->assertTrue($ready);
		$this->assertSame(array_fill(0, 2, 100000), $clock->sleeps);
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	public function testARestartTakesTheSizeBeforeItAndJudgesTheStartItMade(): void
	{
		// Given a proxy that is ready the moment it restarts, and an older start in the log
		$this->box();
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->log($this->healthyStart());
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_restart']);
		// The new start logs its first lines while restart_service() runs, and the rest only after its marker was published
		$GLOBALS['pfb_test_service_hook'] = function (string $fn): void {
			if ($fn === 'restart_service') {
				$this->appendLog(self::PLAIN);
			}
		};
		$clock->setOnSleep(function () use ($clock): void {
			if (count($clock->sleeps) === 3) {
				$this->appendLog(self::DOT_LOOPBACK, self::READY);
			}
		});

		$ready = ($namespace . '\\pfb_dns_proxy_restart')();

		// Then the lines the start logged during its restart count, and so do the ones it logged after the check began to wait
		$this->assertTrue($ready);
		$this->assertSame(array_fill(0, 3, 100000), $clock->sleeps);
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	/** @return array<string,array{string,bool}> the call the apply makes, and whether a live proxy is restarted (its script changed) */
	public static function activations(): array
	{
		return [
			'a start (the proxy is not running)' => ['start_service', FALSE],
			'a restart (a live proxy whose script changed)' => ['restart_service', TRUE],
		];
	}

	#[DataProvider('activations')]
	public function testAnApplyTakesTheSizeBeforeItsStartAndJudgesTheStartItMade(string $call, bool $live): void
	{
		// Given an older start in the log and, for a restart, a live proxy and an rc script that differs from the one a start would run
		$this->box();
		$this->log($this->healthyStart());
		if ($live) {
			$this->proxyServes();
			$this->seedRunningGateway();
			file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n# stale\n");
		}
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_ensure_running']);
		// The new start logs its first lines while the service call runs, and the rest only after its marker was published
		$GLOBALS['pfb_test_service_hook'] = function (string $fn) use ($call): void {
			if ($fn === $call) {
				$this->appendLog(self::PLAIN);
				$this->proxyServes();
				$this->seedRunningGateway();
			}
		};
		$clock->setOnSleep(function () use ($clock): void {
			if (count($clock->sleeps) === 3) {
				$this->appendLog(self::DOT_LOOPBACK, self::READY);
			}
		});

		$ready = ($namespace . '\\pfb_dns_proxy_ensure_running')();

		// Then it made the call, and judged exactly the start that call began
		$this->assertTrue($ready);
		$this->assertSame([[$call, 'pfb_dns_proxy']], $GLOBALS['pfb_test_service_calls']);
		$this->assertSame(array_fill(0, 3, 100000), $clock->sleeps);
		$this->assertSame([$this->problemText(self::DOT_MISSING)], $this->startupTexts());
	}

	public function testAnApplyThatActedOnNothingJudgesTheLatestSegmentAndWaitsForNoLine(): void
	{
		// Given a live proxy whose script is unchanged, and a log with no ready line to judge by
		$this->box();
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->log(self::PLAIN);
		[$clock, $namespace] = $this->onVirtualClock(['pfb_dns_proxy_ensure_running']);

		$ready = ($namespace . '\\pfb_dns_proxy_ensure_running')();

		// Then nothing was started, and no start's line was waited for
		$this->assertTrue($ready);
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
		$this->assertSame([], $clock->sleeps);
	}

	private static function armSizeStatement(): string
	{
		$source = (string) file_get_contents(self::INC);
		if (preg_match('~\belseif\s*\(\s*\$argv\[1\]\s*==\s*\'dns_check\'\s*\)\s*\{~', $source, $branch, PREG_OFFSET_CAPTURE) !== 1) {
			throw new RuntimeException('dns_check branch not found');
		}
		$tokens = token_get_all('<?php ' . substr($source, $branch[0][1] + strlen($branch[0][0])));
		$statement = '';
		$depth = 0;
		foreach ($tokens as $token) {
			$text = is_array($token) ? $token[1] : $token;
			if ($statement === '' && $depth === 0 && is_array($token) && $token[0] === T_VARIABLE && $text === '$since') {
				$statement = $text;
				continue;
			}
			if (in_array($text, ['(', '[', '{'], TRUE)
				|| (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], TRUE))) {
				$depth++;
			} elseif (in_array($text, [')', ']', '}'], TRUE)) {
				if (--$depth < 0) {
					break;
				}
			}
			if ($statement !== '') {
				$statement .= $text;
				if ($text === ';' && $depth === 0) {
					return $statement;
				}
			}
		}
		throw new RuntimeException('dns_check size statement not found');
	}

	/** @return array<string,array{list<string>,int}> the argv the arm gets (the script, `dns_check`, then the hook's argument), the size it judges from; the log holds 4 bytes */
	public static function armArguments(): array
	{
		return [
			'the size the hook took before the start' => [['pfblockerng.inc', 'dns_check', '1234'], 1234],
			'a size of zero' => [['pfblockerng.inc', 'dns_check', '0'], 0],
			'no argument (run by hand): the log\'s size now' => [['pfblockerng.inc', 'dns_check'], 4],
			'a negative number' => [['pfblockerng.inc', 'dns_check', '-1'], 4],
			'digits and a letter' => [['pfblockerng.inc', 'dns_check', '12a'], 4],
			'an empty string' => [['pfblockerng.inc', 'dns_check', ''], 4],
			'a float' => [['pfblockerng.inc', 'dns_check', '1e3'], 4],
			'a number too big for an int' => [['pfblockerng.inc', 'dns_check', '999999999999999999999'], PHP_INT_MAX],
		];
	}

	/** @param list<string> $argv */
	#[DataProvider('armArguments')]
	public function testTheDnsCheckArmJudgesFromTheHooksSizeWhenItIsDigitsAndFromTheLogNowOtherwise(array $argv, int $expected): void
	{
		// Given the arm's own size statement, evaluated as the arm runs it, and a log that holds 4 bytes
		$statement = self::armSizeStatement();
		$this->log('abc');

		// When it gets this argv
		$since = (static function (array $argv) use ($statement): mixed {
			eval($statement);
			return $since;
		})($argv);

		// Then digits are the size taken before the start, and anything else (hostile or absent) falls back, with no TypeError
		$this->assertSame($expected, $since);
	}
}
