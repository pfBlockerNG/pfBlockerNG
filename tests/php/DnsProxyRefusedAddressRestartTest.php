<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3598 -- an address the gateway's start could not assign is served by a restart once the box can bind it.
 *
 * A start whose latest record says `cannot listen on <host:port>: bind: can't assign requested address` (EADDRNOTAVAIL: an address
 * the interface did not have yet) leaves that address unserved until something restarts the proxy. Outside a package operation, when
 * the host named is an IP address that an unprivileged bind now takes, the whole pair is restarted ONCE, from the update pass and from
 * every cron tick; the tick's confirmation then judges the NEW start, not the one it replaced. Nothing else restarts the proxy:
 *   - any other refusal (address in use), an address the box still cannot bind, a host that is no IP address (it would be resolved,
 *     or is not one inet_pton() takes), a log with no complete start, or no refusal at all;
 *   - the tick while an update pass runs, and a tick never takes the restarts only the update pass makes (marker, rc script, gateway).
 *
 * Every row starts from the quiet box (nothing differs: nothing restarts) and gives the gateway a log; the package-operation rows
 * are DnsProxyKeepRunningPkgTest's.
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfblockerng_tick')]
final class DnsProxyRefusedAddressRestartTest extends TestCase
{
	use KeepRunningScenario;

	private const READY = 'ready upstream 127.0.0.1:5353 pid 4242';
	private const CANT = "bind: can't assign requested address";
	private const STARTUP = 'pfBlockerNG DNS Proxy startup';
	/** The addresses the rc script's command listens on in this fixture, as the gateway logs them. */
	private const ADDRESSES = ['192.0.2.1:53', '127.0.0.1:53', '[::1]:53'];

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::krGlobals() as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_refused_address_' . getmypid() . '_' . bin2hex(random_bytes(4)));
	}

	protected function tearDown(): void
	{
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

	/**
	 * The gateway's log of one start: it refuses what $refused maps (host:port as the log spells it => the reason), serves the
	 * other addresses of the command, and ends with its ready line unless $complete is FALSE.
	 *
	 * @param array<string,string> $refused
	 * @return list<string>
	 */
	private static function start(array $refused, bool $complete = TRUE): array
	{
		$lines = [];
		foreach (self::ADDRESSES as $at) {
			$lines[] = isset($refused[$at]) ? "cannot listen on {$at}: {$refused[$at]}" : "listening udp+tcp {$at}";
		}
		foreach (array_diff_key($refused, array_flip(self::ADDRESSES)) as $at => $reason) {
			$lines[] = "cannot listen on {$at}: {$reason}";
		}
		return $complete ? [...$lines, self::READY] : $lines;
	}

	/** Whether this host takes an unprivileged UDP bind on $host (port 0), which it closes at once: the question the restart asks. */
	private static function binds(string $host): bool
	{
		$probe = @stream_socket_server("udp://{$host}:0", $errno, $errstr, STREAM_SERVER_BIND);
		if ($probe === FALSE) {
			return FALSE;
		}
		fclose($probe);
		return TRUE;
	}

	/** The text of every notice filed under the startup check's id, as it stands. */
	private function startupNotices(): array
	{
		return array_column(array_filter($GLOBALS['pfb_test_file_notices'], static fn (array $notice): bool => $notice['id'] === self::STARTUP), 'notice');
	}

	/** The pfB log alone (krLog() joins it to the error log, which pfb_logger() writes the same lines to). */
	private function pfbLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	public static function bindableRefusals(): array
	{
		return [
			'FreeBSD wording' => [self::start(['127.0.0.1:53' => self::CANT]), '127.0.0.1:53'],
			'an IPv6 address, bracketed as the gateway logs it' => [self::start(['[::1]:53' => self::CANT]), '[::1]:53'],
			'Linux wording' => [self::start(['127.0.0.1:53' => 'bind: cannot assign requested address']), '127.0.0.1:53'],
			'trailing spaces after the reason' => [self::start(['127.0.0.1:53' => self::CANT . '   ']), '127.0.0.1:53'],
			'text after the reason' => [self::start(['127.0.0.1:53' => self::CANT . ' (os error 49)']), '127.0.0.1:53'],
		];
	}

	#[DataProvider('bindableRefusals')]
	public function testAnAddressTheStartCouldNotAssignAndTheBoxBindsNowRestartsTheProxyOnce(array $log, string $at): void
	{
		// Given a ready proxy whose latest start could not assign an address that this box binds
		$this->krApply(['gatewayLog' => $log]);

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then the whole pair is restarted once, and the restart names the address as the gateway spelled it
		$this->assertTrue($ready);
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertMatchesRegularExpression('/Restarting the DNS proxy:[^\n]*' . preg_quote($at, '/') . '/', $this->krLog());
	}

	public static function unbindableRefusals(): array
	{
		return [
			'an IPv4 address the box does not have' => [self::start(['192.0.2.1:53' => self::CANT]), '192.0.2.1'],
			'an IPv6 address the box does not have' => [self::start(['[2001:db8::1]:53' => self::CANT]), '[2001:db8::1]'],
		];
	}

	#[DataProvider('unbindableRefusals')]
	public function testAnAddressTheBoxStillCannotBindIsNotRestartedFor(array $log, string $host): void
	{
		// Given a latest start that could not assign an address, and (before) a box that still cannot bind it
		$this->assertFalse(self::binds($host), "before: this host binds {$host}, so the row would not exercise a failing probe");
		$this->krApply(['gatewayLog' => $log]);

		// When the update pass runs
		$this->krEnsure();

		// Then the proxy is left alone
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAnAddressAlreadyInUseIsNotRestartedFor(): void
	{
		// Given a latest start that refused a bindable address for another reason (before: the address binds)
		$this->assertTrue(self::binds('127.0.0.1'), 'before: this host binds 127.0.0.1');
		$this->krApply(['gatewayLog' => self::start(['127.0.0.1:53' => 'bind: address already in use'])]);

		// When the update pass runs
		$this->krEnsure();

		// Then the proxy is left alone
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAStartThatBoundEveryAddressRestartsNothing(): void
	{
		// Given a latest start that listens on every address of the command
		$this->krApply(['gatewayLog' => self::start([])]);

		// When the update pass runs
		$this->krEnsure();

		// Then the proxy is left alone
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testSeveralRefusedAddressesRestartTheProxyOnce(): void
	{
		// Given a latest start that could not assign 127.0.0.1 for its plain DNS, DoT, DoH and DoQ listeners
		$this->krApply(['gatewayLog' => [
			'listening udp+tcp 192.0.2.1:53',
			'cannot listen on 127.0.0.1:53: ' . self::CANT,
			'listening udp+tcp [::1]:53',
			'cannot listen on 127.0.0.1:853: ' . self::CANT,
			'cannot listen on 127.0.0.1:4443: ' . self::CANT,
			'cannot listen on 127.0.0.1:853: ' . self::CANT,
			self::READY,
		]]);

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once, not once per address
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
	}

	public function testALogWithNoCompleteStartIsNotRestartedFor(): void
	{
		// Given a log that holds the refusal but no `ready upstream` line: a start that has not finished logging, which cannot be judged
		$this->krApply(['gatewayLog' => self::start(['127.0.0.1:53' => self::CANT], FALSE)]);

		// When the update pass runs
		$this->krEnsure();

		// Then the proxy is left alone
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAHostThatIsNoIpAddressIsNeverProbed(): void
	{
		// Given a refusal of `127.1`, which the bind would turn into 127.0.0.1 (before: it binds here, so a probe would restart)
		$this->assertTrue(self::binds('127.1'), 'before: this host binds 127.1');
		$this->krApply(['gatewayLog' => self::start(['127.1:53' => self::CANT])]);

		// When the update pass runs
		$this->krEnsure();

		// Then the proxy is left alone: the host was never handed to a bind
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAZonedAddressIsNotRestartedForAndRaisesNothing(): void
	{
		// Given a refusal of a zoned link-local address
		$this->krApply(['gatewayLog' => self::start(['[fe80::1%lo0]:53' => self::CANT])]);

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then the proxy is left alone
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testTheCronTickRestartsTheProxyOnceAndJudgesTheNewStart(): void
	{
		// Given a serving proxy whose old start could not assign 127.0.0.1, with its startup problem standing as a notice
		$this->krApply(['gatewayLog' => self::start(['127.0.0.1:53' => self::CANT]), 'serving' => TRUE, 'restartLog' => self::start([])]);
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertNotSame([], $this->startupNotices(), 'before: the old start left a startup notice');

		// When the cron tick runs and the restart's new start binds every address
		$this->krTick();

		// Then the pair was restarted once, and the new start was judged: the standing notice is closed
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame([], $this->startupNotices());
	}

	public function testTheTickDoesNotJudgeTheStartItReplacedWhileTheNewOneHasNotLoggedYet(): void
	{
		// Given the same old start and standing notice, and a restart whose new start has not logged its record when the tick looks
		$this->krApply(['gatewayLog' => self::start(['127.0.0.1:53' => self::CANT]), 'serving' => TRUE, 'restartLog' => NULL]);
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertNotSame([], $this->startupNotices(), 'before: the old start left a startup notice');
		$logged = strlen($this->pfbLog());

		// When the cron tick runs
		$this->krTick();

		// Then the proxy was restarted once, and what the tick logged says so and does not repeat the old start's problem
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$during = substr($this->pfbLog(), $logged);
		$this->assertStringContainsString('Restarting the DNS proxy:', $during);
		$this->assertStringNotContainsString('pfB-DNS started with problems', $during);
	}

	public function testTheTickStillConfirmsAnAddressTheBoxCannotBind(): void
	{
		// Given a serving proxy whose latest start could not assign 192.0.2.1, which this box does not have
		$this->assertFalse(self::binds('192.0.2.1'), 'before: this host binds 192.0.2.1');
		$this->krApply(['gatewayLog' => self::start(['192.0.2.1:53' => self::CANT]), 'serving' => TRUE]);
		$logged = strlen($this->pfbLog());

		// When the cron tick runs
		$this->krTick();

		// Then nothing is restarted and the confirmation files the problem as it always did
		$this->assertSame([], $this->krProxyCalls());
		$this->assertStringContainsString("Plain DNS is not served on 192.0.2.1:53: bind: can't assign requested address", substr($this->pfbLog(), $logged));
	}

	public function testTheTickRestartsNothingWhileAnUpdatePassRuns(): void
	{
		// Given a serving proxy whose old start could not assign 127.0.0.1, and an update pass running
		$ps = ['/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron'];
		$this->assertTrue(pfb_update_pass_running($ps), 'before: the process table holds an update pass');
		$this->krApply(['gatewayLog' => self::start(['127.0.0.1:53' => self::CANT]), 'serving' => TRUE]);
		$filed = count($GLOBALS['pfb_test_file_notices']);

		// When the cron tick runs
		$this->krTick($ps);

		// Then the pass is left to restart it: nothing is restarted or filed
		$this->assertSame([], $this->krProxyCalls());
		$this->assertCount($filed, $GLOBALS['pfb_test_file_notices']);
	}

	public function testTheTickTakesNoRestartThatOnlyTheUpdatePassMakes(): void
	{
		// Given a start that bound every address, a restart pending, an rc script that differs and another gateway installed
		$this->krApply([
			'gatewayLog' => self::start([]), 'serving' => TRUE,
			'marker' => 'the package changed its rc script', 'rc' => 'stale', 'gateway' => 'different',
		]);
		$rc = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);

		// When the cron tick runs
		$this->krTick();

		// Then nothing is restarted, and the pending restart and the rc script are as they were
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame('the package changed its rc script', $this->krMarker());
		$this->assertSame($rc, (string) file_get_contents(PFB_DNS_PROXY_RCFILE));
	}
}
