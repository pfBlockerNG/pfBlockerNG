<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';
require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- a renewed Resolver certificate reaches the RUNNING pfB-DNS gateway on its control socket
 * (go/pfb_dns_gateway, ctl.go): the gateway is not root after its start and cannot read the root-only key file, so root pushes
 * the new certificate and key to it. The wire is one frame, a 4-byte big-endian length and then that many bytes of PEM (the
 * chain, then the key), and one reply line, `ok` or `error: <reason>`. The stand-in gateway is support/ControlSocketServer.php,
 * a real Unix socket in a real process, so the bytes asserted are the bytes a socket carried. Intent pinned here:
 *   - a certificate is pushed as exactly the file's content in that frame, once per change: the same content is not sent again,
 *     a renewed one is, and a gateway that is not ready (nothing is serving, nothing to push to) is not tried;
 *   - a push the gateway refuses, or cannot be made, is one notice with the reason and is tried again by the next apply or tick:
 *     nothing records it as done, and a certificate that could not be written is not pushed from a stale file;
 *   - a gateway that does not answer is given up on (a bounded wait, not a hang) and a frame bigger than a socket buffer
 *     arrives whole;
 *   - when no encrypted transport is wanted the file, the record of what was pushed and any copy an earlier build left in the
 *     Unbound chroot are removed and nothing is pushed.
 */
#[CoversFunction('pfb_dns_proxy_certificate_push')]
#[CoversFunction('pfb_dns_proxy_certificate_refresh')]
#[CoversFunction('pfb_dns_proxy_certificate_pushed_path')]
final class DnsProxyCertificatePushTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const OK_AT_ONCE = [[0.0, "ok\n"]];

	private string $dir = '';
	private string $socket = '';
	/** @var list<array{resource,array<int,resource>}> */
	private array $servers = [];
	/** @var list<PfbFlockClockFixture> kept for the whole test: a loaded body reaches its clock through a weak reference */
	private array $clocks = [];
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_file_notices', 'pfb_test_valid_pids'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_push_' . bin2hex(random_bytes(5));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
		$this->socket = "{$this->dir}/ctl.sock";
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], ['log' => "{$this->dir}/pfb.log", 'errlog' => "{$this->dir}/pfb.err"]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		DnsProxyCertificateFixtures::seedResolver($this->dir);
		$keys = ['active_interface' => ['present' => TRUE, 'value' => 'lan'], 'enablessl' => ['present' => TRUE, 'value' => ''], 'custom_options' => ['present' => FALSE, 'value' => NULL]];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
	}

	protected function tearDown(): void
	{
		$this->finish();
		$this->clocks = [];
		$this->clearProxyFiles();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->dir);
	}

	/** A gateway that listens on the control socket and takes one push; it writes only what the test releases (see support/ControlSocketServer.php). Returns the file its frame is recorded in. */
	private function listen(): string
	{
		@unlink($this->socket);
		$record = "{$this->dir}/frame." . count($this->servers);
		$proc = proc_open([PHP_BINARY, __DIR__ . '/support/ControlSocketServer.php', $this->socket, $record], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($proc);
		$read = [$pipes[1]];
		$write = $except = NULL;
		$this->assertSame(1, stream_select($read, $write, $except, 15), 'the stand-in gateway did not start listening');
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$proc, $pipes];
		return $record;
	}

	/** Let every stand-in gateway go: its stdin closes, which is all a silent one waits for. */
	private function finish(): void
	{
		foreach ($this->servers as [$proc, $pipes]) {
			@fclose($pipes[0]);
			@fclose($pipes[1]);
			@fclose($pipes[2]);
			proc_close($proc);
		}
		$this->servers = [];
	}

	private function pem(): string
	{
		return (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert']);
	}

	/** @return list<string> the notices raised, their texts */
	private function notices(): array
	{
		return array_column($GLOBALS['pfb_test_file_notices'], 'notice');
	}

	private function frameOf(string $pem): string
	{
		return pack('N', strlen($pem)) . $pem;
	}

	public function testTheCertificateIsPushedAsTheFilesContentInALengthPrefixedFrame(): void
	{
		// Given a gateway that serves and listens on its control socket
		$this->proxyServes();
		$record = $this->listen();

		// When the apply (or the tick) refreshes the certificate
		$refresh = $this->refreshOnVirtualClock();
		$this->assertTrue($refresh(TRUE));
		$this->finish();

		// Then it received the file's content, length first, and nothing else; nothing is wrong
		$this->assertSame($this->frameOf($this->pem()), (string) file_get_contents($record));
		$this->assertStringContainsString('BEGIN PRIVATE KEY', $this->pem());
		$this->assertSame([], $this->notices());
		$this->assertSame(hash('sha256', $this->pem()), (string) file_get_contents(pfb_dns_proxy_certificate_pushed_path()), 'what was pushed is on record');
	}

	public function testAnUnchangedCertificateIsNotPushedAgain(): void
	{
		// Given a certificate that was pushed
		$this->proxyServes();
		$this->listen();
		$refresh = $this->refreshOnVirtualClock();
		$this->assertTrue($refresh(TRUE));
		$this->finish();
		@unlink($this->socket); // nobody listens now: a second push would fail and say so

		// When the next ticks find the same certificate
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));

		// Then nothing was sent and nothing is reported
		$this->assertSame([], $this->notices());
		$this->assertFileDoesNotExist($this->socket);
	}

	public function testARenewedCertificateIsPushedAgain(): void
	{
		// Given a certificate that was pushed
		$this->proxyServes();
		$this->listen();
		$refresh = $this->refreshOnVirtualClock();
		$this->assertTrue($refresh(TRUE));
		$this->finish();
		$first = $this->pem();

		// When the Resolver's certificate is renewed and the next tick runs
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert123', DnsProxyCertificateFixtures::issue('localhost'))];
		$record = $this->listen();
		$refresh = $this->refreshOnVirtualClock();
		$this->assertTrue($refresh(TRUE));
		$this->finish();

		// Then the gateway got the new one, and that is what is on record
		$this->assertNotSame($first, $this->pem());
		$this->assertSame($this->frameOf($this->pem()), (string) file_get_contents($record));
		$this->assertSame(hash('sha256', $this->pem()), (string) file_get_contents(pfb_dns_proxy_certificate_pushed_path()));
		$this->assertSame([], $this->notices());
	}

	public function testAGatewayThatIsNotReadyIsNotPushedToAndTheFileIsStillWritten(): void
	{
		// Given a gateway that is up but has not published its ready marker, and nothing listening
		$this->proxyLivesButNeverServes();

		// When the certificate is refreshed
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));

		// Then the file is there for the start that will read it, no push was tried (that would be a notice), and none is on record
		$this->assertStringContainsString('BEGIN CERTIFICATE', $this->pem());
		$this->assertSame([], $this->notices());
		$this->assertFileDoesNotExist(pfb_dns_proxy_certificate_pushed_path());
	}

	public function testAPushTheGatewayRefusesIsReportedAndTriedAgainByTheNextTick(): void
	{
		// Given a gateway that refuses the certificate it is sent
		$this->proxyServes();
		$this->listen();
		$refresh = $this->refreshOnVirtualClock([[0.0, "error: the key is not the certificate's\n"]]);

		// When the refresh runs
		$this->assertFalse($refresh(TRUE), 'the gateway does not serve the certificate');
		$this->finish();

		// Then there is one notice with the gateway's reason, and nothing records the push as done
		$this->assertCount(1, $this->notices());
		$this->assertStringContainsString('error: the key is not the certificate\'s', $this->notices()[0]);
		$this->assertStringContainsString('keeps being served', $this->notices()[0]);
		$this->assertFileDoesNotExist(pfb_dns_proxy_certificate_pushed_path());

		// When the next tick finds a gateway that takes it
		$record = $this->listen();
		$refresh = $this->refreshOnVirtualClock();
		$this->assertTrue($refresh(TRUE));
		$this->finish();

		// Then the same content is sent again and is on record
		$this->assertSame($this->frameOf($this->pem()), (string) file_get_contents($record));
		$this->assertSame(hash('sha256', $this->pem()), (string) file_get_contents(pfb_dns_proxy_certificate_pushed_path()));
	}

	public function testAGatewayWithNoControlSocketIsOneNoticeAndTheNextTickTriesAgain(): void
	{
		// Given a gateway that serves but has no control socket (it could not make one)
		$this->proxyServes();

		// When two ticks pass
		$this->assertFalse(pfb_dns_proxy_certificate_refresh(TRUE));
		$this->assertFalse(pfb_dns_proxy_certificate_refresh(TRUE));

		// Then the standing condition is one notice that says what it is, and nothing is on record
		$this->assertCount(1, $this->notices());
		$this->assertStringContainsString('cannot connect to ' . $this->socket, $this->notices()[0]);
		$this->assertFileDoesNotExist(pfb_dns_proxy_certificate_pushed_path());
	}

	public function testACertificateThatCannotBeWrittenIsNotPushedFromAStaleFile(): void
	{
		// Given a certificate that was pushed, and a Resolver whose certificate then becomes unusable
		$this->proxyServes();
		$this->listen();
		$refresh = $this->refreshOnVirtualClock();
		$this->assertTrue($refresh(TRUE));
		$this->finish();
		@unlink($this->socket);
		$GLOBALS['config']['unbound']['sslcertref'] = '';
		@unlink(pfb_dns_proxy_certificate_pushed_path());

		// When the next tick cannot write it
		$this->assertFalse(pfb_dns_proxy_certificate_refresh(TRUE));

		// Then the one notice is the export's reason, and the file that is still there was not sent anywhere
		$this->assertCount(1, $this->notices());
		$this->assertStringContainsString('no certificate is selected in the pfB-DNS SSL/TLS Certificate field', $this->notices()[0]);
		$this->assertStringNotContainsString('cannot connect', $this->notices()[0]);
	}

	/** The verdict as the test prints it: the push's own reason, or that the push returned NULL. */
	private static function verdictOf(?string $why): string
	{
		return $why ?? 'ACKNOWLEDGED: the push returned NULL';
	}

	/** The verdict of a push that gave up on a gateway which never answered, after $seconds. */
	private function noReply(float $seconds): string
	{
		return "no reply from {$this->socket} within {$seconds} s";
	}

	/**
	 * Loads $functions onto a virtual clock, against the gateway listen() started last. $script is what that gateway writes, in
	 * order: [seconds after the previous write, bytes], or [seconds, NULL] to hang up. Each write is released by the test, so the
	 * clock, not the host, decides when it arrives. The clock lives until tearDown(), which the loaded bodies need.
	 *
	 * @param list<string> $functions
	 * @param list<array{float,?string}> $script
	 * @return array{0: string, 1: PfbFlockClockFixture} the namespace the functions were loaded into, and the clock
	 */
	private function onVirtualClock(array $functions, array $script): array
	{
		$this->assertNotEmpty($this->servers, 'a gateway must be listening before a push');
		$pipes = end($this->servers)[1];
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain($functions);
		$clock->setIdle(function (float $wait) use (&$script, $pipes): ?float {
			if ($script === [] || $script[0][0] > $wait) {
				return NULL;
			}
			[$delay, $bytes] = array_shift($script);
			$this->release($pipes, $bytes);

			return $delay;
		});
		$this->clocks[] = $clock;

		return [$namespace, $clock];
	}

	/** The certificate refresh on a virtual clock, against the gateway listen() started last: its name in that namespace. */
	private function refreshOnVirtualClock(array $script = self::OK_AT_ONCE): string
	{
		[$namespace] = $this->onVirtualClock(['pfb_dns_proxy_certificate_refresh', 'pfb_dns_proxy_certificate_push', 'pfb_dns_proxy_ctl_exchange'], $script);

		return $namespace . '\\pfb_dns_proxy_certificate_refresh';
	}

	/**
	 * A push (not a refresh) against a gateway that answers as $script says, on the virtual clock: [the verdict, the virtual
	 * seconds it took]. The push's deadline is a count of virtual seconds, never a wait.
	 *
	 * @param list<array{float,?string}> $script
	 * @return array{0: ?string, 1: float}
	 */
	private function pushOnVirtualClock(array $script, float $timeout): array
	{
		$this->listen();
		[$namespace, $clock] = $this->onVirtualClock(['pfb_dns_proxy_certificate_push', 'pfb_dns_proxy_ctl_exchange'], $script);

		return [($namespace . '\\pfb_dns_proxy_certificate_push')('certificate and key', $this->socket, $timeout), $clock->now()];
	}

	/** The stand-in gateway writes $bytes now (or hangs up, for NULL), and acknowledges once it has: PHP's next poll sees the result. */
	private function release($pipes, ?string $bytes): void
	{
		fwrite($pipes[0], ($bytes === NULL ? 'close' : 'x' . bin2hex($bytes)) . "\n");
		fflush($pipes[0]);
		stream_set_timeout($pipes[1], 10);
		$ack = fgets($pipes[1]);
		if ($ack !== "ack\n") {
			throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in gateway did not acknowledge its write: ' . var_export($ack, TRUE));
		}
	}

	public function testAGatewayThatNeverRepliesIsGivenUpOnAndNothingIsRecorded(): void
	{
		// Given a gateway that never writes
		[$why, $took] = $this->pushOnVirtualClock([], 0.3);

		// Then the push gives up at its timeout, and says so
		$this->assertSame($this->noReply(0.3), self::verdictOf($why), 'given up on with no reply');
		$this->assertEqualsWithDelta(0.3, $took, 1e-9, 'given up on after exactly the timeout');
	}

	public function testATrickledReplyCannotExtendTheReplyDeadline(): void
	{
		// Given a gateway that trickles its ok line: 'o' 0.1 s after the push, 'k' 0.1 s later, and the newline 0.25 s after
		// that, which is 0.45 s in, past the 0.3 s deadline
		[$why, $took] = $this->pushOnVirtualClock([[0.1, 'o'], [0.1, 'k'], [0.25, "\n"]], 0.3);

		// Then the push gives up at the deadline, and the ok line that would have completed later is not an acknowledgement
		$this->assertSame($this->noReply(0.3), self::verdictOf($why), 'an ok line completed after the deadline is not an acknowledgement');
		$this->assertEqualsWithDelta(0.3, $took, 1e-9, 'the trickled bytes did not move the deadline');
	}

	public function testAnUnterminatedOkIsNotAnAcknowledgement(): void
	{
		// Given a gateway that writes 'ok' with no newline 0.1 s after the push, and nothing after it
		[$why, $took] = $this->pushOnVirtualClock([[0.1, 'ok']], 0.3);

		// Then the push gives up at the deadline: an incomplete reply must not mark the certificate as pushed
		$this->assertSame($this->noReply(0.3), self::verdictOf($why), 'an incomplete reply must not mark the certificate as pushed');
		$this->assertEqualsWithDelta(0.3, $took, 1e-9, 'given up on at the deadline');
	}

	public function testAnOkLineAfterTheTimeoutIsNotAnAcknowledgement(): void
	{
		// Given a gateway whose ok line comes 3.5 s after the push, past the 3 s timeout
		[$why, $took] = $this->pushOnVirtualClock([[3.5, "ok\n"]], 3.0);

		// Then the push gives up at 3 s, and the late line is never read as an acknowledgement
		$this->assertSame($this->noReply(3.0), self::verdictOf($why), 'a line after the timeout is not an acknowledgement');
		$this->assertEqualsWithDelta(3.0, $took, 1e-9, 'given up on at the timeout, not when the line came');
	}

	public function testAnUnterminatedOkFollowedByEofIsNotAnAcknowledgement(): void
	{
		// Given a gateway that writes 'ok' with no newline, then hangs up
		[$why] = $this->pushOnVirtualClock([[0.0, 'ok'], [0.0, NULL]], 0.3);

		// Then the push reports the hang-up, and does not take the partial reply for an acknowledgement
		$this->assertSame("{$this->socket} closed the connection with no reply", self::verdictOf($why), 'closing after an incomplete ok must not acknowledge the certificate');
	}

	public function testAnOverlongReplyIsRejectedWithoutAcceptingTheCertificate(): void
	{
		// Given a gateway whose reply is longer than the reply cap, with no newline in it
		[$why] = $this->pushOnVirtualClock([[0.0, str_repeat('a', 512)]], 0.3);

		// Then the push rejects it at the cap, and reads no further
		$this->assertSame("{$this->socket} sent no complete reply", self::verdictOf($why), 'an overlong reply is rejected, not waited on');
	}

	public function testASocketNobodyListensOnIsAReasonThatNamesIt(): void
	{
		$why = pfb_dns_proxy_certificate_push('certificate and key', "{$this->dir}/nobody.sock", 0.3);

		$this->assertStringContainsString("cannot connect to {$this->dir}/nobody.sock", (string) $why);
	}

	public function testAFrameBiggerThanASocketBufferArrivesWhole(): void
	{
		$pem = str_repeat("0123456789abcdef\n", 3600); // 61 200 bytes
		$record = $this->listen();

		[$namespace] = $this->onVirtualClock(['pfb_dns_proxy_certificate_push', 'pfb_dns_proxy_ctl_exchange'], self::OK_AT_ONCE);
		$why = ($namespace . '\\pfb_dns_proxy_certificate_push')($pem, $this->socket);
		$this->finish();

		$this->assertNull($why);
		$this->assertSame($this->frameOf($pem), (string) file_get_contents($record));
	}

	public function testWhenNoEncryptedTransportIsWantedTheFileTheRecordAndTheKeyCopyInTheChrootGoAndNothingIsPushed(): void
	{
		// Given a pushed certificate, its record, and a copy an earlier build left in the Unbound chroot
		$this->proxyServes();
		$this->listen();
		$refresh = $this->refreshOnVirtualClock();
		$this->assertTrue($refresh(TRUE));
		$this->finish();
		@unlink($this->socket);
		$legacy = $GLOBALS['pfb']['dns_proxy_cert_legacy'];
		$this->assertTrue(mkdir(dirname($legacy), 0755, TRUE));
		file_put_contents($legacy, 'a key that Unbound\'s user can read');

		// When no encrypted transport is wanted any more
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(FALSE));

		// Then no key is left anywhere, and no push was tried against the gateway that still serves
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_cert']);
		$this->assertFileDoesNotExist(pfb_dns_proxy_certificate_pushed_path());
		$this->assertFileDoesNotExist($legacy);
		$this->assertSame([], $this->notices());
	}

	public function testTheKeyCopyAnEarlierBuildLeftInTheChrootIsRemovedWhileATransportIsWantedToo(): void
	{
		$legacy = $GLOBALS['pfb']['dns_proxy_cert_legacy'];
		$this->assertTrue(mkdir(dirname($legacy), 0755, TRUE));
		file_put_contents($legacy, 'a key that Unbound\'s user can read');

		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));

		$this->assertFileDoesNotExist($legacy);
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_cert']);
	}
}
