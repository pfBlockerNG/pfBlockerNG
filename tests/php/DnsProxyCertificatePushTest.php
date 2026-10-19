<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

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

	private string $dir = '';
	private string $socket = '';
	/** @var list<array{resource,array<int,resource>}> */
	private array $servers = [];
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

	/** A gateway that listens on the control socket and takes one push, answering $mode (see support/ControlSocketServer.php); returns the file its frame is recorded in. */
	private function listen(string $mode = 'ok'): string
	{
		@unlink($this->socket);
		$record = "{$this->dir}/frame." . count($this->servers);
		$proc = proc_open([PHP_BINARY, __DIR__ . '/support/ControlSocketServer.php', $this->socket, $record, $mode], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
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
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
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
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
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
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
		$this->finish();
		$first = $this->pem();

		// When the Resolver's certificate is renewed and the next tick runs
		$GLOBALS['config']['cert'] = [DnsProxyCertificateFixtures::certEntry('cert123', DnsProxyCertificateFixtures::issue('localhost'))];
		$record = $this->listen();
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
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
		$this->listen('error:the key is not the certificate\'s');

		// When the refresh runs
		$this->assertFalse(pfb_dns_proxy_certificate_refresh(TRUE), 'the gateway does not serve the certificate');
		$this->finish();

		// Then there is one notice with the gateway's reason, and nothing records the push as done
		$this->assertCount(1, $this->notices());
		$this->assertStringContainsString('error: the key is not the certificate\'s', $this->notices()[0]);
		$this->assertStringContainsString('keeps being served', $this->notices()[0]);
		$this->assertFileDoesNotExist(pfb_dns_proxy_certificate_pushed_path());

		// When the next tick finds a gateway that takes it
		$record = $this->listen();
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
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
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
		$this->finish();
		@unlink($this->socket);
		$GLOBALS['config']['unbound']['sslcertref'] = '';
		@unlink(pfb_dns_proxy_certificate_pushed_path());

		// When the next tick cannot write it
		$this->assertFalse(pfb_dns_proxy_certificate_refresh(TRUE));

		// Then the one notice is the export's reason, and the file that is still there was not sent anywhere
		$this->assertCount(1, $this->notices());
		$this->assertStringContainsString('unbound/sslcertref is empty', $this->notices()[0]);
		$this->assertStringNotContainsString('cannot connect', $this->notices()[0]);
	}

	public function testAGatewayThatNeverRepliesIsGivenUpOnAndNothingIsRecorded(): void
	{
		$this->listen('silent');

		$why = pfb_dns_proxy_certificate_push('certificate and key', $this->socket, 0.3);

		$this->assertNotNull($why);
		$this->assertStringContainsString('no reply', (string) $why);
	}

	public function testATrickledReplyCannotExtendTheReplyDeadline(): void
	{
		$this->listen('trickle');

		$why = pfb_dns_proxy_certificate_push('certificate and key', $this->socket, 0.3);

		$this->assertNotNull($why, 'an ok line completed after the deadline is not an acknowledgement');
		$this->assertStringContainsString('no reply', $why);
	}

	public function testAnUnterminatedOkIsNotAnAcknowledgement(): void
	{
		$this->listen('partial');

		$why = pfb_dns_proxy_certificate_push('certificate and key', $this->socket, 0.3);

		$this->assertNotNull($why, 'an incomplete reply must not mark the certificate as pushed');
		$this->assertStringContainsString('no reply', $why);
	}

	public function testAnUnterminatedOkFollowedByEofIsNotAnAcknowledgement(): void
	{
		$this->listen('partial-close');

		$why = pfb_dns_proxy_certificate_push('certificate and key', $this->socket, 0.3);

		$this->assertNotNull($why, 'closing after an incomplete ok must not acknowledge the certificate');
	}

	public function testAnOverlongReplyIsRejectedWithoutAcceptingTheCertificate(): void
	{
		$this->listen('long-reply');

		$why = pfb_dns_proxy_certificate_push('certificate and key', $this->socket, 0.3);

		$this->assertNotNull($why);
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

		$why = pfb_dns_proxy_certificate_push($pem, $this->socket);
		$this->finish();

		$this->assertNull($why);
		$this->assertSame($this->frameOf($pem), (string) file_get_contents($record));
	}

	public function testWhenNoEncryptedTransportIsWantedTheFileTheRecordAndTheKeyCopyInTheChrootGoAndNothingIsPushed(): void
	{
		// Given a pushed certificate, its record, and a copy an earlier build left in the Unbound chroot
		$this->proxyServes();
		$this->listen();
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
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
