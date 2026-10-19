<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- a renewed Resolver certificate reaches the running pfB-DNS gateway with no restart: PHP writes the certificate
 * chain and key the Resolver uses (unbound/sslcertref) to one PEM file, readable only by the user the gateway runs as, and the
 * gateway reads it again whenever it changes (go/pfb_dns_gateway, tlsconfig.go). Intent pinned here:
 *   - the file holds the certificate, the CAs its caref leads to nearest first (a missing CA or a loop ends the chain), then the
 *     key, mode 0600, owned by the gateway's user;
 *   - a certificate that is already in the file is not written again, and a new one replaces it in one rename: a reader that
 *     has the old file open never sees a mixture, and no temporary file is left;
 *   - a certificate that cannot be used (no certificate chosen, bad base64, a key that is encrypted or is not the
 *     certificate's) writes nothing: the file keeps the certificate the gateway serves, and the reason comes back;
 *   - the file exists exactly while DoT, DoH or DoQ is wanted, and is renewed by the apply (pfb_dns_proxy_service()) and by the
 *     cron tick (pfb_dns_proxy_certificate_sync()).
 */
#[CoversFunction('pfb_dns_proxy_certificate_export')]
#[CoversFunction('pfb_dns_proxy_certificate_refresh')]
#[CoversFunction('pfb_dns_proxy_certificate_sync')]
#[CoversFunction('pfb_dns_proxy_tls_wanted')]
final class DnsProxyCertificateExportTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';

	private string $dir = '';
	private string $pem = '';
	private string $owner = '';
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_file_notices'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_cert_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
		$this->pem = "{$this->dir}/pfb_dns_cert.pem";
		$this->owner = (string) posix_getpwuid(posix_geteuid())['name'];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], ['dns_proxy_cert' => $this->pem, 'dns_proxy_cert_owner' => $this->owner, 'log' => "{$this->dir}/pfb.log", 'errlog' => "{$this->dir}/pfb.err"]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
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

	/** Install the Resolver's certificate (and the authorities above it) in config.xml. @param list<array> $authorities <ca> entries */
	private function install(array $cert, array $authorities = [], string $ref = 'cert1'): void
	{
		$GLOBALS['config']['unbound']['sslcertref'] = $ref;
		$GLOBALS['config']['cert'] = [$cert];
		$GLOBALS['config']['ca'] = $authorities;
	}

	private function export(): ?string
	{
		return pfb_dns_proxy_certificate_export($this->pem, $this->owner);
	}

	/** @return list<string> the PEM blocks of the file as [type, body] concatenated, in file order */
	private function blocks(): array
	{
		$this->assertGreaterThan(0, preg_match_all('~-----BEGIN ([A-Z ]+)-----\n(.*?)\n-----END \1-----~s', (string) file_get_contents($this->pem), $m, PREG_SET_ORDER));
		return array_map(static fn (array $b): string => "{$b[1]}:{$b[2]}", $m);
	}

	private function body(string $pem): string
	{
		preg_match('~-----BEGIN [A-Z ]+-----\n(.*?)\n-----END~s', $pem, $m);
		return $m[1];
	}

	public function testTheFileHoldsTheCertificateThenItsCAsNearestFirstThenTheKey(): void
	{
		// Given a certificate below an intermediate CA below a root CA
		$root = DnsProxyCertificateFixtures::issue('root');
		$mid = DnsProxyCertificateFixtures::issue('mid', $root);
		$leaf = DnsProxyCertificateFixtures::issue('localhost', $mid);
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', $leaf, 'mid'), [
			DnsProxyCertificateFixtures::caEntry('root', $root),
			DnsProxyCertificateFixtures::caEntry('mid', $mid, 'root'),
		]);

		// When it is exported
		$this->assertNull($this->export());

		// Then the file is the leaf, the intermediate, the root and the key, in that order
		$this->assertSame([
			'CERTIFICATE:' . $this->body($leaf['cert']),
			'CERTIFICATE:' . $this->body($mid['cert']),
			'CERTIFICATE:' . $this->body($root['cert']),
			'PRIVATE KEY:' . $this->body($leaf['key']),
		], $this->blocks());
	}

	public function testTheFileIsPrivateToTheGatewaysUser(): void
	{
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost')));

		$this->assertNull($this->export());

		clearstatcache();
		$this->assertSame(0600, fileperms($this->pem) & 0777, 'a private key is readable by its owner only');
		$this->assertSame($this->owner, posix_getpwuid((int) fileowner($this->pem))['name']);
		$this->assertSame(posix_getegid(), filegroup($this->pem), 'and its primary group');
	}

	public function testAnUnchangedCertificateIsNotWrittenAgain(): void
	{
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost')));
		$this->assertNull($this->export());
		touch($this->pem, time() - 3600);
		clearstatcache();
		$before = [stat($this->pem)['ino'], stat($this->pem)['mtime']];

		$this->assertNull($this->export());

		clearstatcache();
		$this->assertSame($before, [stat($this->pem)['ino'], stat($this->pem)['mtime']], 'same content: the file is left as it is');
	}

	public function testAWrongModeIsCorrectedWithoutWritingTheContentAgain(): void
	{
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost')));
		$this->assertNull($this->export());
		chmod($this->pem, 0644);
		clearstatcache();
		$inode = stat($this->pem)['ino'];

		$this->assertNull($this->export());

		clearstatcache();
		$this->assertSame(0600, fileperms($this->pem) & 0777);
		$this->assertSame($inode, stat($this->pem)['ino']);
	}

	public function testARenewalReplacesTheFileInOneRenameAndLeavesNothingBehind(): void
	{
		// Given the first certificate exported, and a reader that has the file open
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', $first = DnsProxyCertificateFixtures::issue('localhost')));
		$this->assertNull($this->export());
		$reader = fopen($this->pem, 'rb');
		$this->assertIsResource($reader);

		// When the certificate is renewed in config.xml and exported again
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', $second = DnsProxyCertificateFixtures::issue('localhost')));
		$this->assertNull($this->export());

		// Then the file holds the new one, the open reader still sees all of the old one (a new file was renamed over it, the old
		// one was not truncated and rewritten), the mode is still private, and no temporary file is left
		$this->assertSame(['CERTIFICATE:' . $this->body($second['cert']), 'PRIVATE KEY:' . $this->body($second['key'])], $this->blocks());
		$old = (string) stream_get_contents($reader);
		fclose($reader);
		$this->assertStringContainsString($this->body($first['cert']), $old);
		$this->assertStringContainsString($this->body($first['key']), $old);
		clearstatcache();
		$this->assertSame(0600, fileperms($this->pem) & 0777);
		$this->assertSame(['pfb_dns_cert.pem'], array_values(array_diff((array) scandir($this->dir), ['.', '..'])));
	}

	public function testBase64TextWrappedByAnEditorIsAccepted(): void
	{
		$leaf = DnsProxyCertificateFixtures::issue('localhost');
		$entry = DnsProxyCertificateFixtures::certEntry('cert1', $leaf);
		$wrap = static fn (string $text): string => "\n  " . substr($text, 0, 20) . "\r\n\t" . substr($text, 20) . "\n";
		$this->install(['crt' => $wrap($entry['crt']), 'prv' => $wrap($entry['prv'])] + $entry);

		$this->assertNull($this->export());
		$this->assertSame(['CERTIFICATE:' . $this->body($leaf['cert']), 'PRIVATE KEY:' . $this->body($leaf['key'])], $this->blocks());
	}

	public function testAMissingCAAndACarefLoopEndTheChain(): void
	{
		$a = DnsProxyCertificateFixtures::issue('a');
		$b = DnsProxyCertificateFixtures::issue('b', $a);
		$leaf = DnsProxyCertificateFixtures::issue('localhost', $b);

		// A CA whose own caref names nothing
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', $leaf, 'a'), [DnsProxyCertificateFixtures::caEntry('a', $a, 'gone')]);
		$this->assertNull($this->export());
		$this->assertSame(['CERTIFICATE', 'CERTIFICATE', 'PRIVATE KEY'], array_map(static fn (string $b): string => strstr($b, ':', TRUE), $this->blocks()));

		// Two CAs that name each other: each once
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', $leaf, 'a'), [
			DnsProxyCertificateFixtures::caEntry('a', $a, 'b'),
			DnsProxyCertificateFixtures::caEntry('b', $b, 'a'),
		]);
		$this->assertNull($this->export());
		$this->assertSame([
			'CERTIFICATE:' . $this->body($leaf['cert']),
			'CERTIFICATE:' . $this->body($a['cert']),
			'CERTIFICATE:' . $this->body($b['cert']),
			'PRIVATE KEY:' . $this->body($leaf['key']),
		], $this->blocks());
	}

	/** @return array<string,array{callable():void,string}> how config.xml is wrong => a mutation of a good config and the reason's words */
	public static function unusableRows(): array
	{
		return [
			'no certificate chosen' => [static function (): void { $GLOBALS['config']['unbound']['sslcertref'] = ''; }, 'unbound/sslcertref is empty'],
			'no sslcertref at all' => [static function (): void { unset($GLOBALS['config']['unbound']['sslcertref']); }, 'unbound/sslcertref is empty'],
			'the chosen certificate is gone' => [static function (): void { $GLOBALS['config']['cert'] = []; }, 'no certificate with refid "cert1"'],
			'crt is not base64' => [static function (): void { $GLOBALS['config']['cert'][0]['crt'] = '!!not base64!!'; }, 'crt of <cert> "cert1" is not valid base64'],
			'prv is not base64' => [static function (): void { $GLOBALS['config']['cert'][0]['prv'] = '%%%'; }, 'prv of <cert> "cert1" is not valid base64'],
			'crt is empty' => [static function (): void { $GLOBALS['config']['cert'][0]['crt'] = ''; }, '<cert> "cert1" has no crt'],
			'prv is missing' => [static function (): void { unset($GLOBALS['config']['cert'][0]['prv']); }, '<cert> "cert1" has no prv'],
			'crt is base64 of something that is not PEM' => [static function (): void { $GLOBALS['config']['cert'][0]['crt'] = base64_encode('hello'); }, 'does not belong to its certificate, or one of them is not valid PEM'],
			'the key is another certificate\'s' => [static function (): void { $GLOBALS['config']['cert'][0]['prv'] = base64_encode(DnsProxyCertificateFixtures::issue('other')['key']); }, 'does not belong to its certificate'],
			'the key is encrypted (PKCS#8)' => [static function (): void { $GLOBALS['config']['cert'][0]['prv'] = base64_encode("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"); }, 'encrypted with a passphrase'],
			'the key is encrypted (traditional PEM)' => [static function (): void { $GLOBALS['config']['cert'][0]['prv'] = base64_encode("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"); }, 'encrypted with a passphrase'],
			'a CA has invalid base64' => [static function (): void { $GLOBALS['config']['cert'][0]['caref'] = 'ca1'; $GLOBALS['config']['ca'] = [['refid' => 'ca1', 'crt' => '$$$']]; }, 'crt of <ca> "ca1" is not valid base64'],
		];
	}

	/** @param callable():void $break */
	#[DataProvider('unusableRows')]
	public function testACertificateThatCannotBeUsedWritesNothingAndSaysWhy(callable $break, string $reason): void
	{
		// Given a good certificate in the file, then a config.xml that is wrong in one way
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost')));
		$this->assertNull($this->export());
		$served = (string) file_get_contents($this->pem);
		$break();

		// When the export runs
		$why = $this->export();

		// Then it says why, and the certificate the gateway serves is untouched, with nothing left beside it
		$this->assertNotNull($why);
		$this->assertStringContainsString($reason, (string) $why);
		$this->assertSame($served, (string) file_get_contents($this->pem));
		$this->assertSame(['pfb_dns_cert.pem'], array_values(array_diff((array) scandir($this->dir), ['.', '..'])));
	}

	public function testADirectoryThatDoesNotExistIsAReason(): void
	{
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost')));

		$why = pfb_dns_proxy_certificate_export("{$this->dir}/absent/pfb_dns_cert.pem", $this->owner);

		$this->assertStringContainsString('cannot create a temporary file', (string) $why);
	}

	// -----------------------------------------------------------------------
	// when the file exists: the apply and the cron tick
	// -----------------------------------------------------------------------

	private function moveResolver(bool $dot): void
	{
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => $dot, 'value' => $dot ? '' : NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
	}

	/** @return array<string,array{?bool,string,string,bool}> moved Resolver had DoT (NULL = not moved), DoH, DoQ => is a certificate wanted */
	public static function wantedRows(): array
	{
		return [
			'DoT' => [TRUE, '', '', TRUE],
			'DoH only' => [FALSE, 'on', '', TRUE],
			'DoQ only' => [FALSE, '', 'on', TRUE],
			'no encrypted transport' => [FALSE, '', '', FALSE],
			'not moved: no gateway, whatever DoH says' => [NULL, 'on', 'on', FALSE],
		];
	}

	#[DataProvider('wantedRows')]
	public function testTheCronTickWritesTheFileWhileAnEncryptedTransportIsWantedAndRemovesItOtherwise(?bool $dot, string $doh, string $doq, bool $wanted): void
	{
		// Given a good certificate and a stale file
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', $leaf = DnsProxyCertificateFixtures::issue('localhost')));
		file_put_contents($this->pem, 'stale');
		if ($dot !== NULL) {
			$this->moveResolver($dot);
		}
		config_set_path(self::SETTINGS . 'pfb_dns_doh', $doh);
		config_set_path(self::SETTINGS . 'pfb_dns_doq', $doq);

		// When the cron tick looks at it
		pfb_dns_proxy_certificate_sync();

		// Then the file is the Resolver's certificate, or gone
		if ($wanted) {
			$this->assertStringContainsString($this->body($leaf['cert']), (string) file_get_contents($this->pem));
		} else {
			$this->assertFileDoesNotExist($this->pem, 'no transport wants it: no key stays on disk');
		}
	}

	public function testAnUnusableCertificateIsOneNoticePerReasonAndTheServedFileSurvives(): void
	{
		// Given a certificate that was exported, and DoT wanted
		$this->install(DnsProxyCertificateFixtures::certEntry('cert1', DnsProxyCertificateFixtures::issue('localhost')));
		$this->moveResolver(TRUE);
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
		$served = (string) file_get_contents($this->pem);

		// When the certificate is replaced by one whose key is encrypted and three cron ticks follow
		$GLOBALS['config']['cert'][0]['prv'] = base64_encode("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n");
		for ($tick = 0; $tick < 3; $tick++) {
			pfb_dns_proxy_certificate_sync();
		}

		// Then the served certificate is still there and the standing condition is one notice, not three
		$this->assertSame($served, (string) file_get_contents($this->pem));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertStringContainsString('encrypted with a passphrase', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}
}
