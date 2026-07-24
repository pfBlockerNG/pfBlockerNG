<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** CCT_IP CSV extraction and the opt-in cookie-backed download path. */
#[CoversFunction('pfb_cct_ip_parse_record')]
final class CctIpFeedTest extends TestCase
{
	/** @var resource|null */
	private $server = null;
	private string $workdir = '';
	private int $port = 0;

	public static function setUpBeforeClass(): void
	{
		require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
		}
		unset($GLOBALS['pfb_test_resolve_map']);
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $file) {
				@unlink((string) $file);
			}
			@rmdir($this->workdir);
		}
	}

	#[DataProvider('records')]
	public function testCctRecordExtraction(string $record, bool $lenient, ?string $expected): void
	{
		$this->assertSame($expected, pfb_cct_ip_parse_record($record, $lenient));
	}

	/** @return iterable<string,array{string,bool,?string}> */
	public static function records(): iterable
	{
		yield 'header' => ['TYPE,URL,IP', FALSE, NULL];
		yield 'empty' => ['', TRUE, NULL];
		yield 'short' => ['bot,http://1.2.3.4', TRUE, NULL];
		yield 'extra' => ['bot,http://1.2.3.4,1.2.3.4,extra', TRUE, NULL];
		yield 'quoted comma' => ['bot,"https://example.test/a,b",198.51.100.1', FALSE, '198.51.100.1'];
		yield 'third column v4 wins' => ['bot,https://203.0.113.8/1,198.51.100.1', TRUE, '198.51.100.1'];
		yield 'third column v6 wins' => ['bot,https://198.51.100.1/1,2001:db8::1', TRUE, '2001:db8::1'];
		yield 'invalid third strict' => ['bot,https://103.147.185.68:8443/j/p29oa/login.php,invalid', FALSE, NULL];
		yield 'invalid third lenient' => ['bot,https://103.147.185.68:8443/j/p29oa/login.php,invalid', TRUE, '103.147.185.68'];
		yield 'blank third path' => ['bot,103.147.185.68/1/b/,', TRUE, '103.147.185.68'];
		yield 'domain fallback rejected' => ['bot,static.82.150.216.95.clients.example/login,', TRUE, NULL];
		yield 'numeric label rejected' => ['bot,1.2.3.4.example/path,', TRUE, NULL];
		yield 'leading zero rejected' => ['bot,001.2.3.4/path,', TRUE, NULL];
		yield 'bracketed v6 rejected' => ['bot,[2001:db8::1]:8443/path,', TRUE, NULL];
		yield 'fallback never cidr' => ['bot,103.147.185.68/1/b/,', TRUE, '103.147.185.68'];
	}

	public function testCatalogPinsCctCsvEndpoint(): void
	{
		$catalog = json_decode(
			(string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json'),
			TRUE,
			512,
			JSON_THROW_ON_ERROR
		);
		$findCct = static function (array $node) use (&$findCct): array {
			if (($node['header'] ?? '') === 'CCT_IP') {
				return [$node];
			}
			$found = [];
			foreach ($node as $child) {
				if (is_array($child)) {
					$found = array_merge($found, $findCct($child));
				}
			}
			return $found;
		};
		$cct = $findCct($catalog);
		$this->assertCount(1, $cct);
		$this->assertSame('https://cybercrime-tracker.net/csv.php', $cct[0]['url']);
	}

	public function testCctWiringUsesAutoParserOnlyForCctRows(): void
	{
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertStringContainsString('pfb_cct_ip_parse_record', $source);
		$this->assertStringContainsString("\$header === 'CCT_IP'", $source);
		$config = [
			'vtype'         => '_v4',
			'pftype'        => 'auto',
			'custom'        => TRUE,
			'cidr_floor_v4' => 'Disabled',
			'cidr_floor_v6' => 'Disabled',
			'suppression'   => 'off',
			'range'         => '/((?:\d{1,3}\.){3}\d{1,3})-((?:\d{1,3}\.){3}\d{1,3})/',
			'ipv4'          => '/(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/\d{1,2})?/',
			'ipv6'          => '/[0-9A-Fa-f:]+(?:\/\d{1,3})?/',
		];
		$candidate = pfb_cct_ip_parse_record('bot,https://103.147.185.68/1,', TRUE);
		$this->assertSame('103.147.185.68', $candidate);
		$this->assertSame(['103.147.185.68'], pfb_ip_parse_line($candidate, $config)['entries']);
	}

	public function testCctCookiesAreDisabledByDefaultAndOptInPerRequest(): void
	{
		$defaults = new PfbDownloadRequest(
			listUrl: 'https://example.test/feed',
			downloadPath: '/tmp/feed',
			flex: FALSE,
			header: 'CCT_IP',
			format: '',
			logType: 1,
		);
		$this->assertFalse($defaults->cookies);
		$enabled = new PfbDownloadRequest(
			listUrl: 'https://example.test/feed',
			downloadPath: '/tmp/feed',
			flex: FALSE,
			header: 'CCT_IP',
			format: '',
			logType: 1,
			cookies: TRUE,
		);
		$this->assertTrue($enabled->cookies);
	}

	public function testCookieChallengeNeedsOptInAndReplaysAcrossManualRedirects(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$this->startCookieServer();
		$GLOBALS['pfb_test_resolve_map'] = [
			'cct-feed.example.' => [
				['type' => 'A', 'data' => '127.0.0.1'],
				['type' => 'A', 'data' => '203.0.113.20'],
			],
		];
		$url = "http://cct-feed.example:{$this->port}/start?hop=1";
		$without = pfb_download(new PfbDownloadRequest(
			listUrl: $url,
			downloadPath: "{$this->workdir}/without",
			flex: FALSE,
			header: 'CCT_IP',
			format: '',
			logType: 1,
			type: 'change_detect',
		));
		$this->assertFalse($without->success);

		$with = pfb_download(new PfbDownloadRequest(
			listUrl: $url,
			downloadPath: "{$this->workdir}/with",
			flex: FALSE,
			header: 'CCT_IP',
			format: '',
			logType: 1,
			type: 'change_detect',
			cookies: TRUE,
		));
		$this->assertTrue($with->success);
		$this->assertSame('200', $with->responseMeta['status'] ?? '');
	}

	private function startCookieServer(): void
	{
		$this->workdir = tempnam(sys_get_temp_dir(), 'cct');
		$this->assertNotFalse($this->workdir);
		$this->assertTrue(unlink($this->workdir) && mkdir($this->workdir, 0700));
		$router = "{$this->workdir}/router.php";
		$routerSrc = <<<'PHP'
<?php
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/start') {
	header('Location: /hop?next=2', TRUE, 302);
	return;
}
if ($path === '/hop') {
	setcookie('cct_gate', 'ok');
	header('Location: /final', TRUE, 302);
	return;
}
if ($path === '/final' && ($_COOKIE['cct_gate'] ?? '') === 'ok') {
	header('Content-Type: text/plain');
	echo "TYPE,URL,IP\nsource,https://example.test,198.51.100.1\n";
	return;
}
http_response_code(403);
echo "cookie required\n";
PHP;
		$this->assertNotFalse(file_put_contents($router, $routerSrc));
		$descriptors = [1 => ['file', '/dev/null', 'w'], 2 => ['file', "{$this->workdir}/server.err", 'w']];
		for ($try = 0; $try < 10; $try++) {
			$port = random_int(20000, 60000);
			$process = proc_open(
				['php', '-S', "127.0.0.1:{$port}", $router],
				$descriptors,
				$pipes,
				$this->workdir,
				['PATH' => (string) getenv('PATH')]
			);
			if (!is_resource($process)) {
				continue;
			}
			for ($i = 0; $i < 40; $i++) {
				$sock = @fsockopen('127.0.0.1', $port, $errno, $error, 0.05);
				if ($sock !== FALSE) {
					fclose($sock);
					$this->server = $process;
					$this->port = $port;
					return;
				}
				usleep(50000);
			}
			proc_terminate($process);
			proc_close($process);
		}
		$error = (string) @file_get_contents("{$this->workdir}/server.err");
		$this->fail('could not start cookie php -S fixture server: ' . $error);
	}
}
