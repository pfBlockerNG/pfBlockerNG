<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * The Extras parity corpus (#3978) driven against today's PHP: every scenario under tests/extras/fixtures/parity runs
 * through the real pfblockerng_download_extras() against local `php -S` servers and a stand-in resolver. The same files
 * run against go/pfb_core/feedfetch (extras_corpus_test.go there documents the schema); a case that passes here and
 * fails there, or the reverse, is a divergence.
 *
 * The Extras table and the verb selection of pfblockerng.php are top-level code, so a step names its Extras rows
 * itself, as the table builds them (pfblockerng.php:166-256), with the URL pointed at a corpus server.
 * pfblockerng_download_extras() lives in that file too; it is loaded the way Top1mDccDetectorTest loads its helpers.
 *
 * Logical outcome per step:
 *   ok              pfblockerng_download_extras()'s return.
 *   maxmind_error   $pfb['maxmind_feed_error'] after the step.
 *   files           {"db/<path>" or "share/<path>": content, {"b64": bytes} or null when absent}: only the files named.
 *   requests        what the servers recorded (host only where named; query only where named).
 *
 * `pfblockerng.sh asn_table` (the ASN conversion's, #4034) is a stand-in that records its call in db/script.calls.
 */
#[CoversFunction('pfb_download')]
final class ExtrasParityCorpusTest extends TestCase
{
	private string $root = '';
	private string $tools = '';
	/** @var array<string,resource> */
	private array $servers = [];
	/** @var array<string,int> */
	private array $ports = [];
	/** @var array<string,mixed> every global this test or pfb_global() changes, restored whole in tearDown */
	private array $savedGlobals = [];

	private const GLOBALS = ['pfb', 'g', 'config', 'pfb_test_resolve_map', 'pfb_test_configured_ips', 'argv'];

	public static function corpus(): array
	{
		$cases = [];
		foreach (glob(__DIR__ . '/../extras/fixtures/parity/*.json') ?: [] as $file) {
			$cases[basename($file, '.json')] = [$file];
		}
		return $cases;
	}

	protected function setUp(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		self::loadDownloadExtras();
		$base = sys_get_temp_dir() . '/pfb_extras_corpus_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->tools = "{$base}/tools";
		foreach (['db', 'share', 'tools'] as $d) {
			$this->assertTrue(mkdir("{$base}/{$d}", 0700, TRUE));
		}
		$this->root = (string) realpath($base);
		$this->tools = "{$this->root}/tools";
		foreach (self::GLOBALS as $g) {
			if (array_key_exists($g, $GLOBALS)) {
				$this->savedGlobals[$g] = $GLOBALS[$g];
			}
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['dbdir'] = "{$this->root}/db";
		$GLOBALS['pfb']['geoipshare'] = "{$this->root}/share";
		$GLOBALS['pfb']['log'] = "{$this->tools}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->tools}/error.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->tools}/extras.log";
		$GLOBALS['pfb']['pnow'] = 'now';
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
		$GLOBALS['pfb']['curl_retry_sleep'] = 0;
		// pfblockerng.sh asn_table (the ASN lookup table) is the GeoIP and ASN conversion's (#4034): a stand-in that
		// records its call.
		file_put_contents("{$this->tools}/pfblockerng.sh",
			"#!/bin/sh\necho \"\$1\" >> " . escapeshellarg("{$this->root}/db/script.calls") . "\n");
		chmod("{$this->tools}/pfblockerng.sh", 0700);
		$GLOBALS['pfb']['script'] = "{$this->tools}/pfblockerng.sh";
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as $server) {
			proc_terminate($server);
			proc_close($server);
		}
		foreach (self::GLOBALS as $g) {
			if (array_key_exists($g, $this->savedGlobals)) {
				$GLOBALS[$g] = $this->savedGlobals[$g];
			} else {
				unset($GLOBALS[$g]);
			}
		}
		if ($this->root !== '') {
			exec('rm -rf ' . escapeshellarg($this->root));
		}
	}

	#[DataProvider('corpus')]
	public function testCorpusScenarioMatchesPhp(string $file): void
	{
		$case = json_decode((string) file_get_contents($file), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $case['schema'], 'corpus schema');

		$GLOBALS['pfb_test_configured_ips'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		foreach ($case['hosts'] ?? [] as $host => $addrs) {
			$GLOBALS['pfb_test_resolve_map']["{$host}."] = array_map(
				static fn (string $a): array => ['type' => str_contains($a, ':') ? 'AAAA' : 'A', 'data' => $a], $addrs);
		}
		foreach ($case['servers'] ?? [] as $name) {
			$this->startServer($name);
		}
		$this->settings($case['settings'] ?? []);
		$this->seed($case['seed'] ?? []);
		$routes = $case['routes'] ?? [];

		foreach ($case['steps'] as $i => $step) {
			$label = basename($file) . " step {$i} ({$step['run']})";
			$routes = $step['routes'] ?? $routes;
			$this->writeRoutes($routes);
			$this->seed($step['seed'] ?? []);
			file_put_contents("{$this->tools}/requests.log", '');
			file_put_contents($GLOBALS['pfb']['log'], '');
			// No proxy of the developer's (a saved option or http_proxy) may stand between cURL and the corpus servers.
			$curl = $this->savedGlobals['pfb']['curl_defaults'] ?? [];
			foreach ([CURLOPT_PROXYPORT, CURLOPT_PROXYAUTH, CURLOPT_PROXYUSERPWD, CURLOPT_TCP_FASTOPEN] as $opt) {
				unset($curl[$opt]);
			}
			$GLOBALS['pfb']['curl_defaults'] = [CURLOPT_MAXFILESIZE_LARGE => PFB_DOWNLOAD_MAX_BYTES, CURLOPT_PROXY => ''] + $curl;
			// A step where Core deliberately differs (an owner decision) records today's answer as old_expect: it is what
			// PHP is held to, and what decides which files and request fields are observed.
			$want = $step['old_expect'] ?? $step['expect'];
			clearstatcache();
			$before = [];
			foreach ($want['replaced'] ?? [] as $rel) {
				$before[$rel] = @fileinode("{$this->root}/{$rel}");
			}

			$this->assertSame('download', $step['run'], "{$label}: unknown run");
			$GLOBALS['argv'] = ['pfblockerng.php', 'extras'];
			$GLOBALS['pfb']['extras'] = [];
			foreach ($step['extras'] as $extra) {
				$GLOBALS['pfb']['extras'][] = $this->extra($extra);
			}
			$actual = ['ok' => pfblockerng_download_extras(30, 3)];
			$actual['maxmind_error'] = (bool) ($GLOBALS['pfb']['maxmind_feed_error'] ?? FALSE);
			clearstatcache();
			$actual['files'] = [];
			foreach (array_keys($want['files'] ?? []) as $rel) {
				$actual['files'][$rel] = self::state("{$this->root}/{$rel}");
			}
			$actual['requests'] = $this->requests($want['requests'] ?? []);
			if (isset($want['replaced'])) {
				// A path counts as replaced when a new file now stands there: an identical download is still published.
				$actual['replaced'] = array_values(array_filter($want['replaced'],
					fn (string $rel): bool => @fileinode("{$this->root}/{$rel}") !== $before[$rel]));
			}

			$want += ['requests' => []];
			$want['requests'] = array_map(fn (array $r): array => $this->expandRecord($r), $want['requests']);
			foreach ($want['files'] ?? [] as $rel => $content) {
				$want['files'][$rel] = is_array($content) ? (string) base64_decode($content['b64'], TRUE)
					: (is_string($content) ? $this->expand($content) : $content);
			}
			$want += ['files' => []];
			$want += ['maxmind_error' => FALSE];
			ksort($want);
			ksort($actual);
			$this->assertSame($want, $actual, "{$label}: {$case['description']}\nlog:\n" .
				(string) file_get_contents($GLOBALS['pfb']['log']));
		}
	}

	/** The settings pfb_global() reads (pfblockerng_download_extras() calls it), stored where it reads them. */
	private function settings(array $s): void
	{
		PfbConfig::write('ip/maxmind_account', $s['maxmind_account'] ?? '');
		PfbConfig::write('ip/maxmind_key', $s['maxmind_key'] ?? '');
		PfbConfig::write('ip/asn_token', $s['asn_token'] ?? '');
		if (($s['sanity'] ?? FALSE) === TRUE) {
			PfbConfig::write('gen/pfb_feed_sanity', PfbToggle::On);
		}
		// What the rest of pfb_global() reads without a default; none of it touches the Extras.
		PfbConfig::write('gen/skipfeed', '0');
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		$GLOBALS['g']['unbound_chroot_path'] ??= '/var/unbound';
		pfb_global();
		$GLOBALS['pfb']['dbdir'] = "{$this->root}/db";
		$GLOBALS['pfb']['geoipshare'] = "{$this->root}/share";
		$GLOBALS['pfb']['curl_retry_sleep'] = 0;
		$GLOBALS['pfb']['script'] = "{$this->tools}/pfblockerng.sh";
	}

	/** One $pfb['extras'] row as the Extras table builds it. */
	private function extra(array $e): array
	{
		return [
			'url'      => $this->expand($e['url']),
			'file_dwn' => $e['file_dwn'],
			'file'     => $e['file'],
			'folder'   => "{$this->root}/{$e['folder']}",
			'type'     => $e['type'],
		];
	}

	private function seed(array $files): void
	{
		foreach ($files as $rel => $content) {
			$path = "{$this->root}/{$rel}";
			@mkdir(dirname($path), 0755, TRUE);
			file_put_contents($path, is_array($content) ? (string) base64_decode($content['b64'], TRUE) : $this->expand($content));
		}
	}

	/** A file's content, NULL when nothing is at the path, or a marker for an entry that is not a regular file. */
	private static function state(string $path): ?string
	{
		if (!file_exists($path) && !is_link($path)) {
			return NULL;
		}
		return (is_file($path) && !is_link($path)) ? (string) file_get_contents($path) : '<not a regular file>';
	}

	private function expand(string $text): string
	{
		return (string) preg_replace_callback('/\{port:([a-z]+)\}/',
			fn (array $m): string => (string) ($this->ports[$m[1]] ?? $this->fail("no server {$m[1]}")), $text);
	}

	private function expandRecord(array $record): array
	{
		$record = array_map(fn ($v) => is_string($v) ? $this->expand($v) : $v, $record);
		ksort($record);
		return $record;
	}

	private function writeRoutes(array $routes): void
	{
		$expanded = [];
		foreach ($routes as $server => $table) {
			foreach ($table as $path => $route) {
				$expanded[$server][$path] = $this->expandRecord($route);
			}
		}
		file_put_contents("{$this->tools}/routes.json", json_encode($expanded, JSON_UNESCAPED_SLASHES));
	}

	/** @return list<array<string,string>> what the servers recorded, keeping host and query only where $want names them */
	private function requests(array $want): array
	{
		$out = [];
		foreach (file("{$this->tools}/requests.log", FILE_IGNORE_NEW_LINES) ?: [] as $n => $line) {
			$r = json_decode($line, TRUE);
			foreach (['host', 'query'] as $optional) {
				if (!isset($want[$n][$optional])) {
					unset($r[$optional]);
				}
			}
			ksort($r);
			$out[] = $r;
		}
		return $out;
	}

	private static function loadDownloadExtras(): void
	{
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		if (!function_exists('pfblockerng_download_extras')) {
			$start = strpos($source, "\nfunction pfblockerng_download_extras");
			$end = strpos($source, "\n// Function to process the downloaded MaxMind", $start === FALSE ? 0 : $start);
			self::assertNotFalse($start);
			self::assertNotFalse($end);
			eval("\n" . substr($source, $start + 1, $end - $start - 1));
		}
	}

	private function startServer(string $name): void
	{
		$failures = [];
		for ($try = 0; $try < 10; $try++) {
			$nonce = bin2hex(random_bytes(16));
			$stderr = "{$this->tools}/{$name}-{$try}.stderr";
			$proc = proc_open(
				['php', '-S', '127.0.0.1:0', __DIR__ . '/support/FeedFetchCorpusRouter.php'],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->tools,
				[
					'CORPUS_SERVER'   => $name,
					'CORPUS_ROUTES'   => "{$this->tools}/routes.json",
					'CORPUS_REQUESTS' => "{$this->tools}/requests.log",
					'CORPUS_QUERY'    => '1',
					'READY_TOKEN'     => $nonce,
					'PATH'            => (string) getenv('PATH'),
				]
			);
			$this->assertIsResource($proc);
			$port = pfb_test_http_fixture_port($stderr);
			for ($i = 0; $port > 0 && $i < 40; $i++) {
				if (pfb_test_http_fixture_event_received($port, $nonce)) {
					$this->servers[$name] = $proc;
					$this->ports[$name] = $port;
					return;
				}
				usleep(50000);
			}
			proc_terminate($proc);
			proc_close($proc);
			$failures[] = "port {$port}: " . trim((string) @file_get_contents($stderr));
		}
		$this->fail("could not start corpus server {$name}: " . implode(' | ', $failures));
	}
}
