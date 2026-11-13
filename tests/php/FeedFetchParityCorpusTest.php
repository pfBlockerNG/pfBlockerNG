<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * The feed-transfer parity corpus (#3905) driven against today's PHP: every scenario under
 * tests/feedfetch/fixtures/parity runs through the real pfb_download() (an "ingest" step) and pfb_update_check() (a
 * "probe" step) against local `php -S` servers, a stand-in resolver and the shared stand-in rsync. The same files run
 * against go/pfb_core/feedfetch (corpus_test.go there documents the schema); a case that passes here and fails there,
 * or the reverse, is a divergence.
 *
 * Logical outcome per step, mapped from this side's files and log:
 *   ok / decision   the PfbDownloadResult, or pfb_update_check()'s verdict (Success + cron_update = changed, Success
 *                   alone = unchanged, NULL = failed).
 *   published, etag, lastmod, digest   {feed}.orig, {feed}.orig.etag, {feed}.orig.lastmod, {feed}.orig.xxhash128
 *                   (null when absent).
 *   reason          the last "reason=<code>" or "[ FEED ] <text> — skipped" in the step's log.
 *   requests        what the servers recorded (the Host header too, kept only where the expectation names it);
 *                   rsync_source the stand-in's second-to-last argument.
 * Scheduler state that is not transfer behaviour is reset before a probe: the list file exists, no failure marker.
 */
#[CoversFunction('pfb_download')]
#[CoversFunction('pfb_update_check')]
final class FeedFetchParityCorpusTest extends TestCase
{
	private const FEED = 'FEED';

	private string $dir = '';
	private string $tools = '';
	/** @var array<string,resource> */
	private array $servers = [];
	/** @var array<string,int> */
	private array $ports = [];
	private array $savedGlobals = [];
	private array $savedPfb = [];

	public static function corpus(): array
	{
		$cases = [];
		foreach (glob(__DIR__ . '/../feedfetch/fixtures/parity/*.json') ?: [] as $file) {
			$cases[basename($file, '.json')] = [$file];
		}
		return $cases;
	}

	protected function setUp(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$base = sys_get_temp_dir() . '/pfb_ffcorpus_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->dir = "{$base}/feeds";
		$this->tools = "{$base}/tools";
		$this->assertTrue(mkdir($this->dir, 0700, TRUE) && mkdir($this->tools, 0700, TRUE));
		$this->dir = (string) realpath($this->dir);

		foreach (['config', 'pfb_test_resolve_map', 'pfb_test_configured_ips'] as $g) {
			if (array_key_exists($g, $GLOBALS)) {
				$this->savedGlobals[$g] = $GLOBALS[$g];
			}
		}
		foreach (['log', 'errlog', 'pnow', 'dbdir', 'mime_types', 'skipfeed', 'failed', 'runlog', 'runlog_active',
			'curl_defaults', 'curl_retry_sleep', 'rsync_bin', 'rsync_max_bytes', 'local_max_bytes', 'cron_update'] as $k) {
			if (array_key_exists($k, $GLOBALS['pfb'] ?? [])) {
				$this->savedPfb[$k] = $GLOBALS['pfb'][$k];
			}
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['log'] = "{$base}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$base}/error.log";
		$GLOBALS['pfb']['pnow'] = 'now';
		$GLOBALS['pfb']['skipfeed'] = 0;
		$GLOBALS['pfb']['failed'] = [];
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
		$GLOBALS['pfb']['curl_retry_sleep'] = 0;
		$GLOBALS['pfb']['rsync_bin'] = "{$this->tools}/rsync";
		$this->assertTrue(copy(__DIR__ . '/../feedfetch/fixtures/fake-rsync.sh', "{$this->tools}/rsync"));
		$this->assertTrue(chmod("{$this->tools}/rsync", 0700));
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as $server) {
			proc_terminate($server);
			proc_close($server);
		}
		foreach ($this->savedPfb as $k => $v) {
			$GLOBALS['pfb'][$k] = $v;
		}
		foreach (['dbdir', 'log', 'errlog', 'pnow', 'skipfeed', 'failed', 'mime_types', 'curl_defaults', 'curl_retry_sleep',
			'rsync_bin', 'rsync_max_bytes', 'local_max_bytes', 'cron_update'] as $k) {
			if (!array_key_exists($k, $this->savedPfb)) {
				unset($GLOBALS['pfb'][$k]);
			}
		}
		foreach (['config', 'pfb_test_resolve_map', 'pfb_test_configured_ips'] as $g) {
			if (array_key_exists($g, $this->savedGlobals)) {
				$GLOBALS[$g] = $this->savedGlobals[$g];
			} else {
				unset($GLOBALS[$g]);
			}
		}
		if ($this->dir !== '') {
			exec('rm -rf ' . escapeshellarg(dirname($this->dir)));
		}
	}

	#[DataProvider('corpus')]
	public function testCorpusScenarioMatchesPhp(string $file): void
	{
		$case = json_decode((string) file_get_contents($file), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $case['schema'], 'corpus schema');

		if (($case['filter'] ?? TRUE) === FALSE) {
			PfbConfig::write('gen/pfb_feed_internal_filter', PfbToggle::Off);
		}
		if (isset($case['allowlist'])) {
			PfbConfig::write('gen/pfb_feed_internal_allowlist', base64_encode(implode("\n", $case['allowlist'])));
		}
		$GLOBALS['pfb_test_configured_ips'] = $case['self'] ?? [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		foreach ($case['hosts'] as $host => $addrs) {
			$GLOBALS['pfb_test_resolve_map']["{$host}."] = array_map(
				static fn (string $a): array => ['type' => str_contains($a, ':') ? 'AAAA' : 'A', 'data' => $a], $addrs);
		}
		$this->seedLocal($case['local_files'] ?? [], $case['local_symlinks'] ?? []);
		$base = "{$this->dir}/" . self::FEED;
		$seed = $case['seed'] ?? [];
		foreach (['published' => '.orig', 'etag' => '.orig.etag', 'lastmod' => '.orig.lastmod',
			'digest' => '.orig.xxhash128'] as $key => $suffix) {
			if (isset($seed[$key])) {
				file_put_contents("{$base}{$suffix}", (string) $seed[$key]);
			}
		}

		$closed = stream_socket_server('tcp://127.0.0.1:0');
		$this->ports['closed'] = (int) substr(strrchr((string) stream_socket_get_name($closed, FALSE), ':'), 1);
		fclose($closed);
		foreach ($case['servers'] ?? [] as $name) {
			$this->startServer($name);
		}
		$routes = $case['routes'] ?? [];

		foreach ($case['steps'] as $i => $step) {
			$label = basename($file) . " step {$i} ({$step['op']})";
			$routes = $step['routes'] ?? $routes;
			$this->writeRoutes($routes);
			$this->seedLocal($step['local_files'] ?? [], []);
			file_put_contents("{$this->tools}/requests.log", '');
			file_put_contents($GLOBALS['pfb']['log'], '');
			@unlink("{$this->tools}/rsync.argv");
			file_put_contents("{$this->tools}/rsync.body", (string) ($step['rsync']['body'] ?? ''));
			file_put_contents("{$this->tools}/rsync.exit", (string) ($step['rsync']['exit'] ?? 0));
			$ceiling = $step['ceiling'] ?? PFB_DOWNLOAD_MAX_BYTES;
			$GLOBALS['pfb']['curl_defaults'] = [CURLOPT_MAXFILESIZE_LARGE => $ceiling] + ($this->savedPfb['curl_defaults'] ?? []);
			$GLOBALS['pfb']['rsync_max_bytes'] = $ceiling;
			$GLOBALS['pfb']['local_max_bytes'] = $ceiling;
			$url = $this->expand($step['url']);
			$format = $step['format'] ?? '';

			$actual = [];
			if ($step['op'] === 'ingest') {
				$result = pfb_download(new PfbDownloadRequest(
					listUrl: $url,
					downloadPath: $base,
					flex: FALSE,
					header: self::FEED,
					format: $format,
					logType: 1,
					timeout: 30,
					type: '',
					username: $step['username'] ?? '',
					password: $step['password'] ?? '',
					extraHeaders: $step['headers'] ?? [],
				));
				$actual['ok'] = $result->success;
			} else {
				touch("{$this->dir}/" . self::FEED . '.txt');
				@unlink("{$this->dir}/" . self::FEED . '.fail');
				$GLOBALS['pfb']['cron_update'] = FALSE;
				$verdict = pfb_update_check(self::FEED, $url, $this->dir, $this->dir, FALSE, $format, '');
				$decision = $verdict === NULL ? 'failed' : ($GLOBALS['pfb']['cron_update'] ? 'changed' : 'unchanged');
				$actual['ok'] = $decision !== 'failed';
				$actual['decision'] = $decision;
			}
			$actual['published'] = is_file("{$base}.orig") ? file_get_contents("{$base}.orig") : NULL;
			$actual['etag'] = is_file("{$base}.orig.etag") ? file_get_contents("{$base}.orig.etag") : NULL;
			$actual['lastmod'] = is_file("{$base}.orig.lastmod") ? (int) file_get_contents("{$base}.orig.lastmod") : NULL;
			$actual['digest'] = is_file("{$base}.orig.xxhash128") ? file_get_contents("{$base}.orig.xxhash128") : NULL;
			$actual['requests'] = $this->requests();
			$actual['staged'] = is_file("{$base}.raw") && filesize("{$base}.raw") > 0;
			$argv = is_file("{$this->tools}/rsync.argv") ? file("{$this->tools}/rsync.argv", FILE_IGNORE_NEW_LINES) : NULL;
			$actual['rsync_source'] = $argv === NULL ? NULL : $argv[count($argv) - 2];
			$actual['reason'] = $this->reason();

			$want = $step['expect'];
			$want['requests'] = array_map(fn (array $r): array => $this->expandRecord($r), $want['requests']);
			foreach (array_keys($actual['requests']) as $n) {
				if (!isset($want['requests'][$n]['host'])) {
					unset($actual['requests'][$n]['host']);
				}
			}
			$want += ['etag' => $seed['etag'] ?? NULL, 'lastmod' => $seed['lastmod'] ?? NULL,
				'digest' => $seed['digest'] ?? NULL, 'staged' => FALSE, 'rsync_source' => NULL];
			if (!array_key_exists('reason', $want)) {
				unset($actual['reason']);
			}
			if (!array_key_exists('decision', $want)) {
				unset($actual['decision']);
			}
			ksort($want);
			ksort($actual);
			$this->assertSame($want, $actual, "{$label}: {$case['description']}\nlog:\n" .
				(string) file_get_contents($GLOBALS['pfb']['log']));
			// The next step's default validators are what this one left behind.
			$seed['etag'] = $actual['etag'];
			$seed['lastmod'] = $actual['lastmod'];
			$seed['digest'] = $actual['digest'];
		}
	}

	private function seedLocal(array $files, array $links): void
	{
		foreach ($files as $rel => $content) {
			@mkdir(dirname("{$this->dir}/{$rel}"), 0700, TRUE);
			file_put_contents("{$this->dir}/{$rel}", $content);
		}
		foreach ($links as $rel => $target) {
			symlink($target, "{$this->dir}/{$rel}");
		}
	}

	private function expand(string $text): string
	{
		$text = str_replace('{local}', $this->dir, $text);
		return (string) preg_replace_callback('/\{port:([a-z]+)\}/',
			fn (array $m): string => (string) ($this->ports[$m[1]] ?? $this->fail("no server {$m[1]}")), $text);
	}

	private function expandRecord(array $record): array
	{
		return array_map(fn ($v) => is_string($v) ? $this->expand($v) : $v, $record);
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

	/** @return list<array<string,string>> */
	private function requests(): array
	{
		$out = [];
		foreach (file("{$this->tools}/requests.log", FILE_IGNORE_NEW_LINES) ?: [] as $line) {
			$out[] = json_decode($line, TRUE);
		}
		return $out;
	}

	private function reason(): ?string
	{
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		$found = NULL;
		$at = -1;
		if (preg_match_all('/reason=(\S+)/', $log, $m, PREG_OFFSET_CAPTURE)) {
			[$found, $at] = end($m[1]);
		}
		if (preg_match_all('/\[ ' . self::FEED . " \\] (.+?) \xe2\x80\x94 skipped/", $log, $m, PREG_OFFSET_CAPTURE)
			&& end($m[1])[1] > $at) {
			$found = end($m[1])[0];
		}
		return $found;
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
