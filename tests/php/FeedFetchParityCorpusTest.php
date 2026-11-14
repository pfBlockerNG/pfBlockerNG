<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';
require_once __DIR__ . '/support/FeedFetchCorpusNet.php';

/**
 * The feed-transfer parity corpus (#3905) driven against today's PHP: every scenario under
 * tests/feedfetch/fixtures/parity runs through the real pfb_download() (an "ingest" step) and pfb_update_check() (a
 * "probe" step) against local `php -S` servers, a stand-in resolver and the shared stand-in rsync. The same files run
 * against go/pfb_core/feedfetch (corpus_test.go there documents the schema); a case that passes here and fails there,
 * or the reverse, is a divergence.
 *
 * An ftp server is declared in `servers` as an object {"name", "kind": "ftp", ...options} instead of a name: it is the
 * Python server tests/feedfetch/fixtures/ftp_server.py (its header lists the options), driven by cURL here and by the
 * Go client there. Its `files` table, {server: {path: file}}, sits beside `routes`, and a step may replace it the same way.
 *
 * Logical outcome per step, mapped from this side's files and log:
 *   ok / decision   the PfbDownloadResult, or pfb_update_check()'s verdict (Success + cron_update = changed, Success
 *                   alone = unchanged, NULL = failed).
 *   published, etag, lastmod, digest   {feed}.orig, {feed}.orig.etag, {feed}.orig.lastmod, {feed}.orig.xxhash128
 *                   (null when absent).
 *   mtime           the published copy's modification time in Unix seconds, checked only where the expectation names it.
 *   reason          the last "reason=<code>", "[ FEED ] <text> — skipped" or "[pfb_download] <text>" (an extraction's
 *                   refusal) in the step's log.
 *   requests        what the servers recorded (the Host header too, kept only where the expectation names it);
 *                   rsync_source the stand-in's second-to-last argument.
 *   old_expect      a step's optional override, present only where Core differs from this path on purpose (never equal
 *                   to expect, which the Go runner asserts); this runner asserts it in place of expect.
 * TLS and proxy (the schema of go/pfb_core/feedfetch/corpus_test.go):
 *   servers         an entry may be an object {name, tls: true, cert: "trusted"|"untrusted", plain_too}: `php -S` behind a
 *                   TLS front (tests/feedfetch/fixtures/net_fixture.py tls) whose certificate comes from a test CA made
 *                   here, at test time. PHP trusts that CA through $pfb['curl_defaults'][CURLOPT_CAINFO], the option
 *                   pfb_download() applies to its handle; the "untrusted" certificate is self-signed and not signed by
 *                   it. With plain_too the same port also serves plain http (the first byte decides), so a redirect can
 *                   change the scheme and nothing else. Each TLS connection is recorded as {server, tls: "connect"}.
 *   proxy           {server, auth: {user, password}, requires: {user, password}}: the system proxy. `server` names a
 *                   forward proxy this runner starts (net_fixture.py proxy; "closed" is nothing listening) and `auth`
 *                   is the system proxy's user and password. The proxy settings go through config
 *                   system/proxyurl|proxyport|proxyuser|proxypass and the real pfb_global(), which turns them into
 *                   $pfb['curl_defaults']; `requires` makes the proxy demand those Basic credentials (407 otherwise).
 *   step.flex       the feed's Flex flag (PfbDownloadRequest::$flex, pfb_update_check()'s $pflex).
 * Scheduler state that is not transfer behaviour is reset before a probe: the list file exists, no failure marker.
 * Content gates (#3973): stage and detected are those of the step's last "pfb_validate: REJECT" line; raw_retained is a
 * non-empty {feed}.raw left behind (an archive success keeps it); a leftover ".pfbstage_*" file fails the step.
 * published_b64 stands for published when the bytes are not text, published_size when the body is too large to inline.
 * ET IQRisk and xlsx run pfblockerng.sh's et and xlsx verbs for real, their pfSense paths pointed at this run's
 * directories (as tests/shell's specs source the script); et_split and et_match are that split and match file.
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
	/** @var array<string,resource> an ftp server's stdin: closing it ends the server */
	private array $ftpStdin = [];
	/** @var array<string,array> the ftp servers as the scenario declared them */
	private array $ftpDecls = [];
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
		foreach (['log', 'errlog', 'pnow', 'dbdir', 'mime_types', 'skipfeed', 'failed', 'runlog', 'runlog_active', 'config',
			'curl_defaults', 'curl_retry_sleep', 'rsync_bin', 'rsync_max_bytes', 'local_max_bytes', 'cron_update', 'script',
			'etblock', 'etmatch'] as $k) {
			if (array_key_exists($k, $GLOBALS['pfb'] ?? [])) {
				$this->savedPfb[$k] = $GLOBALS['pfb'][$k];
			}
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		// A case starts as a process that has not yet read a system proxy: pfb_global() adds either the proxy options or
		// TCP fast-open to $pfb['curl_defaults'] and never removes the other, so an earlier test's choice must not stay.
		foreach ([CURLOPT_PROXY, CURLOPT_PROXYPORT, CURLOPT_PROXYAUTH, CURLOPT_PROXYUSERPWD, CURLOPT_TCP_FASTOPEN] as $opt) {
			unset($GLOBALS['pfb']['curl_defaults'][$opt]);
		}
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
		// pfblockerng.sh's et and xlsx verbs, run for real with their pfSense paths pointed at this run's directories.
		$this->assertTrue(mkdir("{$this->tools}/ET") && mkdir("{$this->tools}/match"));
		$this->assertNotFalse(file_put_contents("{$this->tools}/pfblockerng.sh", sprintf(<<<'SH'
			#!/bin/sh
			PFB_SOURCED=1
			. %s
			pfborig=%s
			etdir=%s
			pfbmatchgen=%s
			errorlog=%s
			pathtar=%s
			now='2026-01-01 00:00:00'
			ip_placeholder2='127\.1\.7\.7'
			alias="$2"
			etblock="$(echo "${8}" | sed 's/,/, /g')"
			etmatch="$(echo "${9}" | sed 's/,/, /g')"
			case "$1" in
			et) pfb_ensure_tmpdir; processet; exitnow "$?" ;;
			xlsx) pfb_ensure_tmpdir; processxlsx; exitnow "$?" ;;
			esac
			exit 99

			SH, escapeshellarg((string) realpath(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.sh')),
			escapeshellarg("{$this->dir}/"), escapeshellarg("{$this->tools}/ET"), escapeshellarg("{$this->tools}/match/"),
			escapeshellarg("{$this->tools}/sh-error.log"), escapeshellarg(pfb_test_tar()))));
		$this->assertTrue(chmod("{$this->tools}/pfblockerng.sh", 0700));
		$GLOBALS['pfb']['script'] = "{$this->tools}/pfblockerng.sh";
	}

	protected function tearDown(): void
	{
		foreach ($this->ftpStdin as $stdin) {
			fclose($stdin);
		}
		foreach ($this->servers as $server) {
			proc_terminate($server);
			proc_close($server);
		}
		foreach ($this->savedPfb as $k => $v) {
			$GLOBALS['pfb'][$k] = $v;
		}
		foreach (['dbdir', 'log', 'errlog', 'pnow', 'skipfeed', 'failed', 'mime_types', 'config', 'curl_defaults', 'curl_retry_sleep',
			'rsync_bin', 'rsync_max_bytes', 'local_max_bytes', 'cron_update', 'script', 'etblock', 'etmatch'] as $k) {
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
		if (($case['sanity'] ?? FALSE) === TRUE) {
			PfbConfig::write('gen/pfb_feed_sanity', PfbToggle::On);
		}
		if (isset($case['allowlist'])) {
			PfbConfig::write('gen/pfb_feed_internal_allowlist', base64_encode(implode("\n", $case['allowlist'])));
		}
		$GLOBALS['pfb']['etblock'] = $case['et']['block'] ?? 'x';
		$GLOBALS['pfb']['etmatch'] = $case['et']['match'] ?? 'x';
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
			'digest' => '.orig.xxhash128', 'size' => '.orig.size'] as $key => $suffix) {
			if (isset($seed[$key])) {
				file_put_contents("{$base}{$suffix}", (string) $seed[$key]);
			}
		}

		$closed = stream_socket_server('tcp://127.0.0.1:0');
		$this->ports['closed'] = (int) substr(strrchr((string) stream_socket_get_name($closed, FALSE), ':'), 1);
		fclose($closed);
		$pki = NULL;
		$files = $case['files'] ?? [];
		foreach ($case['servers'] ?? [] as $spec) {
			$spec = is_string($spec) ? ['name' => $spec] : $spec;
			if (($spec['kind'] ?? NULL) === 'ftp') {
				$this->startFtpServer($spec, $files);
				continue;
			}
			$tls = NULL;
			if (($spec['tls'] ?? FALSE) === TRUE) {
				$pki ??= pfb_test_corpus_pki("{$this->tools}/pki");
				$cert = $pki[$spec['cert']] ?? $this->fail("server {$spec['name']}: cert must be trusted or untrusted");
				$tls = $cert + ['plain_too' => ($spec['plain_too'] ?? FALSE) === TRUE];
			}
			$this->startServer($spec['name'], $tls);
		}
		$curlDefaults = $this->savedPfb['curl_defaults'] ?? [];
		if ($pki !== NULL) {
			$curlDefaults[CURLOPT_CAINFO] = $pki['ca'];
		}
		if (isset($case['proxy'])) {
			$curlDefaults = $this->systemProxy($case['proxy']) + $curlDefaults;
		}
		$routes = $case['routes'] ?? [];

		foreach ($case['steps'] as $i => $step) {
			$label = basename($file) . " step {$i} ({$step['op']})";
			$routes = $step['routes'] ?? $routes;
			$this->writeRoutes($routes);
			$files = $step['files'] ?? $files;
			$this->writeFtpConfigs($files);
			$this->seedLocal($step['local_files'] ?? [], []);
			file_put_contents("{$this->tools}/requests.log", '');
			file_put_contents($GLOBALS['pfb']['log'], '');
			@unlink("{$this->tools}/rsync.argv");
			file_put_contents("{$this->tools}/rsync.body", (string) ($step['rsync']['body'] ?? ''));
			file_put_contents("{$this->tools}/rsync.exit", (string) ($step['rsync']['exit'] ?? 0));
			$ceiling = $step['ceiling'] ?? PFB_DOWNLOAD_MAX_BYTES;
			$GLOBALS['pfb']['curl_defaults'] = [CURLOPT_MAXFILESIZE_LARGE => $ceiling] + $curlDefaults;
			$GLOBALS['pfb']['rsync_max_bytes'] = $ceiling;
			$GLOBALS['pfb']['local_max_bytes'] = $ceiling;
			$url = $this->expand($step['url']);
			$format = $step['format'] ?? '';

			$actual = [];
			if ($step['op'] === 'ingest') {
				$result = pfb_download(new PfbDownloadRequest(
					listUrl: $url,
					downloadPath: $base,
					flex: $step['flex'] ?? FALSE,
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
				$verdict = pfb_update_check(self::FEED, $url, $this->dir, $this->dir, $step['flex'] ?? FALSE, $format, '');
				$decision = $verdict === NULL ? 'failed' : ($GLOBALS['pfb']['cron_update'] ? 'changed' : 'unchanged');
				$actual['ok'] = $decision !== 'failed';
				$actual['decision'] = $decision;
			}
			clearstatcache();
			$actual['published'] = self::stateFile("{$base}.orig");
			$actual['mtime'] = is_file("{$base}.orig") ? filemtime("{$base}.orig") : NULL;
			$actual['etag'] = self::stateFile("{$base}.orig.etag");
			$actual['lastmod'] = is_file("{$base}.orig.lastmod") ? (int) file_get_contents("{$base}.orig.lastmod") : NULL;
			$actual['size'] = is_file("{$base}.orig.size") ? (int) file_get_contents("{$base}.orig.size") : NULL;
			$actual['digest'] = self::stateFile("{$base}.orig.xxhash128");
			$actual['requests'] = $this->requests();
			$actual['raw_retained'] = is_file("{$base}.raw") && filesize("{$base}.raw") > 0;
			$actual['staged'] = $this->stagedLeftover();
			$argv = is_file("{$this->tools}/rsync.argv") ? file("{$this->tools}/rsync.argv", FILE_IGNORE_NEW_LINES) : NULL;
			$actual['rsync_source'] = $argv === NULL ? NULL : $argv[count($argv) - 2];
			$actual['reason'] = $this->reason();
			[$actual['stage'], $actual['detected']] = $this->rejectLine();
			$actual['et_split'] = [];
			foreach (glob("{$this->tools}/ET/*") ?: [] as $split) {
				if (filesize($split) > 0) {
					$actual['et_split'][basename($split)] = self::stateFile($split);
				}
			}
			$match = "{$this->tools}/match/pfB_Match_ET_v4.txt";
			$actual['et_match'] = self::stateFile($match);

			$want = $step['old_expect'] ?? $step['expect'];
			$want['requests'] = array_map(fn (array $r): array => $this->expandRecord($r), $want['requests']);
			if (isset($want['published_b64'])) {
				$want['published'] = (string) base64_decode($want['published_b64'], TRUE);
				unset($want['published_b64']);
			}
			if (isset($want['published_size'])) {
				// A body too large to inline: its size stands for it.
				$actual['published_size'] = is_file("{$base}.orig") ? filesize("{$base}.orig") : NULL;
				unset($actual['published']);
			}
			foreach (array_keys($actual['requests']) as $n) {
				if (!isset($want['requests'][$n]['host'])) {
					unset($actual['requests'][$n]['host']);
				}
				ksort($actual['requests'][$n]);
			}
			foreach (array_keys($want['requests']) as $n) {
				ksort($want['requests'][$n]);
			}
			$sizeState = $actual['size'];
			$want += ['etag' => $seed['etag'] ?? NULL, 'lastmod' => $seed['lastmod'] ?? NULL,
				'digest' => $seed['digest'] ?? NULL, 'raw_retained' => FALSE, 'staged' => '',
				'rsync_source' => NULL];
			if (array_key_exists('size', $want)) {
				$want += ['size' => $seed['size'] ?? NULL];
			} else {
				unset($actual['size']);
			}
			foreach (['reason', 'decision', 'stage', 'detected', 'et_split', 'et_match'] as $optional) {
				if (!array_key_exists($optional, $want)) {
					unset($actual[$optional]);
				}
			}
			if (!array_key_exists('mtime', $want)) {
				unset($actual['mtime']);
			}
			if (isset($want['et_split'])) {
				ksort($want['et_split']);
				ksort($actual['et_split']);
			}
			ksort($want);
			ksort($actual);
			$this->assertSame($want, $actual, "{$label}: {$case['description']}\nlog:\n" .
				(string) file_get_contents($GLOBALS['pfb']['log']));
			// The next step's default validators are what this one left behind.
			$seed['etag'] = $actual['etag'];
			$seed['lastmod'] = $actual['lastmod'];
			$seed['size'] = $sizeState;
			$seed['digest'] = $actual['digest'];
		}
	}

	/**
	 * A feed file as compared, NULL when absent. Over 1 MiB it becomes its size and SHA-256 (#3989): a ceiling
	 * regression still fails the comparison without holding the file.
	 */
	public static function stateFile(string $path): ?string
	{
		if (!is_file($path)) {
			return NULL;
		}
		$size = (int) filesize($path);
		return $size <= (1 << 20) ? (string) file_get_contents($path) :
			sprintf('<%d bytes, sha256 %s>', $size, hash_file('sha256', $path));
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

	/** The last of three shapes in the step's log: a validation reason code, a skip text, an extraction refusal's text. */
	private function reason(): ?string
	{
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		$found = NULL;
		$at = -1;
		foreach (['/reason=(\S+)/', '/\[ ' . self::FEED . " \\] (.+?) \xe2\x80\x94 skipped/", '/\[pfb_download\] (.+)$/m'] as $shape) {
			if (preg_match_all($shape, $log, $m, PREG_OFFSET_CAPTURE) && end($m[1])[1] > $at) {
				[$found, $at] = end($m[1]);
			}
		}
		return $found;
	}

	private function ftpConfigPath(string $name): string
	{
		return "{$this->tools}/{$name}.ftp.json";
	}

	private function writeFtpConfigs(array $files): void
	{
		foreach ($this->ftpDecls as $name => $decl) {
			unset($decl['kind']);
			file_put_contents($this->ftpConfigPath($name),
				json_encode($decl + ['files' => $files[$name] ?? []], JSON_UNESCAPED_SLASHES));
		}
	}

	/** The server prints "PORT <n>" once it listens, so there is nothing to poll or sleep for. */
	private function startFtpServer(array $decl, array $files): void
	{
		$name = $decl['name'];
		$this->ftpDecls[$name] = $decl;
		$this->writeFtpConfigs($files);
		$stderr = "{$this->tools}/{$name}.ftp.stderr";
		$proc = proc_open(
			['python3', __DIR__ . '/../feedfetch/fixtures/ftp_server.py', $this->ftpConfigPath($name), "{$this->tools}/requests.log"],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $stderr, 'w']],
			$pipes,
			$this->tools
		);
		$this->assertIsResource($proc);
		$this->servers[$name] = $proc;
		$this->ftpStdin[$name] = $pipes[0];
		stream_set_timeout($pipes[1], 30);
		$line = trim((string) fgets($pipes[1]));
		fclose($pipes[1]);
		$this->assertSame(1, preg_match('/^PORT (\d+)$/', $line, $m),
			"ftp server {$name} did not announce its port: '{$line}' " . trim((string) @file_get_contents($stderr)));
		$this->ports[$name] = (int) $m[1];
	}
	/** @return array{?string, ?string} stage and detected of the step's last "pfb_validate: REJECT" line. */
	private function rejectLine(): array
	{
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		if (!preg_match_all('/pfb_validate: REJECT feed=\S+ stage=(\S+) reason=\S+ detected=(.*)$/m', $log, $m)) {
			return [NULL, NULL];
		}
		return [end($m[1]), end($m[2])];
	}

	/** The name of an extraction's staging file left in the feed directory, or ''. */
	private function stagedLeftover(): string
	{
		foreach (glob("{$this->dir}/.pfbstage_*") ?: [] as $file) {
			return basename($file);
		}
		return '';
	}

	private function startServer(string $name, ?array $tls = NULL): void
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
					$this->ports[$name] = $tls === NULL ? $port : $this->startTlsFront($name, $tls, $port);
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

	/** The TLS front of the `php -S` server $name (net_fixture.py tls); returns its port, the one a feed URL names. */
	private function startTlsFront(string $name, array $cert, int $backend): int
	{
		$stderr = "{$this->tools}/{$name}-tls.stderr";
		$args = ['tls', '--name', $name, '--log', "{$this->tools}/requests.log",
			'--cert', $cert['cert'], '--key', $cert['key'], '--backend', (string) $backend];
		if ($cert['plain_too']) {
			$args[] = '--plain-too';
		}
		$started = pfb_test_corpus_net_fixture($args, $stderr);
		if ($started === NULL) {
			$this->fail("could not start the TLS front of {$name}: " . trim((string) @file_get_contents($stderr)));
		}
		$this->servers["{$name}:tls"] = $started[0];
		return $started[1];
	}

	/**
	 * The system proxy as pfSense keeps it (system/proxyurl, proxyport, proxyuser, proxypass), read by the real
	 * pfb_global() into $pfb['curl_defaults']; returns the proxy options that left in it.
	 *
	 * @return array<int,mixed>
	 */
	private function systemProxy(array $proxy): array
	{
		$name = $proxy['server'];
		if ($name === 'closed') {
			$port = $this->ports['closed'];
		} else {
			$args = ['proxy', '--name', $name, '--log', "{$this->tools}/requests.log"];
			if (isset($proxy['requires'])) {
				array_push($args, '--user', $proxy['requires']['user'], '--password', $proxy['requires']['password']);
			}
			$stderr = "{$this->tools}/{$name}.stderr";
			$started = pfb_test_corpus_net_fixture($args, $stderr);
			if ($started === NULL) {
				$this->fail("could not start the corpus proxy {$name}: " . trim((string) @file_get_contents($stderr)));
			}
			$this->servers[$name] = $started[0];
			$port = $this->ports[$name] = $started[1];
		}
		$system = ['proxyurl' => '127.0.0.1', 'proxyport' => (string) $port];
		if (isset($proxy['auth'])) {
			$system += ['proxyuser' => $proxy['auth']['user'], 'proxypass' => $proxy['auth']['password']];
		}
		foreach ($system as $leaf => $value) {
			config_set_path("system/{$leaf}", $value);
		}
		// What the rest of pfb_global() reads without a default; none of it touches the transfer.
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '0');
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport', '8081');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport_ssl', '8443');
		$GLOBALS['g']['unbound_chroot_path'] ??= '/var/unbound';
		pfb_global();
		$defaults = $GLOBALS['pfb']['curl_defaults'];
		$this->assertSame('127.0.0.1', $defaults[CURLOPT_PROXY] ?? NULL, 'pfb_global() reads system/proxyurl');
		$this->assertArrayNotHasKey(CURLOPT_TCP_FASTOPEN, $defaults, 'with a proxy there is no TCP fast-open');
		return array_intersect_key($defaults,
			array_flip([CURLOPT_PROXY, CURLOPT_PROXYPORT, CURLOPT_PROXYAUTH, CURLOPT_PROXYUSERPWD]));
	}
}
