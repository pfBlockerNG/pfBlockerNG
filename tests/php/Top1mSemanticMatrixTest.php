<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * Issue #1542 — provider-shaped TOP1M rows and compressed candidates.
 *
 * The frozen regression test covers a plain HTML/header-only feed. This matrix
 * keeps the provider descriptors, hostile rows, and archive publication path
 * independently exercised without changing that reproduction.
 */
#[CoversFunction('pfb_top1m_parse_source_row')]
#[CoversFunction('pfb_top1m_candidate_valid')]
#[CoversFunction('pfb_download')]
final class Top1mSemanticMatrixTest extends TestCase
{
	private string $dir;

	/** @var resource|null */
	private $server = NULL;

	/** @var array<string,mixed> */
	private array $savedPfb = [];

	/** @var array<string,mixed> */
	private array $savedConfig = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_top1m_matrix_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
		foreach (['dbdir', 'log', 'errlog', 'pnow', 'mime_types', 'dnsbl_top1m_type', 'unbound_py_top1m'] as $key) {
			$this->savedPfb[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? [])
				? $GLOBALS['pfb'][$key] : FALSE;
		}
		$this->savedConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['dbdir'] = "{$this->dir}/db";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/pfblockerng_error.log";
		$GLOBALS['pfb']['pnow'] = 'now';
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
		$GLOBALS['pfb']['dnsbl_top1m_type'] = PfbTop1mSource::Tranco;
		$GLOBALS['pfb']['unbound_py_top1m'] = "{$this->dir}/fixed-top1m.txt";
		$this->assertTrue(mkdir($GLOBALS['pfb']['dbdir']));
	}

	protected function tearDown(): void
	{
		$this->stopServer();
		foreach ($this->savedPfb as $key => $value) {
			if ($value === FALSE) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $value;
			}
		}
		$GLOBALS['config'] = $this->savedConfig;
		if (is_dir($this->dir)) {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ($it as $file) {
				$file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
			}
			rmdir($this->dir);
		}
	}

	public function testAllProviderDescriptorsAcceptValidRowsAndRejectHostileRows(): void
	{
		$providers = pfb_top1m_providers();
		$fixtures = [
			'tranco' => [
				'header' => '',
				'fields' => ['7', 'Example.COM'],
				'domain' => 'example.com',
				'columns' => 2,
			],
			'cisco' => [
				'header' => '',
				'fields' => ['42', 'Mixed.Example'],
				'domain' => 'mixed.example',
				'columns' => 2,
			],
			'openpagerank' => [
				'header' => "Rank,Domain,Extension,Open Page Rank,Referring Domains\n",
				'fields' => ['1', 'Example.COM', 'com', '10', '5'],
				'domain' => 'example.com',
				'columns' => 5,
			],
			'majestic' => [
				'header' => "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n",
				'fields' => ['1', '1', 'Example.COM', 'com', '10', '20', '', '', '2', '2', '9', '19'],
				'domain' => 'example.com',
				'columns' => 12,
			],
			'cloudflare' => [
				'header' => "domain\n",
				'fields' => ['Example.COM'],
				'domain' => 'example.com',
				'columns' => 1,
			],
		];
		$wrongRows = [
			'tranco' => "rank,Example.COM\n",
			'cisco' => "oops,Mixed.Example\n",
			'openpagerank' => "1,Example\n",
			'majestic' => "1,Example.COM\n",
			'cloudflare' => "1,Example.COM\n",
		];

		foreach ($providers as $id => $provider) {
			$validDataLine = implode(',', $fixtures[$id]['fields']) . "\n";
			$validBody = $fixtures[$id]['header'] . $validDataLine;
			$validPath = "{$this->dir}/{$id}-valid.csv";
			$this->assertNotFalse(file_put_contents($validPath, $validBody));
			$this->assertTrue(
				pfb_top1m_candidate_valid($validPath, $provider),
				"{$id}: valid provider-shaped feed must pass"
			);
			$this->assertSame(
				$fixtures[$id]['domain'],
				pfb_top1m_parse_source_row($validDataLine, $provider),
				"{$id}: parsed domain must be canonical lowercase"
			);

			$hostile = [
				"<!doctype html>\n<html><body>503 Service Unavailable</body></html>\n",
				"\x00binary\n",
				"# feed unavailable\n",
				$provider['header'] ? $fixtures[$id]['header'] : "domain\n",
				$wrongRows[$id],
			];
			foreach ($hostile as $n => $body) {
				$path = "{$this->dir}/{$id}-hostile-{$n}.csv";
				$this->assertNotFalse(file_put_contents($path, $body));
				$this->assertFalse(
					pfb_top1m_candidate_valid($path, $provider),
					"{$id}: hostile candidate {$n} must fail closed"
				);
			}

			$shapeRows = [
				'extra' => array_merge($fixtures[$id]['fields'], ['extra']),
				'truncated' => array_slice($fixtures[$id]['fields'], 0, -1),
			];
			foreach ($shapeRows as $shape => $fields) {
				$dataLine = implode(',', $fields) . "\n";
				$path = "{$this->dir}/{$id}-{$shape}.csv";
				$this->assertNotFalse(file_put_contents($path, $fixtures[$id]['header'] . $dataLine));
				$this->assertNull(
					pfb_top1m_parse_source_row($dataLine, $provider),
					"{$id}: {$shape} data row must fail exact-column parsing"
				);
				$this->assertFalse(
					pfb_top1m_candidate_valid($path, $provider),
					"{$id}: valid header plus {$shape} data row must fail closed"
				);
			}

			$domainCol = (int) $provider['domain_col'];
			$invalidUtf8Fields = $fixtures[$id]['fields'];
			$invalidUtf8Fields[$domainCol] = "bad\xFF.example";
			$invalidUtf8Line = implode(',', $invalidUtf8Fields) . "\n";
			$invalidUtf8Path = "{$this->dir}/{$id}-invalid-utf8.csv";
			$this->assertNotFalse(file_put_contents($invalidUtf8Path, $fixtures[$id]['header'] . $invalidUtf8Line));
			$this->assertNull(pfb_top1m_parse_source_row($invalidUtf8Line, $provider), "{$id}: invalid UTF-8 domain rejected");
			$this->assertFalse(pfb_top1m_candidate_valid($invalidUtf8Path, $provider), "{$id}: invalid UTF-8 candidate rejected");

			$unterminatedPrefix = array_slice($fixtures[$id]['fields'], 0, $domainCol);
			$unterminatedLine = ($unterminatedPrefix === [] ? '' : implode(',', $unterminatedPrefix) . ',') . "\"Example.COM\n";
			$unterminatedPath = "{$this->dir}/{$id}-unterminated.csv";
			$this->assertNotFalse(file_put_contents($unterminatedPath, $fixtures[$id]['header'] . $unterminatedLine));
			$this->assertNull(pfb_top1m_parse_source_row($unterminatedLine, $provider), "{$id}: unterminated quoted domain rejected");
			$this->assertFalse(pfb_top1m_candidate_valid($unterminatedPath, $provider), "{$id}: unterminated candidate rejected");

			$this->assertSame($fixtures[$id]['columns'], $provider['columns'] ?? NULL, "{$id}: exact column count descriptor");
		}
	}

	public function testSyntheticDescriptorWithoutColumnCountKeepsMinimumShapeBehavior(): void
	{
		$provider = ['parse' => 'csv', 'header' => FALSE, 'domain_col' => 1];
		$path = "{$this->dir}/synthetic.csv";
		$this->assertNotFalse(file_put_contents($path, "rank,Example.COM,extra\n"));
		$this->assertSame('example.com', pfb_top1m_parse_source_row("rank,Example.COM,extra\n", $provider));
		$this->assertTrue(pfb_top1m_candidate_valid($path, $provider));
	}

	public function testCandidateRejectsEmptyAndMissingFiles(): void
	{
		$provider = pfb_top1m_providers()['tranco'];
		$empty = "{$this->dir}/empty.csv";
		$this->assertNotFalse(file_put_contents($empty, ''));
		$this->assertFalse(pfb_top1m_candidate_valid($empty, $provider));
		$this->assertFalse(pfb_top1m_candidate_valid("{$this->dir}/missing.csv", $provider));
	}

	public function testCandidateRejectsUnreadableFile(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions');
		}
		$provider = pfb_top1m_providers()['tranco'];
		$path = "{$this->dir}/unreadable.csv";
		$this->assertNotFalse(file_put_contents($path, "1,Example.COM\n"));
		$this->assertTrue(chmod($path, 0000));
		try {
			$this->assertFalse(pfb_top1m_candidate_valid($path, $provider));
		} finally {
			chmod($path, 0600);
		}
	}

	public function testInvalidZipAndGzipCandidatesPreserveEveryPublicationArtifact(): void
	{
		$fixtures = [];
		$zip = new ZipArchive();
		$zipPath = "{$this->dir}/invalid.zip";
		$this->assertSame(TRUE, $zip->open($zipPath, ZipArchive::CREATE));
		$this->assertTrue($zip->addFromString('feed/top.csv', "<!doctype html>\n<html><body>503</body></html>\n"));
		$this->assertTrue($zip->close());
		if ($this->tarReadsZip($zipPath)) {
			$fixtures['zip'] = [$zipPath, "{$this->dir}/invalid.csv.zip", "{$this->dir}/invalid.csv"];
		}

		$gzipPath = "{$this->dir}/invalid.gz";
		$this->assertNotFalse(file_put_contents($gzipPath, gzencode("<!doctype html>\n<html><body>503</body></html>\n")));
		$fixtures['gzip'] = [$gzipPath, "{$this->dir}/invalid.csv.gz", "{$this->dir}/invalid-gzip.csv"];

		foreach ($fixtures as $label => [$source, $base, $active]) {
			$before = $this->seedPublication($base, $active, $label);
			$this->assertFalse($this->downloadSource($source, $base, $active), "{$label}: semantic-invalid candidate must fail");
			$this->assertSame([], glob(dirname($base) . '/.pfbtop1m_*') ?: [], "{$label}: rejected download left staging artifacts");
			$this->assertSame($before, $this->snapshotPublication($base, $active), "{$label}: rejected candidate changed last-good state");
		}
	}

	/** @return array<string,string|false> */
	private function seedPublication(string $base, string $active, string $label): array
	{
		$this->assertNotFalse(file_put_contents($active, "old-active-{$label}\n"));
		$this->assertNotFalse(file_put_contents("{$base}.orig", "old-wire-{$label}\n"));
		$this->assertTrue(pfb_hash_write($base, "{$base}.orig"));
		$this->assertNotFalse(file_put_contents("{$base}.source", "old-source-{$label}"));
		pfb_validator_write("{$base}.orig", '"old-etag-' . $label . '"', 1700000000);
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['dbdir'] . '/pfbalexawhitelist.txt', "old-whitelist-{$label}\n"));
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['unbound_py_top1m'], "old-fixed-{$label}\n"));
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['dbdir'] . '/top-1m.update', "old-marker-{$label}"));

		return $this->snapshotPublication($base, $active);
	}

	/** @return array<string,string|false> */
	private function snapshotPublication(string $base, string $active): array
	{
		$paths = [
			'active' => $active,
			'raw' => "{$base}.orig",
			'hash' => "{$base}.xxhash128",
			'source' => "{$base}.source",
			'etag' => "{$base}.orig.etag",
			'lastmod' => "{$base}.orig.lastmod",
			'whitelist' => $GLOBALS['pfb']['dbdir'] . '/pfbalexawhitelist.txt',
			'fixed' => $GLOBALS['pfb']['unbound_py_top1m'],
			'marker' => $GLOBALS['pfb']['dbdir'] . '/top-1m.update',
		];
		$state = [];
		foreach ($paths as $label => $path) {
			$state[$label] = is_file($path) ? file_get_contents($path) : FALSE;
		}
		return $state;
	}

	private function downloadSource(string $source, string $base, string $active): bool
	{
		$this->stopServer();
		$router = "{$this->dir}/router.php";
		$routerSource = <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '';
if ($uri === '/__pfb_ready' || str_starts_with($uri, '/__pfb_ready/')) {
	if ($uri === '/__pfb_ready') {
		echo getenv('READY_TOKEN');
	}
	return;
}
PHP;
		$this->assertNotFalse(file_put_contents(
			$router,
			$routerSource . "\nreadfile(" . var_export($source, TRUE) . ");\n"
		));
		$port = 0;
		$failures = [];
		for ($try = 0; $try < 10 && $port === 0; $try++) {
			$candidate = random_int(20000, 60000);
			$nonce = bin2hex(random_bytes(16));
			$stderr = "{$this->dir}/server-{$candidate}-{$try}.stderr";
			$proc = proc_open(
				['php', '-S', "127.0.0.1:{$candidate}", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->dir,
				['READY_TOKEN' => $nonce, 'PATH' => (string) getenv('PATH')]
			);
			if (!is_resource($proc)) {
				$failures[] = "port {$candidate}: process=proc_open failed stderr=(unavailable)";
				continue;
			}
			for ($poll = 0; $poll < 40; $poll++) {
				if (pfb_test_http_fixture_event_received($candidate, $nonce)) {
					$this->server = $proc;
					$port = $candidate;
					break 2;
				}
				usleep(50000);
			}

			$status = proc_get_status($proc);
			if ($status['running']) {
				proc_terminate($proc);
			}
			$closeExit = proc_close($proc);
			$stderrText = trim((string) @file_get_contents($stderr));
			$failures[] = sprintf(
				'port %d: process[running=%s exit=%d close=%d] stderr=%s',
				$candidate,
				$status['running'] ? 'true' : 'false',
				$status['exitcode'],
				$closeExit,
				$stderrText === '' ? '(empty)' : $stderrText
			);
		}
		if ($port === 0) {
			$this->markTestSkipped(
				'loopback HTTP fixture unavailable; ' . implode(' | ', $failures)
			);
		}
		return pfb_download(new PfbDownloadRequest(
			listUrl: "http://127.0.0.1:{$port}/feed",
			downloadPath: $base,
			flex: FALSE,
			header: $active,
			format: '',
			logType: 1,
			timeout: 30,
			type: 'top1m',
		))->success;
	}

	private function tarReadsZip(string $archive): bool
	{
		exec(escapeshellcmd(pfb_test_tar()) . ' -tf ' . escapeshellarg($archive) . ' >/dev/null 2>&1', $output, $status);
		return $status === 0;
	}

	private function stopServer(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
			$this->server = NULL;
		}
	}
}
