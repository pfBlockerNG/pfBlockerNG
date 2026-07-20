<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

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
		$validRows = [
			'tranco' => ["7,Example.COM\n", 'example.com'],
			'cisco' => ["42,Mixed.Example\n", 'mixed.example'],
			'openpagerank' => ["rank,domain,com,10,5\n1,Example.COM,com,10,5\n", 'example.com'],
			'majestic' => ["rank,ref_subnets,domain,tld,position\n1,1,Example.COM,com,1\n", 'example.com'],
			'cloudflare' => ["domain\nExample.COM\n", 'example.com'],
		];
		$wrongRows = [
			'tranco' => "rank,Example.COM\n",
			'cisco' => "oops,Mixed.Example\n",
			'openpagerank' => "1,Example\n",
			'majestic' => "1,Example.COM\n",
			'cloudflare' => "1,Example.COM\n",
		];

		foreach ($providers as $id => $provider) {
			$validPath = "{$this->dir}/{$id}-valid.csv";
			$this->assertNotFalse(file_put_contents($validPath, $validRows[$id][0]));
			$this->assertTrue(
				pfb_top1m_candidate_valid($validPath, $provider),
				"{$id}: valid provider-shaped feed must pass"
			);
			$validLines = preg_split('/\r\n|\r|\n/', trim($validRows[$id][0]));
			$validDataLine = $provider['header'] ? ($validLines[1] ?? '') : ($validLines[0] ?? '');
			$this->assertSame(
				$validRows[$id][1],
				pfb_top1m_parse_source_row($validDataLine, $provider),
				"{$id}: parsed domain must be canonical lowercase"
			);

			$hostile = [
				"<!doctype html>\n<html><body>503 Service Unavailable</body></html>\n",
				"\x00binary\n",
				"# feed unavailable\n",
				$provider['header'] ? (string) strtok($validRows[$id][0], "\n") . "\n" : "domain\n",
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
		$this->assertNotFalse(file_put_contents($router, "<?php\nreadfile(" . var_export($source, TRUE) . ");\n"));
		$descriptors = [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
		$port = 0;
		for ($try = 0; $try < 10 && $port === 0; $try++) {
			$candidate = random_int(20000, 60000);
			$proc = proc_open(['php', '-S', "127.0.0.1:{$candidate}", $router], $descriptors, $pipes, $this->dir, ['PATH' => (string) getenv('PATH')]);
			if (!is_resource($proc)) {
				continue;
			}
			for ($poll = 0; $poll < 40; $poll++) {
				$sock = @fsockopen('127.0.0.1', $candidate, $errno, $errstr, 0.05);
				if ($sock !== FALSE) {
					fclose($sock);
					$this->server = $proc;
					$port = $candidate;
					break 2;
				}
				usleep(50000);
			}
			proc_terminate($proc);
			proc_close($proc);
		}
		if ($port === 0) {
			$this->markTestSkipped('loopback HTTP fixture unavailable');
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
		exec('/usr/bin/tar -tf ' . escapeshellarg($archive) . ' >/dev/null 2>&1', $output, $status);
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
