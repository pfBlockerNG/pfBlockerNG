<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1542 — TOP1M candidates must pass semantic validation before publication.
 */
#[CoversFunction('pfb_download')]
final class Top1mDownloadSemanticValidationTest extends TestCase
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
		$this->dir = sys_get_temp_dir() . '/pfb_top1m_semantic_' . getmypid() . '_' . uniqid();
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
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
		}
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

	public function testPlainHtmlCandidateFailsClosedAndPreservesLastGoodPublication(): void
	{
		$base = "{$this->dir}/top-1m.csv.zip";
		$active = "{$this->dir}/top-1m.csv";
		$before = $this->seedLastGoodState($base, $active);
		$body = "<!doctype html>\n<html><body><h1>503 Service Unavailable</h1></body></html>\n";

		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_feed_sanity'), 'sanity setting must be off for this gate proof');
		$result = $this->downloadBody($body, $base, $active);

		$this->assertFalse($result->success, 'HTML 200 must fail TOP1M semantic publication even with sanity disabled');
		$this->assertSame($before, $this->snapshotState($base, $active), 'HTML candidate changed last-good publication state');
	}

	public function testHeaderOnlyCandidateFailsClosedAndPreservesLastGoodPublication(): void
	{
		$base = "{$this->dir}/top-1m.csv.zip";
		$active = "{$this->dir}/top-1m.csv";
		$before = $this->seedLastGoodState($base, $active);
		$body = "rank,domain\n";

		$result = $this->downloadBody($body, $base, $active);

		$this->assertFalse($result->success, 'header-only TOP1M candidate must fail provider-semantic validation');
		$this->assertSame($before, $this->snapshotState($base, $active), 'header-only candidate changed last-good publication state');
	}

	public function testValidPlainCandidateReplacesActiveAndPersistsNewBaseline(): void
	{
		$base = "{$this->dir}/top-1m.csv.zip";
		$active = "{$this->dir}/top-1m.csv";
		$before = $this->seedLastGoodState($base, $active);
		$body = "1,new.example.com\n";

		$result = $this->downloadBody($body, $base, $active);

		$this->assertTrue($result->success, 'valid TOP1M candidate must publish');
		$after = $this->snapshotState($base, $active);
		$this->assertSame($body, file_get_contents($active), 'valid candidate active bytes');
		$this->assertSame($body, file_get_contents("{$base}.orig"), 'valid candidate raw baseline bytes');
		$this->assertSame(pfb_content_hash($body, FALSE), pfb_hash_read($base)['digest'], 'valid candidate hash baseline');
		$this->assertSame($before['whitelist'], $after['whitelist'], 'download must not rewrite derived whitelist');
		$this->assertSame($before['fixed'], $after['fixed'], 'download must not rewrite fixed TOP1M sidecar');
		$this->assertFileExists($GLOBALS['pfb']['dbdir'] . '/top-1m.update', 'valid publication must set update marker');
	}

	/** @return array<string,string|false> */
	private function seedLastGoodState(string $base, string $active): array
	{
		$oldActive = "old-active.example\n";
		$oldRaw = "old-wire.example\n";
		$oldSource = 'old-provider-identity';
		$oldWhitelist = ".old.example,,\n,old.example,,\n,www.old.example,,\n";
		$oldFixed = "fixed-old\n";
		$this->assertNotFalse(file_put_contents($active, $oldActive));
		$this->assertNotFalse(file_put_contents("{$base}.orig", $oldRaw));
		$this->assertTrue(pfb_hash_write($base, "{$base}.orig"));
		$this->assertNotFalse(file_put_contents("{$base}.source", $oldSource));
		pfb_validator_write("{$base}.orig", '"old-etag"', 1700000000);
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['dbdir'] . '/pfbalexawhitelist.txt', $oldWhitelist));
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['unbound_py_top1m'], $oldFixed));
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['dbdir'] . '/top-1m.update', 'old-marker'));

		return $this->snapshotState($base, $active);
	}

	/** @return array<string,string|false> */
	private function snapshotState(string $base, string $active): array
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

	private function downloadBody(string $body, string $base, string $active): PfbDownloadResult
	{
		$source = "{$this->dir}/feed-body";
		$this->assertNotFalse(file_put_contents($source, $body));
		$router = "{$this->dir}/router.php";
		$this->assertNotFalse(file_put_contents($router, "<?php\nreadfile(" . var_export($source, TRUE) . ");\n"));
		$descriptors = [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
		$port = 0;
		for ($try = 0; $try < 10 && $port === 0; $try++) {
			$candidate = random_int(20000, 60000);
			$proc = proc_open(
				['php', '-S', "127.0.0.1:{$candidate}", $router],
				$descriptors,
				$pipes,
				$this->dir,
				['PATH' => (string) getenv('PATH')]
			);
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
		));
	}
}
