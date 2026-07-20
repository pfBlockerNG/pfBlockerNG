<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * GeoIP ZIP downloads publish every safe archive member to the directory
 * target and never create TOP1M detector artifacts.
 */
#[CoversFunction('pfb_download')]
final class GeoipZipPublicationTest extends TestCase
{
	private string $dir;

	/** @var resource|null */
	private $server = NULL;

	/** @var array<string,mixed> */
	private array $saved_pfb = [];
	/** @var array<string,bool> */
	private array $saved_pfb_exists = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_geoip_zip_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
		foreach (['log', 'errlog', 'pnow', 'dbdir'] as $key) {
			$this->saved_pfb_exists[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []);
			$this->saved_pfb[$key] = $GLOBALS['pfb'][$key] ?? NULL;
		}
		$this->saved_pfb_exists['mime_types'] = array_key_exists('mime_types', $GLOBALS['pfb'] ?? []);
		$this->saved_pfb['mime_types'] = $GLOBALS['pfb']['mime_types'] ?? NULL;
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['pnow'] = 'now';
		$GLOBALS['pfb']['dbdir'] = "{$this->dir}/db";
		$this->assertTrue(mkdir($GLOBALS['pfb']['dbdir']));
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
		}
		foreach ($this->saved_pfb as $key => $value) {
			if (!$this->saved_pfb_exists[$key]) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $value;
			}
		}
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

	public function testGeoipZipDirectoryPublishesAllMembersWithoutTop1mArtifacts(): void
	{
		$archive = $this->zipFixture([
			'geoip/one.dat' => "one\n",
			'geoip/two.dat' => "two\n",
		]);
		exec('/usr/bin/tar -tf ' . escapeshellarg($archive) . ' >/dev/null 2>&1', $output, $status);
		if ($status !== 0) {
			$this->markTestSkipped('/usr/bin/tar cannot read ZIP on this host; pfSense uses bsdtar');
		}
		$base = "{$this->dir}/geoip-feed";
		$target = "{$this->dir}/geoip-share";
		$this->assertTrue(mkdir($target));
		file_put_contents("{$target}/old.dat", "old\n");

		$result = $this->downloadGeoip($archive, $base, $target);
		$this->assertTrue($result->success);
		$this->assertSame("one\n", file_get_contents("{$target}/one.dat"));
		$this->assertSame("two\n", file_get_contents("{$target}/two.dat"));
		$this->assertSame("old\n", file_get_contents("{$target}/old.dat"));
		$this->assertFileDoesNotExist("{$base}.raw");
		$this->assertFileDoesNotExist("{$base}.orig");
		$this->assertFileDoesNotExist("{$base}.xxhash128");
		$this->assertFileDoesNotExist("{$base}.md5");
		$this->assertFileDoesNotExist("{$base}.source");
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dbdir'] . '/top-1m.update');
		$this->assertSame([], glob("{$this->dir}/.pfbtop1m_*") ?: []);
	}

	/** @param array<string,string> $entries */
	private function zipFixture(array $entries): string
	{
		$path = "{$this->dir}/geoip.zip";
		$zip = new ZipArchive();
		$this->assertSame(TRUE, $zip->open($path, ZipArchive::CREATE));
		foreach ($entries as $member => $body) {
			$this->assertTrue($zip->addFromString($member, $body));
		}
		$this->assertTrue($zip->close());
		return $path;
	}

	private function downloadGeoip(string $source, string $base, string $target): PfbDownloadResult
	{
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
					break;
				}
				usleep(50000);
			}
			if ($port === 0) {
				proc_terminate($proc);
				proc_close($proc);
			}
		}
		if ($port === 0) {
			$this->markTestSkipped('loopback HTTP fixture unavailable');
		}
		return pfb_download(new PfbDownloadRequest(
			"http://127.0.0.1:{$port}/feed",
			$base,
			FALSE,
			$target,
			'',
			1,
			'',
			30,
			'geoip'
		));
	}
}
