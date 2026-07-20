<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1542 — TOP1M's daily DCC detector and fail-safe publication contract.
 *
 * Publication tests drive the shipped pfb_download() path with local archive
 * fixtures, so active-file and baseline contracts run off-appliance.
 */
#[CoversFunction('pfb_top1m_probe_decision')]
#[CoversFunction('pfb_top1m_source_identity')]
#[CoversFunction('pfb_top1m_invalidate_baseline')]
#[CoversFunction('pfb_top1m_persist_baseline')]
#[CoversFunction('pfb_top1m_settings_reprocess')]
#[CoversFunction('pfb_top1m_download_ledger_update')]
#[CoversFunction('pfb_download')]
#[CoversFunction('pfb_validator_read')]
#[CoversFunction('pfb_validator_write')]
final class Top1mDccDetectorTest extends TestCase
{
	private string $dir;

	/** @var resource|null */
	private $server = NULL;

	private int $port = 0;

	/** @var array<string,mixed> */
	private array $saved_pfb = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_top1m_dcc_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
		foreach (['log', 'errlog', 'pnow'] as $key) {
			$this->saved_pfb[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$key] : FALSE;
		}
		$this->saved_pfb['mime_types'] = $GLOBALS['pfb']['mime_types'] ?? FALSE;
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['pnow'] = 'now';
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
		}
		foreach ($this->saved_pfb as $key => $value) {
			if ($value === FALSE) {
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

	public function testProbeDecisionIsFailSafeAcrossDetectorRows(): void
	{
		$this->assertSame('unchanged', pfb_top1m_probe_decision(TRUE, '304', 'ignored', 'ignored'));
		$this->assertSame('unchanged', pfb_top1m_probe_decision(TRUE, '200', 'same', 'same'));
		$this->assertSame('changed', pfb_top1m_probe_decision(TRUE, '200', 'new', 'old'));
		$this->assertSame('changed', pfb_top1m_probe_decision(TRUE, '200', 'new', ''));
		$this->assertSame('changed', pfb_top1m_probe_decision(TRUE, '200', FALSE, 'old'));
		$this->assertSame('changed', pfb_top1m_probe_decision(TRUE, '500', FALSE, 'old'));
		$this->assertSame('failed', pfb_top1m_probe_decision(FALSE, '', FALSE, 'old'));
	}

	public function testProviderIdentityCoversAllFiveProvidersAndAuth(): void
	{
		foreach (pfb_top1m_providers() as $provider => $descriptor) {
			$identity = pfb_top1m_source_identity($provider, $descriptor['url'], pfb_top1m_auth_headers($descriptor, 'token'));
			$this->assertNotSame('', $identity, "{$provider}: source identity must not be empty");
		}
		$base = pfb_top1m_source_identity('tranco', 'https://example.test/feed', []);
		$this->assertNotSame($base, pfb_top1m_source_identity('cisco', 'https://example.test/feed', []));
		$this->assertNotSame($base, pfb_top1m_source_identity('tranco', 'https://example.test/other', []));
		$this->assertNotSame($base, pfb_top1m_source_identity('tranco', 'https://example.test/feed', ['Authorization: Bearer token']));
	}

	public function testProviderChangeInvalidatesActualValidatorsButRetainsActiveDerivedSource(): void
	{
		$base = $this->dir . '/top-1m.csv.zip';
		$validator_base = "{$base}.orig";
		pfb_validator_write($validator_base, '"old-etag"', 1700000000);
		file_put_contents("{$base}.orig", 'old raw');
		file_put_contents("{$base}.xxhash128", str_repeat('a', 32));
		file_put_contents("{$base}.source", 'old identity');
		$active = $this->dir . '/top-1m.csv';
		file_put_contents($active, 'old derived');

		pfb_top1m_invalidate_baseline($base);

		$this->assertFileDoesNotExist("{$base}.orig");
		$this->assertFileDoesNotExist("{$validator_base}.etag");
		$this->assertFileDoesNotExist("{$validator_base}.lastmod");
		$this->assertFileDoesNotExist("{$base}.xxhash128");
		$this->assertFileDoesNotExist("{$base}.source");
		$this->assertFalse(pfb_validator_read($validator_base)['etag']);
		$this->assertFalse(pfb_validator_read($validator_base)['lastmod']);
		$this->assertSame('old derived', file_get_contents($active));
	}

	public function testOnlyLocalFilteringSettingsRequestCachedSourceReprocess(): void
	{
		$before = ['enable' => 'on', 'count' => '1000', 'tld' => 'com', 'provider' => 'tranco'];
		$this->assertFalse(pfb_top1m_settings_reprocess($before, $before));
		$provider = $before;
		$provider['provider'] = 'cisco';
		$this->assertFalse(pfb_top1m_settings_reprocess($before, $provider));
		foreach (['enable', 'count', 'tld'] as $key) {
			$after = $before;
			$after[$key] = $key === 'enable' ? 'off' : ($key === 'count' ? '500' : 'net');
			$this->assertTrue(pfb_top1m_settings_reprocess($before, $after), "{$key} change must reprocess cached source");
		}
	}

	public function testDownloadFailureAndRecoveryUseOneStableLedgerItem(): void
	{
		pfb_top1m_download_ledger_update(FALSE, $this->dir, 'upstream failed');
		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open);
		$this->assertSame('top1m', $open[0]['item']);
		$this->assertSame('download', $open[0]['stage']);
		pfb_top1m_download_ledger_update(FALSE, $this->dir, 'still failed');
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'dnsbl'));
		pfb_top1m_download_ledger_update(TRUE, $this->dir, '');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'));
	}

	public function testChangeDetectUsesActualHttpProbeBodyAndMetadata(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$body = "1,example.com\n";
		$router = "{$this->dir}/router.php";
		$this->assertNotFalse(file_put_contents($router, "<?php\nheader('ETag: \\\"followup-v1\\\"');\necho " . var_export($body, TRUE) . ";\n"));
		$descriptors = [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']];
		for ($try = 0; $try < 10; $try++) {
			$port = random_int(20000, 60000);
			$proc = proc_open(['php', '-S', "127.0.0.1:{$port}", $router], $descriptors, $pipes, $this->dir, ['PATH' => (string) getenv('PATH')]);
			if (!is_resource($proc)) {
				continue;
			}
			for ($poll = 0; $poll < 40; $poll++) {
				$sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.05);
				if ($sock !== FALSE) {
					fclose($sock);
					$this->server = $proc;
					$this->port = $port;
					break 2;
				}
				usleep(50000);
			}
			proc_terminate($proc);
			proc_close($proc);
		}
		$this->assertNotSame(0, $this->port, 'could not start local HTTP fixture');

		$target = $this->dir . '/top-1m.csv.zip.md5';
		$result = pfb_download(new PfbDownloadRequest(
			listUrl: "http://127.0.0.1:{$this->port}/feed.csv",
			downloadPath: $target,
			flex: FALSE,
			header: 'TOP1M probe',
			format: '',
			logType: 1,
			timeout: 30,
			type: 'change_detect',
		));
		$this->assertTrue($result->success);
		$this->assertSame('200', $result->responseMeta['status'] ?? '');
		$this->assertSame($body, file_get_contents("{$target}.raw"));
		$this->assertSame(pfb_content_hash($body, FALSE), pfb_content_hash("{$target}.raw", TRUE));
	}

	public function testDetectorSidecarReadFailsSafeForMissingCorruptAndWrongAlgorithm(): void
	{
		$base = $this->dir . '/top-1m.csv.zip';
		$body_hash = pfb_content_hash('same body', FALSE);
		$this->assertSame('changed', pfb_top1m_probe_decision(TRUE, '200', $body_hash, pfb_hash_read($base)['digest']));
		file_put_contents("{$base}.xxhash128", 'not-a-digest');
		$this->assertSame('changed', pfb_top1m_probe_decision(TRUE, '200', $body_hash, pfb_hash_read($base)['digest']));
		file_put_contents("{$base}.xxhash128", str_repeat('b', 32));
		$this->assertSame('changed', pfb_top1m_probe_decision(TRUE, '200', $body_hash, pfb_hash_read($base)['digest']));
	}

	public function testTop1mZipFileTargetRejectsMultipleMembersAndRetainsActiveAndBaseline(): void
	{
		$archive = $this->zipFixture('multiple.zip', ['feed/a.csv' => "new-a\n", 'feed/b.csv' => "new-b\n"]);
		$base = $this->dir . '/top-1m.csv.zip';
		$active = $this->dir . '/top-1m.csv';
		file_put_contents($active, 'old active');
		file_put_contents("{$base}.orig", 'old raw');
		pfb_hash_write($base, "{$base}.orig");
		$old_hash = file_get_contents("{$base}.xxhash128");

		$this->assertFalse($this->downloadTop1m($archive, $base, $active));
		$this->assertSame('old active', file_get_contents($active));
		$this->assertSame('old raw', file_get_contents("{$base}.orig"));
		$this->assertSame($old_hash, file_get_contents("{$base}.xxhash128"));
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dbdir'] . '/top-1m.update');
	}

	public function testTop1mZipFileTargetPublishesSingleRegularMemberAndThenPersistsBaseline(): void
	{
		$archive = $this->zipFixture('single.zip', ['feed/top.csv' => "rank,example.test\n"]);
		$base = $this->dir . '/top-1m.csv.zip';
		$active = $this->dir . '/top-1m.csv';
		file_put_contents($active, 'old active');

		$this->assertTrue($this->downloadTop1m($archive, $base, $active));
		$this->assertSame("rank,example.test\n", file_get_contents($active));
		$this->assertSame(file_get_contents($archive), file_get_contents("{$base}.orig"));
		$this->assertSame(pfb_content_hash($archive, TRUE), pfb_hash_read($base)['digest']);
		$this->assertFileExists($GLOBALS['pfb']['dbdir'] . '/top-1m.update');
	}

	public function testTop1mZipDirectoryTargetExtractsEveryMember(): void
	{
		$archive = $this->zipFixture('directory.zip', ['feed/a.csv' => "a\n", 'feed/b.csv' => "b\n"]);
		$base = $this->dir . '/top-1m.csv.zip';
		$target = $this->dir . '/out';
		$this->assertTrue(mkdir($target));

		$this->assertTrue($this->downloadTop1m($archive, $base, $target));
		$this->assertSame("a\n", file_get_contents("{$target}/a.csv"));
		$this->assertSame("b\n", file_get_contents("{$target}/b.csv"));
	}

	public function testTop1mZipUnsafeMemberMakesNoActiveOrStagingWrite(): void
	{
		$archive = $this->zipFixture('unsafe.zip', ['feed/good.csv' => "good\n", '../escape.csv' => "escape\n"]);
		$base = $this->dir . '/top-1m.csv.zip';
		$active = $this->dir . '/top-1m.csv';
		file_put_contents($active, 'old active');

		$this->assertFalse($this->downloadTop1m($archive, $base, $active));
		$this->assertSame('old active', file_get_contents($active));
		$this->assertFileDoesNotExist($this->dir . '/escape.csv');
	}

	public function testTop1mGzipAndPlainPublicationKeepActiveOnFailure(): void
	{
		$base = $this->dir . '/top-1m.csv.gz';
		$active = $this->dir . '/top-1m.csv';
		file_put_contents($active, 'old active');
		$gzip = gzencode("rank,example.test\n");
		$gzip_path = $this->dir . '/feed.gz';
		file_put_contents($gzip_path, $gzip);
		$this->assertTrue($this->downloadTop1m($gzip_path, $base, $active));
		$this->assertSame("rank,example.test\n", file_get_contents($active));

		$broken_base = $this->dir . '/broken.csv.gz';
		$broken_active = $this->dir . '/broken.csv';
		file_put_contents($broken_active, 'old broken');
		$broken = $this->dir . '/broken.gz';
		file_put_contents($broken, substr($gzip, 0, -3));
		$this->assertFalse($this->downloadTop1m($broken, $broken_base, $broken_active));
		$this->assertSame('old broken', file_get_contents($broken_active));

		$plain_base = $this->dir . '/plain.csv';
		$plain_active = $this->dir . '/plain.active.csv';
		file_put_contents($plain_active, 'old plain');
		$plain = $this->dir . '/plain.txt';
		file_put_contents($plain, "rank,plain.test\n");
		$this->assertTrue($this->downloadTop1m($plain, $plain_base, $plain_active));
		$this->assertSame("rank,plain.test\n", file_get_contents($plain_active));
	}

	public function testTop1mPersistenceFailureRollsBackActiveAndEveryBaselineAcrossFormats(): void
	{
		$fixtures = [
			'gzip' => [
				'source' => (function (): string {
					$path = $this->dir . '/persist.gz';
					file_put_contents($path, gzencode("rank,gzip.test\n"));
					return $path;
				})(),
				'base' => $this->dir . '/persist-gzip.csv.gz',
				'active' => $this->dir . '/persist-gzip.csv',
				'body' => "rank,gzip.test\n",
			],
			'zip' => [
				'source' => $this->zipFixture('persist.zip', ['feed/top.csv' => "rank,zip.test\n"]),
				'base' => $this->dir . '/persist-zip.csv.zip',
				'active' => $this->dir . '/persist-zip.csv',
				'body' => "rank,zip.test\n",
			],
			'plain' => [
				'source' => (function (): string {
					$path = $this->dir . '/persist.txt';
					file_put_contents($path, "rank,plain.test\n");
					return $path;
				})(),
				'base' => $this->dir . '/persist-plain.csv',
				'active' => $this->dir . '/persist-plain.active.csv',
				'body' => "rank,plain.test\n",
			],
		];

		foreach ($fixtures as $label => $fixture) {
			$base = $fixture['base'];
			$active = $fixture['active'];
			$old_raw = "old raw {$label}\n";
			$old_source = "old source {$label}";
			$old_etag = '"old-' . $label . '"';
			$old_lastmod = 1700000000;
			file_put_contents($active, "old active {$label}\n");
			file_put_contents("{$base}.orig", $old_raw);
			pfb_hash_write($base, "{$base}.orig");
			$old_hash = file_get_contents("{$base}.xxhash128");
			file_put_contents("{$base}.source", $old_source);
			pfb_validator_write("{$base}.orig", $old_etag, $old_lastmod);
			chmod("{$base}.xxhash128", 0444);

			$this->assertFalse($this->downloadTop1m($fixture['source'], $base, $active), "{$label}: persistence failure must fail");
			$this->assertSame("old active {$label}\n", file_get_contents($active), "{$label}: active rollback");
			$this->assertSame($old_raw, file_get_contents("{$base}.orig"), "{$label}: raw rollback");
			$this->assertSame($old_hash, file_get_contents("{$base}.xxhash128"), "{$label}: hash rollback");
			$this->assertSame($old_source, file_get_contents("{$base}.source"), "{$label}: source rollback");
			$this->assertSame($old_etag, pfb_validator_read("{$base}.orig")['etag'], "{$label}: ETag rollback");
			$this->assertSame($old_lastmod, pfb_validator_read("{$base}.orig")['lastmod'], "{$label}: Last-Modified rollback");

			chmod("{$base}.xxhash128", 0644);
			$this->assertTrue($this->downloadTop1m($fixture['source'], $base, $active), "{$label}: recovery succeeds");
			$this->assertSame($fixture['body'], file_get_contents($active), "{$label}: recovered active");
			$this->assertSame($old_source, file_get_contents("{$base}.source"), "{$label}: source preserved until identity update");
		}
	}

	public function testTop1mFirstPersistenceFailureLeavesNoActiveOrBaseline(): void
	{
		$source = $this->dir . '/first-failure.gz';
		file_put_contents($source, gzencode("rank,first.test\n"));
		$base = $this->dir . '/first-failure.csv.gz';
		$active = $this->dir . '/first-failure.csv';
		$this->assertTrue(mkdir("{$base}.xxhash128"));

		$this->assertFalse($this->downloadTop1m($source, $base, $active));
		$this->assertFileDoesNotExist($active);
		$this->assertFileDoesNotExist("{$base}.orig");
		$this->assertFileDoesNotExist("{$base}.source");
		$this->assertDirectoryExists("{$base}.xxhash128");
		$this->assertFileDoesNotExist("{$base}.orig.etag");
		$this->assertFileDoesNotExist("{$base}.orig.lastmod");
	}

	/** @param array<string,string> $entries */
	private function zipFixture(string $name, array $entries): string
	{
		$path = $this->dir . '/' . $name;
		$zip = new ZipArchive();
		$this->assertSame(TRUE, $zip->open($path, ZipArchive::CREATE));
		foreach ($entries as $member => $body) {
			$this->assertTrue($zip->addFromString($member, $body));
		}
		$this->assertTrue($zip->close());
		return $path;
	}

	private function downloadTop1m(string $source, string $base, string $target): bool
	{
		$GLOBALS['pfb']['dbdir'] = $this->dir . '/db';
		$this->assertTrue(is_dir($GLOBALS['pfb']['dbdir']) || mkdir($GLOBALS['pfb']['dbdir']));
		$router = $this->dir . '/router.php';
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
			listUrl: "http://127.0.0.1:{$port}/feed",
			downloadPath: $base,
			flex: FALSE,
			header: $target,
			format: '',
			logType: 1,
			timeout: 30,
			type: 'top1m',
		))->success;
	}

	public function testDccDispatchUsesExistingDnsblTriggerApi(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertIsString($source);
		$this->assertStringContainsString('pfb_trigger scope=dnsbl force=false trigger=cron', $source);
	}
}
