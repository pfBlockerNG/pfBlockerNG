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
	/**
	 * Salvage cap for the dispatch signal below. It exists only to reap a stuck
	 * run; the dispatch verdict is the fixture's own poke, never this number.
	 */
	private const DISPATCH_SALVAGE_SECONDS = 30;

	private string $dir;

	/** @var resource|null */
	private $server = NULL;

	private int $port = 0;

	/** @var array<string,mixed> */
	private array $saved_pfb = [];
	/** @var array<string,bool> */
	private array $saved_pfb_exists = [];

	/** @var list<resource> */
	private array $signals = [];

	protected function setUp(): void
	{
		self::loadWwwDccHelpers();
		$this->dir = sys_get_temp_dir() . '/pfb_top1m_dcc_' . getmypid() . '_' . uniqid();
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
	}

	protected function tearDown(): void
	{
		$this->stopServer();
		foreach ($this->signals as $signal) {
			if (is_resource($signal)) {
				fclose($signal);
			}
		}
		$this->signals = [];
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

	public function testExtractedDetectorDecisionPreservesExistingProbeMatrix(): void
	{
		$this->assertSame('unchanged', pfb_top1m_detector_decision(TRUE, '304', FALSE, 'ignored', NULL, TRUE, FALSE));
		$this->assertSame('unchanged', pfb_top1m_detector_decision(TRUE, '200', 'same', 'same', NULL, TRUE, FALSE));
		$this->assertSame('changed', pfb_top1m_detector_decision(TRUE, '200', 'new', 'old', NULL, TRUE, FALSE));
		$this->assertSame('failed', pfb_top1m_detector_decision(FALSE, '', FALSE, 'old', NULL, TRUE, FALSE));
	}

	public function testDetectorRequiresUsableRawBaselineBeforeUnchangedDecision(): void
	{
		$base = $this->dir . '/top-1m.csv.zip';
		$raw = "{$base}.orig";
		$body = "1,example.test\n";
		$body_hash = pfb_content_hash($body, FALSE);
		file_put_contents($raw, $body);
		$this->assertTrue(pfb_hash_write($base, $raw));
		$persisted_hash = pfb_hash_read($base)['digest'];

		$this->assertSame('unchanged', pfb_top1m_detector_decision(TRUE, '304', FALSE, $persisted_hash, $base, TRUE, FALSE));
		$this->assertSame('unchanged', pfb_top1m_detector_decision(TRUE, '200', $body_hash, $persisted_hash, $base, TRUE, FALSE));

		// A matching hash without a regular raw source cannot make a 304 safe.
		unlink($raw);
		$this->assertSame('changed', pfb_top1m_detector_decision(TRUE, '304', FALSE, $persisted_hash, $base, TRUE, FALSE));
		$this->assertSame('changed', pfb_top1m_detector_decision(TRUE, '200', $body_hash, $persisted_hash, $base, TRUE, FALSE));

		file_put_contents($raw, $body);
		unlink("{$base}.xxhash128");
		$this->assertSame('changed', pfb_top1m_detector_decision(TRUE, '304', FALSE, '', $base, TRUE, FALSE));
		file_put_contents("{$base}.xxhash128", 'not-a-digest');
		$this->assertSame('changed', pfb_top1m_detector_decision(TRUE, '200', $body_hash, $persisted_hash, $base, TRUE, FALSE));

		$this->assertSame('changed', pfb_top1m_detector_decision(TRUE, '304', FALSE, $persisted_hash, $base, FALSE, FALSE));
		$this->assertSame('failed', pfb_top1m_detector_decision(FALSE, '', FALSE, $persisted_hash, $base, TRUE, FALSE));
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
		$this->requireLocalListenerCapability();
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
		$this->requireZipTarSupport($archive);
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
		$archive = $this->zipFixture('single.zip', ['feed/top.csv' => "1,example.test\n"]);
		$this->requireZipTarSupport($archive);
		$base = $this->dir . '/top-1m.csv.zip';
		$active = $this->dir . '/top-1m.csv';
		file_put_contents($active, 'old active');

		$this->assertTrue($this->downloadTop1m($archive, $base, $active));
		$this->assertSame("1,example.test\n", file_get_contents($active));
		$this->assertSame(file_get_contents($archive), file_get_contents("{$base}.orig"));
		$this->assertSame(pfb_content_hash($archive, TRUE), pfb_hash_read($base)['digest']);
		$this->assertFileExists($GLOBALS['pfb']['dbdir'] . '/top-1m.update');
	}

	public function testTop1mZipDirectoryTargetExtractsEveryMember(): void
	{
		$archive = $this->zipFixture('directory.zip', ['feed/a.csv' => "a\n", 'feed/b.csv' => "b\n"]);
		$this->requireZipTarSupport($archive);
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
		$this->requireZipTarSupport($archive);
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
		$gzip = gzencode("1,example.test\n");
		$gzip_path = $this->dir . '/feed.gz';
		file_put_contents($gzip_path, $gzip);
		$this->assertTrue($this->downloadTop1m($gzip_path, $base, $active));
		$this->assertSame("1,example.test\n", file_get_contents($active));

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
		file_put_contents($plain, "1,plain.test\n");
		$this->assertTrue($this->downloadTop1m($plain, $plain_base, $plain_active));
		$this->assertSame("1,plain.test\n", file_get_contents($plain_active));
	}

	public function testTop1mPersistenceFailureRollsBackActiveAndEveryBaselineAcrossFormats(): void
	{
		$fixtures = [
			'gzip' => [
				'source' => (function (): string {
					$path = $this->dir . '/persist.gz';
					file_put_contents($path, gzencode("1,gzip.test\n"));
					return $path;
				})(),
				'base' => $this->dir . '/persist-gzip.csv.gz',
				'active' => $this->dir . '/persist-gzip.csv',
				'body' => "1,gzip.test\n",
			],
			'zip' => [
				'source' => $this->zipFixture('persist.zip', ['feed/top.csv' => "1,zip.test\n"]),
				'base' => $this->dir . '/persist-zip.csv.zip',
				'active' => $this->dir . '/persist-zip.csv',
				'body' => "1,zip.test\n",
			],
			'plain' => [
				'source' => (function (): string {
					$path = $this->dir . '/persist.txt';
					file_put_contents($path, "1,plain.test\n");
					return $path;
				})(),
				'base' => $this->dir . '/persist-plain.csv',
				'active' => $this->dir . '/persist-plain.active.csv',
				'body' => "1,plain.test\n",
			],
		];
		if (!$this->tarReadsZip($fixtures['zip']['source'])) {
			unset($fixtures['zip']);
		}

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
		file_put_contents($source, gzencode("1,first.test\n"));
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

	private function requireZipTarSupport(string $archive): void
	{
		if (!$this->tarReadsZip($archive)) {
			$this->markTestSkipped('/usr/bin/tar cannot read ZIP on this host; pfSense uses bsdtar');
		}
	}

	private function tarReadsZip(string $archive): bool
	{
		exec('/usr/bin/tar -tf ' . escapeshellarg($archive) . ' >/dev/null 2>&1', $output, $status);
		return $status === 0;
	}

	private function downloadTop1m(string $source, string $base, string $target): bool
	{
		$this->stopServer();
		$this->requireLocalListenerCapability();
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
			$this->fail('could not start local HTTP fixture');
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

	private function requireLocalListenerCapability(): void
	{
		$errno = 0;
		$error = '';
		$listener = @stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
		if ($listener === FALSE) {
			$reason = $error !== '' ? $error : "socket error {$errno}";
			$this->markTestSkipped("environment cannot bind a loopback listener: {$reason}");
			return;
		}
		fclose($listener);
	}

	private function stopServer(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
			$this->server = NULL;
		}
	}

	public function testExtractedDispatchSeamRunsExistingCronCommand(): void
	{
		$dispatch_log = "{$this->dir}/dispatch.log";
		$dispatch_fifo = "{$this->dir}/dispatch.fifo";
		$signal = $this->openDispatchSignal($dispatch_fifo);
		$fake_php = $this->dispatchFixture('fake-php', $dispatch_log, $dispatch_fifo);

		$saved_argv = $GLOBALS['argv'];
		$had_php = array_key_exists('php', $GLOBALS['pfb']);
		$saved_php = $GLOBALS['pfb']['php'] ?? NULL;
		$had_runlog = array_key_exists('runlog', $GLOBALS['pfb']);
		$saved_runlog = $GLOBALS['pfb']['runlog'] ?? NULL;
		$had_changed = array_key_exists('top1m_changed', $GLOBALS['pfb']);
		$saved_changed = $GLOBALS['pfb']['top1m_changed'] ?? NULL;
		$had_done = array_key_exists('top1m_dispatch_done', $GLOBALS['pfb']);
		$saved_done = $GLOBALS['pfb']['top1m_dispatch_done'] ?? NULL;
		try {
			$GLOBALS['argv'] = ['pfblockerng.php', 'dcc'];
			$GLOBALS['pfb']['php'] = $fake_php;
			$GLOBALS['pfb']['runlog'] = '/dev/null';
			$GLOBALS['pfb']['top1m_changed'] = TRUE;
			unset($GLOBALS['pfb']['top1m_dispatch_done']);

			$this->assertTrue(pfb_top1m_dispatch_if_changed(TRUE));
			$this->awaitDispatch($signal);
			$lines = file($dispatch_log, FILE_IGNORE_NEW_LINES);
			$this->assertIsArray($lines);
			$this->assertCount(1, $lines);
			$this->assertStringContainsString('pfb_trigger scope=dnsbl force=false trigger=cron', $lines[0]);
		} finally {
			$GLOBALS['argv'] = $saved_argv;
			if (!$had_php) {
				unset($GLOBALS['pfb']['php']);
			} else {
				$GLOBALS['pfb']['php'] = $saved_php;
			}
			if (!$had_runlog) {
				unset($GLOBALS['pfb']['runlog']);
			} else {
				$GLOBALS['pfb']['runlog'] = $saved_runlog;
			}
			if (!$had_changed) {
				unset($GLOBALS['pfb']['top1m_changed']);
			} else {
				$GLOBALS['pfb']['top1m_changed'] = $saved_changed;
			}
			if (!$had_done) {
				unset($GLOBALS['pfb']['top1m_dispatch_done']);
			} else {
				$GLOBALS['pfb']['top1m_dispatch_done'] = $saved_done;
			}
		}
	}

	public function testDispatchSuppressesFailedAndUnchangedButRunsChangedOnce(): void
	{
		$dispatch_log = "{$this->dir}/dispatch-matrix.log";
		$dispatch_fifo = "{$this->dir}/dispatch-matrix.fifo";
		$signal = $this->openDispatchSignal($dispatch_fifo);
		$fake_php = $this->dispatchFixture('fake-php-matrix', $dispatch_log, $dispatch_fifo);

		$saved_argv = $GLOBALS['argv'];
		$had_php = array_key_exists('php', $GLOBALS['pfb']);
		$saved_php = $GLOBALS['pfb']['php'] ?? NULL;
		$had_runlog = array_key_exists('runlog', $GLOBALS['pfb']);
		$saved_runlog = $GLOBALS['pfb']['runlog'] ?? NULL;
		$had_changed = array_key_exists('top1m_changed', $GLOBALS['pfb']);
		$saved_changed = $GLOBALS['pfb']['top1m_changed'] ?? NULL;
		$had_done = array_key_exists('top1m_dispatch_done', $GLOBALS['pfb']);
		$saved_done = $GLOBALS['pfb']['top1m_dispatch_done'] ?? NULL;
		try {
			$GLOBALS['argv'] = ['pfblockerng.php', 'dcc'];
			$GLOBALS['pfb']['php'] = $fake_php;
			$GLOBALS['pfb']['runlog'] = '/dev/null';
			$GLOBALS['pfb']['top1m_changed'] = FALSE;
			unset($GLOBALS['pfb']['top1m_dispatch_done']);

			$this->assertFalse(pfb_top1m_dispatch_if_changed(TRUE), 'unchanged TOP1M must not dispatch');
			$this->assertFalse(pfb_top1m_dispatch_if_changed(FALSE), 'failed extras pass must not dispatch without a TOP1M change');
			$this->assertFileDoesNotExist($dispatch_log);

			$GLOBALS['pfb']['top1m_changed'] = TRUE;
			$this->assertTrue(pfb_top1m_dispatch_if_changed(FALSE), 'TOP1M change must dispatch despite unrelated extras failure');
			$this->assertFalse(pfb_top1m_dispatch_if_changed(FALSE), 'the same TOP1M change must not dispatch twice');
			$this->awaitDispatch($signal);
			$lines = file($dispatch_log, FILE_IGNORE_NEW_LINES);
			$this->assertIsArray($lines);
			$this->assertCount(1, $lines, 'changed TOP1M must dispatch exactly once');
		} finally {
			$GLOBALS['argv'] = $saved_argv;
			if (!$had_php) {
				unset($GLOBALS['pfb']['php']);
			} else {
				$GLOBALS['pfb']['php'] = $saved_php;
			}
			if (!$had_runlog) {
				unset($GLOBALS['pfb']['runlog']);
			} else {
				$GLOBALS['pfb']['runlog'] = $saved_runlog;
			}
			if (!$had_changed) {
				unset($GLOBALS['pfb']['top1m_changed']);
			} else {
				$GLOBALS['pfb']['top1m_changed'] = $saved_changed;
			}
			if (!$had_done) {
				unset($GLOBALS['pfb']['top1m_dispatch_done']);
			} else {
				$GLOBALS['pfb']['top1m_dispatch_done'] = $saved_done;
			}
		}
	}

	public function testScheduledDccReportsChangeWithoutBackgroundDispatch(): void
	{
		$dispatch_log = "{$this->dir}/scheduled-dispatch.log";
		$dispatch_fifo = "{$this->dir}/scheduled-dispatch.fifo";
		$this->openDispatchSignal($dispatch_fifo);
		$fake_php = $this->dispatchFixture('fake-php-scheduled', $dispatch_log, $dispatch_fifo);
		$saved_argv = $GLOBALS['argv'];
		$saved = $GLOBALS['pfb'];
		try {
			$GLOBALS['argv'] = ['pfblockerng.php', 'dcc', 'scheduled'];
			$GLOBALS['pfb']['php'] = $fake_php;
			$GLOBALS['pfb']['runlog'] = '/dev/null';
			$GLOBALS['pfb']['top1m_changed'] = TRUE;
			unset($GLOBALS['pfb']['top1m_dispatch_done']);

			$this->assertTrue(pfb_top1m_dispatch_if_changed(TRUE, FALSE));
			// Scheduled mode returns before the seam's exec(), so no child exists and
			// nothing can create the log after this point -- there is no event to wait
			// for, and the wall-clock spin this replaced only slowed the suite down.
			$this->assertFileDoesNotExist($dispatch_log);

			// Vacuity guard: the SAME fixture does record a dispatch when it is run, so
			// the absence above is the seam's decision and not an inert fixture.
			$probe_output = [];
			$probe_status = -1;
			exec(escapeshellarg($fake_php) . ' scheduled-vacuity-probe', $probe_output, $probe_status);
			$this->assertSame(0, $probe_status, 'the dispatch fixture must be runnable: ' . implode("\n", $probe_output));
			$this->assertStringContainsString(
				'scheduled-vacuity-probe',
				(string) file_get_contents($dispatch_log),
				'the fixture must be able to create the log this test asserts absent'
			);
		} finally {
			$GLOBALS['argv'] = $saved_argv;
			$GLOBALS['pfb'] = $saved;
		}
	}

	public function testGeoipCliCommandsPropagateGenerationFailureStatus(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertIsString($source);
		$this->assertStringContainsString('exit(pfblockerng_uc_countries() ? 0 : 1);', $source);
		$this->assertStringContainsString('exit(pfblockerng_get_countries() ? 0 : 1);', $source);
		$this->assertStringContainsString("if (!pfblockerng_uc_countries('/usr/local/www/pfblockerng'))", $source);
	}

	public function testLockedSyncMarksInternalDcChildAsParentOwned(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertIsString($source);
		$this->assertStringContainsString("\$maxmind_status = pfb_reentry_exec('dc', ['scheduled'], \$pfb['log']);", $source);
		$this->assertStringContainsString('!in_array($maxmind_status, [0, 2], TRUE) || !pfb_geoip_generation_ready()', $source);
	}

	public function testUnrelatedExtrasFailureDoesNotBlockMaxmindConversion(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertIsString($source);
		$this->assertSame(1, substr_count($source, "\$pfb['maxmind_feed_error'] = TRUE;"));
		$this->assertMatchesRegularExpression(
			'/if\s*\(\$feed\[\x27type\x27\]\s*==\s*\x27geoip\x27\)\s*\{\s*'
			. '\$pfb\[\x27maxmind_feed_error\x27\]\s*=\s*TRUE;\s*\}/',
			$source,
			'Only a failed GeoIP feed may block MaxMind conversion.'
		);
		$this->assertStringContainsString("if (empty(\$pfb['maxmind_feed_error']))", $source);
	}

	private static function loadWwwDccHelpers(): void
	{
		if (function_exists('pfb_top1m_detector_decision')) {
			return;
		}
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		if ($source === FALSE) {
			self::fail('failed to read pfblockerng.php');
		}
		$start = strpos($source, "\nfunction pfb_top1m_detector_decision");
		$end = strpos($source, "\nfunction pfblockerng_download_extras", $start === FALSE ? 0 : $start);
		if ($start === FALSE || $end === FALSE || $end <= $start) {
			self::fail('could not locate extracted TOP1M helper block');
		}
		eval("\n" . substr($source, $start + 1, $end - $start - 1));
	}

	/**
	 * Create the dispatch signal and hold its read end. Called BEFORE the seam runs,
	 * so a fixture that dispatches instantly cannot poke into a pipe nobody holds.
	 *
	 * The FIFO is opened 'r+' because a plain 'r' open blocks until a writer arrives,
	 * which would be the very wall-clock race this signal exists to remove.
	 *
	 * @return resource
	 */
	private function openDispatchSignal(string $fifo)
	{
		$this->assertTrue(posix_mkfifo($fifo, 0600), "could not create dispatch signal {$fifo}");
		$handle = fopen($fifo, 'r+');
		$this->assertIsResource($handle, "could not open dispatch signal {$fifo}");
		$this->signals[] = $handle;
		return $handle;
	}

	/**
	 * The fake $pfb['php'] the dispatch seam execs: it records the argv it was handed,
	 * then pokes the signal so the caller can consume the dispatch as an event.
	 *
	 * The poke redirects with '1<>' (open read-write), so it never blocks waiting for a
	 * reader and can never strand the backgrounded child the seam orphans.
	 */
	private function dispatchFixture(string $name, string $log, string $fifo): string
	{
		$path = "{$this->dir}/{$name}";
		$this->assertNotFalse(file_put_contents(
			$path,
			"#!/bin/sh\n"
			. "printf '%s\\n' \"\$*\" >> " . escapeshellarg($log) . "\n"
			. "printf 'dispatched\\n' 1<> " . escapeshellarg($fifo) . "\n"
		));
		$this->assertTrue(chmod($path, 0755));
		return $path;
	}

	/**
	 * Consume the dispatch event itself. The seam backgrounds its child, so the only
	 * honest wait is one that blocks on the child reporting in; the salvage cap below
	 * exists solely to reap a stuck run and says so, and never decides whether the
	 * seam dispatched.
	 *
	 * @param resource $signal
	 */
	private function awaitDispatch($signal): void
	{
		$read = [$signal];
		$write = NULL;
		$except = NULL;
		$ready = stream_select($read, $write, $except, self::DISPATCH_SALVAGE_SECONDS);
		$this->assertSame(1, $ready, sprintf(
			'STUCK/ENVIRONMENT: the dispatched fixture never reported in within %ds, so this '
			. 'run is stuck or its host starved the child -- not a TOP1M dispatch verdict',
			self::DISPATCH_SALVAGE_SECONDS
		));
		$this->assertSame("dispatched\n", fgets($signal), 'the dispatch signal must carry the fixture poke');
	}
}
