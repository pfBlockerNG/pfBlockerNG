<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1542 — TOP1M's daily DCC detector and fail-safe publication contract.
 *
 * The detector tests use the shipped pfb_download() HTTP path where the host
 * permits a local fixture. Archive publication's final rename failure cannot
 * be induced portably off-appliance, so the exact staging seam is also pinned
 * against the production source (the live smoke suite exercises the appliance
 * filesystem failure path).
 */
#[CoversFunction('pfb_top1m_probe_decision')]
#[CoversFunction('pfb_top1m_source_identity')]
#[CoversFunction('pfb_top1m_invalidate_baseline')]
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
		$meta = [];
		$result = pfb_download("http://127.0.0.1:{$this->port}/feed.csv", $target, FALSE, 'TOP1M probe', '', 1, '', 30, 'change_detect', '', '', FALSE, $meta);
		$this->assertTrue($result);
		$this->assertSame('200', $meta['status'] ?? '');
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

	public function testTop1mPublishBranchesUseStagingBeforeActiveDestination(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertIsString($source);
		$this->assertStringContainsString('$top1m_stage = @tempnam', $source);
		$this->assertStringContainsString('pfb_top1m_persist_baseline($file_dwn, $file_download)', $source);
		$this->assertStringContainsString('pfb_top1m_invalidate_baseline($file_dwn)', $source);
	}

	public function testDccDispatchUsesExistingDnsblTriggerApi(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertIsString($source);
		$this->assertStringContainsString('pfb_trigger scope=dnsbl force=false trigger=cron', $source);
	}
}
