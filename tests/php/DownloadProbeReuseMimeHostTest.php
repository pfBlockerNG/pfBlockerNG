<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';

/**
 * Issue #4304 — the MIME gate's host exceptions must see the feed host when pfb_download()
 * reuses the change-detection probe body.
 *
 * After a changed probe, pfb_download_fetch() reads the body from '{file}.md5.raw' instead of
 * fetching it again. libmagic reports an Adblock Plus list holding a '.text' line as
 * text/x-asm, which the allow-list does not name; pfb_filter() accepts it only when the feed
 * host is easylist.to or easylist-downloads.adblockplus.org. The host must come from the feed
 * URL on the reuse path too, and the exception must stay limited to those hosts.
 *
 * The probe body is planted directly, so no request reaches the network: the resolve double
 * maps each feed host to a public address, which PFB_FILTER_URL vets before the reuse fork.
 */
#[CoversFunction('pfb_download')]
final class DownloadProbeReuseMimeHostTest extends TestCase
{
	/** An Adblock Plus list libmagic takes for assembler source (the '.text' line). */
	private const ASM_LIKE_ABP = "! Title: issue 4304\n.text\n||a4304.example^\n||b4304.example^\n";

	private const HEADER = 'pfB_Reuse4304';

	private string $dir = '';

	/** @var array<string,mixed> saved $GLOBALS['pfb'] entries; absent key = was unset */
	private array $savedPfb = [];

	/** @var array<string,mixed> saved fixture globals; absent key = was unset */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_reuse_mime_host_' . getmypid() . '_' . uniqid('', TRUE);
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));

		foreach (['config', 'pfb_test_resolve_map', 'pfb_test_configured_ips'] as $g) {
			if (array_key_exists($g, $GLOBALS)) {
				$this->savedGlobals[$g] = $GLOBALS[$g];
			}
		}
		foreach (['log', 'errlog', 'pnow', 'dbdir', 'mime_types', 'skipfeed', 'failed',
			'runlog', 'runlog_active'] as $k) {
			if (array_key_exists($k, $GLOBALS['pfb'] ?? [])) {
				$this->savedPfb[$k] = $GLOBALS['pfb'][$k];
			}
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		foreach (array_keys(self::hosts()) as $host) {
			$GLOBALS['pfb_test_resolve_map']["{$host}."] = [['type' => 'A', 'data' => '203.0.113.5']];
		}
		// The probe body sits in dbdir: PFB_FILTER_URL only accepts the swapped-in local path
		// directly inside an allowed directory (/var/db/pfblockerng/* on the box).
		$GLOBALS['pfb']['dbdir']      = $this->dir;
		$GLOBALS['pfb']['log']        = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']     = "{$this->dir}/error.log";
		$GLOBALS['pfb']['pnow']       = 'now';
		$GLOBALS['pfb']['skipfeed']   = 0;
		$GLOBALS['pfb']['failed']     = [];
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
	}

	protected function tearDown(): void
	{
		foreach (['log', 'errlog', 'pnow', 'dbdir', 'mime_types', 'skipfeed', 'failed',
			'runlog', 'runlog_active'] as $k) {
			if (array_key_exists($k, $this->savedPfb)) {
				$GLOBALS['pfb'][$k] = $this->savedPfb[$k];
			} else {
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
		if ($this->dir !== '' && is_dir($this->dir)) {
			foreach (new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
				RecursiveIteratorIterator::CHILD_FIRST
			) as $entry) {
				$entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
			}
			rmdir($this->dir);
		}
	}

	/** @return array<string, array{bool}> feed host => whether the reused text/x-asm body is accepted */
	public static function hosts(): array
	{
		return [
			'easylist.to'                       => [TRUE],
			'easylist-downloads.adblockplus.org' => [TRUE],
			'lists4304.example'                 => [FALSE],
		];
	}

	/**
	 * Scenario: a changed probe left the body for the ingest to reuse.
	 *   Given '{file}.md5.raw' holds an Adblock Plus list libmagic reports as text/x-asm;
	 *   When  pfb_download() ingests the feed from http://<host>/list;
	 *   Then  the body is published for the two easylist hosts, as on a direct download;
	 *   And   on any other host the MIME gate still refuses it with mime_not_allowed.
	 */
	#[DataProvider('hosts')]
	public function testReusedProbeBodyKeysTheMimeExceptionOnTheFeedHost(bool $accepted): void
	{
		$host = (string) $this->dataName();
		$base = "{$this->dir}/" . self::HEADER;
		file_put_contents("{$base}.md5.raw", self::ASM_LIKE_ABP);
		$detected = trim((string) shell_exec('/usr/bin/file -b --mime-type ' . escapeshellarg("{$base}.md5.raw")));
		$this->assertSame('text/x-asm', $detected, 'premise: libmagic classifies the probe body as text/x-asm');

		$result = pfb_download(new PfbDownloadRequest(
			listUrl: "http://{$host}/list",
			downloadPath: $base,
			flex: FALSE,
			header: self::HEADER,
			format: '',
			logType: 1,
			timeout: 30,
			type: '',
		));

		$log = is_file($GLOBALS['pfb']['log']) ? (string) file_get_contents($GLOBALS['pfb']['log']) : '';
		$this->assertStringContainsString('( change check )', $log, 'premise: the ingest took the probe-body reuse path');
		$reject = 'pfb_validate: REJECT feed=' . self::HEADER . ' stage=mime reason=mime_not_allowed detected=text/x-asm';
		if ($accepted) {
			$this->assertTrue($result->success, "{$host}: expected the reused body to be published, log:\n{$log}");
			$this->assertStringNotContainsString($reject, $log, "{$host}: expected no MIME reject, log:\n{$log}");
			$this->assertSame(self::ASM_LIKE_ABP, (string) @file_get_contents("{$base}.orig"),
				"{$host}: expected the reused body to be published as the .orig");
		} else {
			$this->assertFalse($result->success, "{$host}: expected the MIME gate to refuse the reused body, log:\n{$log}");
			$this->assertStringContainsString($reject, $log, "{$host}: expected the mime_not_allowed reject, log:\n{$log}");
		}
	}
}
