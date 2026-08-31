<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * Issue #2660 — the content-sanity verdicts must also cover an archive feed's
 * EXTRACTED payload, not only a body libmagic already calls text.
 *
 * Every branch that publishes a decompressed '.orig' (gzip, bzip2, zip, plain tar)
 * is driven end to end through the real pfb_download() over a loopback body, so the
 * assertions ride the production gate instead of a re-implementation. Three things
 * are pinned per row: the same verdict the text path gives those bytes, the same
 * ADR-48 stage=plaintext reject line, and a '.orig' already in service that stays
 * byte-identical — the verdict is evaluated on the STAGED payload, so a refused
 * refresh never reaches the publication. With the scan off every row behaves exactly
 * as it did before the scan covered this path.
 */
#[CoversFunction('pfb_download')]
#[CoversFunction('pfb_extracted_text_sanity')]
final class DownloadExtractedPayloadSanityTest extends TestCase
{
	/** An HTML error page carrying no blocklist-shaped line anywhere. */
	private const HTML_ERROR = "<!doctype html>\n<html><body><h1>403 Forbidden</h1>\n"
		. "<p>Access denied by the origin</p></body></html>\n";

	private const NUL_BEARING = "1.2.3.4\n\x00garbage\n";

	private const HEALTHY = "192.0.2.10/32\n198.51.100.20\n";

	/** Bytes already in service: a refused refresh must leave them untouched. */
	private const SERVED = "203.0.113.7/32\n";

	private const HEADER = 'pfB_Arc2660_v4';

	private string $dir;

	/** @var resource|null */
	private $server = NULL;

	/** @var array<string,mixed> */
	private array $saved_pfb = [];

	/** @var array<string,bool> */
	private array $saved_pfb_exists = [];

	/** @var array<string,mixed> */
	private array $saved_config = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_extracted_sanity_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
		foreach (['log', 'errlog', 'pnow', 'dbdir', 'mime_types', 'script', 'etblock', 'etmatch'] as $key) {
			$this->saved_pfb_exists[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []);
			$this->saved_pfb[$key] = $GLOBALS['pfb'][$key] ?? NULL;
		}
		$this->saved_config = $GLOBALS['config'] ?? [];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['pnow'] = 'now';
		$GLOBALS['pfb']['dbdir'] = "{$this->dir}/db";
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
		$this->assertTrue(mkdir($GLOBALS['pfb']['dbdir']));
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
			$this->server = NULL;
		}
		foreach ($this->saved_pfb as $key => $value) {
			if ($this->saved_pfb_exists[$key]) {
				$GLOBALS['pfb'][$key] = $value;
			} else {
				unset($GLOBALS['pfb'][$key]);
			}
		}
		$GLOBALS['config'] = $this->saved_config;
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

	/**
	 * The cells where the extracted payload is what decides the ingest. gzip and bzip2
	 * hand a NUL-bearing or empty payload to the pre-existing compressed-inner MIME gate
	 * first, and a NUL-bearing zip member to the ZIP inner-content gate; those rows are
	 * pinned separately by preemptedRejectMatrix() so this file records the whole
	 * kind x payload surface, not just the half the new scan owns.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function extractedRejectMatrix(): array
	{
		return [
			'gzip payload is an HTML error page'  => ['gz',  'html',  'html_error_page'],
			'bzip2 payload is an HTML error page' => ['bz2', 'html',  'html_error_page'],
			'zip payload is an HTML error page'   => ['zip', 'html',  'html_error_page'],
			'tar payload is an HTML error page'   => ['tar', 'html',  'html_error_page'],
			'tar payload carries a NUL byte'      => ['tar', 'nul',   'nul_bytes'],
			'tar payload is empty'                => ['tar', 'empty', 'below_min_content'],
			'zip payload is empty'                => ['zip', 'empty', 'below_min_content'],
		];
	}

	/** @return array<string, array{0: string}> */
	public static function archiveKinds(): array
	{
		return [
			'gzip'      => ['gz'],
			'bzip2'     => ['bz2'],
			'zip'       => ['zip'],
			'plain tar' => ['tar'],
		];
	}

	/**
	 * A compressed ET body is only input to processet(): helper refusal must leave
	 * the accepted aggregate/hash pair untouched. The marker proves every archive
	 * kind was extracted into the isolated ET stage, not over the live .orig.
	 */
	#[DataProvider('archiveKinds')]
	public function test_et_archive_refusal_keeps_the_last_good_generation(string $kind): void
	{
		$payload = "192.0.2.10,1,90\n";
		$base = $this->seedPublication();
		$marker = "{$this->dir}/et-helper-input";
		$this->assertNotFalse(file_put_contents("{$base}.orig.xxhash128", 'old-hash'));
		$GLOBALS['pfb']['script'] = $this->rejectingEtHelper($base, $marker);
		$GLOBALS['pfb']['etblock'] = 'ET_Cnc';
		$GLOBALS['pfb']['etmatch'] = 'x';

		$result = $this->downloadArchive($kind, $payload, $base, PfbToggle::Off, TRUE);

		$this->assertFalse($result->success, 'the processet refusal must fail the ingest');
		$this->assertSame($payload, file_get_contents($marker),
			'the helper must receive the decompressed CSV from the isolated ET stage');
		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'refusal must preserve the accepted aggregate byte-for-byte');
		$this->assertSame('old-hash', file_get_contents("{$base}.orig.xxhash128"),
			'refusal must preserve the accepted raw-source hash');
		$this->assertFileDoesNotExist("{$base}.raw");
		$this->assertFileDoesNotExist("{$base}.orig.etstage");
	}

	/**
	 * Rows an earlier gate already refuses. They stay listed so a change that reorders
	 * the gates — letting the sanity scan claim a rejection that names the MIME instead —
	 * is visible rather than silent.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function preemptedRejectMatrix(): array
	{
		return [
			'gzip NUL payload is an inner-MIME reject'  => ['gz',  'nul',   'compressed_mime_not_allowed'],
			'gzip empty payload is an inner-MIME reject' => ['gz',  'empty', 'compressed_mime_not_allowed'],
			'bzip2 NUL payload is an inner-MIME reject' => ['bz2', 'nul',   'compressed_mime_not_allowed'],
			'bzip2 empty payload is an inner-MIME reject' => ['bz2', 'empty', 'compressed_mime_not_allowed'],
			'zip NUL payload is an inner-MIME reject'   => ['zip', 'nul',   'inner_mime_not_allowed'],
		];
	}

	/**
	 * Scenario: an archive feed whose extracted payload is not a list.
	 *   Given the scan on and a healthy '.orig' already in service.
	 *   When the archive's payload is bytes the text path calls $verdict.
	 *   Then the download FAILS with the canonical stage=plaintext line naming that
	 *        same verdict, and the served '.orig' is byte-identical.
	 */
	#[DataProvider('extractedRejectMatrix')]
	public function test_extracted_payload_verdict_fails_the_download_and_keeps_the_publication(
		string $kind,
		string $payload_name,
		string $verdict
	): void {
		$payload = self::payload($payload_name);
		$this->assertSame($verdict, pfb_text_sanity($payload),
			'row premise: these bytes must earn exactly this verdict on the text path');

		$base = $this->seedPublication();
		$result = $this->downloadArchive($kind, $payload, $base, PfbToggle::On);

		$this->assertFalse($result->success, 'a sanity verdict must fail the download');
		$this->assertStringContainsString(
			'pfb_validate: REJECT feed=' . self::HEADER . " stage=plaintext reason={$verdict}"
			. ' detected=' . basename($base) . '.orig',
			$this->log(),
			'the extracted-payload reject must use the same line shape the text path uses'
		);
		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'a refused refresh must leave the previously served payload byte-identical');
		$this->assertFileDoesNotExist("{$base}.raw", 'the refused wire body must not be left behind');
	}

	/**
	 * The scan is a real branch, not a blanket archive refusal: with it on, a healthy
	 * list inside each archive kind still ingests and publishes.
	 */
	#[DataProvider('archiveKinds')]
	public function test_healthy_archive_payload_still_ingests_with_the_scan_on(string $kind): void
	{
		$this->assertNull(pfb_text_sanity(self::HEALTHY),
			'row premise: a healthy list must earn no verdict on the text path');

		$base = $this->seedPublication();
		$result = $this->downloadArchive($kind, self::HEALTHY, $base, PfbToggle::On);

		$this->assertTrue($result->success, 'a healthy archive payload must keep ingesting with the scan on');
		$this->assertSame(self::HEALTHY, file_get_contents("{$base}.orig"),
			'the healthy payload must be published');
		$this->assertStringNotContainsString('stage=plaintext', $this->log(),
			'a healthy payload must never draw a sanity reject');
	}

	/**
	 * The registered default is off, and an off install must be unchanged: every row the
	 * scan refuses when on still publishes when off.
	 */
	#[DataProvider('extractedRejectMatrix')]
	public function test_scan_stays_inert_while_the_flag_is_off(
		string $kind,
		string $payload_name,
		string $verdict
	): void {
		$payload = self::payload($payload_name);
		$this->assertSame($verdict, pfb_text_sanity($payload),
			'row premise: the payload still earns a verdict — only the gate is off');

		$base = $this->seedPublication();
		$result = $this->downloadArchive($kind, $payload, $base, PfbToggle::Off);

		$this->assertTrue($result->success, 'with the scan off the row must behave as it did before the scan existed');
		$this->assertSame($payload, file_get_contents("{$base}.orig"),
			'the off path must publish the extracted payload unchanged');
		$this->assertStringNotContainsString('stage=plaintext', $this->log(),
			'the scan must never log a verdict while it is off');
	}

	/** An earlier gate keeps its rejection; the sanity scan must not claim it. */
	#[DataProvider('preemptedRejectMatrix')]
	public function test_earlier_gate_keeps_its_own_reason(
		string $kind,
		string $payload_name,
		string $reason
	): void {
		$base = $this->seedPublication();
		$result = $this->downloadArchive($kind, self::payload($payload_name), $base, PfbToggle::On);

		$this->assertFalse($result->success, 'the row must still fail closed');
		$log = $this->log();
		$this->assertStringContainsString("reason={$reason}", $log, 'the earlier gate must name the rejection');
		$this->assertStringNotContainsString('stage=plaintext', $log,
			'the sanity scan must not pre-empt a gate that already refuses these bytes');
		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'the previously served payload must survive');
	}

	private static function payload(string $name): string
	{
		switch ($name) {
			case 'html':
				return self::HTML_ERROR;
			case 'nul':
				return self::NUL_BEARING;
			case 'empty':
				return '';
			case 'healthy':
				return self::HEALTHY;
		}
		throw new InvalidArgumentException("unknown payload fixture [{$name}]");
	}

	/** Put a healthy list in service so a refused refresh has something to preserve. */
	private function seedPublication(): string
	{
		$base = "{$this->dir}/feed";
		$this->assertNotFalse(file_put_contents("{$base}.orig", self::SERVED));
		return $base;
	}

	private function log(): string
	{
		return is_file($GLOBALS['pfb']['log']) ? (string) file_get_contents($GLOBALS['pfb']['log']) : '';
	}

	/**
	 * Build the archive with the same absolute binaries pfb_download() extracts with, so
	 * a host whose tar/bzip2 cannot round-trip the fixture fails loudly here instead of
	 * quietly not exercising the gate.
	 */
	private function archiveFixture(string $kind, string $payload): string
	{
		$member = "{$this->dir}/payload.txt";
		$this->assertNotFalse(file_put_contents($member, $payload));
		switch ($kind) {
			case 'gz':
				$path = "{$this->dir}/feed.gz";
				$this->assertNotFalse(file_put_contents($path, gzencode($payload)));
				return $path;
			case 'bz2':
				$path = "{$this->dir}/feed.bz2";
				exec('/usr/bin/bzip2 -zc ' . escapeshellarg($member) . ' > ' . escapeshellarg($path), $out, $rc);
				$this->assertSame(0, $rc, '/usr/bin/bzip2 could not build the fixture');
				return $path;
			case 'zip':
				$path = "{$this->dir}/feed.zip";
				$zip = new ZipArchive();
				$this->assertTrue($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE));
				$this->assertTrue($zip->addFromString('payload.txt', $payload));
				$this->assertTrue($zip->close());
				exec('/usr/bin/tar -tf ' . escapeshellarg($path) . ' >/dev/null 2>&1', $out, $rc);
				$this->assertSame(0, $rc, '/usr/bin/tar cannot read ZIP on this host; the appliance uses bsdtar');
				return $path;
			case 'tar':
				$path = "{$this->dir}/feed.tar";
				exec('/usr/bin/tar -cf ' . escapeshellarg($path) . ' -C ' . escapeshellarg($this->dir)
					. ' payload.txt', $out, $rc);
				$this->assertSame(0, $rc, '/usr/bin/tar could not build the fixture');
				return $path;
		}
		throw new InvalidArgumentException("unknown archive kind [{$kind}]");
	}

	/**
	 * The ZIP arm extracts through a `set -o pipefail` pipeline (issue #819) and PHP's
	 * exec() runs /bin/sh, so a /bin/sh without pipefail cannot exercise that arm at all:
	 * `set` is a special builtin, and Debian's dash -- the Linux CI runner's /bin/sh --
	 * exits on the option error before tar runs. Skip loudly rather than report a host
	 * property as a product defect; FreeBSD's sh has pipefail, so the appliance path is
	 * covered live by tests/smoke/test_smoke_feeds.py.
	 */
	private function requirePipefailShell(): void
	{
		$out = [];
		$rc = 1;
		// `set -e` is what makes the probe loud. Without it $rc is the ECHO's status, so a
		// shell that only WARNS on an unsupported option (bash 3.2) reports a capability it
		// does not have and the ZIP rows run with no pipefail, hiding the issue #819 class.
		exec('{ set -e; set -o pipefail; /bin/echo pfbpipefail; } 2>/dev/null', $out, $rc);
		if ($rc !== 0 || ($out[0] ?? '') !== 'pfbpipefail') {
			$this->markTestSkipped(
				"/bin/sh cannot 'set -o pipefail' (exit {$rc}); the ZIP arm's extraction pipeline "
				. 'never runs on this host'
			);
		}
	}

	private function downloadArchive(
		string $kind,
		string $payload,
		string $base,
		PfbToggle $flag,
		bool $et = FALSE
	): PfbDownloadResult
	{
		// Only the non-ET ZIP arm extracts through a `set -o pipefail` pipeline. The ET
		// arm is a plain `tar -xOf > stage` redirect, so requiring the capability there
		// would skip a row every POSIX /bin/sh can run (issue #2359's gate then reds).
		if ($kind === 'zip' && !$et) {
			$this->requirePipefailShell();
		}
		$source = $this->archiveFixture($kind, $payload);
		PfbConfig::write('gen/pfb_feed_sanity', $flag);
		$this->assertSame($flag, PfbConfig::read('gen/pfb_feed_sanity'), 'the scan flag must be set for this row');

		$router = "{$this->dir}/router.php";
		$routerSrc = <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '';
if ($uri === '/__pfb_ready' || str_starts_with($uri, '/__pfb_ready/')) {
	if ($uri === '/__pfb_ready') {
		echo getenv('READY_TOKEN');
	}
	return;
}
readfile(%s);
PHP;
		$this->assertNotFalse(file_put_contents($router, sprintf($routerSrc, var_export($source, TRUE))));
		$failures = [];
		$port = 0;
		for ($try = 0; $try < 10 && $port === 0; $try++) {
			$candidate = random_int(20000, 60000);
			$nonce = bin2hex(random_bytes(16));
			$stderr = "{$this->dir}/server-{$candidate}-{$try}.stderr";
			$proc = proc_open(
				['php', '-S', "127.0.0.1:{$candidate}", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->dir,
				[
					'READY_TOKEN' => $nonce,
					'PATH' => (string) getenv('PATH'),
				]
			);
			if (!is_resource($proc)) {
				$failures[] = "port {$candidate}: process=proc_open failed stderr=(unavailable)";
				continue;
			}
			for ($poll = 0; $poll < 40; $poll++) {
				if (pfb_test_http_fixture_event_received($candidate, $nonce)) {
					$this->server = $proc;
					$port = $candidate;
					break;
				}
				usleep(50000);
			}
			if ($port === 0) {
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
		}
		$this->assertGreaterThan(
			0,
			$port,
			'loopback HTTP fixture unavailable; ' . implode(' | ', $failures)
		);

		return pfb_download(new PfbDownloadRequest(
			listUrl: "http://127.0.0.1:{$port}/" . ($et ? 'iprepdata.txt' : 'feed'),
			downloadPath: $base,
			flex: FALSE,
			header: self::HEADER,
			format: '',
			logType: 1,
			timeout: 30,
			type: '',
		));
	}

	private function rejectingEtHelper(string $base, string $marker): string
	{
		$script = "{$this->dir}/reject-et";
		$body = "#!/bin/sh\ncat " . escapeshellarg("{$base}.orig.etstage")
			. ' > ' . escapeshellarg($marker) . "\nexit 1\n";
		$this->assertNotFalse(file_put_contents($script, $body));
		$this->assertTrue(chmod($script, 0700));
		return $script;
	}
}
