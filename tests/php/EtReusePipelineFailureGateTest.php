<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #2776 (CodeRabbit round 2): a reuse ET pass whose staged gunzip publish
 * fails must not read as completed. When a leftover .raw exists and
 * pfb_apply_gunzip_orig_pipeline() returns FALSE, the ET consumer never runs,
 * $et_status keeps its initial 0, and a gate reading only the exit status
 * reports success while the pfB_Match_ET_* publications stay stale. The gate
 * must escalate that staging failure exactly like a failed processet().
 *
 * The helper contract tests below are executable; the call-site pins scan the
 * comment-free #993 sync monolith the way EtReuseProcessetStatusTest does.
 */
final class EtReusePipelineFailureGateTest extends TestCase
{
	private static string $source;
	private static string $tmpdir;

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		if (self::$source === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng_apply.inc');
		}
		require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
		self::$tmpdir = sys_get_temp_dir() . '/pfb2776-pipeline-' . getmypid();
	}

	public static function tearDownAfterClass(): void
	{
		foreach (['.raw', '.orig'] as $suffix) {
			@unlink(self::$tmpdir . '/feed' . $suffix);
		}
		@rmdir(self::$tmpdir);
	}

	/** Each test starts with an empty fixture dir -- the corrupt-.raw test
	 * deliberately leaves its .raw behind, and a leaked fixture would turn the
	 * missing-.raw test into a corrupt-.raw run. */
	protected function tearDown(): void
	{
		foreach (['.raw', '.orig'] as $suffix) {
			@unlink(self::$tmpdir . '/feed' . $suffix);
		}
	}

	/**
	 * Comment-free scope of the reuse ET dispatch: from the iprepdata gate
	 * to the download arm that follows the reuse branch.
	 */
	private function reuseEtScope(): string
	{
		$et = strpos(self::$source, 'strpos($row[\'url\'], \'iprepdata.txt\') !== FALSE');
		$this->assertNotFalse($et, 'reuse ET dispatch anchor missing');
		$download = strpos(self::$source, 'pfb_download(new PfbDownloadRequest(', $et);
		$this->assertNotFalse($download, 'reuse scope end anchor missing');
		return substr(self::$source, $et, $download - $et);
	}

	/**
	 * A corrupt .raw must make the helper return FALSE WITHOUT invoking the
	 * consumer -- the exact window the staging-failure gate closes.
	 */
	public function testCorruptRawFailsPipelineWithoutRunningConsumer(): void
	{
		$this->makeTempFeedDir();
		file_put_contents(self::$tmpdir . '/feed.raw', "\x1f\x8bCORRUPT-NOT-GZIP");
		$consumed = FALSE;
		$ok = pfb_apply_gunzip_orig_pipeline(
			self::$tmpdir . '/feed.raw',
			self::$tmpdir . '/feed.orig',
			static function (string $orig) use (&$consumed): void {
				$consumed = TRUE;
			}
		);
		$this->assertFalse($ok, 'a corrupt .raw must fail the staged publish');
		$this->assertFalse($consumed, 'a failed staged publish must not run the ET consumer');
		$this->assertFileExists(self::$tmpdir . '/feed.raw', 'the failing .raw must survive for the operator');
	}

	/**
	 * The supported pure-reuse path: no .raw at all, the already-published
	 * .orig is consumed, and the helper's FALSE return must NOT be read as a
	 * failure -- this is why the call-site gate guards on raw existence.
	 */
	public function testMissingRawConsumesPublishedOrigAndReturnsFalse(): void
	{
		$this->makeTempFeedDir();
		file_put_contents(self::$tmpdir . '/feed.orig', "published\n");
		$consumed = FALSE;
		$ok = pfb_apply_gunzip_orig_pipeline(
			self::$tmpdir . '/feed.raw',
			self::$tmpdir . '/feed.orig',
			static function (string $orig) use (&$consumed): void {
				$consumed = TRUE;
			}
		);
		$this->assertFalse($ok, 'no publish happened, so the publish flag stays FALSE');
		$this->assertTrue($consumed, 'the pure-reuse path must consume the published .orig');
	}

	/**
	 * A good .raw publishes .orig and hands it to the consumer.
	 */
	public function testGoodRawPublishesAndRunsConsumer(): void
	{
		$this->makeTempFeedDir();
		file_put_contents(self::$tmpdir . '/feed.raw', gzencode("fresh content\n"));
		$seen = NULL;
		$ok = pfb_apply_gunzip_orig_pipeline(
			self::$tmpdir . '/feed.raw',
			self::$tmpdir . '/feed.orig',
			static function (string $orig) use (&$seen): void {
				$seen = $orig;
			}
		);
		$this->assertTrue($ok, 'a good .raw must publish');
		$this->assertSame(self::$tmpdir . '/feed.orig', $seen, 'the consumer must receive the published .orig');
		$this->assertStringContainsString('fresh content', (string) file_get_contents(self::$tmpdir . '/feed.orig'));
	}

	/**
	 * The reuse arm must record whether a leftover .raw existed BEFORE calling
	 * the pipeline, or the FALSE return of the supported pure-reuse path would
	 * fail every reuse pass.
	 */
	public function testReuseArmCapturesRawExistenceBeforePipeline(): void
	{
		$scope = self::reuseEtScope();
		$raw = strpos($scope, '$et_raw_exists = file_exists("{$file_dwn}.raw");');
		$pipeline = strpos($scope, 'pfb_apply_gunzip_orig_pipeline(');
		$this->assertNotFalse($raw, 'the reuse arm must capture leftover-.raw existence');
		$this->assertGreaterThan($raw, $pipeline, 'raw existence must be captured before the pipeline call');
	}

	/**
	 * A leftover .raw whose staged publish fails escalates exactly like a
	 * failed processet(): scoped failure log, $pfb_dl_failed, ADR-61 ledger --
	 * before the exit-status gate, which alone would read the skipped
	 * consumer's initial 0 as success.
	 */
	public function testFailedStagedPublishEscalatesBeforeExitStatusGate(): void
	{
		$scope = self::reuseEtScope();
		$staging = strpos($scope, 'if ($et_raw_exists && !$et_pipeline_ok) {');
		$this->assertNotFalse($staging, 'the staging-failure gate is missing');
		// Pin the whole staging block: log, $pfb_dl_failed, and ADR-61 ledger
		// must all sit between the staging gate and the exit-status gate -- a
		// dropped escalation line must fail here, not drift into the elseif.
		$elseif = strpos($scope, 'pfb_download_extraction_succeeded($et_status)', $staging);
		$this->assertGreaterThan($staging, $elseif, 'the exit-status gate must follow the staging gate');
		$block = substr($scope, $staging, $elseif - $staging);
		$this->assertStringContainsString('ET reuse staging failed', $block, 'staging failure must be logged');
		$this->assertStringContainsString('$pfb_dl_failed = TRUE;', $block, 'staging failure must keep the alias pass failed');
		$this->assertStringContainsString(
			'pfb_download_ledger_failure(\'ip\', $alias, $header, $pfb[\'dbdir\']);',
			$block,
			'staging failure must open the ADR-61 sync ledger entry'
		);
	}

	private static function makeTempFeedDir(): void
	{
		if (!is_dir(self::$tmpdir) && !@mkdir(self::$tmpdir, 0700, TRUE) && !is_dir(self::$tmpdir)) {
			throw new RuntimeException('test bootstrap: cannot create temp feed dir');
		}
	}
}
