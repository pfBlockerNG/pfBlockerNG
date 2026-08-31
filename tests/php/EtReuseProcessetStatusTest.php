<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #2776: the ET reuse pass must read processet()'s exit status.
 * The reuse arm lives in the #993 sync monolith (behavior runs above it), so
 * these pins scan the comment-free call site: the exec capture under
 * pfb_extract_cmd(), the post-pipeline gate, and the download-failure
 * escalation a silently aborted reuse pass used to skip.
 */
final class EtReuseProcessetStatusTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		if (self::$source === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng_apply.inc');
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
	 * The reuse consumer captures processet()'s exit status under the same
	 * pfb_extract_cmd() ceiling every pfb_download() extraction runs under
	 * (issue #2683's shape); a bare exec with no capture reads as completed.
	 */
	public function testReuseEtClosureCapturesExitStatusUnderExtractCeiling(): void
	{
		$this->assertStringContainsString(
			'exec(pfb_extract_cmd("{$pfb[\'script\']} et {$header_esc} x x x x x '
			. '{$pfb[\'etblock\']} {$pfb[\'etmatch\']} {$elog}"), $et_output, $et_status);',
			self::reuseEtScope(),
			'the reuse ET exec must capture its exit status under the extraction ceiling'
		);
	}

	/**
	 * A nonzero processet() status on the reuse path escalates the way the
	 * download arm does: a scoped failure log plus the ADR-61 sync ledger.
	 */
	public function testFailedReuseProcessetEscalatesLikeADownloadFailure(): void
	{
		$scope = self::reuseEtScope();
		$pipeline = strpos($scope, 'pfb_apply_gunzip_orig_pipeline(');
		$this->assertNotFalse($pipeline, 'reuse pipeline call missing');
		$gate = strpos($scope, 'if (!pfb_download_extraction_succeeded($et_status)) {');
		$this->assertGreaterThan(
			$pipeline,
			$gate,
			'the reuse pass must gate on the captured exit status after the ET consumer ran'
		);
		$this->assertStringContainsString('ET processet failed', $scope, 'failure must be logged');
		$this->assertStringContainsString('$pfb_dl_failed = TRUE;', $scope, 'failure must keep the alias pass failed');
		$this->assertStringContainsString(
			'pfb_download_ledger_failure(\'ip\', $alias, $header, $pfb[\'dbdir\']);',
			$scope,
			'failure must open the ADR-61 sync ledger entry'
		);
	}
}
