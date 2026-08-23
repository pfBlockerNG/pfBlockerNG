<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Behavioral helper pins remain pure; the outer pfb_download() callsites are
 * static because live decompression/rename paths write appliance files. The
 * php_strip_whitespace() source is comment-free, so prose/docblock edits
 * cannot make the failsafe or final gate disappear from a different scope.
 */
final class DownloadRetvalFailsafeTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		if (self::$source === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng.inc');
		}
	}

	public function testInitialExitStatusIsFailureSafe(): void
	{
		$this->assertSame(1, pfb_download_initial_retval());
	}

	public function testOnlyZeroExitStatusOpensSuccessGate(): void
	{
		$this->assertTrue(pfb_download_retval_success(0));
		$this->assertFalse(pfb_download_retval_success(1));
		$this->assertFalse(pfb_download_retval_success(7));
	}

	public function testNullCannotBeMistakenForSuccess(): void
	{
		$this->assertFalse(pfb_download_retval_success(NULL));
	}

	/**
	 * The live download pipeline must initialize $retval to failure before any
	 * archive branch can fall through; pin the executable callsite, not its
	 * issue comment, because an unassigned status can falsely report success.
	 */
	public function testPfbDownloadInitializesRetvalWithFailureSafeHelper(): void
	{
		$body = strpos(self::$source, 'function pfb_download(PfbDownloadRequest');
		$end = strpos(self::$source, 'function pfb_download_failure(', $body === FALSE ? 0 : $body);
		$this->assertNotFalse($body);
		$this->assertNotFalse($end);
		$scope = substr(self::$source, $body, $end - $body);
		$init = strpos($scope, '$retval = pfb_download_initial_retval();');
		$archive_switch = strpos($scope, 'switch($type)');
		$archive = strpos($scope, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$this->assertNotFalse($init);
		$this->assertNotFalse($archive_switch);
		$this->assertNotFalse($archive);
		$this->assertLessThan($archive_switch, $init);
		$this->assertLessThan($archive, $init);
	}

	/**
	 * The final live success branch must use the strict zero-only helper after
	 * all extraction/rename work; this code-only pin avoids a comment/docblock
	 * anchor and guards against reintroducing loose NULL == 0 success.
	 */
	public function testPfbDownloadUsesZeroOnlyFinalSuccessGate(): void
	{
		$body = strpos(self::$source, 'function pfb_download(PfbDownloadRequest');
		$end = strpos(self::$source, 'function pfb_download_failure(', $body === FALSE ? 0 : $body);
		$this->assertNotFalse($body);
		$this->assertNotFalse($end);
		$scope = substr(self::$source, $body, $end - $body);
		$gate = strpos($scope, 'if (pfb_download_retval_success($retval)) {');
		// issue #2169: the generic gzip branch stages its output before publishing.
		$extract = strpos($scope, 'exec(pfb_extract_cmd("/usr/bin/gunzip -c {$file_dwn_esc} > " . escapeshellarg($staged)), $output, $retval);');
		$this->assertNotFalse($gate);
		$this->assertNotFalse($extract);
		$this->assertLessThan($gate, $extract);
	}
}
