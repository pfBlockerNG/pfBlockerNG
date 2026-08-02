<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The injected finalizer test proves ordering without touching disk. The live
 * pfb_download() caller remains a static pin because its pipeline mutates
 * appliance feed files; php_strip_whitespace() keeps this boundary executable
 * code only, so comments/docblocks cannot be load-bearing.
 */
final class DownloadTrailingNewlineWiringTest extends TestCase
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

	public function testFinalizerRunsHashTranscodeAndNewlineInOrder(): void
	{
		$events = [];
		pfb_download_finalize_text(
			'feed.orig',
			'feed.orig',
			'feed.raw',
			static function (string $base, string $path) use (&$events): bool {
				$events[] = ['hash', $base, $path];
				return TRUE;
			},
			static function (string $path) use (&$events): bool {
				$events[] = ['transcode', $path];
				return TRUE;
			},
			static function (string $path) use (&$events): bool {
				$events[] = ['newline', $path];
				return TRUE;
			}
		);

		$this->assertSame(
			[
				['hash', 'feed.orig', 'feed.raw'],
				['transcode', 'feed.orig'],
				['newline', 'feed.orig'],
			],
			$events
		);
	}

	/**
	 * Pin the live caller's finalizer invocation after the download branch; the
	 * real appliance path is not executed here because it writes feed artifacts.
	 * Comments/docblocks cannot define this callsite boundary.
	 */
	public function testPfbDownloadCallsFinalizerOnOrigAndRawHashTarget(): void
	{
		$body = strpos(self::$source, 'function pfb_download(PfbDownloadRequest');
		$end = strpos(self::$source, 'function pfb_download_failure(', $body === FALSE ? 0 : $body);
		$this->assertNotFalse($body);
		$this->assertNotFalse($end);
		$scope = substr(self::$source, $body, $end - $body);
		$gate = strpos($scope, 'if (pfb_download_retval_success($retval)) {');
		$call = strpos($scope, 'pfb_download_finalize_text(', $gate === FALSE ? 0 : $gate);
		$this->assertNotFalse($gate);
		$this->assertNotFalse($call);
		$this->assertLessThan($call, $gate);
		$this->assertStringContainsString(
			'pfb_download_finalize_text( "{$orig_download}", "{$orig_download}", pfb_source_hash_target($file_download, $orig_download) );',
			substr($scope, $call, 300)
		);
	}
}
