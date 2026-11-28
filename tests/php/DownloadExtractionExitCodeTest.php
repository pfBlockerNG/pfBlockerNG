<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The pure exit-code decision of an archive extraction: only exit 0 is success.
 * The source pins on pfb_download()'s extraction branches went with pfb_download()
 * in the Go cutover (#3977).
 */
final class DownloadExtractionExitCodeTest extends TestCase
{
	public function testSuccessfulExtractionIsObservableOnlyForZeroExit(): void
	{
		$this->assertTrue(pfb_download_extraction_succeeded(0));
		$this->assertFalse(pfb_download_extraction_succeeded(1));
		$this->assertFalse(pfb_download_extraction_succeeded(127));
	}

	public function testFailureExitCannotReachSuccessPath(): void
	{
		foreach ([1, 2, 7, 127] as $exitCode) {
			$this->assertFalse(
				pfb_download_extraction_succeeded($exitCode),
				"extraction exit {$exitCode} must fail"
			);
		}
	}
}
