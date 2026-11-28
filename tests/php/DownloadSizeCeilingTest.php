<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2658 — nothing bounded how much a feed could pull down or expand to.
 *
 * The shared cURL defaults still carry the fetched-body ceiling. The extraction
 * ceiling, the free-space precheck and the pfb_download() wiring that used them
 * were removed with the Go cutover (#3977).
 */
final class DownloadSizeCeilingTest extends TestCase
{
	/**
	 * Scenario: every feed fetch carries the body ceiling
	 *
	 * Given  the shared cURL options every PHP fetch loads
	 * When   they are read
	 * Then   the large-variant maximum file size is set to the configured
	 *        ceiling, so an over-large body is refused by libcurl itself.
	 */
	public function test_curl_defaults_carry_the_fetched_body_ceiling(): void
	{
		$defaults = $GLOBALS['pfb']['curl_defaults'] ?? [];
		$this->assertArrayHasKey(CURLOPT_MAXFILESIZE_LARGE, $defaults);
		$this->assertSame(PFB_DOWNLOAD_MAX_BYTES, $defaults[CURLOPT_MAXFILESIZE_LARGE]);
	}
}
