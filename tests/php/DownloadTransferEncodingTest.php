<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #2634 — feed fetches offer no Accept-Encoding.
 *
 * The end-to-end proof is a live-VM smoke case, and the smoke workflow is dispatch-only,
 * so nothing PR-gating would notice the option coming back. The digest ADR-42 stores
 * covers the RAW fetched bytes and extraction dispatches on those same bytes' MIME type,
 * so a body libcurl decoded in flight is both the wrong digest and the wrong branch.
 */
final class DownloadTransferEncodingTest extends TestCase
{
	/**
	 *  GIVEN the curl defaults every feed fetch loads;
	 *   WHEN they are inspected;
	 *   THEN no transfer-encoding is requested, so libcurl performs no content decoding
	 *        and the body written to disk is the one the origin served.
	 */
	public function testCurlDefaultsRequestNoTransferEncoding(): void
	{
		global $pfb;

		$this->assertIsArray($pfb['curl_defaults'], 'pfb_global() must publish the curl defaults');
		$this->assertArrayNotHasKey(
			CURLOPT_ENCODING,
			$pfb['curl_defaults'],
			'requesting a transfer encoding lets an origin that labels an archive '
			. 'Content-Encoding: gzip have libcurl decode it in flight (issue #2634)'
		);
	}
}
