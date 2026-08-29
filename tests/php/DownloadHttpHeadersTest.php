<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-59 Phase 3 — pfb_download_http_headers().
 *
 * pfb_download() offered only HTTP Basic (CURLOPT_USERPWD) and query-param URLs; a
 * future header-authenticated provider (Cloudflare Radar, Phase 5) needs an
 * 'Authorization: Bearer <token>' header. CURLOPT_HTTPHEADER already carries the
 * ADR-42 conditional-GET 'If-None-Match' header and REPLACES the whole list on every
 * call, so a naive second curl_setopt(CURLOPT_HTTPHEADER, ...) for caller headers would
 * silently clobber the conditional-GET header (or vice-versa). This pins the merge:
 * both headers survive together, and pfb_download() itself has no off-appliance double
 * for its curl/exec surface (tests/php/README.md "Out of scope"), so the assembly is
 * extracted into this pure, directly-testable helper.
 */
#[CoversFunction('pfb_download_http_headers')]
final class DownloadHttpHeadersTest extends TestCase
{
	/**
	 * The pinning case from the phase brief: a conditional-GET header AND a
	 * caller-supplied Bearer token must BOTH survive the merge.
	 *
	 *  GIVEN a conditional-GET header (If-None-Match) and a caller-supplied
	 *        'Authorization: Bearer x' header;
	 *   WHEN pfb_download_http_headers() merges them;
	 *   THEN the assembled CURLOPT_HTTPHEADER list contains BOTH — neither is
	 *        clobbered by the other.
	 */
	public function testConditionalGetAndCallerHeaderBothSurviveTheMerge(): void
	{
		$merged = pfb_download_http_headers(
			array('Authorization: Bearer x'),
			'If-None-Match: "etag123"'
		);

		$this->assertContains(
			'If-None-Match: "etag123"',
			$merged,
			'the conditional-GET header must survive a merge with a caller header'
		);
		$this->assertContains(
			'Authorization: Bearer x',
			$merged,
			'the caller-supplied header must survive a merge with the conditional-GET header'
		);
		$this->assertCount(2, $merged, 'exactly the two headers, nothing dropped or duplicated');
	}

	/**
	 * Today's behaviour (no caller ever sets $extra_headers yet): a conditional-GET
	 * header alone produces the SAME single-element list pfb_download() built directly
	 * before this phase — byte-for-byte, so every existing conditional-GET probe is
	 * unaffected by the refactor.
	 *
	 *  GIVEN no caller-supplied headers and a conditional-GET header;
	 *   WHEN pfb_download_http_headers() merges them;
	 *   THEN the result is the single conditional-GET header, unchanged.
	 */
	public function testConditionalGetHeaderAloneIsUnchanged(): void
	{
		$merged = pfb_download_http_headers(array(), 'If-None-Match: "etag123"');

		$this->assertSame(
			array('If-None-Match: "etag123"'),
			$merged,
			'with no extra headers, the merge must reproduce the pre-Phase-3 single-element list exactly'
		);
	}

	/**
	 * A caller header with no conditional-GET in play (the Cloudflare Radar shape,
	 * Phase 5): the Bearer header rides alone.
	 *
	 *  GIVEN a caller-supplied header and NO conditional-GET header ('');
	 *   WHEN pfb_download_http_headers() merges them;
	 *   THEN the result is just the caller header.
	 */
	public function testCallerHeaderAloneWithNoConditionalGet(): void
	{
		$merged = pfb_download_http_headers(array('Authorization: Bearer x'), '');

		$this->assertSame(array('Authorization: Bearer x'), $merged);
	}

	/**
	 * Neither side supplies anything (every feed today, outside an in-flight
	 * change_detect probe with a stored ETag): the merge returns an empty list, so
	 * pfb_download() knows to skip curl_setopt(CURLOPT_HTTPHEADER, ...) entirely —
	 * matching the pre-Phase-3 code path exactly.
	 *
	 *  GIVEN no caller headers and no conditional-GET header;
	 *   WHEN pfb_download_http_headers() merges them;
	 *   THEN the result is an empty array.
	 */
	public function testBothEmptyProducesEmptyList(): void
	{
		$this->assertSame(array(), pfb_download_http_headers(array(), ''));
	}

	/**
	 * Defensive: a non-string or empty entry in $extra_headers is dropped rather than
	 * corrupting the CURLOPT_HTTPHEADER list (curl_setopt would choke on a non-string).
	 *
	 *  GIVEN $extra_headers containing a valid header, an empty string, and a non-string;
	 *   WHEN pfb_download_http_headers() merges them;
	 *   THEN only the valid header survives.
	 */
	public function testNonStringAndEmptyEntriesAreDropped(): void
	{
		$merged = pfb_download_http_headers(array('X-Ok: 1', '', 123, NULL), '');

		$this->assertSame(array('X-Ok: 1'), $merged);
	}
}
