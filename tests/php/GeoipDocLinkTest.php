<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1215 — the GeoIP continent page's NOTES section links out to MaxMind's
 * "What's new in GeoIP2" document. MaxMind retired the `/geoip/geoip2/...` path
 * in a site restructure, so the shipped link 404'd. This is a source tripwire:
 * the page must carry the live document path and must not reintroduce the
 * retired one (external liveness itself cannot be asserted in CI — the check is
 * that the retired path stays gone).
 */
final class GeoipDocLinkTest extends TestCase
{
	private const PFBLOCKERNG_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng.php';

	private const LIVE_DOC_URL    = 'https://dev.maxmind.com/geoip/whats-new-in-geoip2/';
	private const RETIRED_DOC_URL = 'https://dev.maxmind.com/geoip/geoip2/whats-new-in-geoip2/';

	private function pageSource(): string
	{
		$source = file_get_contents(self::PFBLOCKERNG_PHP);
		$this->assertNotFalse($source, 'failed to read pfblockerng.php');
		return $source;
	}

	public function testGeoipNotesLinkUsesTheLiveMaxmindDocPath(): void
	{
		$this->assertStringContainsString(
			'href="' . self::LIVE_DOC_URL . '"',
			$this->pageSource(),
			"issue #1215: the \"What's new in GeoIP2\" link must point at MaxMind's current doc path"
		);
	}

	public function testRetiredMaxmindDocPathIsGone(): void
	{
		$this->assertStringNotContainsString(
			self::RETIRED_DOC_URL,
			$this->pageSource(),
			'issue #1215: the retired /geoip/geoip2/ doc path 404s and must not come back'
		);
	}
}
