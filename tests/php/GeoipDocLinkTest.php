<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #1215 — the generated GeoIP page renders the MaxMind notes link helper. */
final class GeoipDocLinkTest extends TestCase
{
	private const LIVE_DOC_URL    = 'https://dev.maxmind.com/geoip/whats-new-in-geoip2/';
	private const RETIRED_DOC_URL = 'https://dev.maxmind.com/geoip/geoip2/whats-new-in-geoip2/';

	public function testGeoipNotesLinkUsesTheLiveMaxmindDocPath(): void
	{
		$this->assertStringContainsString(
			'href="' . self::LIVE_DOC_URL . '"',
			pfb_geoip_doc_link(),
			"issue #1215: the \"What's new in GeoIP2\" link must point at MaxMind's current doc path"
		);
	}

	public function testRetiredMaxmindDocPathIsGone(): void
	{
		$this->assertStringNotContainsString(
			self::RETIRED_DOC_URL,
			pfb_geoip_doc_link(),
			'issue #1215: the retired /geoip/geoip2/ doc path 404s and must not come back'
		);
	}
}
