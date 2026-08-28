<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class AnchorRowRelocationWiringTest extends TestCase
{
	public function testDnsblLayoutUsesWhitelistSectionAndNoLegacyRows(): void
	{
		$layout = pfb_dnsbl_anchor_layout_render();

		$this->assertSame([], $layout['legacy_rows']);
		$this->assertSame('DNSBL_Whitelist_customlist', $layout['whitelist']);
	}

	public function testIpLayoutUsesSuppressionSectionAndNoLegacyRows(): void
	{
		$layout = pfb_ip_anchor_layout_render();

		$this->assertSame([], $layout['legacy_rows']);
		$this->assertSame('IPv4_Suppression_customlist', $layout['suppression']);
	}

	public function testLogLayoutRendersEndAnchorOutsideTheForm(): void
	{
		$layout = pfb_log_anchor_layout_render();

		$this->assertSame([], $layout['legacy_rows']);
		$this->assertSame('<div id="endofpage"></div>', $layout['endofpage']);
		$this->assertTrue($layout['outside_form']);
	}

	public function testUnknownPageCannotSilentlyProduceAnAnchor(): void
	{
		$this->expectException(InvalidArgumentException::class);
		pfb_page_anchor_layout('unknown');
	}
}
