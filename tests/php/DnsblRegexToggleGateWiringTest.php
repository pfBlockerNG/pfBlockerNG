<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsblRegexToggleGateWiringTest extends TestCase
{
	public function testUsableInterpreterAlwaysRunsValidation(): void
	{
		$this->assertTrue(pfb_dnsbl_regex_validation_required_page(TRUE, 'off'));
		$this->assertTrue(pfb_dnsbl_regex_validation_required_page(TRUE, 'on'));
		$this->assertTrue(pfb_dnsbl_regex_validation_required_page(TRUE, ''));
	}

	public function testUnusableInterpreterRunsValidationOnlyWhenRegexFeatureIsOn(): void
	{
		$this->assertTrue(pfb_dnsbl_regex_validation_required_page(FALSE, 'on'));
		$this->assertFalse(pfb_dnsbl_regex_validation_required_page(FALSE, 'off'));
		$this->assertFalse(pfb_dnsbl_regex_validation_required_page(FALSE, ''));
		$this->assertFalse(pfb_dnsbl_regex_validation_required_page(FALSE, ['on']));
	}
}
