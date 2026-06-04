<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Sanity check that the bootstrap loaded the real pfblockerng.inc and its
 * constants/functions are reachable. If this fails, every other test is moot.
 */
final class BootstrapSmokeTest extends TestCase
{
	public function testProductionFunctionsAreDefined(): void
	{
		foreach ([
			'pfb_filter',
			'pfbng_text_area_decode',
			'pfb_dnsbl_abp_extract_ip',
			'sanitize_ipaddr',
			'pfb_validate_domain_labels',
			'pfb_strtolower',
			'pfb_unbound_python_sources',
		] as $fn) {
			$this->assertTrue(function_exists($fn), "missing production function {$fn}()");
		}
	}

	public function testFilterConstantsAreDefined(): void
	{
		$this->assertSame(6, PFB_FILTER_DOMAIN);
		$this->assertSame(9, PFB_FILTER_IP);
		$this->assertSame(21, PFB_FILTER_ON_OFF);
	}
}
