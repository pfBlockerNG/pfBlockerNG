<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Reports/Alerts addwhitelistdom must persist a leading-dot wildcard even when
 * the exact apex is already listed. The old gate keyed only on $domain (no
 * dot), so Wildcard whitelist was a silent no-op for storage.googleapis.com
 * while the page still said the domain was removed from DNSBL.
 */
final class AlertsWhitelistNeedsWriteTest extends TestCase
{
	public function testEmptyListWritesExact(): void
	{
		$this->assertTrue(
			pfb_alerts_whitelist_needs_write([], 'storage.googleapis.com', FALSE),
			'an empty whitelist must accept an exact add'
		);
	}

	public function testEmptyListWritesWildcard(): void
	{
		$this->assertTrue(
			pfb_alerts_whitelist_needs_write([], 'storage.googleapis.com', TRUE),
			'an empty whitelist must accept a wildcard add'
		);
	}

	public function testExactApexDoesNotBlockWildcardWrite(): void
	{
		$data = ['storage.googleapis.com' => "storage.googleapis.com\r\n"];
		$this->assertTrue(
			pfb_alerts_whitelist_needs_write($data, 'storage.googleapis.com', TRUE),
			'Wildcard whitelist must still persist .apex when exact apex is already listed'
		);
	}

	public function testExactApexSkipsSecondExactWrite(): void
	{
		$data = ['storage.googleapis.com' => "storage.googleapis.com\r\n"];
		$this->assertFalse(
			pfb_alerts_whitelist_needs_write($data, 'storage.googleapis.com', FALSE),
			'a second exact add of the same apex is a no-op'
		);
	}

	public function testExistingWildcardSkipsExactAndWildcard(): void
	{
		$data = ['.storage.googleapis.com' => ".storage.googleapis.com\r\n"];
		$this->assertFalse(
			pfb_alerts_whitelist_needs_write($data, 'storage.googleapis.com', FALSE),
			'exact add is already covered by a leading-dot line'
		);
		$this->assertFalse(
			pfb_alerts_whitelist_needs_write($data, 'storage.googleapis.com', TRUE),
			'a second wildcard add of the same apex is a no-op'
		);
	}

	public function testBlankDomainNeverWrites(): void
	{
		$this->assertFalse(
			pfb_alerts_whitelist_needs_write([], '', TRUE),
			'a blank domain must not append'
		);
	}

	public function testAddwhitelistdomUsesNeedsWriteGate(): void
	{
		$src = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$start = strpos($src, "elseif (isset(\$_POST['addwhitelistdom'])");
		$end = strpos($src, "elseif (isset(\$_POST['entry_delete'])", $start === FALSE ? 0 : $start);
		$this->assertNotFalse($start, 'addwhitelistdom handler must exist');
		$this->assertNotFalse($end, 'entry_delete must follow addwhitelistdom');
		$region = substr($src, $start, $end - $start);
		$this->assertStringContainsString(
			'pfb_alerts_whitelist_needs_write($clists[\'dnsblwhitelist\'][\'data\'], $domain, $wildcard)',
			$region,
			'addwhitelistdom must consult the exact-vs-wildcard write gate, not isset($data[$domain]) alone'
		);
		$this->assertStringNotContainsString(
			'isset($clists[\'dnsblwhitelist\'][\'data\'][$domain])',
			$region,
			'the old exact-only isset skip must not remain in addwhitelistdom'
		);
	}
}
