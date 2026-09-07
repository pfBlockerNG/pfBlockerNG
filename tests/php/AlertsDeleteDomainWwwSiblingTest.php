<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Exact whitelist add writes apex and www.apex. delete_domain must unset both.
 *
 * The lookup concatenated 'www' and $entry with no dot, so the sibling key
 * www.apex was never the key it unsets and stayed in dnsbl/whitelist.
 */
final class AlertsDeleteDomainWwwSiblingTest extends TestCase
{
	public function testDeleteDomainUnsetsDottedWwwSibling(): void
	{
		$src = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
		);
		$this->assertNotSame('', $src, 'comment-free Alerts source must be readable');

		$start = strpos($src, "case 'delete_domain':");
		$end = strpos($src, "case 'delete_domainwildcard':", $start === FALSE ? 0 : $start);
		$this->assertNotFalse($start, 'delete_domain case must exist');
		$this->assertNotFalse($end, 'delete_domainwildcard must follow delete_domain');
		$region = substr($src, $start, $end - $start);

		$this->assertStringContainsString(
			"isset(\$clists['dnsblwhitelist']['data']['www.' . \$entry])",
			$region,
			'delete_domain must look up the www.apex sibling that exact add writes'
		);
		$this->assertStringContainsString(
			"unset(\$clists['dnsblwhitelist']['data']['www.' . \$entry])",
			$region,
			'delete_domain must unset the www.apex sibling that exact add writes'
		);
		$this->assertStringNotContainsString(
			"['www' . \$entry]",
			$region,
			"delete_domain must not look up wwwapex; that is not the key exact add writes"
		);
	}
}
