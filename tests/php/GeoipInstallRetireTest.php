<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #4261 -- the package install retires PHP's ISO list once the Core Updater publishes the country folder:
 * pfblockerng_install.inc runs as a script, so its call is pinned by source; pfb_geoip_retire_php_isos() itself is covered
 * by GeoipGoLayoutTest.
 */
final class GeoipInstallRetireTest extends TestCase
{
	public function testTheInstallRetiresPhpsIsoList(): void
	{
		$install = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$retire = strpos($install, "pfb_geoip_retire_php_isos(\$pfb['ccdir'], \$pfb['dbdir']);");
		$this->assertIsInt($retire, "the install retires PHP's ISO list");
		$this->assertLessThan(strpos($install, 'if (empty($pfb[\'maxmind_key\']))'), $retire, 'whether or not MaxMind is configured');
	}

	/** The ISO list's path is the layout's from the include on, and the apply's MaxMind check reads it. */
	public function testTheIsoListPathFollowsTheLayoutWhereverItIsRead(): void
	{
		$src = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/';
		$this->assertStringContainsString("\$pfb['geoip_isos']\t= pfb_geoip_isos_path(\$pfb['ccdir'], \$pfb['dbdir']);",
			(string) file_get_contents("{$src}pfblockerng.inc"));
		$apply = (string) file_get_contents("{$src}pfblockerng_apply.inc");
		$this->assertStringNotContainsString("{\$pfb['dbdir']}/geoip.txt", $apply);
	}
}
