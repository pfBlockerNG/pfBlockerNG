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
	public function testTheInstallRetiresPhpsIsoListBeforeItRebuildsTheGeoipTabs(): void
	{
		$install = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$retire = strpos($install, "pfb_geoip_retire_php_isos(\$pfb['ccdir'], \$pfb['dbdir']);");
		$this->assertIsInt($retire, "the install retires PHP's ISO list");
		$this->assertLessThan(strpos($install, 'Rebuilding GeoIP tabs'), $retire, 'before the GeoIP tabs are rebuilt from the ISO list');
	}
}
