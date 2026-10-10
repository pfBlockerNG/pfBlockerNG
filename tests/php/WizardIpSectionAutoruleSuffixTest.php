<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #3450 (N1): the setup wizard rebuilds the IP settings section from scratch. A section
 * missing `autorule_suffix` reads the registry default ('autorule') until the next upgrade
 * pass, which grandfathers the absent key to 'standard' and silently drops the suffix. The
 * wizard must therefore write the key, so what it installs is what every later pass keeps.
 */
final class WizardIpSectionAutoruleSuffixTest extends TestCase
{
	private const WIZARD  = '/src/usr/local/www/wizards/pfblockerng_wizard.inc';
	private const SECTION = 'installedpackages/pfblockerngipsettings/config/0';

	public function testWizardIpSectionKeepsTheFreshInstallSuffixThroughTheUpgradePass(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . self::WIZARD);
		$start  = $source === FALSE ? FALSE : strpos($source, "\t\$new_config['pfblockerngipsettings']['config'][0]['enable_dup']");
		$end    = $start === FALSE ? FALSE : strpos($source, "\n\n\t// foreign section", $start);
		if ($source === FALSE || $start === FALSE || $end === FALSE) {
			throw new RuntimeException('test bootstrap: wizard IP section region not found');
		}

		$saved_config = $GLOBALS['config'] ?? NULL;
		try {
			$GLOBALS['config'] = ['pfblockerng_wizard' => ['step2' => ['inbound_interface' => 'wan', 'outbound_interface' => 'lan']]];
			$new_config = [];
			eval(substr($source, $start, $end - $start));
			$section = $new_config['pfblockerngipsettings']['config'][0] ?? NULL;
			$this->assertIsArray($section, 'vacuity guard: the wizard region built the IP section');
			$this->assertSame('wan', $section['inbound_interface'], 'vacuity guard: the region ran against the seeded wizard step');

			$GLOBALS['config'] = [];
			config_set_path(self::SECTION, $section);
			$this->assertSame('autorule', PfbConfig::read('ip/autorule_suffix'), 'the wizard install reads the registry default');

			$pass = pfb_registry_pass([self::SECTION => $section])[self::SECTION] ?? $section;
			$this->assertSame('autorule', $pass['autorule_suffix'], 'the upgrade pass must not flip the wizard install to no suffix');
		} finally {
			$GLOBALS['config'] = $saved_config;
		}
	}
}
