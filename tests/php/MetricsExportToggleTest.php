<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3522: the gen/pfb_metrics_export toggle, the save gate that refuses 'on' without the
 * node_exporter package, and the General page wiring around both.
 */
#[CoversFunction('pfb_metrics_export_allowed')]
final class MetricsExportToggleTest extends TestCase
{
	private const GENERAL_PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_general.php';
	private const PATH         = 'installedpackages/pfblockerng/config/0/pfb_metrics_export';
	private const PKG_LINK     = 'pkg_mgr_install.php?pkg=pfSense-pkg-node_exporter';
	private const PKG_ERROR    = 'Metrics export requires the node_exporter package.';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	public function testRegistryDefaultIsOff(): void
	{
		$this->assertSame('', pfb_cfg_registry()['gen/pfb_metrics_export']['default']);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_metrics_export'));
	}

	public function testRoundTripOn(): void
	{
		config_set_path(self::PATH, 'on');
		$this->assertSame('on', config_get_path(self::PATH), "before: pfb_metrics_export seed is 'on'");

		$enum = PfbConfig::read('gen/pfb_metrics_export');
		$this->assertSame(PfbToggle::On, $enum, "read: pfb_metrics_export 'on' -> PfbToggle::On");

		PfbConfig::write('gen/pfb_metrics_export', $enum);
		$this->assertSame('on', config_get_path(self::PATH), "write(read('on'))=='on' for pfb_metrics_export");
	}

	public function testRoundTripOff(): void
	{
		config_set_path(self::PATH, '');
		$this->assertSame('', config_get_path(self::PATH), "before: pfb_metrics_export seed is ''");

		$enum = PfbConfig::read('gen/pfb_metrics_export');
		$this->assertSame(PfbToggle::Off, $enum, "read: pfb_metrics_export '' -> PfbToggle::Off");

		PfbConfig::write('gen/pfb_metrics_export', $enum);
		$this->assertSame('', config_get_path(self::PATH), "write(read(''))=='' for pfb_metrics_export");
	}

	public function testSaveOnWithoutNodeExporterIsRefusedWithTheExactError(): void
	{
		$this->assertSame(self::PKG_ERROR, pfb_metrics_export_allowed('on', FALSE));
	}

	public function testSaveOnWithNodeExporterAndSaveOffAreAccepted(): void
	{
		$this->assertNull(pfb_metrics_export_allowed('on', TRUE));
		$this->assertNull(pfb_metrics_export_allowed('', FALSE));
	}

	public function testSaveBindingSitsInsideTheSaveWindow(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$start  = "if (isset(\$_POST['save'])) {";
		$end    = 'PfbConfig::writeSection(';
		$from   = strpos($source, $start);
		$to     = $from === FALSE ? FALSE : strpos($source, $end, $from + strlen($start));

		$this->assertNotFalse($from, 'general page save branch must remain present');
		$this->assertNotFalse($to, 'general page save must persist through the config gateway');
		$window = substr($source, $from, $to - $from);
		$needle = "\$pfb['gconfig']['pfb_metrics_export'] = pfb_filter(\$_POST['pfb_metrics_export'] ?? '', PFB_FILTER_ON_OFF, 'general') ?: '';";
		$this->assertSame(1, substr_count($window, $needle), 'save branch must bind the toggle exactly once');
	}

	public function testPageRefusesOnBeforeTheSaveBranchRuns(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$gate   = strpos($source, 'pfb_metrics_export_allowed(');
		$branch = strpos($source, 'if (!$input_errors)');

		$this->assertNotFalse($gate, 'general page must call pfb_metrics_export_allowed()');
		$this->assertNotFalse($branch, 'general page must keep its input_errors save guard');
		$this->assertLessThan($branch, $gate, 'the node_exporter gate must run before the save guard');
	}

	public function testPageLinksTheNodeExporterInstaller(): void
	{
		$this->assertStringContainsString(self::PKG_LINK, (string) file_get_contents(self::GENERAL_PAGE));
	}
}
