<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3522: the gen/pfb_metrics_export toggle, the save gate that refuses 'on' without the
 * node_exporter package, and the General page wiring around both.
 */
#[CoversFunction('pfb_metrics_export_allowed')]
#[CoversFunction('pfb_metrics_export_value')]
final class MetricsExportToggleTest extends TestCase
{
	private const PATH      = 'installedpackages/pfblockerng/config/0/pfb_metrics_export';
	private const PKG_ERROR = 'Metrics export requires the node_exporter package.';

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

	public function testSaveWithoutNodeExporterKeepsTheStoredValue(): void
	{
		// The disabled checkbox is not posted, so the posted value is empty whatever is stored.
		$this->assertSame('on', pfb_metrics_export_value('', FALSE, 'on'), 'an unrelated save must not turn a stored on off');
		$this->assertSame('', pfb_metrics_export_value('', FALSE, ''));
	}

	public function testSaveWithNodeExporterStoresTheTickedBox(): void
	{
		$this->assertSame('on', pfb_metrics_export_value('on', TRUE, ''));
		$this->assertSame('', pfb_metrics_export_value('', TRUE, 'on'), 'unticking the box turns it off');
		$this->assertSame('', pfb_metrics_export_value(NULL, TRUE, 'on'));
	}
}
