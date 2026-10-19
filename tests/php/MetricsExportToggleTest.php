<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * #3522: the gen/pfb_metrics_export toggle, the save gate that refuses turning 'on' without the
 * node_exporter package, and the rule for when the General page offers the checkbox.
 */
#[CoversFunction('pfb_metrics_export_allowed')]
#[CoversFunction('pfb_metrics_export_box_disabled')]
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
		$this->assertSame(self::PKG_ERROR, pfb_metrics_export_allowed('on', FALSE, FALSE));
	}

	public function testSaveOnWithNodeExporterAndSaveOffAreAccepted(): void
	{
		$this->assertNull(pfb_metrics_export_allowed('on', TRUE, FALSE));
		$this->assertNull(pfb_metrics_export_allowed('', FALSE, FALSE));
	}

	public function testAStoredOnStaysAcceptedWithoutNodeExporterSoUnrelatedSavesAndUntickingWork(): void
	{
		// The enabled box re-posts its 'on' with every General save; refusing it would block them all.
		$this->assertNull(pfb_metrics_export_allowed('on', FALSE, TRUE));
		$this->assertNull(pfb_metrics_export_allowed('', FALSE, TRUE), 'unticking must be accepted');
	}

	/** @return array<string,array{0:bool,1:bool,2:bool}> package present, stored on, box disabled */
	public static function boxProvider(): array
	{
		return [
			'package present, stored off' => [TRUE, FALSE, FALSE],
			'package present, stored on'  => [TRUE, TRUE, FALSE],
			'package absent, stored off'  => [FALSE, FALSE, TRUE],
			'package absent, stored on'   => [FALSE, TRUE, FALSE],
		];
	}

	#[DataProvider('boxProvider')]
	public function testTheBoxIsDisabledOnlyWithoutNodeExporterAndWithoutAStoredOn(bool $pkgPresent, bool $storedOn, bool $disabled): void
	{
		$this->assertSame($disabled, pfb_metrics_export_box_disabled($pkgPresent, $storedOn), 'a stored on keeps the box enabled so it can be unticked');
	}
}
