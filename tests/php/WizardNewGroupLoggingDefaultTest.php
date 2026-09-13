<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * New wizard DNSBL groups use logged null blocking; IP groups stay unchanged.
 * Executes the same source region as ScheduleProducerCanonicalizationTest.
 */
final class WizardNewGroupLoggingDefaultTest extends TestCase
{
	private static function sourceRegion(string $path, string $after, string $start, string $end): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . $path);
		if ($source === FALSE) {
			throw new RuntimeException("test bootstrap: failed to read {$path}");
		}
		$after_offset = strpos($source, $after);
		$start_offset = $after_offset === FALSE ? FALSE : strpos($source, $start, $after_offset);
		$end_offset = $start_offset === FALSE ? FALSE : strpos($source, $end, $start_offset);
		if ($start_offset === FALSE || $end_offset === FALSE) {
			throw new RuntimeException("test bootstrap: producer region not found in {$path}");
		}
		return substr($source, $start_offset, $end_offset - $start_offset);
	}

	/** Runs the REAL per-alias $add-assembly region for one $key ('pfblockerngdnsbl' / 'pfblockernglistsv4'). */
	private function wizardGroupAdd(string $key): array
	{
		$add = [];
		$pfb_general_schedule = ['pfb_schedule_weekday' => '7', 'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0'];
		eval(self::sourceRegion(
			'/src/usr/local/www/wizards/pfblockerng_wizard.inc',
			'// Selected Alias/Groups to add to default installation',
			"\t\t\tif (strpos(\$key, 'dnsbl') !== FALSE)",
			"\n\t\t\t\$new_config[\$key]['config'][] = \$add;"
		));
		return $add;
	}

	public function testNewDnsblGroupSeedsDisabledLogLogging(): void
	{
		$add = $this->wizardGroupAdd('pfblockerngdnsbl');
		$this->assertArrayHasKey('logging', $add);
		$this->assertSame(
			'disabled_log',
			$add['logging'],
			"the wizard's default DNSBL group must seed Logging/Blocking Mode to 'disabled_log' (Null Blocking, "
			. 'logging), not the VIP webserver override (issue #3285)'
		);
	}

	public function testNewIpv4GroupIsUnaffectedAndCarriesNoLoggingKey(): void
	{
		$add = $this->wizardGroupAdd('pfblockernglistsv4');
		$this->assertArrayNotHasKey('logging', $add, "the wizard's IPv4 group must never gain a logging key");
		$this->assertSame('enabled', $add['aliaslog'], "the wizard's IPv4 group aliaslog default must stay unchanged");
	}
}
