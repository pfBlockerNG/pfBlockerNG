<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * New wizard DNSBL groups seed the Default token (issue #3288: a fresh producer
 * stores 'default', not a copied concrete mechanism -- Default is LIVE inheritance
 * of the global mechanism, never a value baked in at creation time). IP groups stay
 * unchanged. Executes the same source region as ScheduleProducerCanonicalizationTest.
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

	public function testNewDnsblGroupSeedsDefaultLogging(): void
	{
		$add = $this->wizardGroupAdd('pfblockerngdnsbl');
		$this->assertArrayHasKey('logging', $add);
		$this->assertSame(
			'default',
			$add['logging'],
			"the wizard's default DNSBL group must seed Logging/Blocking Mode to 'default' (live inheritance of "
			. "the global mechanism), not a copied concrete mechanism (issue #3288; supersedes #3285's 'disabled_log' seed)"
		);
	}

	public function testNewIpv4GroupIsUnaffectedAndCarriesNoLoggingKey(): void
	{
		$add = $this->wizardGroupAdd('pfblockernglistsv4');
		$this->assertArrayNotHasKey('logging', $add, "the wizard's IPv4 group must never gain a logging key");
		$this->assertSame('enabled', $add['aliaslog'], "the wizard's IPv4 group aliaslog default must stay unchanged");
	}
}
