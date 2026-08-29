<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * IP tab round-one layout: callout above the form, checkbox IP Configuration,
 * Interface second, ASN and MaxMind above IPv4 Suppression, Advanced Settings collapsed,
 * and delta-batch hidden in Replace mode.
 */
final class IpTabLayoutUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read IP page');
		}
		return $source;
	}

	public function testCalloutPrintsAboveTheForm(): void
	{
		$source = self::source();
		$callout = strpos($source, "print_callout('<strong>Setting changes are applied via CRON");
		$form = strpos($source, 'print ($form)');
		$this->assertNotFalse($callout, 'IP tab callout missing');
		$this->assertNotFalse($form, 'print ($form) missing');
		$this->assertLessThan($form, $callout, 'the CRON/Force-Update callout must render above the form');
	}

	public function testSectionOrderPutsInterfaceSecondAndSuppressionWithItsToggle(): void
	{
		$source = self::source();
		$positions = [];
		foreach ([
			'IP Configuration',
			'IP Interface/Rules Configuration',
			'ASN configuration',
			'MaxMind GeoIP configuration',
			'IPv4 Suppression',
			'IPv6 Suppression',
			'Advanced Settings',
		] as $title) {
			$pos = strpos($source, "new Form_Section('{$title}'");
			$this->assertNotFalse($pos, "Form_Section('{$title}') missing");
			$positions[$title] = $pos;
		}
		$order = array_keys($positions);
		$this->assertSame(
			[
				'IP Configuration',
				'IP Interface/Rules Configuration',
				'ASN configuration',
				'MaxMind GeoIP configuration',
				'IPv4 Suppression',
				'IPv6 Suppression',
				'Advanced Settings',
			],
			$order
		);
		foreach (array_keys($positions) as $i => $title) {
			if ($i === 0) {
				continue;
			}
			$prev = array_keys($positions)[$i - 1];
			$this->assertGreaterThan(
				$positions[$prev],
				$positions[$title],
				"'{$title}' must follow '{$prev}'"
			);
		}
	}

	public function testKillStatesLivesInIpConfigurationNotInterface(): void
	{
		$source = self::source();
		$kill = strpos($source, "new Form_Checkbox(\n\t'killstates'");
		$iface = strpos($source, "new Form_Section('IP Interface/Rules Configuration')");
		$adv = strpos($source, "new Form_Section('Advanced Settings'");
		$this->assertNotFalse($kill, 'Kill States checkbox missing');
		$this->assertNotFalse($iface);
		$this->assertNotFalse($adv);
		$this->assertLessThan($iface, $kill, 'Kill States must sit in IP Configuration, before Interface/Rules');
		$this->assertLessThan($adv, $kill, 'Kill States must not move into Advanced Settings');
	}

	public function testNonCheckboxControlsLiveInCollapsedAdvanced(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			"/new Form_Section\(\s*'Advanced Settings'\s*,\s*'ip_advanced'\s*,\s*COLLAPSIBLE\s*\|\s*SEC_CLOSED\s*\)/",
			$source
		);
		$adv = strpos($source, "new Form_Section('Advanced Settings'");
		foreach ([
			'pfb_agg_types' => 'Form_Select',
			'pfb_alias_delta_mode' => 'Form_Select',
			'pfb_alias_delta_batch' => 'Form_Input',
			'ip_placeholder' => 'Form_Input',
		] as $id => $widget) {
			$this->assertSame(
				1,
				preg_match("/new {$widget}\(\s*'{$id}'/", $source, $m, PREG_OFFSET_CAPTURE),
				"{$widget}('{$id}') missing"
			);
			$this->assertGreaterThan(
				$adv,
				$m[0][1],
				"{$id} widget must be added after the Advanced section opens"
			);
		}
	}

	public function testDeltaBatchIsDisabledWhenApplyModeIsReplace(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			"/function enable_delta_batch\(\)\s*\{.*?disableInput\('pfb_alias_delta_batch'/s",
			$source
		);
		$this->assertStringContainsString("$('#pfb_alias_delta_mode').val() == 'replace'", $source);
		$this->assertStringContainsString("enable_delta_batch();", $source);
	}
}
