<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4161 -- the dashboard widget's CrowdSec rows count the bouncer's rules and their packets through the widget's own
 * tracker matching (pfb_rule_alias_packets()), so pfb_crowdsec_widget_rules() gives those rules as filter/rule rows.
 *
 * Intent pinned here:
 *   - while the bouncer should run, one inbound and one outbound row per enabled family, each naming its table on the side
 *     the rule matches it and carrying the tracker the generated rule carries;
 *   - nothing while it should not run, so the widget shows no CrowdSec rows then;
 *   - fed to pfb_rule_alias_packets() with the loaded rules' counters, each table gets its rule count and packets.
 */
#[CoversFunction('pfb_crowdsec_widget_rules')]
final class CrowdsecWidgetRulesTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngcrowdsec/config/0';

	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb_test_mwexec'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		unset($GLOBALS['pfb_test_mwexec'], $GLOBALS['pfb_test_valid_pids']);
	}

	private static function store(array $over = []): void
	{
		config_set_path(self::SECTION, array_replace(['enable' => 'on', 'lapi_url' => 'https://lapi.example.net/', 'api_key' => 'k3y',
			'log_level' => 'info', 'rules_all_interfaces' => 'on', 'rules_interfaces' => '', 'rules_log' => '', 'rules_tag' => '',
			'rule_v4' => 'on', 'rule_v6' => 'on'], $over));
	}

	private static function row(string $descr, int $tracker, string $source, string $destination): array
	{
		return ['descr' => $descr, 'tracker' => $tracker, 'type' => 'block', 'source' => ['address' => $source],
			'destination' => ['address' => $destination]];
	}

	public function testWhileTheBouncerShouldRunEachEnabledFamilyGivesItsTwoRules(): void
	{
		self::store();
		$this->assertSame([
			self::row('CrowdSec IPv4', 177400401, 'crowdsec_v4', 'any'),
			self::row('CrowdSec IPv4 out', 177400402, 'any', 'crowdsec_v4'),
			self::row('CrowdSec IPv6', 177400601, 'crowdsec_v6', 'any'),
			self::row('CrowdSec IPv6 out', 177400602, 'any', 'crowdsec_v6'),
		], pfb_crowdsec_widget_rules());
	}

	public function testAFamilyTurnedOffGivesNoRules(): void
	{
		self::store(['rule_v6' => '']);
		$this->assertSame([
			self::row('CrowdSec IPv4', 177400401, 'crowdsec_v4', 'any'),
			self::row('CrowdSec IPv4 out', 177400402, 'any', 'crowdsec_v4'),
		], pfb_crowdsec_widget_rules());
	}

	public function testNothingWhileTheBouncerShouldNotRun(): void
	{
		self::store();
		$this->assertCount(4, pfb_crowdsec_widget_rules(), 'before: the bouncer should run');

		self::store(['enable' => '']);
		$this->assertSame([], pfb_crowdsec_widget_rules(), 'CrowdSec disabled');

		self::store(['api_key' => '']);
		$this->assertSame([], pfb_crowdsec_widget_rules(), 'no key stored on this node');

		self::store();
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->assertSame([], pfb_crowdsec_widget_rules(), 'pfBlockerNG disabled');
	}

	public function testEachRowCarriesTheTrackerOfTheRuleTheHookGenerates(): void
	{
		self::store();
		$generated = [];
		foreach (explode("\n", trim(pfb_crowdsec_rules('pfearly'))) as $line) {
			$this->assertSame(1, preg_match('/label "([^"]+)" ridentifier (\d+)/', $line, $m), $line);
			$generated[$m[1]] = (int) $m[2];
		}
		$this->assertSame($generated, array_column(pfb_crowdsec_widget_rules(), 'tracker', 'descr'));
	}

	public function testTheWidgetsTrackerMatchingCountsEachTablesRulesAndPackets(): void
	{
		self::store();
		$pf_rules = [
			['tracker' => 177400401, 'packets' => 12],
			['tracker' => 177400402, 'packets' => 3],
			['tracker' => 177400601, 'packets' => 0],
			['tracker' => 177400602, 'packets' => 5],
		];
		$this->assertSame([
			'crowdsec_v4' => ['rule' => 2, 'packets' => 15, 'type' => 'Block'],
			'crowdsec_v6' => ['rule' => 2, 'packets' => 5, 'type' => 'Block'],
		], pfb_rule_alias_packets(pfb_crowdsec_widget_rules(), $pf_rules));
	}
}
