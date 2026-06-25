<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_collect_foreign_trackers() (#482) — collect tracker IDs from non-pfBlockerNG
 * filter/rule rows so both tracker generators can exclude them and never mint an ID
 * that collides with a GUI or third-party rule, preventing stale rule edit/delete ops.
 *
 * These tests are INTENTIONALLY RED until Step 2 adds pfb_collect_foreign_trackers()
 * to pfblockerng.inc. They pin the contract that function must satisfy.
 */
#[CoversFunction('pfb_collect_foreign_trackers')]
final class ForeignTrackerCollectionTest extends TestCase
{
	/** @var array<string,mixed> Saved config, restored in tearDown. */
	private array $savedConfig = [];
	private bool $hadConfig    = false;

	protected function setUp(): void
	{
		$this->hadConfig    = array_key_exists('config', $GLOBALS);
		$this->savedConfig  = $GLOBALS['config'] ?? [];
		$GLOBALS['config']  = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	// -------------------------------------------------------------------------
	// Scenario: the function exists (red until Step 2 implements it)
	// -------------------------------------------------------------------------

	public function testFunctionExists(): void
	{
		// THEN pfb_collect_foreign_trackers() must be defined.
		// RED until Step 2 adds it.
		$this->assertTrue(
			function_exists('pfb_collect_foreign_trackers'),
			'pfb_collect_foreign_trackers() is not defined — Step 2 must add it to pfblockerng.inc'
		);
	}

	// -------------------------------------------------------------------------
	// Scenario: empty / absent filter/rule → returns empty array
	// -------------------------------------------------------------------------

	public function testEmptyConfigReturnsEmptyArray(): void
	{
		// GIVEN no filter/rule key in config at all,
		$GLOBALS['config'] = [];

		// WHEN collecting foreign trackers,
		$result = pfb_collect_foreign_trackers();

		// THEN the result is an empty array.
		$this->assertIsArray($result, 'Expected array, got: ' . gettype($result));
		$this->assertEmpty(
			$result,
			'Expected empty array for absent filter/rule, got: ' . json_encode($result)
		);
	}

	public function testEmptyRuleListReturnsEmptyArray(): void
	{
		// GIVEN an explicitly empty filter/rule array,
		$GLOBALS['config'] = ['filter' => ['rule' => []]];

		$result = pfb_collect_foreign_trackers();

		$this->assertIsArray($result, 'Expected array, got: ' . gettype($result));
		$this->assertEmpty(
			$result,
			'Expected empty array for empty filter/rule, got: ' . json_encode($result)
		);
	}

	// -------------------------------------------------------------------------
	// Scenario: foreign rules contribute their tracker IDs
	// -------------------------------------------------------------------------

	public function testForeignRuleTrackerIsIncluded(): void
	{
		// GIVEN a single foreign rule with tracker 9991234567,
		$GLOBALS['config'] = [
			'filter' => [
				'rule' => [
					['descr' => 'GUI LAN rule', 'tracker' => '9991234567'],
				],
			],
		];

		// WHEN collecting,
		$result = pfb_collect_foreign_trackers();

		// THEN 9991234567 (as int) is in the result.
		$this->assertContains(
			9991234567,
			$result,
			'Expected foreign tracker 9991234567 in result, got: ' . json_encode($result)
		);
	}

	public function testMultipleForeignRulesContributeAllTrackers(): void
	{
		// GIVEN two foreign rules,
		$GLOBALS['config'] = [
			'filter' => [
				'rule' => [
					['descr' => 'Rule A',  'tracker' => '1111111111'],
					['descr' => 'Rule B',  'tracker' => '2222222222'],
				],
			],
		];

		$result = pfb_collect_foreign_trackers();

		$this->assertContains(1111111111, $result,
			'Expected tracker 1111111111 in result, got: ' . json_encode($result));
		$this->assertContains(2222222222, $result,
			'Expected tracker 2222222222 in result, got: ' . json_encode($result));
	}

	// -------------------------------------------------------------------------
	// Scenario: pfBlockerNG-owned rows are EXCLUDED
	// -------------------------------------------------------------------------

	public function testPfbOwnedRowWithPfBUnderscorePrefixIsExcluded(): void
	{
		// GIVEN a pfB_-prefixed rule (owned by pfBlockerNG) and a foreign rule,
		$foreignTracker = 8881234567;
		$pfbTracker     = 1760000001;
		$GLOBALS['config'] = [
			'filter' => [
				'rule' => [
					['descr' => 'pfB_Deny_Inbound',       'tracker' => (string) $pfbTracker],
					['descr' => 'Third-party VPN rule',   'tracker' => (string) $foreignTracker],
				],
			],
		];

		$result = pfb_collect_foreign_trackers();

		// THEN the pfB_-owned tracker is absent,
		$this->assertNotContains(
			$pfbTracker,
			$result,
			'pfB_-prefixed row should be excluded; got: ' . json_encode($result)
		);
		// AND the foreign tracker is present.
		$this->assertContains(
			$foreignTracker,
			$result,
			'Foreign tracker should be included; got: ' . json_encode($result)
		);
	}

	public function testPfbOwnedRowWithLegacyDnsblMarkerIsExcluded(): void
	{
		// GIVEN a row whose descr contains 'pfB DNSBL' (the legacy NAT marker),
		$pfbTracker     = 1760000002;
		$foreignTracker = 7771234567;
		$GLOBALS['config'] = [
			'filter' => [
				'rule' => [
					['descr' => 'some pfB DNSBL rule',  'tracker' => (string) $pfbTracker],
					['descr' => 'GUI WAN out',           'tracker' => (string) $foreignTracker],
				],
			],
		];

		$result = pfb_collect_foreign_trackers();

		$this->assertNotContains(
			$pfbTracker,
			$result,
			'Legacy pfB DNSBL row should be excluded; got: ' . json_encode($result)
		);
		$this->assertContains(
			$foreignTracker,
			$result,
			'Foreign tracker should be included; got: ' . json_encode($result)
		);
	}

	// -------------------------------------------------------------------------
	// Scenario: rows with missing or empty tracker are skipped
	// -------------------------------------------------------------------------

	public function testRowWithMissingTrackerIsSkipped(): void
	{
		// GIVEN a rule row with no 'tracker' key,
		$GLOBALS['config'] = [
			'filter' => [
				'rule' => [
					['descr' => 'No tracker here'],
					['descr' => 'Has tracker', 'tracker' => '5551234567'],
				],
			],
		];

		$result = pfb_collect_foreign_trackers();

		// THEN only the row with a tracker contributes,
		$this->assertContains(5551234567, $result,
			'Row with tracker should be included; got: ' . json_encode($result));
		$this->assertCount(
			1,
			$result,
			'Only one row has a tracker; expected count 1, got: ' . json_encode($result)
		);
	}

	public function testRowWithEmptyTrackerIsSkipped(): void
	{
		// GIVEN a rule row with an empty 'tracker' string,
		$GLOBALS['config'] = [
			'filter' => [
				'rule' => [
					['descr' => 'Empty tracker', 'tracker' => ''],
					['descr' => 'Valid tracker',  'tracker' => '4441234567'],
				],
			],
		];

		$result = pfb_collect_foreign_trackers();

		$this->assertContains(4441234567, $result,
			'Row with valid tracker should be included; got: ' . json_encode($result));
		$this->assertCount(
			1,
			$result,
			'Only one row has a non-empty tracker; expected count 1, got: ' . json_encode($result)
		);
	}

	// -------------------------------------------------------------------------
	// Scenario: NAT rules (nat/rule) are NOT read — only filter/rule
	// -------------------------------------------------------------------------

	public function testNatRuleTrackersAreNotIncluded(): void
	{
		// GIVEN a nat/rule row with a tracker (NAT rules don't carry a meaningful
		// tracker in pfSense — but the point is we must never read nat/rule at all),
		$natOnlyTracker = 6661234567;
		$GLOBALS['config'] = [
			'nat'    => ['rule' => [['descr' => 'NAT redirect', 'tracker' => (string) $natOnlyTracker]]],
			'filter' => ['rule' => []],
		];

		$result = pfb_collect_foreign_trackers();

		// THEN the NAT tracker does NOT appear — only filter/rule is consulted.
		$this->assertNotContains(
			$natOnlyTracker,
			$result,
			'NAT rule trackers must not be included; got: ' . json_encode($result)
		);
		$this->assertEmpty(
			$result,
			'Expected empty result when only nat/rule has rows; got: ' . json_encode($result)
		);
	}

	// -------------------------------------------------------------------------
	// Scenario: trackers are cast to int
	// -------------------------------------------------------------------------

	public function testTrackerIsCastToInt(): void
	{
		// GIVEN a tracker stored as a string (as pfSense serialises it),
		$GLOBALS['config'] = [
			'filter' => [
				'rule' => [['descr' => 'GUI rule', 'tracker' => '3331234567']],
			],
		];

		$result = pfb_collect_foreign_trackers();

		// THEN the result contains an int, not a string.
		$this->assertContains(
			3331234567,
			$result,
			'Tracker must be cast to int; got: ' . json_encode($result)
		);
		foreach ($result as $id) {
			$this->assertIsInt($id,
				'Every returned tracker must be int; got ' . gettype($id) . ' in: ' . json_encode($result));
		}
	}
}
