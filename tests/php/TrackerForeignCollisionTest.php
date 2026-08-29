<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Collision avoidance against $pfb['foreign_trackerids'] (#482).
 *
 * Both tracker generators (pfb_tracker / pfb_managed_rule_tracker) must refuse to
 * mint an ID that appears in $pfb['foreign_trackerids'] — the set seeded at registry
 * init from pfb_collect_foreign_trackers(). Without this guard a new pfBlockerNG rule
 * can silently collide with a GUI/third-party rule's tracker, causing pfSense to edit
 * or delete the wrong rule.
 *
 * These tests are INTENTIONALLY RED until Step 2 expands BOTH generators' collision
 * checks to also reject IDs in $pfb['foreign_trackerids']. The tests that exercise
 * pfb_managed_rule_tracker() will go red on the "foreign set avoidance" assertions;
 * the pfb_tracker() tests will go red too. The "before-state" determinism assertions
 * stay green (they pin existing behaviour), so any red is exclusively the missing guard.
 */
#[CoversFunction('pfb_managed_rule_tracker')]
#[CoversFunction('pfb_tracker')]
final class TrackerForeignCollisionTest extends TestCase
{
	/** @var mixed Saved $pfb, restored in tearDown. */
	private $savedPfb;
	private bool $hadPfb = false;

	/** @var array<string,mixed> Saved config. */
	private array $savedConfig = [];
	private bool $hadConfig    = false;

	protected function setUp(): void
	{
		global $pfb;
		$this->hadPfb  = array_key_exists('pfb', $GLOBALS);
		$this->savedPfb = $pfb ?? null;
		$pfb = [
			'trackerids'         => [],
			'foreign_trackerids' => [],
			'last_trackerid'     => 1700000009,
		];

		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['config'] = [];

		// Seed interface doubles used by pfb_tracker() tests.
		// get_real_interface: identity mapping.
		$GLOBALS['pfb_test_real_interface']    = [];
		// get_interface_ip: 'lan' -> '192.0.2.1' (TEST-NET, deterministic).
		$GLOBALS['pfb_test_interface_ip']      = ['lan' => '192.0.2.1'];
		// ip2long32: already handled by the double (it calls ip2long + unsigned-cast).
		// find_interface_subnet: 'lan' -> '24'.
		$GLOBALS['pfb_test_find_interface_subnet'] = ['lan' => '24'];
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->savedPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		unset(
			$GLOBALS['pfb_test_real_interface'],
			$GLOBALS['pfb_test_interface_ip'],
			$GLOBALS['pfb_test_find_interface_subnet']
		);
	}

	// =========================================================================
	// pfb_managed_rule_tracker() — foreign-set collision avoidance
	// =========================================================================

	/**
	 * Scenario: pfb_managed_rule_tracker() avoids IDs in foreign_trackerids.
	 *
	 * Background: the natural (deterministic) ID for a given descr is computed once
	 * with an empty foreign set, confirmed as the before-state, then seeded into
	 * foreign_trackerids and the function is called again. The returned ID must differ
	 * and must NOT be in the foreign set.
	 */
	public function testManagedRuleTrackerAvoidsIdInForeignSet(): void
	{
		global $pfb;

		// GIVEN a fresh registry (empty foreign set),
		$pfb = [
			'trackerids'         => [],
			'foreign_trackerids' => [],
			'last_trackerid'     => 1700000009,
		];

		// WHEN we derive the natural ID (before-state — existing behaviour, stays green),
		$naturalId = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// THEN it is in the 176 namespace (sanity: existing behaviour).
		$this->assertStringStartsWith(
			'176',
			(string) $naturalId,
			'Before-state: natural ID must be in the 176 namespace'
		);

		// WHEN we reset and seed that ID into foreign_trackerids,
		$pfb = [
			'trackerids'         => [],
			'foreign_trackerids' => [$naturalId],  // Step 2 seeds this key
			'last_trackerid'     => 1700000009,
		];
		$avoidedId = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// THEN the returned ID differs from the one in the foreign set
		// (RED until Step 2 expands the collision check to include foreign_trackerids).
		$this->assertNotSame(
			$naturalId,
			$avoidedId,
			sprintf(
				'pfb_managed_rule_tracker() must not return an ID in foreign_trackerids. ' .
				'Expected something other than %d, got %d. ' .
				'foreign_trackerids=%s',
				$naturalId,
				$avoidedId,
				json_encode($pfb['foreign_trackerids'] ?? [])
			)
		);

		// AND the fallback is not in the foreign set either.
		$this->assertNotContains(
			$avoidedId,
			$pfb['foreign_trackerids'] ?? [],
			'Returned ID must not be in foreign_trackerids; got: ' . (string) $avoidedId .
			', foreign_trackerids: ' . json_encode($pfb['foreign_trackerids'] ?? [])
		);

		// AND the fallback is still in the 176 namespace.
		$this->assertStringStartsWith(
			'176',
			(string) $avoidedId,
			'Fallback ID must still be in the 176 namespace; got: ' . (string) $avoidedId
		);
	}

	/**
	 * Scenario: determinism is preserved when the foreign set is empty.
	 *
	 * A same descr across two syncs (each with an empty foreign set) must yield the
	 * same ID. This is existing behaviour — the test stays green before and after Step 2.
	 */
	public function testManagedRuleTrackerDeterminismWithEmptyForeignSet(): void
	{
		global $pfb;

		// GIVEN a fresh sync with an empty foreign set,
		$pfb = ['trackerids' => [], 'foreign_trackerids' => [], 'last_trackerid' => 1700000009];
		$first = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// WHEN the next sync also starts with an empty foreign set,
		$pfb = ['trackerids' => [], 'foreign_trackerids' => [], 'last_trackerid' => 1700000009];
		$second = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// THEN the IDs are identical (determinism preserved).
		$this->assertSame(
			$first,
			$second,
			sprintf(
				'Same descr with empty foreign set must yield the same ID across syncs. ' .
				'First sync: %d, second sync: %d',
				$first,
				$second
			)
		);
	}

	/**
	 * Scenario: foreign_trackerids key absence is handled gracefully.
	 *
	 * When Step 2 is NOT yet applied, $pfb['foreign_trackerids'] may be absent.
	 * Existing code must not crash — this tests for a PHP notice / TypeError.
	 * After Step 2 the key is always seeded at registry init, so this is belt-and-
	 * suspenders; the test stays green before and after.
	 */
	public function testManagedRuleTrackerWithAbsentForeignSetDoesNotCrash(): void
	{
		global $pfb;
		$pfb = ['trackerids' => [], 'last_trackerid' => 1700000009];
		// 'foreign_trackerids' deliberately absent.

		// WHEN called with no foreign set in $pfb,
		$id = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// THEN it returns a valid 176-namespace int (no crash, no TypeError).
		$this->assertIsInt($id, 'Expected int return; got: ' . gettype($id));
		$this->assertStringStartsWith('176', (string) $id);
	}

	// =========================================================================
	// pfb_tracker() — foreign-set collision avoidance
	// =========================================================================

	/**
	 * Scenario: pfb_tracker() avoids IDs in foreign_trackerids.
	 *
	 * Uses a deterministic interface fixture so char-sum → natural ID is stable.
	 * We derive the natural ID with an empty foreign set (before-state), then seed it
	 * into foreign_trackerids and assert the next call produces a different ID.
	 */
	public function testPfbTrackerAvoidsIdInForeignSet(): void
	{
		global $pfb;

		// GIVEN a fresh registry with a known interface fixture (IPv4 path),
		// get_real_interface('lan') -> 'lan' (identity), get_interface_ip('lan') -> '192.0.2.1',
		// ip2long32('192.0.2.1') -> deterministic, find_interface_subnet('lan') -> '24'.
		$pfb = [
			'trackerids'         => [],
			'foreign_trackerids' => [],
			'last_trackerid'     => 1700000009,
		];

		// WHEN we derive the natural ID (before-state),
		$naturalId = pfb_tracker('pfB_Test_Alias', 'lan', 'Deny');

		// THEN it is in the 177 namespace (existing behaviour, stays green).
		$this->assertStringStartsWith(
			'177',
			(string) $naturalId,
			'Before-state: pfb_tracker() natural ID must be in the 177 namespace'
		);

		// WHEN we reset and seed that ID into foreign_trackerids,
		$pfb = [
			'trackerids'         => [],
			'foreign_trackerids' => [$naturalId],  // Step 2 seeds this key
			'last_trackerid'     => 1700000009,
		];
		$avoidedId = pfb_tracker('pfB_Test_Alias', 'lan', 'Deny');

		// THEN the returned ID differs from the one in the foreign set
		// (RED until Step 2 expands the collision check to include foreign_trackerids).
		$this->assertNotSame(
			$naturalId,
			$avoidedId,
			sprintf(
				'pfb_tracker() must not return an ID in foreign_trackerids. ' .
				'Expected something other than %d, got %d. ' .
				'foreign_trackerids=%s, trackerids=%s',
				$naturalId,
				$avoidedId,
				json_encode($pfb['foreign_trackerids'] ?? []),
				json_encode($pfb['trackerids'] ?? [])
			)
		);

		// AND the fallback is not in the foreign set.
		$this->assertNotContains(
			$avoidedId,
			$pfb['foreign_trackerids'] ?? [],
			'Returned ID must not be in foreign_trackerids; got: ' . (string) $avoidedId .
			', foreign_trackerids: ' . json_encode($pfb['foreign_trackerids'] ?? [])
		);
	}

	/**
	 * Scenario: pfb_tracker() still registers its chosen ID in trackerids.
	 *
	 * Whether or not a foreign-set skip occurred, the ID must be appended to
	 * $pfb['trackerids'] so future calls within the same sync cannot reuse it.
	 * This is existing behaviour for the non-collision path (stays green); after
	 * Step 2 it must hold for the foreign-collision-avoidance path too.
	 */
	public function testPfbTrackerRegistersIdInTrackerids(): void
	{
		global $pfb;

		$pfb = [
			'trackerids'         => [],
			'foreign_trackerids' => [],
			'last_trackerid'     => 1700000009,
		];

		$id = pfb_tracker('pfB_Test_Alias', 'lan', 'Deny');

		// pfb_tracker() stores trackerids as strings (the '177'.$padded concatenation).
		// assertContains with strict=false to match int vs string interchangeably.
		$this->assertContains(
			(string) $id,
			array_map('strval', $pfb['trackerids']),
			'pfb_tracker() must register its ID in $pfb[\'trackerids\']; got trackerids: ' .
			json_encode($pfb['trackerids'])
		);
	}
}
