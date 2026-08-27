<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_managed_rule_tracker() (ADR-37) — the deterministic, IP-independent tracker for
 * pfBlockerNG MANAGED static firewall rules (the DoT/DoQ block rule). Unlike the GUI's
 * (int)microtime() tracker, it is derived from the rule's stable descr ALONE, so:
 *   - the SAME rule always yields the SAME id across re-syncs (no change-detection churn);
 *   - DIFFERENT rules get DIFFERENT ids;
 *   - it lives in the '176' namespace (a PAST epoch, so it can never collide with a future
 *     GUI microtime tracker) and stays < 2^32 so pf's uint32 ridentifier never overflows;
 *   - a same-sync char-sum collision probes DETERMINISTICALLY (re-derived from the descr's
 *     char-sum, not a global counter) to another id in the same namespace, registered in
 *     $pfb['trackerids'] so it never clashes with a feed tracker and stays re-sync-stable.
 *
 * Behaviour, not the firewall apply, is pinned here; the live rule load is ADR-37 smoke.
 */
#[CoversFunction('pfb_managed_rule_tracker')]
final class ManagedRuleTrackerTest extends TestCase
{
	private const UINT32_MAX = 4294967295;

	/** @var mixed Saved global $pfb, restored in tearDown so we don't pollute other tests. */
	private $savedPfb;

	/** Whether $GLOBALS['pfb'] existed before setUp — so tearDown can unset vs restore. */
	private bool $hadPfb = false;

	/** Each sync starts with a fresh tracker registry (pfblockerng.inc inits it per run). */
	protected function setUp(): void
	{
		global $pfb;
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->savedPfb = $pfb ?? null;
		$pfb = ['trackerids' => []];
	}

	protected function tearDown(): void
	{
		// Restore to its ORIGINAL shape: unset entirely if it was absent before setUp,
		// so we don't leak a (possibly null) $pfb global into later tests.
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->savedPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	public function testSameDescrAcrossSeparateSyncsYieldsSameTracker(): void
	{
		// Scenario: the rule is rebuilt on the next sync (fresh registry) — its id must
		// be identical, or change-detection would fire and churn a filter reload.
		global $pfb;

		// GIVEN a fresh registry, WHEN the tracker is minted for a descr,
		$first = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// WHEN the next sync starts fresh and mints the same descr,
		$pfb = ['trackerids' => []];
		$second = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// THEN the id is identical (deterministic, not time-based).
		$this->assertSame($first, $second);
	}

	public function testDifferentDescrsYieldDifferentTrackers(): void
	{
		// Scenario: one rule per interface — each must get its own id.
		$lan  = pfb_managed_rule_tracker('pfB_DoT_Block_lan');
		$opt1 = pfb_managed_rule_tracker('pfB_DoT_Block_opt1');
		$this->assertNotSame($lan, $opt1);
	}

	public function testTrackerIsNamespacedNumericAndWithinUint32(): void
	{
		// THEN: '176' namespace, 10-digit numeric int, and below pf's uint32 ceiling.
		$t = pfb_managed_rule_tracker('pfB_DoT_Block_lan');
		$s = (string) $t;
		$this->assertStringStartsWith('176', $s, 'managed-rule trackers live in the 176 namespace');
		$this->assertSame(10, strlen($s), 'a 10-digit tracker');
		$this->assertTrue(ctype_digit($s), 'numeric (is_numericint-compatible)');
		$this->assertLessThanOrEqual(self::UINT32_MAX, $t, 'must fit pf uint32 ridentifier');
	}

	public function testTrackerIsRegisteredSoFeedTrackersCannotReuseIt(): void
	{
		global $pfb;
		$t = pfb_managed_rule_tracker('pfB_DoT_Block_lan');
		$this->assertContains($t, $pfb['trackerids']);
	}

	public function testCharSumCollisionProbesDeterministicallyInNamespace(): void
	{
		// Scenario: a descr whose char-sum maps onto an already-registered id must NOT
		// return a duplicate — it probes to another id in the 176 namespace, and the
		// probe is DETERMINISTIC (same descr + same occupant set => same id every re-sync),
		// which is the whole point of a descr-derived tracker.
		global $pfb;

		// GIVEN the deterministic id for this descr is already taken (seed the registry),
		$pfb = ['trackerids' => []];
		$deterministic = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		$pfb = ['trackerids' => [$deterministic]];

		// WHEN the same descr is minted again,
		$fallback = pfb_managed_rule_tracker('pfB_DoT_Block_lan');

		// THEN it is distinct, still a 10-digit 176-namespace uint32 id, and registered.
		$this->assertNotSame($deterministic, $fallback);
		$this->assertStringStartsWith('176', (string) $fallback);
		$this->assertSame(10, strlen((string) $fallback));
		$this->assertLessThanOrEqual(self::UINT32_MAX, $fallback);
		$this->assertContains($fallback, $pfb['trackerids']);

		// AND the probe is re-sync-stable: the SAME descr against the SAME occupant set
		// yields the SAME fallback id — not an order-dependent sequential counter.
		$pfb = ['trackerids' => [$deterministic]];
		$this->assertSame($fallback, pfb_managed_rule_tracker('pfB_DoT_Block_lan'));
	}
}
