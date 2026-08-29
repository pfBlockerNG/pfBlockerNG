<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_resolve_tracker() — testable seam for the filter.log tracker-resolution logic.
 *
 * Covers every branch of the helper:
 *   - Negative-cache hit ($miss_cache)        → FALSE, zero reparses
 *   - 'other' cache hit ($rule_list['other'])  → FALSE, zero reparses
 *   - Positive cache hit ($rule_list[$tracker])→ TRUE,  zero reparses
 *   - Unknown → reparse resolves as pfB        → TRUE,  exactly one reparse
 *   - Unknown → reparse resolves as 'other'    → FALSE, one reparse, NOT in miss_cache
 *   - Unknown → reparse still absent           → FALSE, one reparse, added to miss_cache
 *   - Type mismatch → reparse, resolved on fresh list → TRUE, one reparse
 *
 * The two regression anchors (#326 fix) prove the negative-cache behaviour:
 *   testUnresolvedTrackerTriggersAtMostOneReparse   (was RED, now GREEN)
 *   testRepeatedUnresolvedTrackerUsesNegativeCache  (was RED, now GREEN)
 *
 * All tests use a call-counting $reparse closure and assert the count before and
 * after so green proves the cache—not coincidence—caused the drop.
 */
#[CoversFunction('pfb_resolve_tracker')]
final class FilterlogTrackerResolveTest extends TestCase
{
	// ---------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------

	/**
	 * Build a rule_list containing a known pfB rule.
	 * @return array<string, mixed>
	 */
	private function ruleListWithPfb(string $tracker, string $type): array
	{
		return [
			'id'     => [$tracker],
			'other'  => [],
			'int'    => [],
			$tracker => ['name' => 'pfB_TestAlias', 'type' => $type],
		];
	}

	/**
	 * Build a rule_list that has $tracker in the 'other' bucket (known non-pfB).
	 * @return array<string, mixed>
	 */
	private function ruleListWithOther(string $tracker): array
	{
		return [
			'id'    => [],
			'other' => [$tracker => ''],
			'int'   => [],
		];
	}

	/**
	 * Build an empty rule_list (tracker unknown to pfB).
	 * @return array<string, mixed>
	 */
	private function emptyRuleList(): array
	{
		return ['id' => [], 'other' => [], 'int' => []];
	}

	// ---------------------------------------------------------------------------
	// Positive-cache hit: known pfB tracker, matching type
	// ---------------------------------------------------------------------------

	/**
	 * A pfB tracker already present in rule_list with the correct type resolves TRUE
	 * with zero reparse calls. Behaviour pinned: positive cache hit on the fast path.
	 */
	public function testKnownPfbTrackerResolvesWithoutReparse(): void
	{
		$reparseCount = 0;
		$reparse      = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};

		$ruleList   = $this->ruleListWithPfb('1001', 'block');
		$missCache  = [];

		// When: tracker is in rule_list and types match
		$result = pfb_resolve_tracker($ruleList, $missCache, '1001', 'block', $reparse);

		// Then: resolves TRUE, no reparse needed
		$this->assertTrue($result, 'Known pfB tracker with matching type must resolve TRUE');
		$this->assertSame(0, $reparseCount, 'No reparse should occur when tracker is already in rule_list');
	}

	// ---------------------------------------------------------------------------
	// 'other' cache hit: known non-pfB tracker in rule_list
	// ---------------------------------------------------------------------------

	/**
	 * A known 'other' (non-pfB) tracker cached in rule_list resolves FALSE immediately
	 * with zero reparse calls. Behaviour pinned: 'other' cache hit.
	 */
	public function testKnownOtherTrackerResolvesWithoutReparse(): void
	{
		$reparseCount = 0;
		$reparse      = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};

		$ruleList  = $this->ruleListWithOther('9999');
		$missCache = [];

		// When: tracker is in rule_list['other']
		$result = pfb_resolve_tracker($ruleList, $missCache, '9999', 'block', $reparse);

		// Then: resolves FALSE, no reparse needed
		$this->assertFalse($result, 'Known other tracker must resolve FALSE');
		$this->assertSame(0, $reparseCount, 'No reparse should occur for a cached other tracker');
	}

	// ---------------------------------------------------------------------------
	// Negative-cache hit: tracker already in miss_cache
	// ---------------------------------------------------------------------------

	/**
	 * A tracker already in the persistent miss_cache resolves FALSE immediately with
	 * zero reparse calls. Behaviour pinned: negative cache hit on the fast path.
	 */
	public function testNegativeCacheHitResolvesWithoutReparse(): void
	{
		$reparseCount = 0;
		$reparse      = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};

		$ruleList  = $this->emptyRuleList();
		$missCache = ["7777\0block" => TRUE];  // pre-loaded into the negative cache (tracker\0type key)

		// When: tracker is in miss_cache
		$result = pfb_resolve_tracker($ruleList, $missCache, '7777', 'block', $reparse);

		// Then: resolves FALSE without touching reparse
		$this->assertFalse($result, 'Negatively-cached tracker must resolve FALSE');
		$this->assertSame(0, $reparseCount, 'No reparse should occur for a miss_cache hit');
	}

	// ---------------------------------------------------------------------------
	// Regression anchor #1 — #326 fix: at most ONE reparse per first encounter
	// ---------------------------------------------------------------------------

	/**
	 * Scenario: unresolved tracker triggers at most ONE reparse on its first encounter.
	 *
	 * Given  a rule_list and miss_cache with no entry for the tracker
	 * When   pfb_resolve_tracker() is called for that tracker
	 * Then   the reparse callable is invoked EXACTLY ONCE (not 5×)
	 *        and the tracker is added to miss_cache
	 *
	 * This was RED against the old code (which reparsed up to 5×). GREEN proves the fix.
	 */
	public function testUnresolvedTrackerTriggersAtMostOneReparse(): void
	{
		$reparseCount = 0;
		// Reparse double always returns an empty rule_list (tracker stays unknown).
		$reparse = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};

		$ruleList  = $this->emptyRuleList();
		$missCache = [];

		// Before: no reparses yet, tracker absent from both caches
		$this->assertSame(0, $reparseCount, 'Precondition: zero reparses before call');
		$this->assertArrayNotHasKey("4242\0block", $missCache, 'Precondition: tracker not in miss_cache');

		$result = pfb_resolve_tracker($ruleList, $missCache, '4242', 'block', $reparse);

		// Then: FALSE with exactly one reparse, tracker now in miss_cache
		$this->assertFalse($result, 'Unresolved tracker must return FALSE');
		$this->assertSame(1, $reparseCount, '#326 fix: an unresolved tracker must trigger at most ONE reparse per first encounter, not 5');
		$this->assertArrayHasKey("4242\0block", $missCache, 'Unresolved tracker must be added to miss_cache after one reparse');
	}

	// ---------------------------------------------------------------------------
	// Regression anchor #2 — #326 fix: negative cache prevents further reparses
	// ---------------------------------------------------------------------------

	/**
	 * Scenario: repeated calls for the same unresolved tracker use the persistent negative cache.
	 *
	 * Given  a first call has already negative-cached the tracker in miss_cache
	 * When   pfb_resolve_tracker() is called again for the same tracker
	 * Then   the reparse callable is NOT called (count stays at 1)
	 *
	 * Also proves the cache survives a reparse for a DIFFERENT tracker: even after
	 * $rule_list is rebuilt for tracker '6666', the miss_cache entry for '5555' remains,
	 * so a third call for '5555' still triggers zero reparses. This is the critical
	 * correctness property: the negative cache must be separate from $rule_list.
	 *
	 * This was RED against the old code (no negative cache, every call reparsed). GREEN proves the fix.
	 */
	public function testRepeatedUnresolvedTrackerUsesNegativeCache(): void
	{
		$reparseCount = 0;
		$reparse      = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};

		$ruleList  = $this->emptyRuleList();
		$missCache = [];

		// Given: first call for '5555' — populates the negative cache (1 reparse expected)
		$first = pfb_resolve_tracker($ruleList, $missCache, '5555', 'block', $reparse);
		$afterFirst = $reparseCount;

		$this->assertFalse($first, 'First call for unresolved tracker must return FALSE');
		$this->assertSame(1, $afterFirst, 'First call must trigger exactly one reparse');
		$this->assertArrayHasKey("5555\0block", $missCache, 'First call must add tracker to miss_cache');

		// When: second call for the SAME tracker — miss_cache already has the entry
		$second = pfb_resolve_tracker($ruleList, $missCache, '5555', 'block', $reparse);

		// Then: FALSE, zero additional reparses
		$this->assertFalse($second, 'Negatively-cached tracker must still resolve FALSE');
		$this->assertSame($afterFirst, $reparseCount, '#326 fix: a negatively-cached tracker must not trigger any further reparse');

		// Prove the cache survives a reparse for a DIFFERENT tracker ('6666'):
		// $rule_list is rebuilt by this call, but miss_cache['5555'] must survive.
		pfb_resolve_tracker($ruleList, $missCache, '6666', 'block', $reparse);
		$afterOtherTracker = $reparseCount;

		$this->assertSame($afterFirst + 1, $afterOtherTracker, 'A different unresolved tracker triggers one more reparse');
		$this->assertArrayHasKey("5555\0block", $missCache, 'miss_cache entry for 5555 must survive a reparse triggered by a different tracker');
		$this->assertArrayHasKey("6666\0block", $missCache, 'New unresolved tracker 6666 must also be added to miss_cache');

		// And now '5555' is still negative-cached even though $rule_list was just rebuilt
		$third = pfb_resolve_tracker($ruleList, $missCache, '5555', 'block', $reparse);
		$this->assertFalse($third, '5555 must still resolve FALSE after rule_list rebuild for 6666');
		$this->assertSame($afterOtherTracker, $reparseCount, '5555 must not trigger a reparse after rule_list rebuild — cache is separate from rule_list');
	}

	// ---------------------------------------------------------------------------
	// Unknown → reparse resolves as pfB (newly added rule)
	// ---------------------------------------------------------------------------

	/**
	 * An unknown tracker that the reparse resolves as a pfB rule of the matching type
	 * returns TRUE after exactly one reparse and is NOT added to miss_cache.
	 * Behaviour pinned: newly added/changed pfB rule discovered on first reparse.
	 */
	public function testUnknownTrackerResolvedByReparseAsPfb(): void
	{
		$reparseCount = 0;
		// Reparse returns a rule_list that now includes the tracker.
		$reparse = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->ruleListWithPfb('3333', 'block');
		};

		$ruleList  = $this->emptyRuleList();
		$missCache = [];

		// Before: tracker absent from both lists
		$this->assertSame(0, $reparseCount, 'Precondition: zero reparses before call');

		$result = pfb_resolve_tracker($ruleList, $missCache, '3333', 'block', $reparse);

		// Then: TRUE after exactly one reparse; NOT negative-cached (it resolved positively)
		$this->assertTrue($result, 'Tracker resolved by reparse as pfB must return TRUE');
		$this->assertSame(1, $reparseCount, 'Exactly one reparse must occur when the tracker is found on the fresh rule_list');
		$this->assertArrayNotHasKey('3333', $missCache, 'A positively-resolved tracker must NOT be added to miss_cache');
	}

	// ---------------------------------------------------------------------------
	// Unknown → reparse resolves as 'other'
	// ---------------------------------------------------------------------------

	/**
	 * An unknown tracker that the reparse places in rule_list['other'] returns FALSE
	 * after one reparse and is NOT added to miss_cache (it is in rule_list['other']).
	 * Behaviour pinned: the 'other' path after a reparse.
	 */
	public function testUnknownTrackerResolvedByReparseAsOther(): void
	{
		$reparseCount = 0;
		$reparse      = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->ruleListWithOther('8888');
		};

		$ruleList  = $this->emptyRuleList();
		$missCache = [];

		$this->assertSame(0, $reparseCount, 'Precondition: zero reparses before call');

		$result = pfb_resolve_tracker($ruleList, $missCache, '8888', 'block', $reparse);

		// Then: FALSE after one reparse; in rule_list['other'], NOT in miss_cache
		$this->assertFalse($result, 'Tracker resolved as other by reparse must return FALSE');
		$this->assertSame(1, $reparseCount, 'Exactly one reparse must occur');
		$this->assertArrayNotHasKey('8888', $missCache, 'Tracker in rule_list["other"] must NOT be added to miss_cache');
		$this->assertArrayHasKey('8888', $ruleList['other'], 'Tracker must be in rule_list["other"] after reparse');
	}

	// ---------------------------------------------------------------------------
	// Type mismatch → reparse resolves with fresh correct type
	// ---------------------------------------------------------------------------

	/**
	 * A tracker present in rule_list but with a different type triggers exactly one
	 * reparse. If the fresh rule_list has the tracker with the correct type, returns TRUE.
	 * Behaviour pinned: changed rule type discovered on reparse.
	 */
	public function testTypeMismatchTriggersOneReparseAndResolvesOnFreshList(): void
	{
		$reparseCount = 0;
		// Reparse returns the tracker with the correct type ('block').
		$reparse = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->ruleListWithPfb('2222', 'block');
		};

		// Initial rule_list has the tracker but with the WRONG type ('permit').
		$ruleList  = $this->ruleListWithPfb('2222', 'permit');
		$missCache = [];

		// Before: type mismatch exists; no reparses yet
		$this->assertSame('permit', $ruleList['2222']['type'], 'Precondition: type in rule_list is permit, not block');
		$this->assertSame(0, $reparseCount, 'Precondition: zero reparses before call');

		$result = pfb_resolve_tracker($ruleList, $missCache, '2222', 'block', $reparse);

		// Then: TRUE after exactly one reparse (type now matches on fresh list)
		$this->assertTrue($result, 'Type-matched tracker on fresh rule_list must return TRUE');
		$this->assertSame(1, $reparseCount, 'Type mismatch must trigger exactly one reparse');
		$this->assertSame('block', $ruleList['2222']['type'], 'rule_list must reflect the fresh parse result');
		$this->assertArrayNotHasKey('2222', $missCache, 'A positively-resolved tracker must NOT be in miss_cache');
	}

	// ---------------------------------------------------------------------------
	// Regression: a type mismatch must NOT poison the cache for the matching type
	// ---------------------------------------------------------------------------

	/**
	 * Scenario: a transient type mismatch must never suppress a later matching event.
	 *
	 * Given  a pfB tracker present in rule_list as type 'block'
	 * When   a log line arrives with a mismatched type 'match' (and the reparse does NOT
	 *        resolve that type), then a later line arrives with the correct type 'block'
	 * Then   the mismatched call is FALSE and caches only the (tracker,'match') key;
	 *        the matching call returns TRUE via the positive cache with ZERO reparses —
	 *        the negative cache did not poison the tracker.
	 *
	 * Guards the keyed-by-(tracker,type) + positive-first design: keying the miss cache
	 * by tracker alone would have suppressed the matching event for the daemon's life.
	 */
	public function testTypeMismatchDoesNotPoisonCacheForMatchingType(): void
	{
		$reparseCount = 0;
		// Reparse returns the tracker still only as type 'block' — the 'match' type stays unresolved.
		$reparse = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->ruleListWithPfb('1212', 'block');
		};

		$ruleList  = $this->ruleListWithPfb('1212', 'block');
		$missCache = [];

		// When: a mismatched-type ('match') line is resolved — unresolved, one reparse, cached by (tracker,type)
		$mismatch = pfb_resolve_tracker($ruleList, $missCache, '1212', 'match', $reparse);
		$this->assertFalse($mismatch, 'A type mismatch that the reparse cannot resolve must return FALSE');
		$this->assertSame(1, $reparseCount, 'The mismatched type triggers exactly one reparse');
		$this->assertArrayHasKey("1212\0match", $missCache, 'Only the mismatched (tracker,type) pair is negative-cached');
		$this->assertArrayNotHasKey("1212\0block", $missCache, 'The matching type must NOT be negative-cached');

		// Then: a later correctly-typed ('block') line resolves TRUE via the positive cache, no reparse
		$match = pfb_resolve_tracker($ruleList, $missCache, '1212', 'block', $reparse);
		$this->assertTrue($match, 'The matching type must still resolve TRUE — the cache was not poisoned');
		$this->assertSame(1, $reparseCount, 'The matching-type lookup must not trigger any further reparse (positive cache first)');
	}

	// ---------------------------------------------------------------------------
	// $on_reparse callback is invoked on a reparse
	// ---------------------------------------------------------------------------

	/**
	 * When $on_reparse is provided and a reparse occurs, the callback is invoked once.
	 * Behaviour pinned: daemon-local refresh runs alongside rule_list rebuild.
	 */
	public function testOnReparseCallbackInvokedOnReparse(): void
	{
		$reparseCount   = 0;
		$callbackCount  = 0;
		$reparse        = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};
		$onReparse = function () use (&$callbackCount): void {
			$callbackCount++;
		};

		$ruleList  = $this->emptyRuleList();
		$missCache = [];

		// Before: no reparses, no callbacks
		$this->assertSame(0, $reparseCount, 'Precondition: zero reparses');
		$this->assertSame(0, $callbackCount, 'Precondition: zero callbacks');

		pfb_resolve_tracker($ruleList, $missCache, '1234', 'block', $reparse, $onReparse);

		// Then: reparse and callback each invoked exactly once
		$this->assertSame(1, $reparseCount, 'Reparse must be called once for an unknown tracker');
		$this->assertSame(1, $callbackCount, 'on_reparse callback must be called once alongside the reparse');
	}

	// ---------------------------------------------------------------------------
	// $on_reparse callback is NOT invoked when tracker is already known
	// ---------------------------------------------------------------------------

	/**
	 * When the tracker hits the positive cache, $on_reparse is never invoked.
	 * Behaviour pinned: callback is reparse-only; no spurious side-effects on cache hits.
	 */
	public function testOnReparseCallbackNotInvokedOnCacheHit(): void
	{
		$reparseCount  = 0;
		$callbackCount = 0;
		$reparse       = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};
		$onReparse = function () use (&$callbackCount): void {
			$callbackCount++;
		};

		$ruleList  = $this->ruleListWithPfb('5050', 'block');
		$missCache = [];

		pfb_resolve_tracker($ruleList, $missCache, '5050', 'block', $reparse, $onReparse);

		$this->assertSame(0, $reparseCount, 'No reparse on positive cache hit');
		$this->assertSame(0, $callbackCount, 'on_reparse callback must NOT fire on a positive cache hit');
	}
}
