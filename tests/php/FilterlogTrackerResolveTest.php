<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_resolve_tracker() — testable seam for the filter.log tracker-resolution logic.
 *
 * The two "unresolved tracker" cases are the REGRESSION ANCHORS for #326: they pin
 * the DESIRED post-fix behaviour and intentionally FAIL (RED) against the current
 * code, which calls the reparse callable up to 5× per unresolved tracker and has no
 * negative cache. Step 2 adds the negative cache + single-parse-per-line fix to turn
 * them GREEN.
 *
 * The "sanity" cases (already-cached pfB rule, already-cached 'other' tracker) are
 * GREEN today and must remain GREEN after the fix.
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
			'id'    => [$tracker],
			'other' => [],
			'int'   => [],
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
	// Sanity cases — GREEN today, must stay GREEN after the fix
	// ---------------------------------------------------------------------------

	/**
	 * A pfB tracker already present in rule_list with the correct type resolves TRUE
	 * with zero reparse calls. Behaviour pinned: cache hit on the fast path.
	 */
	public function testKnownPfbTrackerResolvesWithoutReparse(): void
	{
		$reparseCount = 0;
		$reparse      = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};
		$noSleep = static function (int $s): void { /* no-op */ };

		$ruleList    = $this->ruleListWithPfb('1001', 'block');
		$maxRetries  = 0;

		// When: tracker is in rule_list and types match
		$result = pfb_resolve_tracker($ruleList, '1001', 'block', $maxRetries, $reparse, $noSleep);

		// Then: resolves TRUE, no reparse needed
		$this->assertTrue($result, 'Known pfB tracker with matching type must resolve TRUE');
		$this->assertSame(0, $reparseCount, 'No reparse should occur when tracker is already in rule_list');
	}

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
		$noSleep = static function (int $s): void { /* no-op */ };

		$ruleList   = $this->ruleListWithOther('9999');
		$maxRetries = 0;

		// When: tracker is in rule_list['other']
		$result = pfb_resolve_tracker($ruleList, '9999', 'block', $maxRetries, $reparse, $noSleep);

		// Then: resolves FALSE, no reparse needed
		$this->assertFalse($result, 'Known other tracker must resolve FALSE');
		$this->assertSame(0, $reparseCount, 'No reparse should occur for a cached other tracker');
	}

	// ---------------------------------------------------------------------------
	// Regression anchors — RED today, must be GREEN after Step 2 fixes #326
	// ---------------------------------------------------------------------------

	/**
	 * Scenario: unresolved tracker triggers at most ONE reparse per first encounter.
	 *
	 * Given  a rule_list with no entry for the tracker
	 * When   pfb_resolve_tracker() is called for that tracker
	 * Then   the reparse callable is invoked AT MOST ONCE (not 5×)
	 *
	 * RED today: the current code calls the reparse callable once per retry loop
	 * iteration (up to 5 times) before giving up. The fix should attempt a single
	 * reparse, cache the miss in rule_list['other'], and return FALSE immediately.
	 */
	public function testUnresolvedTrackerTriggersAtMostOneReparse(): void
	{
		$reparseCount = 0;
		// The reparse double always returns an empty rule_list (tracker stays unknown).
		$reparse = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};
		$noSleep = static function (int $s): void { /* no-op */ };

		$ruleList   = $this->emptyRuleList();
		$maxRetries = 0;

		$result = pfb_resolve_tracker($ruleList, '4242', 'block', $maxRetries, $reparse, $noSleep);

		$this->assertFalse($result, 'Unresolved tracker must return FALSE');

		// DESIRED post-fix behaviour: exactly 1 reparse (try once, then give up + cache miss).
		// RED today: the current implementation calls reparse 5 times before returning FALSE.
		$this->assertSame(1, $reparseCount, '#326 fix: an unresolved tracker must trigger at most ONE reparse per first encounter, not 5');
	}

	/**
	 * Scenario: repeated calls for the same unresolved tracker use the negative cache.
	 *
	 * Given  a rule_list that has already been returned from a previous resolve call
	 *        (so the tracker's miss was negative-cached in rule_list['other'])
	 * When   pfb_resolve_tracker() is called again for the same tracker
	 * Then   the reparse callable is NOT called (counter stays at the prior value)
	 *
	 * RED today: the current code has no negative cache, so the second call also
	 * triggers up to 5 reparses. The fix must write the unresolved tracker into
	 * rule_list['other'] on miss so subsequent calls short-circuit immediately.
	 */
	public function testRepeatedUnresolvedTrackerUsesNegativeCache(): void
	{
		$reparseCount = 0;
		$reparse      = function () use (&$reparseCount): array {
			$reparseCount++;
			return $this->emptyRuleList();
		};
		$noSleep = static function (int $s): void { /* no-op */ };

		$ruleList   = $this->emptyRuleList();
		$maxRetries = 0;

		// First call: populates the negative cache (1 reparse expected post-fix)
		pfb_resolve_tracker($ruleList, '5555', 'block', $maxRetries, $reparse, $noSleep);
		$afterFirst = $reparseCount;

		// Second call with the SAME $ruleList (which now carries the negative-cache entry)
		$result = pfb_resolve_tracker($ruleList, '5555', 'block', $maxRetries, $reparse, $noSleep);

		$this->assertFalse($result, 'Negatively-cached tracker must still resolve FALSE');

		// DESIRED post-fix behaviour: zero additional reparses on the second call.
		// RED today: the current code has no negative cache, so a second call also
		// hits the reparse loop.
		$this->assertSame($afterFirst, $reparseCount, '#326 fix: a negatively-cached tracker must not trigger any further reparse');
	}
}
