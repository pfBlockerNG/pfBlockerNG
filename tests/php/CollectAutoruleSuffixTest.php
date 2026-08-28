<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_collect_autorule_suffix() — scans the firewall 'filter/rule' entries for an
 * already-deployed pfB_ rule and, when one exists, extracts its suffix so
 * sync_package_pfblockerng() can preserve it instead of silently re-applying the
 * currently configured suffix setting (issue #713).
 *
 * Two compounding defects in the original inline code made the "preserve
 * existing suffix" branch permanently unreachable:
 *   (a) $pfbfound was declared FALSE and never set TRUE anywhere in the loop,
 *       so the caller's "!$pfbfound" guard was always TRUE.
 *   (b) the suffix-collection guard was inverted — "!empty($pfb_suffix_match)"
 *       required the match to ALREADY be non-empty before it could be set, a
 *       chicken-and-egg deadlock that left $pfb_suffix_match permanently ''.
 *
 * This helper fixes both: 'found' is set TRUE exactly when a rule's descr
 * matches the pfBlockerNG auto-rule naming pattern, and the collection guard
 * is the correct "empty($suffix)" (collect the FIRST pre-existing suffix, then
 * stop overwriting it).
 */
#[CoversFunction('pfb_collect_autorule_suffix')]
final class CollectAutoruleSuffixTest extends TestCase
{
	/**
	 * A rule whose descr carries the pfBlockerNG auto-rule pattern
	 * ('pfB_<Type><suffix>') is both detected ('found' = TRUE) and yields its
	 * suffix — the exact case the pre-fix code could never produce.
	 */
	public function testExistingPfbRuleIsFoundAndItsSuffixExtracted(): void
	{
		$rules = [
			['descr' => 'user rule, not pfB'],
			['descr' => 'pfB_Deny auto rule'],
		];

		$result = pfb_collect_autorule_suffix($rules);

		$this->assertTrue(
			$result['found'],
			'a pre-existing pfB_ rule must be detected (found = TRUE) so the caller preserves its suffix'
		);
		$this->assertSame(
			' auto rule',
			$result['suffix'],
			"the suffix captured after 'pfB_<Type>' must be extracted verbatim"
		);
	}

	/**
	 * No pfB_-descr rule anywhere in the set -> nothing found, empty suffix.
	 * Paired with the case above so a green result there is proven to be a
	 * real branch and not an always-FALSE/empty path.
	 */
	public function testNoExistingPfbRuleReturnsNotFoundAndEmptySuffix(): void
	{
		$rules = [
			['descr' => 'user rule one'],
			['descr' => 'user rule two'],
		];

		$result = pfb_collect_autorule_suffix($rules);

		$this->assertFalse($result['found'], 'no pfB_ rule present must leave found = FALSE');
		$this->assertSame('', $result['suffix'], 'no pfB_ rule present must leave suffix empty');
	}

	/**
	 * Only the FIRST pre-existing suffix is collected — a later differently
	 * suffixed pfB_ rule must not overwrite it (the fixed 'empty($suffix)'
	 * guard stops collecting once a suffix is set).
	 */
	public function testOnlyFirstPreexistingSuffixIsCollected(): void
	{
		$rules = [
			['descr' => 'pfB_Deny auto rule'],
			['descr' => 'pfB_Permit AR'],
		];

		$result = pfb_collect_autorule_suffix($rules);

		$this->assertTrue($result['found']);
		$this->assertSame(
			' auto rule',
			$result['suffix'],
			'the FIRST matching suffix must win; a later differently-suffixed rule must not overwrite it'
		);
	}

	/**
	 * A rule missing the 'descr' key entirely must not error and must not be
	 * mistaken for a match.
	 */
	public function testRuleWithoutDescrKeyIsIgnored(): void
	{
		$rules = [
			['action' => 'pass'],
		];

		$result = pfb_collect_autorule_suffix($rules);

		$this->assertFalse($result['found']);
		$this->assertSame('', $result['suffix']);
	}
}
