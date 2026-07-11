<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Category-edit auto-sort golden oracle (ADR-63 Phase 1).
 *
 * Pins TODAY's row-reorder transform applied when 'sort' is absent/empty or
 * literally 'sort': split rows into enabled/disabled buckets keyed by their
 * 'header' field, ksort(SORT_NATURAL | SORT_FLAG_CASE) each bucket, then
 * concatenate enabled-first. A duplicate header within one bucket collapses
 * to the last row seen (array key overwrite) -- a pre-existing lossy quirk
 * this suite pins so a later change to it is a deliberate, visible diff.
 *
 * Like CategoryEditRowMoveTest, the page carries top-level execution and
 * cannot be require()d off-appliance: the sort block is eval-extracted
 * verbatim from the REAL source, anchored on its own leading comment, as a
 * pure array transform.
 */
final class CategoryEditAutoSortTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('pfb_category_oracle_auto_sort')) {
			if (!preg_match(
				'/\/\/ Sort row by Header\/Label field followed by Enabled\/Disabled State settings\n'
				. '(if \(!isset\(\$input_errors\).*?\$rowdata\[\$rowid\]\[\'row\'\] = \$final;\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: auto-sort block not found');
			}
			eval(
				'function pfb_category_oracle_auto_sort(array $rowdata, $rowid): array {'
				. $m[1]
				. '}'
				. ' return $rowdata[$rowid][\'row\']; }'
			);
		}
	}

	private function row(string $header, string $state): array
	{
		return ['format' => 'Auto', 'state' => $state, 'url' => '', 'header' => $header];
	}

	private function rowdata(array $rows, $sort): array
	{
		return [0 => ['row' => $rows, 'sort' => $sort]];
	}

	// --- Row 1: sort absent/empty -- auto-sorts (the empty(...) arm) -----------

	public function testEmptySortFieldTriggersAutoSort(): void
	{
		// Given: two enabled rows out of alphabetical header order, sort field empty.
		$rowdata = $this->rowdata([$this->row('Bravo', 'Enabled'), $this->row('Alpha', 'Enabled')], '');

		// When: the auto-sort block runs.
		$result = pfb_category_oracle_auto_sort($rowdata, 0);

		// Then: rows are re-ordered alphabetically by header -- proves the
		// empty(...) arm of the guard fires, not a no-op passthrough.
		$this->assertSame(
			['Alpha', 'Bravo'],
			array_column($result, 'header'),
			'an empty sort field must trigger auto-sort (alphabetical by header)'
		);
	}

	// --- Row 2: sort=='sort' -- auto-sorts identically (the equality arm) ------

	public function testSortEqualsSortTriggersAutoSort(): void
	{
		// Given: same out-of-order rows, sort explicitly set to 'sort'.
		$rowdata = $this->rowdata([$this->row('Bravo', 'Enabled'), $this->row('Alpha', 'Enabled')], 'sort');

		// When: the auto-sort block runs.
		$result = pfb_category_oracle_auto_sort($rowdata, 0);

		// Then: identical outcome to the empty-sort case -- pins the equality arm.
		$this->assertSame(
			['Alpha', 'Bravo'],
			array_column($result, 'header'),
			"sort=='sort' must trigger auto-sort identically to an empty sort field"
		);
	}

	// --- Row 3: sort=='no-sort' -- row order returned byte-unchanged -----------

	public function testNoSortSkipsAutoSortLeavingOrderUnchanged(): void
	{
		// Given: out-of-order rows, sort explicitly set to 'no-sort'.
		$original = [$this->row('Bravo', 'Enabled'), $this->row('Alpha', 'Enabled')];
		$rowdata = $this->rowdata($original, 'no-sort');

		// When: the auto-sort block runs.
		$result = pfb_category_oracle_auto_sort($rowdata, 0);

		// Then: the block is skipped entirely -- order (and every field) is unchanged.
		$this->assertSame($original, $result, "sort=='no-sort' must skip the auto-sort block, leaving row order byte-unchanged");
	}

	// --- Row 4: ordering semantics -- enabled-first, natural+case-insensitive ---

	public function testEnabledFirstThenNaturalCaseInsensitiveOrderWithinEachState(): void
	{
		// Given: a mixed set -- enabled/disabled, out-of-alphabetical, case-mixed,
		// and natural-numbered headers (Feed10 sorts after Feed2 under SORT_NATURAL).
		$rows = [
			$this->row('feed10', 'Enabled'),
			$this->row('Feed2', 'Enabled'),
			$this->row('zulu', 'Disabled'),
			$this->row('Alpha', 'Disabled'),
			$this->row('bravo', 'Enabled'),
		];
		$rowdata = $this->rowdata($rows, '');

		// When: the auto-sort block runs.
		$result = pfb_category_oracle_auto_sort($rowdata, 0);

		// Then: ALL enabled rows first (natural, case-insensitive: bravo, Feed2,
		// feed10), THEN all disabled rows (Alpha, zulu) -- expected order computed
		// by hand, not by re-implementing ksort here.
		$this->assertSame(
			['bravo', 'Feed2', 'feed10', 'Alpha', 'zulu'],
			array_column($result, 'header'),
			'enabled rows must sort naturally/case-insensitively first, then disabled rows the same way'
		);
	}

	// --- Row 5: duplicate header within one state -- last-wins collapse (lossy) -

	public function testDuplicateHeaderWithinSameStateCollapsesToLastWins(): void
	{
		// Given: two ENABLED rows sharing the header 'dup' -- distinguished by URL
		// so we can see which one survives.
		$first = $this->row('dup', 'Enabled');
		$first['url'] = 'first';
		$second = $this->row('dup', 'Enabled');
		$second['url'] = 'second';
		$rowdata = $this->rowdata([$first, $second], '');

		// When: the auto-sort block runs.
		$result = pfb_category_oracle_auto_sort($rowdata, 0);

		// Then: TODAY's lossy behaviour -- the row count shrinks to 1 and the
		// LAST row with that header wins (array-key overwrite in $new_enabled).
		// Pinned so a later "fix" of this collapse is a visible, deliberate diff.
		$this->assertCount(1, $result, 'a duplicate header within one state must collapse to a single row');
		$this->assertSame('second', $result[0]['url'], 'the LAST row with a duplicate header must win the collapse');
	}
}
