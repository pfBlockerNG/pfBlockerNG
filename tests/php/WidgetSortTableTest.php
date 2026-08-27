<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Pin the widget dashboard table-sort rewrite: pfbsort() (a manual insertion
 * sort) -> uasort()/uksort() (issue #563 simplification), inside the
 * $sort_table closure defined in pfBlockerNG_update_table()
 * (src/usr/local/www/widgets/widgets/pfblockerng.widget.php).
 *
 * Both the CURRENT $sort_table closure (extracted live from the shipped widget
 * source, like the eval-extraction in WidgetAliasHiddenTest.php) and the OLD
 * pfbsort() (copied verbatim from `git show origin/devel:src/usr/local/www/
 * widgets/widgets/pfblockerng.widget.php`, renamed to avoid a symbol clash --
 * see ORACLE_PFBSORT_SOURCE) are loaded off-appliance and run side-by-side
 * against the same fixture inputs, so a real behavioural divergence between
 * old and new fails HERE rather than shipping silently.
 *
 * pfbsort()'s own $sort_ascending flag is INVERTED relative to the new
 * closure's $ascending: devel's `sortdir == 'asc'` branch calls
 * pfbsort($table, $col, FALSE) (FALSE takes the array_reverse() path, which is
 * what actually produces ascending output), and the `else` (descending) branch
 * calls it with TRUE. So :meth:`assertMatchesOracle` below always passes
 * `!$ascending` to the oracle to compensate -- verified empirically (every
 * fixture in this file) to reproduce the exact devel order.
 *
 * Coverage mandate (CLAUDE.md): the value-column branch (incl. a tie, both
 * sort directions), the 'alias' key-sort branch (case-insensitive, both
 * directions), the 'update' strtotime branch (incl. one malformed date), and
 * the empty/single-element edge cases.
 *
 * No #[CoversFunction] attribute: the sort closure lives inside
 * pfBlockerNG_update_table() in the widget file, which the PHPUnit bootstrap
 * never loads — the tests exercise a source-extracted copy of the closure, so
 * there is no loadable coverage target (an attribute here fails the CI
 * --coverage-text run with "not a valid target for code coverage").
 */
final class WidgetSortTableTest extends TestCase
{
	// Copied VERBATIM from `git show origin/devel:src/usr/local/www/widgets/widgets/pfblockerng.widget.php`
	// (the pfbsort() function pre-#563), function renamed to avoid colliding with
	// any production symbol. This is the ORACLE the new closure must match.
	private const ORACLE_PFBSORT_SOURCE = <<<'PHP'
	function pfbsort_devel_oracle(&$array, $subkey, $sort_ascending) {
		if (empty($array)) {
			return;
		}

		if (count($array)) {
			$temp_array[key($array)] = array_shift($array);
		}

		foreach ($array as $key => $val) {
			$offset = 0;
			$found = FALSE;

			foreach ($temp_array as $tmp_key => $tmp_val) {
				if (!$found) {
					switch($subkey) {
						case 'alias':
							(strtolower($key) > strtolower($tmp_key)) ? $found = TRUE : $found = FALSE;
							break;
						case 'update':
							(strtotime($val[$subkey]) > strtotime($tmp_val[$subkey])) ? $found = TRUE : $found = FALSE;
							break;
						default:
							(strtolower($val[$subkey]) > strtolower($tmp_val[$subkey])) ? $found = TRUE : $found = FALSE;
							break;
					}
				}
				if ($found) {
					$temp_array = array_merge((array)array_slice($temp_array, 0, $offset), array($key => $val), array_slice($temp_array, $offset));
				}
				$offset++;
			}

			if (!$found) {
				$temp_array = array_merge($temp_array, array($key => $val));
			}
		}

		if (!$sort_ascending) {
			$array = array_reverse($temp_array);
		} else {
			$array = $temp_array;
		}
		return;
	}
	PHP;

	public static function setUpBeforeClass(): void
	{
		if (!function_exists('pfbsort_devel_oracle')) {
			eval(self::ORACLE_PFBSORT_SOURCE);
		}

		if (!function_exists('pfb_widget_sort_table_new')) {
			$src = file_get_contents(
				dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php'
			);
			if ($src === false) {
				throw new RuntimeException('test bootstrap: failed to read pfblockerng.widget.php');
			}
			// Extract the $sort_table closure assignment VERBATIM (2-tab indent through
			// its matching 2-tab-indented closing "};") and wrap it in a standalone
			// function taking $sortkey/$ascending as parameters -- the closure's own
			// `use ($sortkey, $ascending)` captures those same names from the wrapper's
			// scope exactly as it would from pfBlockerNG_update_table()'s.
			if (!preg_match('/\$sort_table = static function.*?\n\t\t\};/s', $src, $m)) {
				throw new RuntimeException('test bootstrap: $sort_table closure not found in widget source');
			}
			eval('function pfb_widget_sort_table_new($sortkey, $ascending) { ' . $m[0] . ' return $sort_table; }');
		}
	}

	/**
	 * Run both the new closure and the devel oracle against the same fixture and
	 * assert they produce IDENTICAL order (keys AND values, in sequence).
	 *
	 * @param array<string,array<string,mixed>> $fixture
	 */
	private function assertMatchesOracle(array $fixture, string $sortkey, bool $ascending): void
	{
		$new = $fixture;
		$sort = pfb_widget_sort_table_new($sortkey, $ascending);
		$sort($new);

		$old = $fixture;
		pfbsort_devel_oracle($old, $sortkey, !$ascending);

		$this->assertSame(
			$old,
			$new,
			"new \$sort_table('{$sortkey}', ascending=" . ($ascending ? 'true' : 'false') . ') '
				. 'diverges from the devel pfbsort() oracle'
		);
	}

	// -----------------------------------------------------------------------
	// (1) Default value-column branch ('count'), including a tie.
	// -----------------------------------------------------------------------

	/** @return array<string,array<string,mixed>> */
	private function countFixtureWithTie(): array
	{
		return [
			'pfB_a' => ['count' => 10, 'update' => '2024-01-01'],
			'pfB_b' => ['count' => 5,  'update' => '2024-01-02'],
			'pfB_c' => ['count' => 5,  'update' => '2024-01-03'],
			'pfB_d' => ['count' => 20, 'update' => '2024-01-04'],
		];
	}

	public function testValueColumnDescendingKeepsTieInsertionOrder(): void
	{
		$table = $this->countFixtureWithTie();
		$sort = pfb_widget_sort_table_new('count', FALSE);
		$sort($table);

		// PHP 8's uasort() is stable: the tied pair (pfB_b, pfB_c, both count=5)
		// keeps its original relative order in the descending build.
		$this->assertSame(['pfB_d', 'pfB_a', 'pfB_b', 'pfB_c'], array_keys($table), 'descending order with a stable tie');
		$this->assertMatchesOracle($this->countFixtureWithTie(), 'count', FALSE);
	}

	public function testValueColumnAscendingReversesTiesToo(): void
	{
		$table = $this->countFixtureWithTie();
		$sort = pfb_widget_sort_table_new('count', TRUE);
		$sort($table);

		// Ascending is array_reverse() of the descending build, so the tied pair's
		// order is ALSO reversed (pfB_c before pfB_b) -- proving ascending is a real
		// reverse of descending, not an independently-stable ascending sort.
		$this->assertSame(['pfB_c', 'pfB_b', 'pfB_a', 'pfB_d'], array_keys($table), 'ascending reverses tie order too');
		$this->assertMatchesOracle($this->countFixtureWithTie(), 'count', TRUE);
	}

	// -----------------------------------------------------------------------
	// (2) 'alias' key-sort branch, case-insensitive, both directions.
	// -----------------------------------------------------------------------

	/** @return array<string,array<string,mixed>> */
	private function mixedCaseAliasFixture(): array
	{
		return [
			'pfB_Zulu'  => ['count' => 1, 'update' => '2024-01-01'],
			'pfb_alpha' => ['count' => 2, 'update' => '2024-01-02'],
			'PFB_Mike'  => ['count' => 3, 'update' => '2024-01-03'],
		];
	}

	public function testAliasKeySortDescendingIsCaseInsensitive(): void
	{
		$table = $this->mixedCaseAliasFixture();
		$sort = pfb_widget_sort_table_new('alias', FALSE);
		$sort($table);

		// Case-folded descending: Zulu > Mike > alpha, regardless of the keys' own case.
		$this->assertSame(['pfB_Zulu', 'PFB_Mike', 'pfb_alpha'], array_keys($table));
		$this->assertMatchesOracle($this->mixedCaseAliasFixture(), 'alias', FALSE);
	}

	public function testAliasKeySortAscendingIsCaseInsensitive(): void
	{
		$table = $this->mixedCaseAliasFixture();
		$sort = pfb_widget_sort_table_new('alias', TRUE);
		$sort($table);

		$this->assertSame(['pfb_alpha', 'PFB_Mike', 'pfB_Zulu'], array_keys($table));
		$this->assertMatchesOracle($this->mixedCaseAliasFixture(), 'alias', TRUE);
	}

	// -----------------------------------------------------------------------
	// (3) 'update' branch via strtotime(), including one malformed date.
	// -----------------------------------------------------------------------

	/** @return array<string,array<string,mixed>> */
	private function updateFixtureWithMalformedDate(): array
	{
		return [
			// strtotime('not-a-date') === FALSE; the comparator still runs (PHP's
			// bool<=>int juggling), matching whatever the devel oracle does with it.
			'pfB_a' => ['count' => 1, 'update' => '2024-01-01'],
			'pfB_b' => ['count' => 2, 'update' => 'not-a-date'],
			'pfB_c' => ['count' => 3, 'update' => '2024-06-01'],
		];
	}

	public function testUpdateColumnSortDescendingWithMalformedDate(): void
	{
		$table = $this->updateFixtureWithMalformedDate();
		$sort = pfb_widget_sort_table_new('update', FALSE);
		$sort($table);

		$this->assertSame(['pfB_c', 'pfB_a', 'pfB_b'], array_keys($table));
		$this->assertMatchesOracle($this->updateFixtureWithMalformedDate(), 'update', FALSE);
	}

	public function testUpdateColumnSortAscendingWithMalformedDate(): void
	{
		$table = $this->updateFixtureWithMalformedDate();
		$sort = pfb_widget_sort_table_new('update', TRUE);
		$sort($table);

		$this->assertSame(['pfB_b', 'pfB_a', 'pfB_c'], array_keys($table));
		$this->assertMatchesOracle($this->updateFixtureWithMalformedDate(), 'update', TRUE);
	}

	// -----------------------------------------------------------------------
	// (4) Empty and single-element tables.
	// -----------------------------------------------------------------------

	public function testEmptyTableSortIsNoop(): void
	{
		$table = [];
		$sort = pfb_widget_sort_table_new('count', TRUE);
		$sort($table);

		$this->assertSame([], $table, 'sorting an empty table must stay an empty array');
	}

	public function testSingleElementTableSortIsNoop(): void
	{
		$single = ['pfB_only' => ['count' => 42, 'update' => '2024-05-05']];
		$table = $single;
		$sort = pfb_widget_sort_table_new('count', TRUE);
		$sort($table);

		$this->assertSame($single, $table, 'sorting a single-element table must not change it');
	}
}
