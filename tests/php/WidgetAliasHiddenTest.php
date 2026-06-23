<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_widget_alias_hidden() — the dashboard widget's display-only exclusion
 * predicate (issue #481).
 *
 * The widget enumerates every pfB_* pf table and renders one row per alias. A
 * handful of those tables are internal and must NOT be shown:
 *
 *   - pfB_DNSBL_VIPs                : the DNSBL sinkhole VIP table.
 *   - pfB_<Type>_Aggregated_v4/v6   : the ADR-11 aggregate ("Uber") aliases —
 *     deduped Native reference IP-sets with no firewall rule of their own. Listing
 *     them clutters the widget and double-counts entries already shown by their
 *     source lists.
 *
 * The predicate lives inside pfblockerng.widget.php, which carries top-level
 * execution (it is a rendered web page, not a library) and therefore cannot be
 * require()d off-appliance. So — like the wizard-function extraction in
 * tests/php/bootstrap.php — this test reads the widget source and evals ONLY the
 * pfb_widget_alias_hidden() definition, pinning the predicate without pulling in
 * the page's runtime wiring.
 */
#[CoversFunction('pfb_widget_alias_hidden')]
final class WidgetAliasHiddenTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_widget_alias_hidden')) {
			return;
		}

		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.widget.php');
		}

		// Extract just the function definition (signature through its closing brace).
		// The body is a single return statement, so the first '}' after the signature
		// closes the function.
		if (!preg_match('/function\s+pfb_widget_alias_hidden\s*\([^)]*\)\s*\{.*?\}/s', $src, $m)) {
			throw new RuntimeException('test bootstrap: pfb_widget_alias_hidden() not found in widget source');
		}
		eval($m[0]);
	}

	/**
	 * A normal, user-facing feed alias is SHOWN (the predicate returns false) — the
	 * "before" half that proves hiding is a real branch, not an always-true path.
	 *
	 * @return list<array{string}>
	 */
	public static function shownAliasProvider(): array
	{
		return [
			['pfB_Example_v4'],          // ordinary IPv4 feed alias
			['pfB_Example_v6'],          // ordinary IPv6 feed alias
			['pfB_PRI1_v4'],             // a real shipped alias name shape
			['pfB_Deny_Aggregated_v5'],  // wrong family digit — must NOT match the pattern
			['pfB_Geo_Aggregated_v4'],   // GeoIP folds into action types; no such alias, stays shown
			['pfB_Deny_Aggregated_v4_x'],// trailing suffix — anchored regex must reject
			['xpfB_Deny_Aggregated_v4'], // leading prefix — anchored regex must reject
		];
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('shownAliasProvider')]
	public function testOrdinaryAliasIsShown(string $alias): void
	{
		$this->assertFalse(
			pfb_widget_alias_hidden($alias),
			"alias {$alias} should be displayed in the widget"
		);
	}

	/**
	 * Every one of the eight ADR-11 aggregate aliases is HIDDEN.
	 *
	 * @return list<array{string}>
	 */
	public static function aggregateAliasProvider(): array
	{
		$out = [];
		foreach (['Deny', 'Permit', 'Match', 'Native'] as $type) {
			foreach (['v4', 'v6'] as $fam) {
				$out[] = ["pfB_{$type}_Aggregated_{$fam}"];
			}
		}
		return $out;
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('aggregateAliasProvider')]
	public function testAggregateAliasIsHidden(string $alias): void
	{
		$this->assertTrue(
			pfb_widget_alias_hidden($alias),
			"aggregate alias {$alias} must be hidden from the widget"
		);
	}

	// The pre-existing DNSBL VIP exclusion is preserved by the refactor.
	public function testDnsblVipsIsHidden(): void
	{
		$this->assertTrue(pfb_widget_alias_hidden('pfB_DNSBL_VIPs'));
	}

	// An empty alias name (strstr() found no 'pfB' token) is hidden, as before.
	public function testEmptyAliasIsHidden(): void
	{
		$this->assertTrue(pfb_widget_alias_hidden(''));
	}
}
