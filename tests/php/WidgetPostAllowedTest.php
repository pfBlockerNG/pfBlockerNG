<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_widget_post_allowed() — the dashboard widget's CSRF stand-in (issue #1050).
 *
 * pfblockerng.widget.php sets $nocsrf=TRUE for the whole endpoint (its read-only
 * AJAX GETs need no token), so its mutating POST handlers (pfb_submit,
 * pfblockerngack, and the three packet-count clears) gate on this instead: reject a cross-site-shaped POST via the
 * Sec-Fetch-Site fetch metadata header, allow everything else -- including an
 * ABSENT header (a legacy browser sending none at all), a deliberate fail-open
 * documented at the call site.
 *
 * widget-pfblockerng.inc carries no top-level pfSense-dependent execution (just
 * two title-string assignments plus this function), so it is require_once()d
 * directly -- unlike pfblockerng.widget.php's eval-extraction (WidgetAliasHiddenTest),
 * this file needs no page-runtime stripping.
 */
#[CoversFunction('pfb_widget_post_allowed')]
final class WidgetPostAllowedTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_widget_post_allowed')) {
			return;
		}
		require_once dirname(__DIR__, 2) . '/src/usr/local/www/widgets/include/widget-pfblockerng.inc';
	}

	/**
	 * Full truth table: absent, 'same-origin', 'none', 'cross-site', 'same-site',
	 * empty string.
	 *
	 * @return array<string,array{array<string,string>,bool}>
	 */
	public static function truthTableProvider(): array
	{
		return [
			'absent header -- fail-open (legacy browser)' => [[], true],
			"'same-origin' -- allowed"                     => [['HTTP_SEC_FETCH_SITE' => 'same-origin'], true],
			"'none' -- allowed (direct navigation/bookmark)" => [['HTTP_SEC_FETCH_SITE' => 'none'], true],
			"'cross-site' -- blocked"                       => [['HTTP_SEC_FETCH_SITE' => 'cross-site'], false],
			"'same-site' -- blocked (not in the allowed set)" => [['HTTP_SEC_FETCH_SITE' => 'same-site'], false],
			'empty string -- present but not an allowed token, blocked' => [['HTTP_SEC_FETCH_SITE' => ''], false],
		];
	}

	/** @param array<string,string> $server */
	#[DataProvider('truthTableProvider')]
	public function testTruthTable(array $server, bool $expected): void
	{
		$this->assertSame(
			$expected,
			pfb_widget_post_allowed($server),
			'pfb_widget_post_allowed(' . var_export($server, true) . ') expected ' . var_export($expected, true)
		);
	}

	/**
	 * Wiring pin (Sonnet review on PR #1061): EVERY mutating $_POST branch in
	 * the widget's dispatch chain must call the guard -- a new handler added
	 * without it silently reopens the cross-site hole #1050 closed.
	 */
	public function testEveryMutatingPostBranchCallsTheGuard(): void
	{
		$widget = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php'
		);
		// Dispatch branches sit at one tab of indentation; nested validation reads
		// (in_array($_POST[...]) inside pfb_submit) are deeper and excluded.
		preg_match_all('/^\t(?:if|elseif)\s*\(([^\n]*\$_POST\[[^\n]*)\)\s*\{/m', $widget, $m);
		$branches = $m[1];
		$this->assertNotEmpty($branches, 'no $_POST dispatch branches found -- extraction regex broke');
		foreach ($branches as $cond) {
			$this->assertStringContainsString(
				'pfb_widget_post_allowed($_SERVER)',
				$cond,
				"unguarded mutating \$_POST branch in pfblockerng.widget.php: {$cond}"
			);
		}
		$this->assertGreaterThanOrEqual(5, count($branches),
			'expected at least the 5 known mutating branches (pfb_submit, ack, 3 clears); got ' . count($branches));
	}
}
