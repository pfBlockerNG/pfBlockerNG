<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Fresh Alerts-page top-level block guard (issue #1768).
 *
 * A fresh install / first page load runs pfblockerng_alerts.php's top-level
 * block (:35-80) -- $aglobal_array defaults, the PfbConfig::readSection()
 * read that populates $pfb['aglobal'], and the explode() calls that derive
 * $pfbreplytypes/$pfbreplyrec/$pfbblockstat/$pfbpermitstat/$pfbmatchstat/
 * $pfbdnsblstat/$pfbdnsblreplystat from it -- against an EMPTY
 * installedpackages/pfblockerngglobal section (the shape PfbConfig::readSection()
 * returns when the section has never been saved, i.e. $GLOBALS['config'] has
 * no such path). Each explode() reads its $pfb['aglobal'][...] operand
 * directly; on an absent key that operand is NULL, and PHP 8.1+ deprecates
 * passing NULL to explode()'s non-nullable string parameter -- these are the
 * "Passing null" deprecations issue #1768 reports blocking the release
 * functional-UI gate.
 *
 * Scope: the assertions below check only the "Passing null" deprecation
 * class. The SAME block also has bare `$pfb['aglobal']['key'] != ''`/`?:`
 * reads (e.g. $pfbpageload, $pfbmaxtable, the uni_defaults colour loop) that
 * still emit "Undefined array key" warnings on an absent key -- those are
 * the pre-existing, explicitly out-of-scope "3e bare-read class" (#1768
 * brief); asserting the FULL diagnostics list empty would conflate the two
 * and this test would never go green.
 *
 * AlertsPageLoader (tests/php/AlertsPageLoader.php) deliberately starts its
 * eval at the first `function` keyword, EXCLUDING this top-level block -- so
 * it is extracted directly here instead, anchored on the unique
 * `$aglobal_array = array(` line through the last explode() assignment
 * (`$pfbdnsblreplystat = explode(...)`), non-greedy so the regex matches
 * whatever the RHS guard state is and survives the fix.
 */
final class AlertsFreshTopBlockTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
		);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_alerts.php');
		}

		if (!function_exists('pfb_alerts_oracle_fresh_top')) {
			if (!preg_match(
				'/(\$aglobal_array\s*=\s*array\(.*?\n\$pfbdnsblreplystat\s*=\s*pfb_csv_list\([^\n]*\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: alerts fresh top-level block not found');
			}
			eval(
				'function pfb_alerts_oracle_fresh_top(): array {'
				. ' global $pfb;'
				. $m[1]
				. ' return get_defined_vars(); }'
			);
		}
	}

	private $savedConfig;
	private $savedPfb;

	protected function setUp(): void
	{
		// Isolate from whatever a sibling test left in these globals.
		$this->savedConfig = $GLOBALS['config'] ?? null;
		$this->savedPfb    = $GLOBALS['pfb'] ?? null;
		unset($GLOBALS['config']);
	}

	protected function tearDown(): void
	{
		if ($this->savedConfig === null) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->savedPfb === null) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
	}

	/** @return array{0: array, 1: string[]} [$vars, $diagnostics] */
	private function runCapturingDiagnostics(): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$vars = pfb_alerts_oracle_fresh_top();
		} finally {
			restore_error_handler();
		}
		return [$vars, $diagnostics];
	}

	/** @return string[] the diagnostics whose message is a "Passing null" deprecation */
	private static function nullDeprecationsOnly(array $diagnostics): array
	{
		return array_values(array_filter(
			$diagnostics,
			static fn(string $d): bool => str_contains($d, 'Passing null')
		));
	}

	public function testFreshAlertsTopBlockEmitsNoPassingNullDeprecations(): void
	{
		// No $GLOBALS['config'] -> PfbConfig::readSection() returns [] ->
		// $pfb['aglobal'] = [] -- the fresh-install shape.
		[$vars, $diagnostics] = $this->runCapturingDiagnostics();

		$nullDeprecations = self::nullDeprecationsOnly($diagnostics);
		$this->assertSame(
			[],
			$nullDeprecations,
			"fresh Alerts top-level block must emit zero 'Passing null' deprecations, got:\n" . implode("\n", $nullDeprecations)
		);
		// issue #1792: pfb_csv_list() answers an absent scalar with NO entries
		// -- the phantom [''] the old explode(',', '') shape produced is gone.
		$this->assertSame([], $vars['pfbreplytypes']);
	}

	public function testPopulatedAlertsTopBlockExplodeSitesPassThroughUnchanged(): void
	{
		// Axis 2 (populated key): the guard must be a no-op when the field IS
		// present -- proves the fix didn't clobber real explode() output.
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerngglobal' => [
					'pfbreplytypes'      => 'A,AAAA',
					'pfbreplyrec'        => '1,2',
					'pfbblockstat'       => 'x,y',
					'pfbpermitstat'      => 'p,q',
					'pfbmatchstat'       => 'm,n',
					'pfbdnsblstat'       => 'd1,d2',
					'pfbdnsblreplystat'  => 'r1,r2',
				],
			],
		];

		[$vars, $diagnostics] = $this->runCapturingDiagnostics();

		$this->assertSame([], self::nullDeprecationsOnly($diagnostics));
		$this->assertSame(['A', 'AAAA'], $vars['pfbreplytypes']);
		$this->assertSame(['1', '2'], $vars['pfbreplyrec']);
		$this->assertSame(['x', 'y'], $vars['pfbblockstat']);
		$this->assertSame(['p', 'q'], $vars['pfbpermitstat']);
		$this->assertSame(['m', 'n'], $vars['pfbmatchstat']);
		$this->assertSame(['d1', 'd2'], $vars['pfbdnsblstat']);
		$this->assertSame(['r1', 'r2'], $vars['pfbdnsblreplystat']);
	}
}
