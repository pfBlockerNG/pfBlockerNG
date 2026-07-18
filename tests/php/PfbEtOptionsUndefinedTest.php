<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

/**
 * pfblockerng.php's pfblockerng_get_countries() (issue #1493 defect 1): line
 * ~2220 assigns the dead-store typo `$etoptions = '';` -- every subsequent
 * read in the reputation-tab options loop (2229/2234/2236) and the call to
 * pfb_build_reputation_tab($et_options) at 2242 reads the never-assigned
 * `$et_options` instead. With $roptions4 empty (no GeoIP continent data --
 * the fresh-install/bare-`gc` path) the loop body never runs, so the ONLY
 * read is the unconditional call at 2242: PHP 8 emits "Undefined variable
 * $et_options" and passes NULL to the builder.
 *
 * The file carries top-level execution and cannot be require()d
 * off-appliance (house precedent: CountryNetworksCountGuardTest.php,
 * GeoipContinentCatStderrGuardTest.php). Calling the real
 * pfblockerng_get_countries() is additionally unsafe here: it flows on to
 * pfb_build_reputation_tab(), which unconditionally file_put_contents()s the
 * hardcoded absolute path /usr/local/www/pfblockerng/pfblockerng_reputation.php
 * with no sandboxing hook. So this test eval-extracts only the
 * $roptions4 -> $et_options options-build block (sort()..the
 * pfb_build_reputation_tab() call) verbatim, swapping the builder call for a
 * recording test double -- the real defect line runs unmocked, with zero
 * file I/O.
 *
 * Feature: the reputation-tab options string reaching the builder must
 *          always be a defined string, never an undefined-variable read
 *
 *   Scenario: no GeoIP country data collected (empty $roptions4) -> the
 *             options-build loop body never executes, so $et_options must
 *             still be a defined '' at the builder call, with no warning
 */
final class PfbEtOptionsUndefinedTest extends TestCase
{
	use PfbNoPhpWarningTrait;

	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php';
		$src = file_get_contents($path);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.php');
		}
		self::$src = $src;

		if (!function_exists('pfb_et_options_oracle')) {
			if (!preg_match(
				'/sort\(\$roptions4, SORT_STRING\);.*?pfb_build_reputation_tab\(\$et_options\);/s',
				$src,
				$m
			)) {
				throw new RuntimeException('oracle extraction failed: the reputation-tab options-build block was not found in pfblockerng.php');
			}
			$block = str_replace('pfb_build_reputation_tab(', 'pfb_et_options_test_sink(', $m[0]);
			eval(
				'function pfb_et_options_oracle(array $roptions4): void {'
				. ' ' . $block
				. ' }'
			);
		}
	}

	protected function setUp(): void
	{
		$GLOBALS['pfb_et_options_test_sink_arg'] = 'sink-not-called';
	}

	public function testEtOptionsReachesReputationTabBuilderDefinedAndEmpty(): void
	{
		$this->assertNoPhpWarning(static function (): void {
			pfb_et_options_oracle([]);
		});

		$this->assertSame(
			'',
			$GLOBALS['pfb_et_options_test_sink_arg'],
			'$et_options must reach pfb_build_reputation_tab() as the empty string produced by the (empty) options loop, not an undefined-variable NULL'
		);
	}
}

function pfb_et_options_test_sink($et_options): void
{
	$GLOBALS['pfb_et_options_test_sink_arg'] = $et_options;
}
