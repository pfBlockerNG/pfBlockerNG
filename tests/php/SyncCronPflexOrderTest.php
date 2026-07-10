<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1154 — pfblockerng_sync_cron()'s .fail-marker retry called
 * pfb_update_check() BEFORE the per-row `$pflex` derivation ran that
 * iteration. PHP loop variables persist across iterations, so the retry
 * read the PREVIOUS row's $pflex — undefined on the first row, emitting a
 * PHP undefined-variable warning per cron run. The stale value is never
 * CONSUMED (pfb_update_check() returns on its own .fail check before any
 * $pflex use), so this pins warning hygiene and the per-row invariant,
 * not a TLS behaviour change.
 *
 * pfblockerng.php carries top-level execution and is never require()'d
 * off-appliance (the PHPUnit bootstrap doesn't load www/ dispatcher
 * scripts), and pfb_update_check() performs real network downloads, so
 * driving pfblockerng_sync_cron() behaviourally is infeasible here. Per
 * the TickEntrypointTest/PfbReflectorGuardTest house precedent, this suite
 * instead reads the function's source text and pins the ORDER of the two
 * statements: the first `$pflex = FALSE` derivation line must precede the
 * first `pfb_update_check(` call site (the .fail retry) textually.
 * Whole-line comments are stripped before scanning so a comment mentioning
 * either token cannot satisfy or break the ordering assertion.
 */
final class SyncCronPflexOrderTest extends TestCase
{
	private static string $functionBody;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.php');
		}

		if (!preg_match(
			'/function pfblockerng_sync_cron\b.*?(?=\nfunction )/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: pfblockerng_sync_cron() body not found');
		}

		// Scan code only: a whole-line comment naming either token must not
		// shift the first-occurrence offsets (bit this PR once mid-review).
		self::$functionBody = preg_replace('#^\s*//.*$#m', '', $m[0]);
	}

	public function testDerivationAndCallSiteBothPresentExactlyOnceAndTwoOrMoreTimes(): void
	{
		$body = self::$functionBody;

		$derivationCount = substr_count($body, '$pflex = FALSE');
		$this->assertSame(
			1,
			$derivationCount,
			"expected exactly 1 occurrence of '\$pflex = FALSE' in pfblockerng_sync_cron(), found {$derivationCount} -- "
			. 'the derivation must not have been duplicated or removed by the fix'
		);

		$callSiteCount = substr_count($body, 'pfb_update_check(');
		$this->assertGreaterThanOrEqual(
			2,
			$callSiteCount,
			"expected at least 2 'pfb_update_check(' call sites in pfblockerng_sync_cron(), found {$callSiteCount} -- "
			. 'the .fail retry site plus at least one cron-schedule site must both still exist'
		);
	}

	/**
	 * Scenario: pfblockerng_sync_cron() processes a row whose .fail marker
	 * exists (the retry branch).
	 * Given the per-row $pflex derivation and the .fail retry's
	 *   pfb_update_check() call both live in the same loop iteration,
	 * When the retry branch reads $pflex,
	 * Then it must read THIS row's own flag, which requires the
	 *   derivation to execute (textually precede) before the retry's call
	 *   site -- never the previous iteration's leftover value.
	 */
	public function testPflexDerivationPrecedesEveryUpdateCheckCallSite(): void
	{
		$body = self::$functionBody;

		$derivationPos = strpos($body, '$pflex = FALSE');
		$callSitePos   = strpos($body, 'pfb_update_check(');

		if ($derivationPos === false || $callSitePos === false) {
			$this->fail('precondition failed: derivation or call site missing -- see the vacuity-guard test');
		}

		$snippet = static function (string $body, int $pos): string {
			$start = max(0, $pos - 60);
			return substr($body, $start, 120);
		};

		$this->assertLessThan(
			$callSitePos,
			$derivationPos,
			"expected \$pflex derivation offset ({$derivationPos}) < first pfb_update_check() call offset ({$callSitePos})\n"
			. "--- around derivation (offset {$derivationPos}) ---\n" . $snippet($body, $derivationPos) . "\n"
			. "--- around first call site (offset {$callSitePos}) ---\n" . $snippet($body, $callSitePos)
		);
	}
}
