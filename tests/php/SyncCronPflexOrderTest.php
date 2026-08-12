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
 * The cron module is an appliance-only scheduler surface. This suite scans executable
 * tokens with php_strip_whitespace and pins the ORDER of the two statements: the first
 * `$pflex = FALSE` derivation line must precede the row call wrapper invocation.
 */
final class SyncCronPflexOrderTest extends TestCase
{
	private static string $functionBody;

	public static function setUpBeforeClass(): void
	{
		$src = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc'
		);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_cron.inc');
		}

		if (!preg_match(
			'/function pfblockerng_sync_cron\b.*?(?=\nfunction |\z)/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: pfblockerng_sync_cron() body not found');
		}

		self::$functionBody = $m[0];
	}

	public function testDerivationAndRowCallArePresentExactlyOnce(): void
	{
		$body = self::$functionBody;

		$derivationCount = substr_count($body, '$pflex = FALSE');
		$this->assertSame(
			1,
			$derivationCount,
			"expected exactly 1 occurrence of '\$pflex = FALSE' in pfblockerng_sync_cron(), found {$derivationCount} -- "
			. 'the derivation must not have been duplicated or removed by the fix'
		);

		$callSiteCount = substr_count($body, '$check($feed_id, $header,');
		$this->assertSame(
			3,
			$callSiteCount,
			"expected exactly 3 row check calls in pfblockerng_sync_cron(), found {$callSiteCount} -- "
			. 'the urgent retry, force-all, and selected scheduled paths must all remain'
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
		$callSitePos   = strpos($body, '$check($feed_id, $header,');

		if ($derivationPos === FALSE || $callSitePos === FALSE) {
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
