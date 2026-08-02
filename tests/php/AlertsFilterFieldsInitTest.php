<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1777: pfblockerng_alerts.php's top-of-file $filterfieldsarray init
 * block (:110-125) is 3 independent foreach loops seeding slots 0/1/2 with
 * their own key set (blank placeholders later populated per-row). The slot-2
 * loop is a copy-paste of the slot-1 loop with the assignment target never
 * updated: it writes `$filterfieldsarray[1][$field_2]` instead of
 * `$filterfieldsarray[2][$field_2]`. Two live consequences on a fresh box:
 *
 *   - $filterfieldsarray[2] never gets its 9 keys (81-89), so every
 *     pfb_match_filter_field($pfbalertreply, $filterfieldsarray[2]) read in
 *     convert_dns_reply_log() hits an undefined array key -- 9-10 of the
 *     #1777 sweep's diagnostics.
 *   - $filterfieldsarray[1] (the DNSBL slot) picks up 9 junk keys (81-89)
 *     that don't belong to it and leak into the `?refresh=` JSON dump
 *     (:~4907).
 *
 * The init block is pure array assignment with zero external dependencies
 * (no $pfb/$_POST/DB), so -- unlike the page's request-scoped blocks -- it is
 * eval-extracted and run standalone, guard-state-agnostic (matches whichever
 * slot the RHS currently writes to, so this file is red pre-fix and green
 * post-fix unchanged).
 */
final class AlertsFilterFieldsInitTest extends TestCase
{
	private const ALERTS_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php';
	private static string $initRegion;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_alerts_oracle_filterfieldsarray_init')) {
			return;
		}
		$src = file_get_contents(self::ALERTS_PHP);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_alerts.php');
		}
		if (!preg_match(
			'/((?:\$filterfieldsarray\s*=\s*array\(\);\n).*?\$filterfieldsarray\[\d\]\[\$field_2\] = \'\';\n\})\n/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: filterfieldsarray init block not found');
		}
		self::$initRegion = $m[1];
		eval(
			'function pfb_alerts_oracle_filterfieldsarray_init(): array {'
			. $m[1]
			. ' return $filterfieldsarray; }'
		);
	}

	public function testExtractionStartsAtExecutableCodeNotProductionComment(): void
	{
		$this->assertStringStartsWith('$filterfieldsarray', self::$initRegion);
		$this->assertStringNotContainsString('Initialize filterfieldsarray', self::$initRegion);
	}

	public function testSlotTwoIsSeededWithItsOwn81Through89KeySet(): void
	{
		$filterfieldsarray = pfb_alerts_oracle_filterfieldsarray_init();

		$this->assertSame(
			[81, 82, 83, 84, 85, 86, 87, 88, 89],
			array_keys($filterfieldsarray[2]),
			'$filterfieldsarray[2] must be seeded with its own 81-89 key set (the slot-2 loop must write to slot 2, not slot 1)'
		);
	}

	public function testSlotOneKeepsExactlyItsOwnKeySetNoSlotTwoJunk(): void
	{
		$filterfieldsarray = pfb_alerts_oracle_filterfieldsarray_init();

		$this->assertSame(
			[2, 7, 8, 13, 15, 17, 19, 20, 99],
			array_keys($filterfieldsarray[1]),
			'$filterfieldsarray[1] must keep ONLY its own key set -- no 81-89 junk leaking in from the slot-2 loop'
		);
	}

	public function testSlotZeroIsUnaffectedControl(): void
	{
		$filterfieldsarray = pfb_alerts_oracle_filterfieldsarray_init();

		$this->assertSame(
			[0, 2, 6, 7, 8, 9, 10, 12, 13, 15, 16, 17, 18, 99],
			array_keys($filterfieldsarray[0]),
			'$filterfieldsarray[0] is untouched by the bug -- control assertion'
		);
	}
}
