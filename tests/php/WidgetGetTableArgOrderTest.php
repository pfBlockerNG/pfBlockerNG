<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Pins the pfBlockerNG_get_table($pfb_table, $mode='') argument-order
 * contract in two complementary halves, established by issue #1693's
 * reorder of $mode/$pfb_table (matching the #1657 shape for the same PHP 8
 * optional-before-required-parameter defect class):
 *
 *   - testJsModeCallPathEmitsPipeDelimitedFieldsInOrder /
 *     testDefaultModeCallPathEmitsTableMarkupWithFieldsInTheRightCells
 *     (runtime, DECLARATION pin): eval-extract the REAL function body --
 *     same idiom PfbWidgetOracleTest already uses for
 *     pfBlockerNG_get_failed()/pfBlockerNG_clearfailed() -- and invoke it
 *     directly the same two ways the widget does (js mode with both
 *     positional args, default mode relying on $mode's default). A
 *     reverted declaration (optional $mode moved back before required
 *     $pfb_table) then throws before producing output -- TypeError from
 *     reset() on the js-mode call, ArgumentCountError on the default-mode
 *     call, both proven by mutation -- and a silent field-order corruption
 *     inside the function body is caught by asserting the exact rendered
 *     output, not merely that the call did not throw. This half pins ONLY
 *     the declaration's own argument contract: it hand-writes its own call
 *     expressions and cannot see a mistake in the widget's actual call-site
 *     source.
 *
 *   - testEveryCallSitePassesPfbTableFirstArgument (source pin, CALL-SITE
 *     pin): closes exactly the gap the runtime half leaves open --
 *     a declaration/call-site positional drift where the declaration stays
 *     correct but a call site in pfblockerng.widget.php is edited to pass
 *     its arguments in the wrong order. `php -l` cannot see that either
 *     (SrcPhpDeprecationLintTest), for the identical reason: a caller is
 *     never part of what -l parses. This test extracts every literal
 *     `pfBlockerNG_get_table(` call expression from the widget source and
 *     asserts each one's first argument is literally `$pfb_table`, with an
 *     `assertCount(2, ...)` vacuity guard so a second, unpinned call site
 *     cannot appear silently -- same shape as
 *     DnsblRegexToggleGateWiringTest's `substr_count(...) === 1` guard.
 *
 * Together the two halves close the finding SrcPhpDeprecationLintTest
 * structurally cannot: a declaration reorder is caught by the runtime half,
 * a call-site-only argument swap is caught by the source-pin half.
 */
final class WidgetGetTableArgOrderTest extends TestCase
{
	private static string $src;

	/** Saved $GLOBALS['pfb'], restored in tearDown (repo convention, PfbWidgetOracleTest). */
	private bool $hadPfb = false;
	private mixed $savedPfb = null;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.widget.php');
		}
		self::$src = $src;

		if (function_exists('pfBlockerNG_get_table')) {
			return;
		}

		if (!preg_match('/function\s+pfBlockerNG_get_table\s*\([^)]*\).*?\n\}/s', $src, $m)) {
			throw new RuntimeException('test bootstrap: pfBlockerNG_get_table() not found in widget source');
		}
		eval($m[0]);
	}

	protected function setUp(): void
	{
		$this->hadPfb   = array_key_exists('pfb', $GLOBALS);
		$this->savedPfb = $GLOBALS['pfb'] ?? null;
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->savedPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	/**
	 * A single alias row is enough to pin field order -- no fixture factory needed.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private function fixture(): array
	{
		return [
			'pfB_Example_v4' => [
				'count'   => 7,
				'packets' => 0,
				'update'  => '2024-06-01',
				'img'     => '<i class="fa-solid fa-check"></i>',
				'rule'    => 0,
				'id'      => 1,
			],
		];
	}

	/**
	 * The Ajax refresh path, invoked the same way pfblockerng.widget.php:66 does:
	 * pfBlockerNG_get_table($pfb_table, 'js'). Declaration pin only -- see class
	 * docblock; this hand-writes its own call and cannot see a call-site-only
	 * argument swap in the widget source (testEveryCallSitePassesPfbTableFirstArgument
	 * covers that).
	 */
	public function testJsModeCallPathEmitsPipeDelimitedFieldsInOrder(): void
	{
		$GLOBALS['pfb'] = ['pfctlerr' => '', 'err' => '', 'popup' => ''];

		ob_start();
		pfBlockerNG_get_table($this->fixture(), 'js');
		$out = ob_get_clean();

		$this->assertSame(
			"pfB_Example_v4||7||0||2024-06-01||<i class=\"fa-solid fa-check\"></i><span title=\"Alias Firewall Rule count\"></span>\n",
			$out,
			'js-mode call path must emit the fixture row fields pipe-delimited in count/packets/update/img order'
		);
	}

	/**
	 * The default HTML-render path, invoked the same way pfblockerng.widget.php:1080
	 * does: pfBlockerNG_get_table($pfb_table), relying on $mode's default ''.
	 * Declaration pin only -- see class docblock. Asserts the exact rendered
	 * fragment (byte-for-byte, like the js-mode sibling's assertSame) so a swap
	 * between two columns inside the function body -- which a presence-only
	 * assertStringContainsString per column cannot catch -- fails here.
	 */
	public function testDefaultModeCallPathEmitsTableMarkupWithFieldsInTheRightCells(): void
	{
		$GLOBALS['pfb'] = ['pfctlerr' => '', 'err' => '', 'popup' => ''];

		ob_start();
		pfBlockerNG_get_table($this->fixture());
		$out = ob_get_clean();

		$expected = "<tr>\n"
			. "\t\t\t\t\t\t<td><small>pfB_Example_v4</small></td>\n"
			. "\t\t\t\t\t\t<td><small>7</small></td>\n"
			. "\t\t\t\t\t\t<td><small>0</small></td>\n"
			. "\t\t\t\t\t\t<td><small>2024-06-01</small></td>\n"
			. "\t\t\t\t\t\t<td><i class=\"fa-solid fa-check\"></i><span title=\"Alias Firewall Rule count\"></span></td>\n"
			. "\t\t\t\t</tr>\n"
			. "\t\t\t\t";

		$this->assertSame(
			$expected,
			$out,
			'default-mode call path must emit alias/count/packets/update/img in exactly those column positions'
		);
	}

	/**
	 * Call-site pin -- see class docblock. Extracts every literal
	 * `pfBlockerNG_get_table(` call expression from the widget source (the
	 * negative lookbehind excludes the `function pfBlockerNG_get_table(...)`
	 * declaration line itself) and asserts each call's first positional
	 * argument is literally `$pfb_table`. Robust to whitespace/reformatting
	 * and to the second argument's presence/value -- it pins only the
	 * property that actually matters: which parameter slot gets $pfb_table.
	 */
	public function testEveryCallSitePassesPfbTableFirstArgument(): void
	{
		preg_match_all('/(?<!function )pfBlockerNG_get_table\(([^)]*)\)/', self::$src, $m);
		$calls = $m[1];

		// Vacuity-safe: proves the extraction found the real call sites (not zero,
		// not a broken regex) AND that no third, unpinned call site has appeared.
		$this->assertCount(
			2,
			$calls,
			'expected exactly 2 pfBlockerNG_get_table( call sites in the widget source -- '
				. 'a new, unpinned call site must not appear silently. Found: ' . implode(' | ', $calls)
		);

		foreach ($calls as $i => $args) {
			$firstArg = trim(explode(',', $args, 2)[0]);
			$this->assertSame(
				'$pfb_table',
				$firstArg,
				"call site #{$i} (pfBlockerNG_get_table({$args})) must pass \$pfb_table as its first positional argument"
			);
		}
	}
}
