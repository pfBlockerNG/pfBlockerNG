<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Pins the pfBlockerNG_get_table($pfb_table, $mode='') argument-order
 * contract between its declaration and both call sites in
 * pfblockerng.widget.php, established by issue #1693's reorder of
 * $mode/$pfb_table (matching the #1657 shape for the same PHP 8
 * optional-before-required-parameter defect class).
 *
 * SrcPhpDeprecationLintTest's `php -l` sweep can only inspect the
 * declaration in isolation -- it structurally cannot see a
 * declaration/call-site positional drift, because a caller is never part of
 * what `php -l` parses. If the declaration's parameter order is ever
 * reverted, or either call site's arguments are ever swapped, the first
 * positional argument stops landing in $pfb_table and this test must fail.
 *
 * Same eval-extraction idiom already used in PfbWidgetOracleTest for
 * pfBlockerNG_get_failed()/pfBlockerNG_clearfailed(): pull the function body
 * verbatim out of the real shipped widget source and eval() it, rather than
 * reimplementing the logic or asserting on source text. No new shim needed.
 */
final class WidgetGetTableArgOrderTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfBlockerNG_get_table')) {
			return;
		}

		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.widget.php');
		}

		if (!preg_match('/function\s+pfBlockerNG_get_table\s*\([^)]*\).*?\n\}/s', $src, $m)) {
			throw new RuntimeException('test bootstrap: pfBlockerNG_get_table() not found in widget source');
		}
		eval($m[0]);
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
	 * The Ajax refresh path: pfBlockerNG_get_table($pfb_table, 'js') (:66).
	 *
	 * If the declaration or this call site's argument order drifted, the
	 * fixture array would no longer land in $pfb_table -- e.g. under the OLD
	 * declaration order ($mode='', $pfb_table) with this SAME call site, the
	 * fixture array binds to $mode and the literal string 'js' binds to the
	 * required $pfb_table, and reset('js') throws
	 * "TypeError: reset(): Argument #1 ($array) must be of type array,
	 * string given" before any output is produced -- proven by mutation
	 * below. A silent field-order corruption is equally detectable: this
	 * assertion pins count/packets/update/img in their exact pipe-delimited
	 * slots, not merely that the call did not throw.
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
	 * The default HTML-render path: pfBlockerNG_get_table($pfb_table) (:1080),
	 * relying on $mode's default ''. Under the OLD declaration order
	 * ($mode='', $pfb_table required, no default), this single-argument call
	 * would bind the fixture array to $mode and leave $pfb_table -- required,
	 * no default -- unsatisfied, throwing an ArgumentCountError before any
	 * output is produced -- proven by mutation below.
	 */
	public function testDefaultModeCallPathEmitsTableMarkupWithFieldsInTheRightCells(): void
	{
		$GLOBALS['pfb'] = ['pfctlerr' => '', 'err' => '', 'popup' => ''];

		ob_start();
		pfBlockerNG_get_table($this->fixture());
		$out = ob_get_clean();

		$this->assertStringContainsString('<td><small>pfB_Example_v4</small></td>', $out, 'alias must land in the 1st column');
		$this->assertStringContainsString('<td><small>7</small></td>', $out, 'count must land in the 2nd column');
		$this->assertStringContainsString('<td><small>0</small></td>', $out, 'packets must land in the 3rd column');
		$this->assertStringContainsString('<td><small>2024-06-01</small></td>', $out, 'update must land in the 4th column');
		$this->assertStringContainsString(
			'<td><i class="fa-solid fa-check"></i><span title="Alias Firewall Rule count"></span></td>',
			$out,
			'img must land in the 5th column'
		);
	}
}
