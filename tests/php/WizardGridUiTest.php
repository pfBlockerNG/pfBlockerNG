<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Bootstrap columns in the wizard's CDATA must sit in a row, and a row must fit in 12.
 *
 * col-sm-* carries Bootstrap's negative gutter margins, which a row parent exists to
 * cancel; without one the columns bleed against the container wizard.php supplies.
 * Step 1 was fixed for this in issue #2863 and step 2 kept the defect (issue #2890),
 * so the whole file is checked rather than the step that was noticed.
 */
final class WizardGridUiTest extends TestCase
{
	private const WIZARD = __DIR__ . '/../../src/usr/local/www/wizards/pfblockerng_wizard.xml';

	/** @return list<array{block: int, cols: list<string>, rows: int}> */
	private static function cdataGrids(): array
	{
		$body = file_get_contents(self::WIZARD);
		self::assertIsString($body, 'the wizard must be readable');
		preg_match_all('/<!\[CDATA\[(.*?)\]\]>/s', $body, $blocks);

		$grids = [];
		foreach ($blocks[1] as $index => $block) {
			preg_match_all('/<div class="([^"]*)"/', $block, $divs);
			$cols = array_values(array_filter($divs[1],
				static fn (string $class): bool => str_contains($class, 'col-sm-')));
			if ($cols === []) {
				continue;
			}
			$grids[] = [
				'block' => $index,
				'cols' => $cols,
				'rows' => substr_count($block, 'class="row"'),
			];
		}
		return $grids;
	}

	public function testEveryColumnBlockDeclaresARow(): void
	{
		$grids = self::cdataGrids();
		$this->assertNotSame([], $grids, 'the scan found no columns at all -- it is not looking where it should');

		foreach ($grids as $grid) {
			$this->assertGreaterThan(0, $grid['rows'],
				"wizard CDATA block {$grid['block']} uses col-sm-* with no row parent, so the columns "
				. 'carry Bootstrap negative gutters uncancelled: ' . implode(', ', $grid['cols']));
		}
	}

	public function testNoRowIsAskedToHoldMoreThanTwelveColumns(): void
	{
		foreach (self::cdataGrids() as $grid) {
			$width = 0;
			foreach ($grid['cols'] as $class) {
				if (preg_match('/col-sm-(\d+)/', $class, $m) === 1) {
					$width += (int) $m[1];
				}
			}
			$this->assertLessThanOrEqual(12 * max(1, $grid['rows']), $width,
				"wizard CDATA block {$grid['block']} declares {$width} columns across {$grid['rows']} row(s): "
				. implode(', ', $grid['cols']));
		}
	}
}
