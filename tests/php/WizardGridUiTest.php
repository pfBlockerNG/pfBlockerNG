<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Bootstrap columns in the wizard's CDATA must sit in a row, and a row must fit in 12.
 *
 * col-sm-* carries gutter padding that a row's negative margins exist to cancel; without
 * a row the columns sit inset against a flush sibling, and their widths are unbounded.
 * Step 1 was fixed for this in issue #2863 and step 2 kept the defect (issue #2890),
 * so the whole file is checked rather than the step that was noticed.
 */
final class WizardGridUiTest extends TestCase
{
	private const WIZARD = __DIR__ . '/../../src/usr/local/www/wizards/pfblockerng_wizard.xml';

	/**
	 * Columns attributed to the row that actually encloses them.
	 *
	 * Depth-tracked rather than counted: a flat tally cannot tell an orphaned column
	 * from one whose sibling happens to sit in a row, nor an overfull row from two
	 * rows whose widths average out.
	 *
	 * @return list<array{block: int, row: int|null, cols: list<string>}>
	 */
	private static function cdataColumns(): array
	{
		$body = file_get_contents(self::WIZARD);
		self::assertIsString($body, 'the wizard must be readable');
		preg_match_all('/<!\[CDATA\[(.*?)\]\]>/s', $body, $blocks);

		$groups = [];
		foreach ($blocks[1] as $index => $block) {
			preg_match_all('/<div(?:\s+class="([^"]*)")?[^>]*>|<\/div>/', $block, $tags, PREG_SET_ORDER);
			$stack = [];
			$rowSeq = 0;
			foreach ($tags as $tag) {
				if ($tag[0] === '</div>') {
					array_pop($stack);
					continue;
				}
				$class = $tag[1] ?? '';
				if (str_contains($class, 'row')) {
					$stack[] = ['row', ++$rowSeq];
					continue;
				}
				if (str_contains($class, 'col-sm-')) {
					$row = NULL;
					foreach (array_reverse($stack) as $frame) {
						if ($frame[0] === 'row') {
							$row = $frame[1];
							break;
						}
					}
					$key = $index . ':' . ($row ?? 'none');
					$groups[$key] ??= ['block' => $index, 'row' => $row, 'cols' => []];
					$groups[$key]['cols'][] = $class;
				}
				$stack[] = ['div', 0];
			}
		}
		return array_values($groups);
	}

	public function testEveryColumnSitsInsideARow(): void
	{
		$groups = self::cdataColumns();
		$this->assertNotSame([], $groups, 'the scan found no columns at all -- it is not looking where it should');

		foreach ($groups as $group) {
			$this->assertNotNull($group['row'],
				"wizard CDATA block {$group['block']} has col-sm-* outside any row, so those columns "
				. 'carry their gutter padding with no row to cancel it: ' . implode(', ', $group['cols']));
		}
	}

	public function testNoSingleRowIsAskedToHoldMoreThanTwelveColumns(): void
	{
		foreach (self::cdataColumns() as $group) {
			$width = 0;
			foreach ($group['cols'] as $class) {
				if (preg_match('/col-sm-(\d+)/', $class, $m) === 1) {
					$width += (int) $m[1];
				}
			}
			$where = $group['row'] === NULL ? 'outside any row' : "row {$group['row']}";
			$this->assertLessThanOrEqual(12, $width,
				"wizard CDATA block {$group['block']}, {$where}, declares {$width} columns: "
				. implode(', ', $group['cols']));
		}
	}
}
