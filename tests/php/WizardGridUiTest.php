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
	 * Parsed, not pattern-matched. A hand-rolled tag scanner reproduces every classic
	 * failure of reading markup with regex -- a self-closing div desyncs the stack, a
	 * comment reads as live, and attribute order decides whether a tag is seen at all.
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
			$doc = new DOMDocument();
			$previous = libxml_use_internal_errors(TRUE);
			$doc->loadHTML('<?xml encoding="UTF-8"><div id="pfb-scan-root">' . $block . '</div>',
				LIBXML_NOERROR | LIBXML_NOWARNING);
			libxml_clear_errors();
			libxml_use_internal_errors($previous);

			$rowSeq = 0;
			$rowIds = new SplObjectStorage();
			foreach ($doc->getElementsByTagName('div') as $div) {
				if (self::hasClass($div, 'row')) {
					$rowIds[$div] = ++$rowSeq;
				}
			}
			foreach ($doc->getElementsByTagName('div') as $div) {
				$class = $div->getAttribute('class');
				if (!self::hasColumnClass($class)) {
					continue;
				}
				$row = NULL;
				for ($node = $div->parentNode; $node instanceof DOMElement; $node = $node->parentNode) {
					if (isset($rowIds[$node])) {
						$row = $rowIds[$node];
						break;
					}
				}
				$key = $index . ':' . ($row ?? 'none');
				$groups[$key] ??= ['block' => $index, 'row' => $row, 'cols' => []];
				$groups[$key]['cols'][] = $class;
			}
		}
		return array_values($groups);
	}

	/** Class membership by token, so "narrow" is not a row and "col-sm-offset" is not a width. */
	private static function hasClass(DOMElement $element, string $wanted): bool
	{
		return in_array($wanted, preg_split('/\s+/', trim($element->getAttribute('class'))) ?: [], TRUE);
	}

	private static function hasColumnClass(string $class): bool
	{
		foreach (preg_split('/\s+/', trim($class)) ?: [] as $token) {
			if (preg_match('/^col-sm-\d+$/', $token) === 1) {
				return TRUE;
			}
		}
		return FALSE;
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
