<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
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
	 * @param list<string> $blocks
	 * @return list<array{block: int, row: int|null, cols: list<string>}>
	 */
	private static function columnGroups(array $blocks): array
	{
		$groups = [];
		foreach ($blocks as $index => $block) {
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
				if (!self::isColumn($class)) {
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

	/** @return list<array{block: int, row: int|null, cols: list<string>}> */
	private static function cdataColumns(): array
	{
		$body = file_get_contents(self::WIZARD);
		self::assertIsString($body, 'the wizard must be readable');
		preg_match_all('/<!\[CDATA\[(.*?)\]\]>/s', $body, $blocks);
		return self::columnGroups($blocks[1]);
	}

	/** @return list<string> */
	private static function classTokens(string $class): array
	{
		return preg_split('/\s+/', trim($class)) ?: [];
	}

	/** Membership by token, so "narrow" is not a row and "row-fluid" is not one either. */
	private static function hasClass(DOMElement $element, string $wanted): bool
	{
		return in_array($wanted, self::classTokens($element->getAttribute('class')), TRUE);
	}

	/**
	 * An offset-only column still needs a row.
	 *
	 * col-sm-offset-* carries the same gutter padding as a width class, so it is a column
	 * for the purpose of "must sit in a row" while contributing nothing to the 12 that a
	 * row holds. Matching the width pattern alone made these invisible to both assertions.
	 */
	private static function isColumn(string $class): bool
	{
		foreach (self::classTokens($class) as $token) {
			if (preg_match('/^col-sm-(?:offset-)?\d+$/', $token) === 1) {
				return TRUE;
			}
		}
		return FALSE;
	}

	/** Width from whole tokens, so an offset never reads as the width it offsets by. */
	private static function columnWidth(string $class): int
	{
		$width = 0;
		foreach (self::classTokens($class) as $token) {
			if (preg_match('/^col-sm-(\d+)$/', $token, $m) === 1) {
				$width += (int) $m[1];
			}
		}
		return $width;
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
				$width += self::columnWidth($class);
			}
			$where = $group['row'] === NULL ? 'outside any row' : "row {$group['row']}";
			$this->assertLessThanOrEqual(12, $width,
				"wizard CDATA block {$group['block']}, {$where}, declares {$width} columns: "
				. implode(', ', $group['cols']));
		}
	}

	/**
	 * The guard's own blind spots, pinned.
	 *
	 * Each row states a markup shape and whether an orphaned column is expected. Without
	 * this the scan can only be checked against a file that currently passes, which says
	 * nothing about the shapes it silently skips.
	 *
	 * @return list<array{0: string, 1: bool, 2: string}>
	 */
	public static function columnShapes(): array
	{
		return [
			['<div class="row"><div class="col-sm-6">a</div></div>', FALSE, 'a column in a row'],
			['<div class="col-sm-6">a</div>', TRUE, 'a bare column'],
			['<div class="row"><div class="col-sm-offset-3">a</div></div>', FALSE, 'an offset-only column in a row'],
			['<div class="col-sm-offset-3">a</div>', TRUE, 'an offset-only column with no row'],
			['<div class="narrow"><div class="col-sm-6">a</div></div>', TRUE, '"narrow" is not "row"'],
			['<div class="row-fluid"><div class="col-sm-6">a</div></div>', TRUE, '"row-fluid" is not "row"'],
			['<div class="row"><div><div class="col-sm-6">a</div></div></div>', FALSE, 'a column nested below its row'],
			['<div class="panel row"><div class="col-sm-6">a</div></div>', FALSE, 'a row carrying a second class'],
			['<!-- <div class="col-sm-6">a</div> -->', FALSE, 'a commented-out column is not live'],
			['<div class="col-sm-6"/><div class="row"><div class="col-sm-6">a</div></div>', TRUE, 'a self-closing div does not hide the orphan'],
		];
	}

	#[DataProvider('columnShapes')]
	public function testTheRowGuardSeesEachColumnShape(string $markup, bool $expectOrphan, string $why): void
	{
		$orphaned = FALSE;
		foreach (self::columnGroups([$markup]) as $group) {
			if ($group['row'] === NULL) {
				$orphaned = TRUE;
			}
		}
		$this->assertSame($expectOrphan, $orphaned, $why);
	}

	/** @return list<array{0: string, 1: int}> */
	public static function columnWidths(): array
	{
		return [
			['col-sm-6', 6],
			['col-sm-offset-3', 0],
			['col-sm-offset-3 col-sm-6', 6],
			['col-sm-6 col-sm-offset-3', 6],
			['col-md-8 col-sm-4', 4],
			['narrow', 0],
		];
	}

	#[DataProvider('columnWidths')]
	public function testAnOffsetNeverCountsAsWidth(string $class, int $expected): void
	{
		$this->assertSame($expected, self::columnWidth($class));
	}
}
