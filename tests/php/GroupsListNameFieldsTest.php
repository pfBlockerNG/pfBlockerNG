<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * issue #3945 -- the Groups list's bulk update (Save) posts the form's fields as `postdata` and the row order as `ids`, both by row
 * index. The index alone can be another group by the time the update is served, so every row of the list carries the name of its
 * group in a hidden `aliasname-N` field, which the form serializes with the row's own selects, and the handler refuses an update
 * whose names are not the groups at those rows (GroupsPageConfigLockTest).
 *
 * These cases render the page's own markup of a row's name cell: the field is there for every row, named for the row's index, and
 * holds exactly the stored name -- the whole of a long name the cell shows cut short, and every character of an odd one.
 */
final class GroupsListNameFieldsTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_category.php';

	/** @return array<string, array{string}> */
	public static function storedNames(): array
	{
		return [
			'a plain name' => ['Alpha_1'],
			'a name the cell shows cut short' => ['AVeryLongGroupNameOfThirtyChars_x'],
			'a name with quotes and markup' => ['a"b\'c<d>&e'],
			'a name with a non-ASCII letter' => ["caf\u{e9}"],
			'a continent with a space' => ['North America'],
		];
	}

	#[DataProvider('storedNames')]
	public function testEveryRowCarriesItsGroupsExactNameInAHiddenFieldNamedForItsIndex(string $name): void
	{
		$region = pfb_test_page_region(self::PAGE, '$aliasname_raw = $row[\'aliasname\'];', '</td>');

		ob_start();
		try {
			pfb_test_page_eval($region, ['row' => ['aliasname' => $name], 'r_id' => 4]);
		} finally {
			$html = (string) ob_get_clean();
		}
		$document = new DOMDocument();
		libxml_use_internal_errors(TRUE);
		$document->loadHTML('<html><head><meta charset="utf-8"></head><body><table><tr><td>' . $html . '</td></tr></table></body></html>');
		libxml_clear_errors();
		$fields = (new DOMXPath($document))->query('//td/input[@type="hidden"]');

		$this->assertCount(1, $fields, "the name cell has one hidden field: {$html}");
		$this->assertSame('aliasname-4', $fields->item(0)->getAttribute('name'), 'it is named for the row index the selects are named for');
		$this->assertSame($name, $fields->item(0)->getAttribute('value'), 'it holds the stored name, whole and as it is');
	}
}
