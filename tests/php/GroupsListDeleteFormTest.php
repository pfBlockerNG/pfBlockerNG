<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * issue #3945 -- the Groups list deletes the group at a row index. The index alone can be another group by the time the request is
 * served (the group it was shown for was deleted since), so the page's delete posts the group's name too and the handler refuses a
 * delete whose name is not the group at that index (GroupsPageConfigLockTest).
 *
 * The delete is a form post: the trash icon's onclick fills the form's hidden fields (row index, action) and submits it. These cases
 * render the page's own markup for it: the form has the hidden `aliasname` field, and each icon fills it with exactly the group's name,
 * whatever characters a stored name holds. The page's row loop keeps the raw name ($aliasname_raw) and escapes $row['aliasname'] for HTML.
 */
final class GroupsListDeleteFormTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_category.php';

	/** @param array<string, mixed> $vars */
	private static function render(string $region, array $vars): string
	{
		ob_start();
		try {
			pfb_test_page_eval('?>' . $region, $vars);
		} finally {
			$html = (string) ob_get_clean();
		}
		return $html;
	}

	private static function document(string $html): DOMXPath
	{
		$document = new DOMDocument();
		libxml_use_internal_errors(TRUE);
		$document->loadHTML('<html><body>' . $html . '</body></html>');
		libxml_clear_errors();
		return new DOMXPath($document);
	}

	public function testTheListFormHasAHiddenAliasnameFieldForTheDelete(): void
	{
		$region = pfb_test_page_region(self::PAGE, '<form action="pfblockerng_category.php"', '<div class="panel panel-default">');

		$fields = self::document(self::render($region, ['gtype' => 'dnsbl']) . '</form>')->query('//form[@id="iform"]//input[@type="hidden"]');

		$names = [];
		foreach ($fields as $field) {
			$names[(string) $field->getAttribute('id')] = (string) $field->getAttribute('name');
		}
		$this->assertSame('aliasname', $names['aliasname'] ?? NULL, 'the delete posts the group name in the hidden aliasname field, next to rowid and act');
		$this->assertSame('rowid', $names['rowid'] ?? NULL);
		$this->assertSame('act', $names['act'] ?? NULL);
	}

	/** @return array<string, array{string}> */
	public static function storedNames(): array
	{
		return [
			'a plain name' => ['Alpha_1'],
			'a name with quotes and markup' => ['a"b\'c<d>&e'],
			'a name with a backslash' => ['a\\b'],
			'a name with a non-ASCII letter' => ["caf\u{e9}"],
		];
	}

	#[DataProvider('storedNames')]
	public function testEachTrashIconFillsTheAliasnameFieldWithTheNameOfItsGroup(string $name): void
	{
		$region = pfb_test_page_region(self::PAGE, '<i class="fa-solid fa-trash-can', '</i>');

		$icons = self::document(self::render($region . '</i>', ['row' => ['aliasname' => htmlspecialchars($name)], 'aliasname_raw' => $name, 'r_id' => 3]))->query('//i[contains(@class, "fa-trash-can")]');

		$this->assertCount(1, $icons, 'one trash icon');
		$onclick = (string) $icons->item(0)->getAttribute('onclick');
		$this->assertStringContainsString("\$('#rowid').val('3')", $onclick, 'it still fills the row index');
		$this->assertSame(1, preg_match("~\\\$\\('#aliasname'\\)\\.val\\((\".*\")\\);\\\$\\('#act'\\)\\.val\\('del'\\)~s", $onclick, $found), "it fills the group name before it submits: {$onclick}");
		$this->assertSame($name, json_decode($found[1], TRUE, 512, JSON_THROW_ON_ERROR), 'the value it fills is exactly the stored name');
	}
}
