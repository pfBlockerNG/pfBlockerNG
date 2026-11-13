<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

if (!class_exists('Form_Input', FALSE)) {
	/** Off-appliance stand-in for pfSense's Form_Input: it renders as Form_Element::__toString does, every attribute value through htmlspecialchars(). */
	class Form_Input
	{
		public function __construct(public string $name, public string $title, public string $type = 'text', public mixed $value = '')
		{
		}

		public function __toString(): string
		{
			return '<input name="' . htmlspecialchars($this->name) . '" id="' . htmlspecialchars($this->name) . '" type="' . htmlspecialchars($this->type)
				. '" value="' . htmlspecialchars((string) $this->value) . '"/>';
		}
	}
}

if (!class_exists('Form', FALSE)) {
	/** Off-appliance stand-in for pfSense's Form: it keeps what the page adds as a global (hidden) field. */
	class Form
	{
		/** @var list<Form_Input> */
		public array $globals = [];

		public function addGlobal(Form_Input $input): Form_Input
		{
			$this->globals[] = $input;
			return $input;
		}
	}
}

/**
 * issue #3955 -- the group editor's save refuses a form whose row is another group by the time it is saved (a group deleted and
 * replaced at the same index between the page's render and Save). The form therefore carries the name of the group it loaded in a
 * hidden `aliasname_loaded` field, apart from the editable `aliasname` (a Save can rename), and the save compares it with the row
 * under the config lock (GroupsPageConfigLockTest).
 *
 * The page cannot be require()d off-appliance, so its own statements for the field are extracted from the shipped source and evaluated
 * (PageStatementLoader.php). Form_Input writes the value it is given through htmlspecialchars() itself, so the page hands it the raw
 * stored name: the browser decodes the attribute back to exactly that name, and posts it.
 * The live render of the same markup is pinned by tests/smoke/ui/test_category_config_lock.py.
 *
 * Scenario R1: the form of a stored group -> the hidden field holds its stored name, whole and as it is
 * Scenario R2: the form of a group that does not exist yet (an add) -> the hidden field is empty
 * Scenario R3: the field is written from the name $pconfig holds for it, never read from config.xml there (which name $pconfig holds after a
 *              refused save is decided where it is prepared: GroupsEditLoadedNameRerenderTest)
 */
final class GroupsEditLoadedNameFieldTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
	private const FIELD_STATEMENT = '/\$form->addGlobal\(new Form_Input\(\'aliasname_loaded\'/';
	private const LOADED_STATEMENT = '/\$pconfig\[\'aliasname_loaded\'\]\s*=/';

	private mixed $savedConfig;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
	}

	protected function tearDown(): void
	{
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
	}

	/** @param array<string, mixed> $vars the page's variables at that point @return list<DOMElement> the hidden fields the form carries */
	private function hiddenFields(array $vars, bool $loadsFromConfig): array
	{
		$this->assertSame(1, preg_match(self::FIELD_STATEMENT, pfb_test_page_source(self::PAGE)), 'the edit form carries a hidden aliasname_loaded field');
		$code = ($loadsFromConfig ? pfb_test_page_statement(self::PAGE, self::LOADED_STATEMENT) . "\n" : '') . pfb_test_page_statement(self::PAGE, self::FIELD_STATEMENT);
		$form = pfb_test_page_eval($code, $vars + ['form' => new Form(), 'pconfig' => []])['form'];

		$document = new DOMDocument();
		libxml_use_internal_errors(TRUE);
		$document->loadHTML('<html><head><meta charset="utf-8"></head><body>' . implode('', array_map('strval', $form->globals)) . '</body></html>');
		libxml_clear_errors();
		return iterator_to_array((new DOMXPath($document))->query('//input[@type="hidden"]'));
	}

	/** @return array<string, array{string}> */
	public static function storedNames(): array
	{
		return [
			'a plain name' => ['Alpha_1'],
			'a name with quotes and markup' => ['Br"a<v>&o\'s'],
			'a name with a backslash' => ['a\\b'],
			'a name with a non-ASCII letter' => ["caf\u{e9}"],
		];
	}

	#[DataProvider('storedNames')]
	public function testTheFormOfAStoredGroupCarriesItsStoredNameInAHiddenFieldApartFromTheEditableName(string $name): void
	{
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsbl' => ['config' => [['aliasname' => 'Other'], ['aliasname' => $name]]]]];

		$fields = $this->hiddenFields(['conf_type' => 'pfblockerngdnsbl', 'rowid' => 1], TRUE);

		$this->assertCount(1, $fields, 'one hidden field');
		$this->assertSame('aliasname_loaded', $fields[0]->getAttribute('name'), 'it is not the editable aliasname field, which a Save can change');
		$this->assertSame($name, $fields[0]->getAttribute('value'), 'it holds the name stored at the row the form edits, whole and as it is');
	}

	public function testTheFormOfAGroupThatDoesNotExistYetCarriesAnEmptyLoadedName(): void
	{
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsbl' => ['config' => [['aliasname' => 'Alpha']]]]];

		$fields = $this->hiddenFields(['conf_type' => 'pfblockerngdnsbl', 'rowid' => 1], TRUE);

		$this->assertCount(1, $fields);
		$this->assertSame('', $fields[0]->getAttribute('value'), 'no group is loaded: a new group saves only at a row that is still free');
	}

	public function testTheHiddenFieldIsWrittenFromTheNamePconfigHoldsForItNotFromTheNameStoredAtTheRow(): void
	{
		// Given $pconfig holding Alpha for the field, while the config holds Bravo at the row
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsbl' => ['config' => [['aliasname' => 'Bravo']]]]];

		// When the field's own statement runs (the one before it, that prepares $pconfig, does not)
		$fields = $this->hiddenFields(['conf_type' => 'pfblockerngdnsbl', 'rowid' => 0, 'pconfig' => ['aliasname' => 'Alpha', 'aliasname_loaded' => 'Alpha']], FALSE);

		// Then the field holds Alpha
		$this->assertCount(1, $fields);
		$this->assertSame('Alpha', $fields[0]->getAttribute('value'));
	}
}
