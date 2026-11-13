<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * issue #3955 -- the group editor's form carries the name of the group it loaded (aliasname_loaded), and the save refuses a form
 * whose row holds another group by then (GroupsPageConfigLockTest). The Feeds tab and the Reports tab open the editor through two
 * add flows that fill the page's in-memory group before the form is built: `act=addgroup&atype=<alias>` (a new group from a catalog
 * alias, or an IP whitelist) and `act=add&atype=<feed>` (a feed into the group of its alias, or into a new one). That in-memory
 * group carries the catalog's name for a group that is not stored yet, so the loaded name must be read from config.xml, the
 * way the save reads it, never from the in-memory group: else every new group made from the Feeds or Reports tab is refused.
 *
 * The page cannot be require()d off-appliance, so its own add-flow prologue and its loaded-name statement are extracted from the
 * shipped source and evaluated in turn (PageStatementLoader.php), over a catalog file of one alias with two feeds. The live render
 * and a save through each flow are pinned by tests/smoke/ui/test_category_edit_new_group_logging_default.py.
 *
 * Scenario A1: addgroup of a catalog alias onto a list that holds two groups -> the row is free, so no name
 * Scenario A2: addgroup of an IP whitelist (the Reports tab) -> no name
 * Scenario A3: addgroup onto an empty list -> no name
 * Scenario A4: add of a feed whose alias is not stored -> a new group at the next row, no name
 * Scenario A5: add of a feed whose alias is stored at row 1 -> that row, and its stored name
 */
final class GroupsEditAddFlowLoadedNameTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
	private const DNSBL = 'pfblockerngdnsbl';
	private const IPV4 = 'pfblockernglistsv4';

	private mixed $savedConfig;
	private mixed $savedFeeds;
	private string $catalog;

	protected function setUp(): void
	{
		global $pfb;
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedFeeds = $pfb['feeds'] ?? NULL;
		$this->catalog = sys_get_temp_dir() . '/pfb_add_flow_' . bin2hex(random_bytes(6)) . '.json';
		file_put_contents($this->catalog, json_encode(['dnsbl' => ['ADs' => [
			'description' => 'Ad servers',
			'cron' => 'EveryDay',
			'feeds' => [
				['header' => 'Feed_One', 'url' => 'https://example.invalid/one.txt'],
				['header' => 'Feed_Two', 'url' => 'https://example.invalid/two.txt'],
			],
		]]], JSON_THROW_ON_ERROR));
		$pfb['feeds'] = $this->catalog;
	}

	protected function tearDown(): void
	{
		global $pfb;
		@unlink($this->catalog);
		$pfb['feeds'] = $this->savedFeeds;
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
	}

	/**
	 * @param list<string> $stored the names of the groups stored in the section, in row order
	 * @return array{rowid: int|string, loaded: mixed, rowdata: array<mixed>} the row the form edits, the name it is to carry, the page's in-memory groups
	 */
	private function addFlow(string $gtype, string $conf, array $stored, string $action, string $atype): array
	{
		$GLOBALS['config'] = $stored === [] ? [] : ['installedpackages' => [$conf => ['config' => array_map(static fn (string $name): array => ['aliasname' => $name, 'row' => []], $stored)]]];
		unset($_POST['save']);
		$prologue = pfb_test_page_region(self::PAGE, "if ((\$action == 'add' || \$action == 'addgroup') && !empty(\$atype)", '// Catalog links prepopulate $rowdata');
		// act=add onto an alias that is not stored yet reads the new group's 'row' before it exists: a notice of the page, not of this test
		set_error_handler(static fn (int $level, string $message): bool => $message === 'Undefined array key "row"');
		try {
			$scope = pfb_test_page_eval($prologue, ['action' => $action, 'atype' => $atype, 'gtype' => $gtype, 'conf_type' => $conf, 'rowid' => 0]);
		} finally {
			restore_error_handler();
		}

		$region = pfb_test_page_region(self::PAGE, '// issue #3955: the group as this form loads it', 'if (!pfb_group_action_valid(');
		$page = pfb_test_page_eval($region, $scope + ['pconfig' => []]);

		return ['rowid' => $scope['rowid'], 'loaded' => $page['pconfig']['aliasname_loaded'] ?? NULL, 'rowdata' => $scope['rowdata']];
	}

	public function testAGroupAddedFromACatalogAliasCarriesNoLoadedNameWhateverTheCatalogCallsIt(): void
	{
		$form = $this->addFlow('dnsbl', self::DNSBL, ['Alpha', 'Bravo'], 'addgroup', 'ADs');

		$this->assertSame(2, $form['rowid'], 'before-state: the new group is the third row');
		$this->assertSame('ADs', $form['rowdata'][2]['aliasname'] ?? NULL, 'before-state: the page\'s in-memory group already carries the catalog\'s name');
		$this->assertSame('', $form['loaded'], 'no group is loaded: the row is free, which the save checks');
	}

	public function testAnIpWhitelistAddedFromTheReportsTabCarriesNoLoadedName(): void
	{
		$form = $this->addFlow('ipv4', self::IPV4, ['Alpha', 'Bravo'], 'addgroup', 'Whitelist|192.0.2.55|a note');

		$this->assertSame(2, $form['rowid'], 'before-state: the whitelist is the third row');
		$this->assertSame('Whitelist', $form['rowdata'][2]['aliasname'] ?? NULL, 'before-state: the page\'s in-memory group already carries the name Whitelist');
		$this->assertSame('', $form['loaded']);
	}

	public function testAGroupAddedOntoAnEmptyListCarriesNoLoadedName(): void
	{
		$form = $this->addFlow('dnsbl', self::DNSBL, [], 'addgroup', 'ADs');

		$this->assertSame(0, $form['rowid'], 'before-state: the first group is row 0');
		$this->assertSame('ADs', $form['rowdata'][0]['aliasname'] ?? NULL, 'before-state: the page\'s in-memory group already carries the catalog\'s name');
		$this->assertSame('', $form['loaded']);
	}

	public function testAFeedAddedToAnAliasThatIsNotStoredYetCarriesNoLoadedName(): void
	{
		$form = $this->addFlow('dnsbl', self::DNSBL, ['Alpha', 'Bravo'], 'add', 'Feed_One');

		$this->assertSame(2, $form['rowid'], 'before-state: the new group is the third row');
		$this->assertSame('ADs', $form['rowdata'][2]['aliasname'] ?? NULL, 'before-state: the page\'s in-memory group already carries the alias\'s name');
		$this->assertSame('', $form['loaded']);
	}

	/** @return array<string, array{string}> a feed of the stored group's alias */
	public static function feedsOfTheStoredAlias(): array
	{
		return ['its first feed' => ['Feed_One'], 'its second feed' => ['Feed_Two']];
	}

	#[DataProvider('feedsOfTheStoredAlias')]
	public function testAFeedAddedToAnAliasThatIsStoredCarriesThatGroupsStoredName(string $feed): void
	{
		$form = $this->addFlow('dnsbl', self::DNSBL, ['Alpha', 'ADs'], 'add', $feed);

		$this->assertSame(1, $form['rowid'], 'before-state: the form edits the stored group, row 1');
		$this->assertSame('ADs', $form['loaded'], 'the group is loaded: the save checks that row 1 still holds it');
	}
}
