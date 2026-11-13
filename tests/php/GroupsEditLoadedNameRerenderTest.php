<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * issue #3955 -- the group editor's form carries the name of the group it loaded (aliasname_loaded), and the save refuses a form whose
 * row is another group by then (GroupsPageConfigLockTest). Which name the form carries is decided where the page prepares $pconfig for
 * the render: a form shown fresh takes the name stored at its row; a form shown again after a refused or invalid save keeps the name
 * it was posted with (the save branch leaves $pconfig = $_POST), because a refresh to the group that took the row meanwhile would let
 * the next Save through. The page's own statement is extracted from the shipped source and evaluated (PageStatementLoader.php); how the
 * field is written is pinned by GroupsEditLoadedNameFieldTest.
 *
 * Scenario P1: a form shown fresh -> the name stored at the row
 * Scenario P2: a form shown again after a refused save, a different group at the row now -> the name it was posted with
 * Scenario P3: a new group's form shown again, a group at the row now -> still the empty name it was posted with
 * Scenario P4: a form shown again after a save that posted no loaded name (a tab rendered before the field existed), another group at
 *              the row now -> no name, so a second Save is refused as the first was
 */
final class GroupsEditLoadedNameRerenderTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';

	private mixed $savedConfig;
	/** @var array<string, mixed> */
	private array $savedPost;

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsbl' => ['config' => [['aliasname' => 'Other'], ['aliasname' => 'Bravo']]]]];
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
	}

	/**
	 * @param array<string, mixed> $pconfig what the page holds for the render when it reaches the statement
	 * @return mixed the name the form is to carry
	 */
	private function loadedNameFor(array $pconfig): mixed
	{
		$region = pfb_test_page_region(self::PAGE, '// issue #3955: the group as this form loads it', 'if (!pfb_group_action_valid(');

		return pfb_test_page_eval($region, ['conf_type' => 'pfblockerngdnsbl', 'rowid' => 1, 'pconfig' => $pconfig])['pconfig']['aliasname_loaded'] ?? NULL;
	}

	public function testAFormShownFreshCarriesTheNameStoredAtItsRow(): void
	{
		$this->assertSame('Bravo', $this->loadedNameFor(['aliasname' => 'Bravo']));
	}

	public function testAFormShownAgainAfterARefusedSaveKeepsTheNameItWasPostedWith(): void
	{
		// Given a form loaded for Alpha, posted when row 1 holds Bravo
		$this->assertSame('Alpha', $this->loadedNameFor(['aliasname' => 'Alpha', 'aliasname_loaded' => 'Alpha']), 'not refreshed to Bravo');
	}

	public function testANewGroupsFormShownAgainKeepsItsEmptyNameWhenAGroupHasTakenTheRowSince(): void
	{
		$this->assertSame('', $this->loadedNameFor(['aliasname' => 'Delta', 'aliasname_loaded' => '']), 'an empty name is a name: it is not refreshed to Bravo');
	}

	/**
	 * The name the form is to carry after a POST whose save was refused: the page starts its form data from the request ($pconfig =
	 * $_POST ...), then reaches the statement above.
	 *
	 * @param array<string, mixed> $post
	 */
	private function loadedNameAfterAPost(array $post): mixed
	{
		$_POST = $post;
		$start = pfb_test_page_statement(self::PAGE, '/\$pconfig\s*=\s*\$_POST/');
		$region = pfb_test_page_region(self::PAGE, '// issue #3955: the group as this form loads it', 'if (!pfb_group_action_valid(');

		return pfb_test_page_eval($start . "\n" . $region, ['conf_type' => 'pfblockerngdnsbl', 'rowid' => 1])['pconfig']['aliasname_loaded'] ?? NULL;
	}

	public function testAFormShownAgainAfterASaveThatPostedNoLoadedNameCarriesNoneNotTheNameStoredNow(): void
	{
		// Given a save from a form that posted no loaded name, refused while row 1 holds Bravo
		$this->assertSame('Bravo', $GLOBALS['config']['installedpackages']['pfblockerngdnsbl']['config'][1]['aliasname'], 'before-state: row 1 holds Bravo');

		// Then the form shown again carries none: were it refreshed to Bravo, the next Save would overwrite Bravo
		$this->assertSame('', $this->loadedNameAfterAPost(['save' => 'save', 'aliasname' => 'Alpha']));
	}

	public function testAFormShownAgainAfterASaveThatPostedALoadedNameKeepsExactlyThatName(): void
	{
		$this->assertSame('Alpha', $this->loadedNameAfterAPost(['save' => 'save', 'aliasname' => 'AlphaRenamed', 'aliasname_loaded' => 'Alpha']));
	}
}
