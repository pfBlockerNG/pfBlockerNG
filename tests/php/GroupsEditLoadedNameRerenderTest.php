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
 */
final class GroupsEditLoadedNameRerenderTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';

	private mixed $savedConfig;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsbl' => ['config' => [['aliasname' => 'Other'], ['aliasname' => 'Bravo']]]]];
	}

	protected function tearDown(): void
	{
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
}
