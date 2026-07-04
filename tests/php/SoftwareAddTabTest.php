<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #729 (origin PR #527) — pfb_software_add_tab() previously appended the "Software" tab
 * on provenance alone, while pfblockerng_software.php itself enforces a SECONDARY PRIVILEGE
 * GATE (issue #485: isAllowedPage('pkg_mgr_installed.php')). A user with the pfBlockerNG page
 * priv but without the Package Manager "Installed" priv saw the tab, clicked it, and silently
 * bounced to /index.php. The fix requires BOTH gates before the tab is appended.
 *
 * $provenance_ok is the function's injectable seam (mirrors the $io pattern in
 * pfb_software_update_check): NULL falls through to the real pfb_software_provenance_ok(),
 * an explicit bool bypasses it (the real predicate reads on-appliance state, unreachable
 * off-box). The privilege gate has no seam — every case goes through the real isAllowedPage()
 * call, controlled by its double via $GLOBALS['pfb_test_allowed_pages'] (absent key = allowed),
 * so the tests prove the production code actually calls isAllowedPage().
 *
 * Documented out-of-CI limitation: the live restricted-user leg (a GUI session holding the
 * pfBlockerNG priv but not pkg_mgr_installed, asserting the tab absent) is not automatable —
 * the WebUI harness logs in as admin only (uid-0 short-circuits isAllowedPage), and building
 * non-admin user provisioning/login is disproportionate here. This class pins the branch
 * off-box; the admin-visible/provenance tab behaviour stays pinned by the Tier-A UI tests.
 */
#[CoversFunction('pfb_software_add_tab')]
final class SoftwareAddTabTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['pfb_test_allowed_pages'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_allowed_pages']);
	}

	private function hasSoftwareTab(array $tab_array): bool
	{
		foreach ($tab_array as $tab) {
			if (($tab[2] ?? null) === '/pfblockerng/pfblockerng_software.php') {
				return true;
			}
		}
		return false;
	}

	/**
	 * Given an our-repo build AND a user holding the Package Manager "Installed" privilege,
	 * When the tab is built,
	 * Then the Software tab is appended.
	 */
	public function testProvenanceOkAndPageAllowedAppendsTab(): void
	{
		$tab_array = [];
		$this->assertFalse($this->hasSoftwareTab($tab_array), 'before: no tab yet');

		// Page priv rides the isAllowedPage() double's default (absent key = allowed).
		pfb_software_add_tab($tab_array, false, true);

		$this->assertTrue($this->hasSoftwareTab($tab_array), 'after: tab appended when both gates pass');
	}

	/**
	 * THE FIX — Given an our-repo build (provenance OK) but a user WITHOUT the Package Manager
	 * "Installed" privilege (isAllowedPage('pkg_mgr_installed.php') === false via its double),
	 * When the tab is built,
	 * Then the Software tab is NOT appended — it must never dead-end at /index.php.
	 * Red/green evidence: with the $provenance_ok seam in place, removing the isAllowedPage()
	 * clause makes this test FAIL (proven at the gate). Against the literal pre-fix two-param
	 * signature the extra arg is ignored and the off-box provenance predicate already withholds
	 * the tab, so there the pre-fix red is carried by testProvenanceOkAndPageAllowedAppendsTab.
	 */
	public function testProvenanceOkButPageNotAllowedDoesNotAppendTab(): void
	{
		$GLOBALS['pfb_test_allowed_pages']['pkg_mgr_installed.php'] = false;

		$tab_array = [];
		$this->assertFalse($this->hasSoftwareTab($tab_array), 'before: no tab yet');

		pfb_software_add_tab($tab_array, false, true);

		$this->assertFalse($this->hasSoftwareTab($tab_array), 'after: tab withheld without the Package Manager priv');
	}

	/**
	 * Existing behaviour pinned — Given a NON our-repo build (provenance not OK), even with the
	 * Package Manager privilege granted,
	 * When the tab is built,
	 * Then the Software tab is NOT appended (a Netgate/sideloaded install never shows it).
	 */
	public function testProvenanceNotOkDoesNotAppendTab(): void
	{
		$tab_array = [];
		$this->assertFalse($this->hasSoftwareTab($tab_array), 'before: no tab yet');

		pfb_software_add_tab($tab_array, false, false);

		$this->assertFalse($this->hasSoftwareTab($tab_array), 'after: tab withheld on a non-our-repo build');
	}
}
