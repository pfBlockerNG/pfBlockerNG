<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-23 — the setup wizard's Auto VIP gate (Phase 1). The wizard offers a
 * pfb_dnsvip_auto checkbox so a fresh install can let ADR-13 auto-provision the
 * DNSBL sinkhole VIP instead of forcing the operator to pick a manual VIP on the
 * wizard step. Phase 1 added the same boolean gate
 *   $pfb_auto = isset($_POST['pfb_dnsvip_auto']) && $_POST['pfb_dnsvip_auto'] == 'on'
 * to TWO controllers:
 *   1. step3_submitphpaction() — SKIPS pfb_validate_vips()/the 'none'->'' normalise
 *      when auto is ON (the operator supplies no VIP in auto mode, so requiring a
 *      valid one would block the wizard).
 *   2. step4_submitphpaction() — persists the flag and guards the VIP-id writes.
 *
 * This pins the REAL shipped branch in step3_submitphpaction() (loaded verbatim by
 * tests/php/bootstrap.php) rather than re-implementing the predicate in the test:
 * the gate is inlined in the controller (no extracted helper to call), so asserting
 * the inlined boolean would be coverage theater. Instead we drive the controller and
 * observe whether VIP validation runs — the OBSERVABLE consequence of the gate.
 *
 * Branch coverage per CLAUDE.md: auto OFF and auto ON are both exercised with the
 * SAME invalid (empty) VIP selection, and the OFF before-state is asserted first so
 * green proves the auto flip CAUSED validation to be skipped — not an always-skip
 * path. The falsey strings '' and '0' are pinned as OFF too (mirrors
 * WizardDecisionTest::testSuppressCheckboxFalseyValuesStaySkip).
 *
 * Part B (the persisted DNSBL-VIP settings shape) is covered directly via the pure
 * helper pfb_wizard_dnsvip_settings() (ADR-23), which step4_submitphpaction() now
 * calls to build the slice it merges into the DNSBL config — see
 * testAutoVipToggleDecidesPersistedDnsvipSettings.
 */
#[CoversFunction('step3_submitphpaction')]
#[CoversFunction('pfb_wizard_dnsvip_settings')]
final class WizardVipAutoTest extends TestCase
{
	/**
	 * Reset the shared globals step3_submitphpaction() reads/writes via
	 * `global $stepid, $input_errors;` so each case starts clean (input_errors is
	 * accumulated, not replaced, by the controller — a leaked entry would give a
	 * false pass/fail).
	 */
	protected function setUp(): void
	{
		$GLOBALS['input_errors'] = [];
		$GLOBALS['stepid'] = 2;
		$_POST = [];
	}

	protected function tearDown(): void
	{
		$_POST = [];
		$GLOBALS['input_errors'] = [];
	}

	/** Did the controller surface a DNSBL VIP-validation error this run? */
	private function hasDnsblError(): bool
	{
		foreach ($GLOBALS['input_errors'] as $err) {
			if (is_string($err) && str_starts_with($err, 'DNSBL:')) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A wizard step3 POST with an empty (invalid) VIP selection and valid ports — the
	 * common knobs both auto OFF and auto ON cases share. Ports are deliberately valid
	 * so the separate port-validation branch never adds an unrelated error that could
	 * mask the VIP branch under test.
	 *
	 * @return array<string,string>
	 */
	private function postWithInvalidVip(): array
	{
		return [
			'back'           => '',   // present so the controller's $_POST['back'] read is defined
			'pfb_dnsvip4'    => '',   // no VIP -> pfb_validate_vips() returns "no VIP configured"
			'pfb_dnsvip6'    => '',
			'pfb_dnsport'    => '8081',
			'pfb_dnsport_ssl' => '8443',
		];
	}

	/**
	 * Scenario: the Auto VIP checkbox decides whether the wizard validates the VIP.
	 *
	 *   Background:
	 *     Given a wizard step3 POST whose VIP selection is empty (invalid)
	 *       and whose DNSBL ports are valid
	 *
	 *   When pfb_dnsvip_auto is absent (auto OFF)
	 *   Then step3 runs pfb_validate_vips() and surfaces a "DNSBL: ..." input error
	 *
	 *   --- the OFF before-state above is asserted FIRST ---
	 *
	 *   When pfb_dnsvip_auto = 'on' (auto ON), same invalid VIP
	 *   Then step3 SKIPS validation and surfaces NO "DNSBL: ..." error
	 *
	 * The two halves sharing one invalid VIP is what proves the auto flip — not the
	 * VIP value — caused the change.
	 */
	public function testAutoOnSkipsVipValidationThatAutoOffEnforces(): void
	{
		// Given/When: auto OFF (checkbox absent), invalid VIP.
		$GLOBALS['input_errors'] = [];
		$_POST = $this->postWithInvalidVip();
		step3_submitphpaction();

		// Then (before-state): validation ran -> a DNSBL error is present.
		$this->assertTrue(
			$this->hasDnsblError(),
			'auto OFF must run pfb_validate_vips() and reject the empty VIP'
		);

		// When: flip auto ON, SAME invalid VIP.
		$GLOBALS['input_errors'] = [];
		$_POST = $this->postWithInvalidVip();
		$_POST['pfb_dnsvip_auto'] = 'on';
		step3_submitphpaction();

		// Then (after-state): validation skipped -> no DNSBL error. Green here only
		// because the auto flag flipped, proving the gate is a real branch.
		$this->assertFalse(
			$this->hasDnsblError(),
			'auto ON must SKIP VIP validation (ADR-13 auto-provisions the VIP)'
		);
	}

	/**
	 * The gate is strict equality to the checkbox-checked value 'on'. Every other
	 * value — the falsey strings '' and '0' a stale/empty submit can carry — must be
	 * treated as OFF so validation still runs (mirrors the suppress-checkbox falsey
	 * handling in WizardDecisionTest). Without this, an empty 'pfb_dnsvip_auto' POST
	 * field would silently disable VIP validation.
	 *
	 * @testWith [""]
	 *           ["0"]
	 */
	public function testAutoFalseyValuesStillEnforceVipValidation(string $falsey): void
	{
		$GLOBALS['input_errors'] = [];
		$_POST = $this->postWithInvalidVip();
		$_POST['pfb_dnsvip_auto'] = $falsey;
		step3_submitphpaction();

		$this->assertTrue(
			$this->hasDnsblError(),
			"pfb_dnsvip_auto='{$falsey}' is falsey -> auto OFF -> VIP validation must run"
		);
	}

	/**
	 * Part B — the persisted DNSBL-VIP settings shape, on the pure helper
	 * step4_submitphpaction() now calls (pfb_wizard_dnsvip_settings). The controller
	 * itself can't be unit-invoked (it ends in header()+exit), so ADR-23 extracts the
	 * VIP-settings decision into this helper and the controller merges the returned
	 * slice into the DNSBL config — so testing the helper pins exactly what is written.
	 *
	 * Scenario: the Auto VIP choice decides which DNSBL-VIP keys are persisted.
	 *
	 *   Background:
	 *     Given step3 selected the manual lo0 VIP ids pfb_dnsvip4='_vip1', pfb_dnsvip6='_vip2'
	 *
	 *   When auto is OFF
	 *   Then pfb_dnsvip_auto persists as '' AND both manual ids are written through
	 *
	 *   --- the OFF before-state above is asserted FIRST ---
	 *
	 *   When auto is ON (same step3 ids passed)
	 *   Then pfb_dnsvip_auto persists as 'on' AND neither manual id is written
	 *        (ADR-13 owns/provisions the VIP, so the wizard must not pin a manual id)
	 *
	 * Passing the SAME ids to both calls proves the auto flag — not the id values —
	 * decides whether the manual ids are persisted.
	 */
	public function testAutoVipToggleDecidesPersistedDnsvipSettings(): void
	{
		// Given: step3's manual VIP selections.
		$vip4 = '_vip1';
		$vip6 = '_vip2';

		// When/Then (before-state): auto OFF persists the flag '' and BOTH manual ids.
		$off = pfb_wizard_dnsvip_settings(false, $vip4, $vip6);
		$this->assertSame('', $off['pfb_dnsvip_auto'], 'auto OFF must persist pfb_dnsvip_auto as empty');
		$this->assertSame('_vip1', $off['pfb_dnsvip4'], 'auto OFF must persist the manual IPv4 VIP id');
		$this->assertSame('_vip2', $off['pfb_dnsvip6'], 'auto OFF must persist the manual IPv6 VIP id');

		// When/Then (after-state): auto ON persists the flag 'on' and OMITS the manual
		// ids — the same ids are passed, so green here proves the flag drove the change.
		$on = pfb_wizard_dnsvip_settings(true, $vip4, $vip6);
		$this->assertSame('on', $on['pfb_dnsvip_auto'], 'auto ON must persist pfb_dnsvip_auto as on');
		$this->assertArrayNotHasKey('pfb_dnsvip4', $on, 'auto ON must NOT pin a manual IPv4 VIP id (ADR-13 owns it)');
		$this->assertArrayNotHasKey('pfb_dnsvip6', $on, 'auto ON must NOT pin a manual IPv6 VIP id (ADR-13 owns it)');
	}
}
