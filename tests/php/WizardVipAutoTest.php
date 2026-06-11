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
 * Part B (step4_submitphpaction persistence shape) is NOT unit-invoked here — see
 * the @todo on testStep4PersistenceShapeIsNotUnitInvokable for the concrete blocker.
 */
#[CoversFunction('step3_submitphpaction')]
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
	 * Part B (step4_submitphpaction persistence shape) — FALLBACK, documented.
	 *
	 * @todo step4_submitphpaction() cannot be unit-invoked under the tests/php/
	 *   doubles without a src/ refactor, so its persistence shape (writing
	 *   pfb_dnsvip_auto and guarding the pfb_dnsvip4/6 id writes) is NOT covered here.
	 *   Reading the shipped function end-to-end, three hard blockers stand before any
	 *   assertable persistence:
	 *     1. It ends in `header("Location: .../pfblockerng_update.php?wizard=reload"); exit;`
	 *        — `exit` would terminate the PHPUnit process.
	 *     2. It early-returns with an input_error unless `json_decode(@file_get_contents(
	 *        $pfb['feeds']))` yields a feeds array — i.e. it requires a live feeds DB
	 *        fixture before reaching the config-mutation block.
	 *     3. Before the exit it calls undoubled pfSense services —
	 *        services_unbound_configure(), system_resolvconf_generate(),
	 *        system_dhcpleases_configure() — with live side effects.
	 *   Exercising it cleanly needs the config-mutation block (the auto gate + the
	 *   $new_config[...]['pfblockerngdnsblsettings'][0][...] writes) extracted into a
	 *   pure helper returning the array — a src/-touching change, hence its own
	 *   ADR-23 phase/PR, out of scope for this tests-only phase. The step3 direct
	 *   invocation above already pins the SAME inlined auto-gate predicate on shipped
	 *   code, and DnsblMarkedVipTest pins the ADR-13 engine that step4's flag drives.
	 */
	public function testStep4PersistenceShapeIsNotUnitInvokable(): void
	{
		$this->markTestSkipped(
			'step4_submitphpaction() ends in header()+exit, requires a feeds-DB fixture, '
			. 'and calls undoubled pfSense services — its persistence shape needs a src/ '
			. 'refactor to a pure helper (own ADR-23 phase). See the @todo above.'
		);
	}
}
