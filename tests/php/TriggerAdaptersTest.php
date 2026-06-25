<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-43 Phase 3 — trigger API changes and deprecated verb adapters.
 *
 * These tests go RED on the Phase 1 code and GREEN after the Phase 3 changes:
 *
 * 1. pfb_trigger_request('update') now returns trigger='manual' (was 'cron').
 * 2. pfb_req_to_hook_trigger() maps 'manual'→'update', 'force'→'force-reload', 'cron'→'cron'.
 * 3. pfb_verb_deprecation_warning() returns a non-empty message for the deprecated verbs
 *    and '' for non-deprecated ones.
 *
 * Red→green evidence (pre-Phase-3 failures):
 *   testUpdateVerbMapsToManualTrigger           — pfb_trigger_request('update')['trigger']
 *                                                  returned 'cron', expected 'manual'
 *   testReqToHookTriggerMapping                 — fatal: pfb_req_to_hook_trigger undefined
 *   testDeprecatedVerbsHaveWarningMessages       — fatal: pfb_verb_deprecation_warning undefined
 *   testNonDeprecatedVerbsHaveNoWarningMessage   — fatal: pfb_verb_deprecation_warning undefined
 *
 * Existing oracle tests that go RED after Phase 3 (updated in TriggerRequestTest.php):
 *   TriggerRequestTest::testUpdateVerbMapsIdenticallyToCronToday — trigger was 'cron', now 'manual'
 */
#[CoversFunction('pfb_trigger_request')]
#[CoversFunction('pfb_req_to_hook_trigger')]
#[CoversFunction('pfb_verb_deprecation_warning')]
final class TriggerAdaptersTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_trigger_request — Phase 3 'update' verb gets 'manual' trigger
	// -----------------------------------------------------------------------

	/**
	 * Phase 3: 'update' verb now maps to trigger='manual', not 'cron'.
	 *
	 * This distinguishes a GUI Force Update (manual, operator-initiated) from the scheduled
	 * cron tick. PFB_TRIGGER = pfb_req_to_hook_trigger('manual') = 'update'.
	 *
	 * RED before Phase 3: pfb_trigger_request('update')['trigger'] === 'cron' (not 'manual').
	 */
	public function testUpdateVerbMapsToManualTrigger(): void
	{
		$req = pfb_trigger_request('update');

		$this->assertSame('both',   $req['scope'],
			"'update': scope must still be 'both'\ngot: " . json_encode($req['scope']));
		$this->assertFalse($req['force'],
			"'update': force must still be false\ngot: " . json_encode($req['force']));
		$this->assertSame('manual', $req['trigger'],
			"'update': Phase 3 assigns trigger='manual' (distinct from cron)\ngot: " . json_encode($req['trigger']));
	}

	/**
	 * Phase 3: non-deprecated verbs keep their Phase 1 structs unchanged.
	 *
	 * Only 'update' changed; 'cron', 'updateip', 'updatednsbl', 'noupdates', '' are
	 * preserved so existing callers and oracle tests stay green.
	 */
	public function testNonUpdatedVerbsKeepPhase1Structs(): void
	{
		$cases = [
			['cron',         'both',  FALSE, 'cron'],
			['noupdates',    'both',  FALSE, 'cron'],
			['updateip',     'ip',    TRUE,  'force'],
			['updatednsbl',  'dnsbl', TRUE,  'force'],
			['',             'both',  FALSE, 'cron'],
		];
		foreach ($cases as [$verb, $scope, $force, $trigger]) {
			$req = pfb_trigger_request($verb);
			$this->assertSame($scope,   $req['scope'],   "verb={$verb}: scope\ngot: " . json_encode($req['scope']));
			$this->assertSame($force,   $req['force'],   "verb={$verb}: force\ngot: " . json_encode($req['force']));
			$this->assertSame($trigger, $req['trigger'], "verb={$verb}: trigger\ngot: " . json_encode($req['trigger']));
		}
	}

	// -----------------------------------------------------------------------
	// pfb_req_to_hook_trigger — new pure helper (Phase 3)
	// -----------------------------------------------------------------------

	/**
	 * pfb_req_to_hook_trigger() maps the struct's 'trigger' field to the ADR-12 PFB_TRIGGER.
	 *
	 *   'force'  → 'force-reload'
	 *   'manual' → 'update'
	 *   'cron'   → 'cron'  (default)
	 *   unknown  → 'cron'  (safe default)
	 *
	 * RED before Phase 3: function undefined (fatal error).
	 */
	public function testReqToHookTriggerMapping(): void
	{
		$cases = [
			['force',   'force-reload'],
			['manual',  'update'],
			['cron',    'cron'],
			['',        'cron'],		// unknown → safe default
			['bogus',   'cron'],		// unknown → safe default
		];
		foreach ($cases as [$trigger, $expected]) {
			$pfb_trigger = pfb_req_to_hook_trigger($trigger);
			$this->assertSame($expected, $pfb_trigger,
				"pfb_req_to_hook_trigger('{$trigger}'): expected '{$expected}'\ngot: " . json_encode($pfb_trigger));
		}
	}

	/**
	 * pfb_req_to_hook_trigger() round-trips with pfb_trigger_request() for scheduled verbs.
	 *
	 * For the scheduled verbs (cron/noupdates/updateip/updatednsbl), the chain
	 * pfb_req_to_hook_trigger(pfb_trigger_request($verb)['trigger']) must agree with
	 * pfb_hook_trigger($verb).
	 *
	 * NOTE: '' (settings save) is a KNOWN asymmetry: pfb_trigger_request('')['trigger'] is
	 * 'cron' (default), but pfb_hook_trigger('') returns 'update'. The string path in
	 * sync_package_pfblockerng() uses pfb_hook_trigger() directly for '', preserving 'update'.
	 * '' is NOT in this test because the mismatch is intentional.
	 */
	public function testReqToHookTriggerAgreesWithHookTriggerForScheduledVerbs(): void
	{
		// Verbs where the two-function chain agrees with pfb_hook_trigger (PFB_TRIGGER unchanged)
		$verbs = ['cron', 'noupdates', 'updateip', 'updatednsbl'];
		foreach ($verbs as $verb) {
			$via_req  = pfb_req_to_hook_trigger(pfb_trigger_request($verb)['trigger']);
			$via_hook = pfb_hook_trigger($verb);
			$this->assertSame($via_hook, $via_req,
				"verb='{$verb}': pfb_req_to_hook_trigger(pfb_trigger_request(verb)['trigger'])" .
				" must equal pfb_hook_trigger(verb)\n" .
				"req path: " . json_encode($via_req) . "\nhook path: " . json_encode($via_hook));
		}
	}

	/**
	 * 'update' verb: Phase 3 PFB_TRIGGER is 'update' (via trigger='manual'), not 'cron'.
	 *
	 * Before Phase 3: pfblockerng.php called sync_package_pfblockerng('cron') for 'update',
	 * making PFB_TRIGGER='cron'. After Phase 3: 'update' → trigger='manual' → PFB_TRIGGER='update'.
	 */
	public function testUpdateVerbPfbTriggerIsUpdateAfterPhase3(): void
	{
		$req         = pfb_trigger_request('update');
		$pfb_trigger = pfb_req_to_hook_trigger($req['trigger']);

		$this->assertSame('manual', $req['trigger'],
			"'update' struct trigger must be 'manual'\ngot: " . json_encode($req['trigger']));
		$this->assertSame('update', $pfb_trigger,
			"'update' PFB_TRIGGER must be 'update' after Phase 3\ngot: " . json_encode($pfb_trigger));
	}

	// -----------------------------------------------------------------------
	// pfb_verb_deprecation_warning — new pure helper (Phase 3)
	// -----------------------------------------------------------------------

	/**
	 * Deprecated verbs return a non-empty warning message containing the verb name.
	 *
	 * The verbs 'update', 'updateip', 'updatednsbl' are deprecated as string arguments to
	 * sync_package_pfblockerng(). Each must produce a distinct, non-empty deprecation string.
	 *
	 * RED before Phase 3: function undefined (fatal error).
	 */
	public function testDeprecatedVerbsHaveWarningMessages(): void
	{
		foreach (['update', 'updateip', 'updatednsbl'] as $verb) {
			$msg = pfb_verb_deprecation_warning($verb);
			$this->assertNotEmpty($msg,
				"verb '{$verb}' must produce a non-empty deprecation warning\ngot: " . json_encode($msg));
			$this->assertStringContainsString($verb, $msg,
				"deprecation warning for '{$verb}' must name the verb\ngot: " . json_encode($msg));
			$this->assertStringContainsString('DEPRECATED', $msg,
				"deprecation warning for '{$verb}' must contain 'DEPRECATED'\ngot: " . json_encode($msg));
		}
	}

	/**
	 * Non-deprecated verbs return '' (no warning).
	 *
	 * The strings 'cron', 'noupdates', '', and unknown verbs are NOT deprecated; they must
	 * return an empty string so sync_package_pfblockerng() skips the log call.
	 *
	 * RED before Phase 3: function undefined (fatal error).
	 */
	public function testNonDeprecatedVerbsHaveNoWarningMessage(): void
	{
		foreach (['cron', 'noupdates', '', 'bogus', 'CRON', 'pfb_trigger'] as $verb) {
			$msg = pfb_verb_deprecation_warning($verb);
			$this->assertSame('', $msg,
				"verb '{$verb}' must produce no deprecation warning\ngot: " . json_encode($msg));
		}
	}

	/**
	 * Each deprecated verb warning mentions its canonical replacement args.
	 *
	 * The replacement hint (e.g. 'scope=both force=false trigger=manual') must appear in
	 * the warning so operators know the new API to use.
	 */
	public function testDeprecatedVerbWarningsMentionReplacementArgs(): void
	{
		$expected_hints = [
			'update'      => 'scope=both force=false trigger=manual',
			'updateip'    => 'scope=ip force=true trigger=force',
			'updatednsbl' => 'scope=dnsbl force=true trigger=force',
		];
		foreach ($expected_hints as $verb => $hint) {
			$msg = pfb_verb_deprecation_warning($verb);
			$this->assertStringContainsString($hint, $msg,
				"deprecation warning for '{$verb}' must mention replacement '{$hint}'\ngot: " . json_encode($msg));
		}
	}
}
