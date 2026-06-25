<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-43 Phase 1 — oracle-pin the trigger-verb → {scope, force, trigger} map.
 *
 * pfb_trigger_request() encapsulates the mapping that sync_package_pfblockerng()
 * previously derived implicitly from the $cron switch. These are ORACLE tests —
 * they stay GREEN across Phase 1's behaviour-preserving extraction and go RED in
 * Phase 3 when the trigger API is changed (e.g. 'update' → trigger='manual',
 * PFB_TRIGGER='update' instead of 'cron').
 *
 * Contract table pinned here (today's behaviour):
 *
 *   verb/path    scope   force   trigger  PFB_TRIGGER
 *   ----------   -----   -----   -------  -----------
 *   'cron'       both    false   cron     cron
 *   'update'     both    false   cron     cron  (indistinguishable from 'cron' inside the pass)
 *   'updateip'   ip      true    force    force-reload
 *   'updatednsbl' dnsbl  true    force    force-reload
 *   'noupdates'  both    false   cron     cron  (save-only pass, no reload)
 *
 * NOTE: 'update' and 'cron' share identical structs. This is the current code reality:
 * pfblockerng.php calls sync_package_pfblockerng('cron') for BOTH verbs, making them
 * indistinguishable. Phase 3 will give 'update' its own 'manual' trigger identity.
 *
 * NOTE: pfb_hook_trigger() is the current PFB_TRIGGER deriver; Phase 3 will fold its
 * mapping into pfb_trigger_request()'s 'trigger' field derivation.
 */
#[CoversFunction('pfb_trigger_request')]
#[CoversFunction('pfb_hook_trigger')]
final class TriggerRequestTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_trigger_request — struct oracles (one per verb / Force path)
	// -----------------------------------------------------------------------

	/**
	 * Oracle: 'cron' verb → both sides, no force, cron trigger.
	 *
	 * The scheduled cron job (pfblockerng.php cron → pfblockerng_sync_cron →
	 * sync_package_pfblockerng('cron')) runs both IP and DNSBL processing, respects the
	 * change detector, and identifies itself as a cron trigger for ADR-12 hooks.
	 */
	public function testCronVerbMapsToBothScopeNoForce(): void
	{
		$req = pfb_trigger_request('cron');

		$this->assertSame('both',  $req['scope'],
			"'cron': scope must be 'both' — scheduled run covers IP + DNSBL\n" .
			'got: ' . json_encode($req['scope']));
		$this->assertFalse($req['force'],
			"'cron': force must be false — respects change detector / fingerprint\n" .
			'got: ' . json_encode($req['force']));
		$this->assertSame('cron',  $req['trigger'],
			"'cron': trigger must be 'cron' — scheduled identity for ADR-12 hooks\n" .
			'got: ' . json_encode($req['trigger']));
	}

	/**
	 * Oracle: 'update' verb → same struct as 'cron' (indistinguishable today).
	 *
	 * pfblockerng.php calls sync_package_pfblockerng('cron') for BOTH the 'cron' and
	 * 'update' verbs; inside the pass they are IDENTICAL. The PFB_TRIGGER is 'cron' for
	 * both. Phase 3 will break this test by assigning 'update' its own 'manual' trigger.
	 */
	public function testUpdateVerbMapsIdenticallyToCronToday(): void
	{
		$req = pfb_trigger_request('update');

		$this->assertSame('both',  $req['scope'],
			"'update': scope must be 'both' — covers IP + DNSBL (same as cron)\n" .
			'got: ' . json_encode($req['scope']));
		$this->assertFalse($req['force'],
			"'update': force must be false — respects change detector (same as cron)\n" .
			'got: ' . json_encode($req['force']));
		$this->assertSame('cron',  $req['trigger'],
			"'update': trigger must be 'cron' today — indistinguishable from scheduled cron\n" .
			"Phase 3 will change this to 'manual' (red→green signal)\n" .
			'got: ' . json_encode($req['trigger']));
	}

	/**
	 * Oracle: 'updateip' verb → IP scope only, force=true, force trigger.
	 *
	 * GUI "Force Reload - IP" (pfblockerng_update.php → pfblockerng.php updateip →
	 * sync_package_pfblockerng('updateip')): applies IP tables from cached lists (no
	 * feed re-download), bypassing the change detector for the IP side.
	 */
	public function testUpdateipVerbMapsToIpScopeForced(): void
	{
		$req = pfb_trigger_request('updateip');

		$this->assertSame('ip',   $req['scope'],
			"'updateip': scope must be 'ip' — IP-side reload only\n" .
			'got: ' . json_encode($req['scope']));
		$this->assertTrue($req['force'],
			"'updateip': force must be true — applies from cache, bypasses change detector\n" .
			'got: ' . json_encode($req['force']));
		$this->assertSame('force', $req['trigger'],
			"'updateip': trigger must be 'force' — operator-initiated force-reload identity\n" .
			'got: ' . json_encode($req['trigger']));
	}

	/**
	 * Oracle: 'updatednsbl' verb → DNSBL scope only, force=true, force trigger.
	 *
	 * GUI "Force Reload - DNSBL" (pfblockerng_update.php → pfblockerng.php updatednsbl →
	 * sync_package_pfblockerng('updatednsbl')): applies DNSBL from cached data and always
	 * reloads Unbound, independent of the content fingerprint ($pfb['updatednsbl']=TRUE).
	 */
	public function testUpdatednsblVerbMapsToDnsblScopeForced(): void
	{
		$req = pfb_trigger_request('updatednsbl');

		$this->assertSame('dnsbl', $req['scope'],
			"'updatednsbl': scope must be 'dnsbl' — DNSBL-side reload only\n" .
			'got: ' . json_encode($req['scope']));
		$this->assertTrue($req['force'],
			"'updatednsbl': force must be true — always reloads Unbound, bypasses fingerprint\n" .
			'got: ' . json_encode($req['force']));
		$this->assertSame('force', $req['trigger'],
			"'updatednsbl': trigger must be 'force' — operator-initiated force-reload identity\n" .
			'got: ' . json_encode($req['trigger']));
	}

	/**
	 * Oracle: 'noupdates' verb → both scope, no force, cron trigger (save-only pass).
	 *
	 * pfblockerng_sync_cron() calls sync_package_pfblockerng('noupdates') when no feeds
	 * need updating — the function sets $pfb['save']=TRUE and performs no reload. The
	 * struct captures the declared scope/force; the save-only side-channel is separate.
	 */
	public function testNoupdatesVerbMapsToBothScopeNoForce(): void
	{
		$req = pfb_trigger_request('noupdates');

		$this->assertSame('both',  $req['scope'],
			"'noupdates': scope must be 'both' — save-only pass (no reload performed)\n" .
			'got: ' . json_encode($req['scope']));
		$this->assertFalse($req['force'],
			"'noupdates': force must be false — no reload at all on this path\n" .
			'got: ' . json_encode($req['force']));
		$this->assertSame('cron',  $req['trigger'],
			"'noupdates': trigger must be 'cron' — cron path's no-change branch\n" .
			'got: ' . json_encode($req['trigger']));
	}

	/**
	 * Oracle: unknown / empty $verb → both scope, no force, cron trigger (safe default).
	 *
	 * The '' value is passed by settings saves (pfblockerng_general.php) and the
	 * de-install path. Any unknown verb falls through to the safe default.
	 */
	public function testUnknownVerbFallsToSafeDefault(): void
	{
		foreach (['', 'bogus', 'CRON'] as $verb) {
			$req = pfb_trigger_request($verb);

			$this->assertSame('both',  $req['scope'],
				"verb={$verb}: unknown verb scope must fall to 'both'\ngot: " . json_encode($req['scope']));
			$this->assertFalse($req['force'],
				"verb={$verb}: unknown verb force must fall to false\ngot: " . json_encode($req['force']));
			$this->assertSame('cron',  $req['trigger'],
				"verb={$verb}: unknown verb trigger must fall to 'cron'\ngot: " . json_encode($req['trigger']));
		}
	}

	// -----------------------------------------------------------------------
	// PFB_TRIGGER oracles — pfb_hook_trigger() maps $cron to the hook env value.
	// These are the ADR-12 PFB_TRIGGER values the hook contract must preserve.
	// Phase 3 will derive PFB_TRIGGER from pfb_trigger_request()'s 'trigger' field
	// instead; the tests below will go RED when that derivation changes.
	// -----------------------------------------------------------------------

	/**
	 * Oracle: PFB_TRIGGER for 'cron' $cron is 'cron'.
	 *
	 * Scheduled cron and GUI "Force Update" (both pass $cron='cron') emit 'cron'
	 * as the ADR-12 hook trigger. Pinned so Phase 3's new derivation can be verified.
	 */
	public function testCronCronArgYieldsPfbTriggerCron(): void
	{
		$pfb_trigger = pfb_hook_trigger('cron');

		$this->assertSame('cron', $pfb_trigger,
			'cron=$cron: PFB_TRIGGER must be \'cron\' today' . "\n" .
			'got: ' . json_encode($pfb_trigger));
	}

	/**
	 * Oracle: PFB_TRIGGER for the 'update' verb is 'cron' (pfblockerng.php passes 'cron').
	 *
	 * pfblockerng.php case 'update': calls sync_package_pfblockerng('cron'), so the
	 * effective PFB_TRIGGER is pfb_hook_trigger('cron') = 'cron'. Phase 3 will change
	 * this: 'update' verb → PFB_TRIGGER='update' (a distinct non-cron identity).
	 */
	public function testUpdateVerbYieldsPfbTriggerCronTodayViaPassthrough(): void
	{
		// pfblockerng.php translates 'update' → sync_package_pfblockerng('cron').
		// The hook sees pfb_hook_trigger('cron').
		$pfb_trigger = pfb_hook_trigger('cron');

		$this->assertSame('cron', $pfb_trigger,
			"'update' verb path (cron='cron'): PFB_TRIGGER must be 'cron' today\n" .
			"Phase 3 will change 'update' to emit PFB_TRIGGER='update' (red->green signal)\n" .
			'got: ' . json_encode($pfb_trigger));
	}

	/**
	 * Oracle: PFB_TRIGGER for 'updateip' $cron is 'force-reload'.
	 *
	 * GUI "Force Reload - IP" passes $cron='updateip' → PFB_TRIGGER='force-reload'.
	 * Pinned for Phase 3 which will derive 'force-reload' from trigger='force' instead.
	 */
	public function testUpdateipCronArgYieldsPfbTriggerForceReload(): void
	{
		$pfb_trigger = pfb_hook_trigger('updateip');

		$this->assertSame('force-reload', $pfb_trigger,
			"cron='updateip': PFB_TRIGGER must be 'force-reload' today\n" .
			'got: ' . json_encode($pfb_trigger));
	}

	/**
	 * Oracle: PFB_TRIGGER for 'updatednsbl' $cron is 'force-reload'.
	 *
	 * GUI "Force Reload - DNSBL" passes $cron='updatednsbl' → PFB_TRIGGER='force-reload'.
	 * Pinned for Phase 3 which will derive 'force-reload' from trigger='force' instead.
	 */
	public function testUpdatednsblCronArgYieldsPfbTriggerForceReload(): void
	{
		$pfb_trigger = pfb_hook_trigger('updatednsbl');

		$this->assertSame('force-reload', $pfb_trigger,
			"cron='updatednsbl': PFB_TRIGGER must be 'force-reload' today\n" .
			'got: ' . json_encode($pfb_trigger));
	}

	/**
	 * Oracle: PFB_TRIGGER for 'noupdates' $cron is 'cron'.
	 *
	 * The no-change cron branch emits 'cron' as the trigger (save-only pass).
	 */
	public function testNoupdatesCronArgYieldsPfbTriggerCron(): void
	{
		$pfb_trigger = pfb_hook_trigger('noupdates');

		$this->assertSame('cron', $pfb_trigger,
			"cron='noupdates': PFB_TRIGGER must be 'cron' — no-change cron pass\n" .
			'got: ' . json_encode($pfb_trigger));
	}

	/**
	 * Oracle: PFB_TRIGGER for '' (settings save / de-install) is 'update'.
	 *
	 * The empty $cron default (pfblockerng_general.php save, de-install) emits 'update'
	 * as the trigger. This is the distinct non-cron path the '' case identifies.
	 */
	public function testEmptyCronArgYieldsPfbTriggerUpdate(): void
	{
		$pfb_trigger = pfb_hook_trigger('');

		$this->assertSame('update', $pfb_trigger,
			"cron='': PFB_TRIGGER must be 'update' — settings save / de-install path\n" .
			'got: ' . json_encode($pfb_trigger));
	}

	// -----------------------------------------------------------------------
	// Consistency oracle: pfb_trigger_request()'s 'trigger' field must agree with
	// pfb_hook_trigger() for the verbs where their mapping is the same.
	// -----------------------------------------------------------------------

	/**
	 * Oracle: pfb_trigger_request() 'trigger' and pfb_hook_trigger() agree on 'cron'.
	 *
	 * For verbs where both functions exist today, the 'trigger' vocab must be
	 * consistent: 'cron' struct trigger → pfb_hook_trigger emits 'cron'.
	 * Phase 3 breaks this for 'update' (struct 'manual' → hook 'update').
	 */
	public function testStructTriggerAndHookTriggerAgreeForCronVerb(): void
	{
		$req         = pfb_trigger_request('cron');
		$pfb_trigger = pfb_hook_trigger('cron');

		// struct trigger='cron' → pfb_hook_trigger maps 'cron' → 'cron'
		$this->assertSame('cron',  $req['trigger'], 'struct trigger for cron verb');
		$this->assertSame('cron', $pfb_trigger,     'PFB_TRIGGER for cron verb');
	}

	/**
	 * Oracle: pfb_trigger_request() 'trigger'='force' and pfb_hook_trigger() agree
	 * on 'force-reload' for both force-reload verbs (updateip, updatednsbl).
	 *
	 * Phase 3 will derive 'force-reload' from trigger='force' rather than from $cron.
	 */
	public function testStructTriggerForceAgreesWithHookTriggerForceReload(): void
	{
		foreach (['updateip', 'updatednsbl'] as $verb) {
			$req         = pfb_trigger_request($verb);
			$pfb_trigger = pfb_hook_trigger($verb);

			$this->assertSame('force',        $req['trigger'],
				"struct trigger for '{$verb}' must be 'force'\ngot: " . json_encode($req['trigger']));
			$this->assertSame('force-reload', $pfb_trigger,
				"PFB_TRIGGER for '{$verb}' must be 'force-reload'\ngot: " . json_encode($pfb_trigger));
		}
	}
}
