<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #340 — pin the action -> folder routing that distinguishes the DNSBL-IPs
 * "Alias Deny" and "Alias Native" List Actions, the distinction the report conflated.
 *
 * pfb_determine_list_detail() is the single decision point that maps a list action to
 * its working folder. The folder is what the downstream pass treats the list as:
 *   * denydir  -> the DENY set, which the De-Duplication + Reputation passes process
 *                 (pfblockerng.sh dedup/reputation operate over the deny folder);
 *   * nativedir -> the NATIVE set, kept verbatim, De-Duplication + Reputation BYPASSED.
 * The ' Auto ' vs '' descr is the second axis: a non-'Alias' action also gets auto
 * firewall rules; every 'Alias' action is alias-only (no auto rules).
 *
 * This is exactly the contract the DNSBL-IPs help text now states and the issue
 * questioned ("does Alias Deny dedup / add rules?"). The DNSBLIP synthetic list is
 * processed through this same function with $list['action'] = $pfb['dnsbl_ip']
 * (pfblockerng.inc, "Add DNSBLIP" block), so exposing 'Alias_Native' in the DNSBL
 * dropdown routes DNSBLIP to nativedir with no further change.
 *
 * Feature: DNSBL-IPs List Action routing
 *   Background:
 *     Given the per-action-class working dirs (deny/native) and a settings section
 *           with no Advanced Invert (so the force-Native override does not fire)
 *   Branch coverage (each action class, both axes):
 *     * Alias Native -> native folder, alias-only  (dedup/reputation bypassed)
 *     * Alias Deny   -> deny  folder, alias-only   (dedup/reputation eligible)
 *     * Deny Both    -> deny  folder, auto rules   (proves the descr axis is real)
 */
#[CoversFunction('pfb_determine_list_detail')]
final class DnsblIpAliasActionTest extends TestCase
{
	/** @var array<string,array{bool,mixed}> Saved globals to restore (key => [existed, value]). */
	private array $saved = [];

	protected function setUp(): void
	{
		// Snapshot the shared globals this test mutates, so tearDown restores the
		// bootstrap-seeded state other tests depend on (a wholesale unset would
		// break later suites that read $pfb/$config seeded once at bootstrap).
		foreach (['pfb', 'pfbarr', 'config'] as $g) {
			$this->saved[$g] = [array_key_exists($g, $GLOBALS), $GLOBALS[$g] ?? null];
		}

		// The action -> folder targets the function routes to.
		$GLOBALS['pfb']['denydir']   = '/tmp/pfb_deny';
		$GLOBALS['pfb']['nativedir'] = '/tmp/pfb_native';
		$GLOBALS['pfb']['origdir']   = '/tmp/pfb_orig';
		$GLOBALS['pfb']['reuse']     = '';

		// A settings section with every advanced key present but OFF, so the
		// autoports/autoaddr block is a no-op AND the "Invert -> force Native"
		// override (which would mask the routing under test) does not fire.
		$off = [];
		foreach (['autoproto', 'autonot', 'autoaddrnot', 'agateway', 'autoports', 'autoaddr'] as $k) {
			$off["{$k}_in"]  = '';
			$off["{$k}_out"] = '';
		}
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsblsettings' => ['config' => [0 => $off]]]];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $g => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$g] = $value;
			} else {
				unset($GLOBALS[$g]);
			}
		}
	}

	/** @return array<string,mixed> */
	private function routeFor(string $action): array
	{
		return pfb_determine_list_detail($action, 'DNSBLIP_v4', 'pfblockerngdnsblsettings', '0');
	}

	public function testAliasNativeRoutesToNativeFolderBypassingDedup(): void
	{
		// When: the DNSBL-IPs action is 'Alias Native'
		$r = $this->routeFor('Alias_Native');

		// Then: the list lands in the NATIVE folder (kept verbatim; dedup/reputation
		// bypassed) and carries no auto firewall rules ('Alias' => '' descr).
		$this->assertSame($GLOBALS['pfb']['nativedir'], $r['folder']);
		$this->assertSame('', $r['descr']);
	}

	public function testAliasDenyRoutesToDenyFolderForDedup(): void
	{
		// When: the DNSBL-IPs action is 'Alias Deny'
		$r = $this->routeFor('Alias_Deny');

		// Then: the list lands in the DENY folder (the set De-Duplication + Reputation
		// process) yet still carries no auto firewall rules ('Alias' => '' descr) --
		// i.e. it DOES dedup, contrary to the issue's premise, and is NOT == Native.
		$this->assertSame($GLOBALS['pfb']['denydir'], $r['folder']);
		$this->assertSame('', $r['descr']);
		$this->assertNotSame($GLOBALS['pfb']['nativedir'], $r['folder']);
	}

	public function testDenyBothRoutesToDenyFolderWithAutoRules(): void
	{
		// When: the action is a non-'Alias' Deny
		$r = $this->routeFor('Deny_Both');

		// Then: deny folder AND ' Auto ' descr -> auto firewall rules are created,
		// proving the alias-only ('' descr) result above is a real branch, not constant.
		$this->assertSame($GLOBALS['pfb']['denydir'], $r['folder']);
		$this->assertSame(' Auto ', $r['descr']);
	}
}
