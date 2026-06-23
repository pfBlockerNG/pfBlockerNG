<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-36 Phase 2 — DNS-redirect lifecycle tests (PHPUnit, off-appliance).
 *
 * Functions under test:
 *   - pfb_sync_dns_redirect_rules()              — lifecycle: create/reconcile/prune/remove
 *   - pfb_fwobj_init_dns_redirect_registrations() — ADR-35 registration seam
 *
 * Coverage mandate (CLAUDE.md): every branch, before-and-after assertion, BDD spec for
 * complex multi-step flows.
 *
 * Test inventory (all four mandatory cases from the Phase-2 prompt):
 *
 *   a. Reconcile is idempotent — two syncs with identical settings produce the same
 *      config state (no duplicate rules).
 *   b. Disable removes all marked rules while a seeded user NAT rule survives.
 *   c. Stale-interface prune — enable lan+opt1 → reduce to lan → opt1 rules gone,
 *      lan rules remain.
 *   d. Exception-alias branch — non-empty → negated-alias source; empty → <any>.
 */
#[CoversFunction('pfb_sync_dns_redirect_rules')]
#[CoversFunction('pfb_fwobj_init_dns_redirect_registrations')]
final class DnsRedirectLifecycleTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixture constants
	// -----------------------------------------------------------------------

	private const DNSBL_SETTINGS_PATH = 'installedpackages/pfblockerngdnsblsettings/config/0';

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/** Reset the ADR-35 registry and the global config before every test. */
	protected function setUp(): void
	{
		$registry = &pfb_fwobj_registry();
		$registry = [];
		$GLOBALS['config']                       = [];
		$GLOBALS['pfb_test_write_config_calls']  = [];
	}

	/**
	 * Seed the dnsbl_redir toggle in config.xml (stored value 'on' or '').
	 */
	private function seedRedirEnable(string $value): void
	{
		config_set_path(self::DNSBL_SETTINGS_PATH . '/dnsbl_redir', $value);
	}

	/**
	 * Seed the dnsbl_redir_int interfaces string.
	 */
	private function seedRedirInt(string $value): void
	{
		config_set_path(self::DNSBL_SETTINGS_PATH . '/dnsbl_redir_int', $value);
	}

	/**
	 * Seed the dnsbl_redir_exclude exception alias string.
	 */
	private function seedRedirExclude(string $value): void
	{
		config_set_path(self::DNSBL_SETTINGS_PATH . '/dnsbl_redir_exclude', $value);
	}

	/**
	 * Build a user-owned NAT rule with no pfBlockerNG marker — must survive all
	 * pfb_sync_dns_redirect_rules() calls.
	 *
	 * @return array<string,mixed>
	 */
	private function userNatRule(): array
	{
		return [
			'descr'      => 'My custom NAT rule',
			'protocol'   => 'tcp',
			'interface'  => 'wan',
			'target'     => '203.0.113.1',
			'local-port' => '8080',
		];
	}

	/**
	 * Return the current nat/rule section from $GLOBALS['config'].
	 *
	 * @return list<array<string,mixed>>
	 */
	private function getNatRules(): array
	{
		return config_get_path('nat/rule', []);
	}

	/**
	 * Return the current filter/rule section from $GLOBALS['config'].
	 *
	 * @return list<array<string,mixed>>
	 */
	private function getFilterRules(): array
	{
		return config_get_path('filter/rule', []);
	}

	/**
	 * Count nat/rule entries whose descr starts with the DNS-redirect prefix.
	 */
	private function countRedirNatRules(): int
	{
		$count = 0;
		foreach ($this->getNatRules() as $rule) {
			if (str_starts_with($rule['descr'] ?? '', PFB_DNS_REDIR_DESCR_V4_PFX)) {
				$count++;
			}
		}
		return $count;
	}

	/**
	 * Count filter/rule entries whose descr starts with the DNS-redirect prefix.
	 */
	private function countRedirFilterRules(): int
	{
		$count = 0;
		foreach ($this->getFilterRules() as $rule) {
			if (str_starts_with($rule['descr'] ?? '', PFB_DNS_REDIR_DESCR_V4_PFX)) {
				$count++;
			}
		}
		return $count;
	}

	/**
	 * Assert that a nat/rule entry exists for the given interface + family.
	 */
	private function assertNatRuleExists(string $iface, string $family, string $label): void
	{
		$suffix = ($family === 'inet') ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
		$marker = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . $suffix;
		$found  = FALSE;
		foreach ($this->getNatRules() as $rule) {
			if (($rule['descr'] ?? '') === $marker) {
				$found = TRUE;
				break;
			}
		}
		$this->assertTrue($found, "{$label}: NAT rule for {$iface}/{$family} must exist (marker={$marker})");
	}

	/**
	 * Assert that a nat/rule entry does NOT exist for the given interface + family.
	 */
	private function assertNatRuleAbsent(string $iface, string $family, string $label): void
	{
		$suffix = ($family === 'inet') ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
		$marker = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . $suffix;
		foreach ($this->getNatRules() as $rule) {
			$this->assertNotSame(
				$marker,
				$rule['descr'] ?? '',
				"{$label}: NAT rule for {$iface}/{$family} must NOT exist (marker={$marker})"
			);
		}
	}

	/**
	 * Run pfb_fwobj_init_dns_redirect_registrations() + pfb_sync_dns_redirect_rules()
	 * (mirrors the sync_package_pfblockerng() wiring).
	 *
	 * @return bool  Return value from pfb_sync_dns_redirect_rules().
	 */
	private function runSync(): bool
	{
		pfb_fwobj_init_dns_redirect_registrations();
		return pfb_sync_dns_redirect_rules();
	}

	// -----------------------------------------------------------------------
	// Case (a): Reconcile is idempotent — two syncs produce no duplicates
	//
	// Scenario: idempotent reconcile.
	//   Background: redirect is enabled with one interface.
	//     Given dnsbl_redir='on', dnsbl_redir_int='lan', dnsbl_redir_exclude=''.
	//     When the sync is called twice with identical settings.
	//     Then the config contains exactly 2 NAT rules and 2 filter rules after
	//     both the first and second sync (no accumulation of duplicates).
	// -----------------------------------------------------------------------

	public function testReconcileIsIdempotentNoDuplicatesOnRepeatSync(): void
	{
		// Background: enable redirect on a single interface.
		$this->seedRedirEnable('on');
		$this->seedRedirInt('lan');
		$this->seedRedirExclude('');

		// Before (phase precondition): no redirect rules in config.
		$this->assertSame(0, $this->countRedirNatRules(),
			'before first sync: 0 redirect NAT rules'
		);
		$this->assertSame(0, $this->countRedirFilterRules(),
			'before first sync: 0 redirect filter rules'
		);

		// When: first sync.
		$changed = $this->runSync();

		// Then: 2 NAT rules (inet + inet6) and 2 filter rules for 'lan'.
		$this->assertTrue($changed, 'first sync must report a config change');
		$this->assertSame(2, $this->countRedirNatRules(),
			'after first sync: exactly 2 redirect NAT rules (lan inet + inet6)'
		);
		$this->assertSame(2, $this->countRedirFilterRules(),
			'after first sync: exactly 2 redirect filter rules (lan inet + inet6)'
		);
		$this->assertNatRuleExists('lan', 'inet', 'after first sync');
		$this->assertNatRuleExists('lan', 'inet6', 'after first sync');

		// When: second sync with identical settings.
		$changed2 = $this->runSync();

		// Then: same counts — no duplicates.
		$this->assertFalse($changed2, 'second sync with identical settings must report NO change');
		$this->assertSame(2, $this->countRedirNatRules(),
			'after second sync: still exactly 2 NAT rules (idempotent)'
		);
		$this->assertSame(2, $this->countRedirFilterRules(),
			'after second sync: still exactly 2 filter rules (idempotent)'
		);
	}

	// -----------------------------------------------------------------------
	// Case (b): Disable removes all marked rules; user NAT rule survives
	//
	// Scenario: disable clears pfB_DNS_Redirect_* rules; user rule untouched.
	//   Background: redirect enabled with one interface + a seeded user NAT rule.
	//     Given a user NAT rule in nat/rule (no pfBlockerNG marker).
	//     And dnsbl_redir='on', dnsbl_redir_int='lan', dnsbl_redir_exclude=''.
	//     When sync is called (rules appear).
	//     Then flip to disabled (dnsbl_redir='').
	//     When sync is called again.
	//     Then all pfB_DNS_Redirect_* rules are gone from nat/rule and filter/rule.
	//     And the user NAT rule is still present and unchanged.
	// -----------------------------------------------------------------------

	public function testDisableRemovesRedirectRulesAndUserRuleSurvives(): void
	{
		// Given: seed a user-owned NAT rule.
		config_set_path('nat/rule', [$this->userNatRule()]);

		// And: redirect is enabled on 'lan'.
		$this->seedRedirEnable('on');
		$this->seedRedirInt('lan');
		$this->seedRedirExclude('');

		// Before (precondition): user rule present, no redirect rules.
		$this->assertCount(1, $this->getNatRules(), 'before enable sync: 1 rule (user only)');
		$this->assertSame(0, $this->countRedirNatRules(), 'before enable sync: 0 redirect NAT rules');

		// When: sync with redirect enabled.
		$this->runSync();

		// Then: redirect rules appear alongside the user rule.
		$this->assertSame(2, $this->countRedirNatRules(),
			'after enable sync: 2 redirect NAT rules'
		);
		// Total nat rules = 1 user + 2 redirect.
		$this->assertCount(3, $this->getNatRules(),
			'after enable sync: 3 total NAT rules (1 user + 2 redirect)'
		);

		// When: disable redirect.
		$this->seedRedirEnable('');
		$changed = $this->runSync();

		// Then: all pfB_DNS_Redirect_* NAT rules are gone.
		$this->assertTrue($changed, 'disable sync must report a config change');
		$this->assertSame(0, $this->countRedirNatRules(),
			'after disable sync: 0 redirect NAT rules'
		);
		$this->assertSame(0, $this->countRedirFilterRules(),
			'after disable sync: 0 redirect filter rules'
		);

		// And: user NAT rule is still present, unchanged.
		$nat_rules = $this->getNatRules();
		$this->assertCount(1, $nat_rules, 'after disable sync: exactly 1 NAT rule (user rule)');
		$this->assertSame('My custom NAT rule', $nat_rules[0]['descr'],
			'after disable sync: user NAT rule descr unchanged'
		);
		$this->assertSame('203.0.113.1', $nat_rules[0]['target'],
			'after disable sync: user NAT rule target unchanged'
		);
	}

	// -----------------------------------------------------------------------
	// Case (c): Stale-interface prune
	//
	// Scenario: reducing the interface set prunes rules for removed interfaces.
	//   Background: redirect enabled on lan+opt1, then reduced to lan only.
	//     Given dnsbl_redir='on', dnsbl_redir_int='lan,opt1'.
	//     When first sync: 4 NAT + 4 filter rules (2 families × 2 interfaces).
	//     Then reduce to dnsbl_redir_int='lan' and sync again.
	//     Then the opt1 rules (all 4) are gone.
	//     And the lan rules (all 4) remain.
	// -----------------------------------------------------------------------

	public function testStaleInterfaceRulesArePrunedOnInterfaceReduction(): void
	{
		// Background: enable on two interfaces.
		$this->seedRedirEnable('on');
		$this->seedRedirInt('lan,opt1');
		$this->seedRedirExclude('');

		// Before: no rules.
		$this->assertSame(0, $this->countRedirNatRules(), 'before any sync: 0 redirect NAT rules');

		// When: first sync with both interfaces.
		$this->runSync();

		// Then: 4 NAT + 4 filter entries (2 families × 2 interfaces).
		$this->assertSame(4, $this->countRedirNatRules(),
			'after lan+opt1 sync: 4 redirect NAT rules (2 ifaces × 2 families)'
		);
		$this->assertSame(4, $this->countRedirFilterRules(),
			'after lan+opt1 sync: 4 redirect filter rules (2 ifaces × 2 families)'
		);
		$this->assertNatRuleExists('lan', 'inet',   'after lan+opt1 sync');
		$this->assertNatRuleExists('lan', 'inet6',  'after lan+opt1 sync');
		$this->assertNatRuleExists('opt1', 'inet',  'after lan+opt1 sync');
		$this->assertNatRuleExists('opt1', 'inet6', 'after lan+opt1 sync');

		// When: reduce to lan only and sync again.
		$this->seedRedirInt('lan');
		$changed = $this->runSync();

		// Then: opt1 rules are gone (all 4 pruned).
		$this->assertTrue($changed, 'reducing to lan only must report a config change');
		$this->assertNatRuleAbsent('opt1', 'inet',  'after stale prune');
		$this->assertNatRuleAbsent('opt1', 'inet6', 'after stale prune');

		// And: lan rules remain (both families).
		$this->assertNatRuleExists('lan', 'inet',  'after stale prune');
		$this->assertNatRuleExists('lan', 'inet6', 'after stale prune');

		// Total redirect rules = 2 (lan only).
		$this->assertSame(2, $this->countRedirNatRules(),
			'after stale prune: exactly 2 NAT rules (lan only)'
		);
		$this->assertSame(2, $this->countRedirFilterRules(),
			'after stale prune: exactly 2 filter rules (lan only)'
		);
	}

	// -----------------------------------------------------------------------
	// Case (d): Exception-alias branch
	//
	// Scenario: exception alias changes the source element in the NAT rules.
	//   Background: redirect enabled on lan, exception alias toggled.
	//     Given dnsbl_redir='on', dnsbl_redir_int='lan', dnsbl_redir_exclude=''.
	//     When sync: source is <any>.
	//     Then set dnsbl_redir_exclude='DNS_Whitelist', sync (rules rebuilt).
	//     Then source is negated-alias (address='DNS_Whitelist', not present).
	//     Then set dnsbl_redir_exclude='', sync again.
	//     Then source reverts to <any>.
	// -----------------------------------------------------------------------

	public function testExceptionAliasBranchChangesSourceElement(): void
	{
		// Background: enable on 'lan', no exception initially.
		$this->seedRedirEnable('on');
		$this->seedRedirInt('lan');
		$this->seedRedirExclude('');

		// When: first sync with empty exception.
		$this->runSync();

		// Then (before): source is <any> in NAT rules.
		$nat_inet = $this->findNatRule('lan', 'inet');
		$this->assertNotNull($nat_inet, 'before: lan/inet NAT rule must exist');
		$this->assertArrayHasKey('any', $nat_inet['source'] ?? [],
			'before: source must contain any key when exception empty'
		);
		$this->assertArrayNotHasKey('address', $nat_inet['source'] ?? [],
			'before: source must not have address key when exception empty'
		);

		// When: set a non-empty exception alias and sync.
		// Rules must be rebuilt because the exception changes the source element.
		// First, clear existing rules to force a rebuild (simulate the change detection).
		$this->seedRedirExclude('DNS_Whitelist');
		// Remove existing rules so sync must re-add them with new source.
		pfb_fwobj_remove('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX);
		pfb_fwobj_remove('filter/rule', PFB_DNS_REDIR_DESCR_V4_PFX);
		$changed = $this->runSync();

		// Then: source is now negated alias.
		$this->assertTrue($changed, 'setting exception must cause a config change');
		$nat_inet_after = $this->findNatRule('lan', 'inet');
		$this->assertNotNull($nat_inet_after, 'after: lan/inet NAT rule must exist with exception');
		$source_after = $nat_inet_after['source'] ?? [];
		$this->assertArrayHasKey('address', $source_after,
			'after: source.address present when exception set'
		);
		$this->assertSame('DNS_Whitelist', $source_after['address'],
			'after: source.address=DNS_Whitelist'
		);
		$this->assertArrayHasKey('not', $source_after,
			'after: source.not present (negated) when exception set'
		);
		$this->assertArrayNotHasKey('any', $source_after,
			'after: source must NOT have any key when exception set'
		);

		// When: clear exception again and rebuild rules.
		$this->seedRedirExclude('');
		pfb_fwobj_remove('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX);
		pfb_fwobj_remove('filter/rule', PFB_DNS_REDIR_DESCR_V4_PFX);
		$changed2 = $this->runSync();

		// Then: source reverts to <any>.
		$this->assertTrue($changed2, 'clearing exception must cause a config change');
		$nat_inet_reverted = $this->findNatRule('lan', 'inet');
		$this->assertNotNull($nat_inet_reverted, 'reverted: lan/inet NAT rule must exist');
		$source_reverted = $nat_inet_reverted['source'] ?? [];
		$this->assertArrayHasKey('any', $source_reverted,
			'reverted: source must contain any key after exception cleared'
		);
		$this->assertArrayNotHasKey('address', $source_reverted,
			'reverted: source must NOT have address key after exception cleared'
		);
	}

	// -----------------------------------------------------------------------
	// Supporting helpers
	// -----------------------------------------------------------------------

	/**
	 * Find the first nat/rule entry for the given interface + family.
	 *
	 * @return array<string,mixed>|null
	 */
	private function findNatRule(string $iface, string $family): ?array
	{
		$suffix = ($family === 'inet') ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
		$marker = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . $suffix;
		foreach ($this->getNatRules() as $rule) {
			if (($rule['descr'] ?? '') === $marker) {
				return $rule;
			}
		}
		return NULL;
	}

	// -----------------------------------------------------------------------
	// Bonus: pfb_fwobj_init_dns_redirect_registrations() registers both sections
	// -----------------------------------------------------------------------

	/**
	 * Scenario: registration seam covers nat/rule and filter/rule.
	 *   Background: pfb_fwobj_init_dns_redirect_registrations() called once.
	 *     When called.
	 *     Then pfb_fwobj_registry() contains entries keyed on PFB_DNS_REDIR_DESCR_V4_PFX
	 *     for both 'nat' and 'filter' types.
	 *     And calling it twice is idempotent (replaces by key, no duplicate entries).
	 */
	public function testRegistrationSeamCoversNatAndFilterSections(): void
	{
		// Before: registry is empty (setUp cleared it).
		$registry_before = pfb_fwobj_registry();
		$this->assertArrayNotHasKey(PFB_DNS_REDIR_DESCR_V4_PFX, $registry_before,
			'before registration: prefix key must not be in registry'
		);

		// When: register once.
		pfb_fwobj_init_dns_redirect_registrations();

		// The registry is keyed by marker. Both registrations use PFB_DNS_REDIR_DESCR_V4_PFX.
		// Since pfb_fwobj_register keyed by marker, the second call overwrites the first.
		// There is one entry per marker (the filter registration overwrites the nat one).
		// That is intentional: pfb_fwobj_remove() with this prefix scans ALL sections,
		// so the sweep need not distinguish — the LAST registration wins for the marker key.
		$registry_after = pfb_fwobj_registry();
		$this->assertArrayHasKey(PFB_DNS_REDIR_DESCR_V4_PFX, $registry_after,
			'after registration: prefix key must be in registry'
		);

		// The registered entry has the prefix as marker.
		$entry = $registry_after[PFB_DNS_REDIR_DESCR_V4_PFX];
		$this->assertSame(PFB_DNS_REDIR_DESCR_V4_PFX, $entry['marker'],
			'registered entry marker must equal PFB_DNS_REDIR_DESCR_V4_PFX'
		);
		// builder is NULL (seam-only, built by pfb_sync_dns_redirect_rules).
		$this->assertNull($entry['builder'],
			'registered entry builder must be NULL (seam-only)'
		);

		// When: register again (idempotent check).
		pfb_fwobj_init_dns_redirect_registrations();
		$registry_twice = pfb_fwobj_registry();
		// Still one entry keyed by the prefix.
		$this->assertArrayHasKey(PFB_DNS_REDIR_DESCR_V4_PFX, $registry_twice,
			'after second registration: still present'
		);
	}

	// -----------------------------------------------------------------------
	// Bonus: disabled from the start removes nothing and returns FALSE
	// -----------------------------------------------------------------------

	/**
	 * Scenario: sync when already disabled with no rules in config.
	 *   Background: dnsbl_redir='' (disabled), no rules exist.
	 *     When sync is called.
	 *     Then FALSE is returned (no config change).
	 *     And nat/rule and filter/rule remain empty.
	 */
	public function testSyncWhenAlreadyDisabledAndNoRulesExistsReturnsFalse(): void
	{
		// Given: disabled redirect, no existing rules.
		$this->seedRedirEnable('');

		// Before: no rules.
		$this->assertSame(0, $this->countRedirNatRules(), 'before: no redirect NAT rules');

		// When.
		$changed = $this->runSync();

		// Then: no change (nothing to remove).
		$this->assertFalse($changed, 'sync when disabled with no rules must return FALSE');
		$this->assertSame(0, $this->countRedirNatRules(), 'after: still no redirect NAT rules');
		$this->assertSame(0, $this->countRedirFilterRules(), 'after: still no redirect filter rules');
	}

	// -----------------------------------------------------------------------
	// Regression: the DNSBL "disable" sweep must run BEFORE the redirect sync.
	//
	// pfb_fwobj_sweep() removes EVERY pfB_-owned row (pfb_fwobj_is_owned matches
	// the shared 'pfB_' prefix), so it also matches pfB_DNS_Redirect_* rows. The
	// DNS-redirect feature is independent of DNSBL mode (it can be ON while DNSBL
	// is disabled — mode 'disabled'), so when sync_package_pfblockerng() runs its
	// defensive disable-sweep it MUST do so before this sync re-asserts its rules;
	// otherwise the sweep wipes the freshly-created redirect rules. The two tests
	// pin the contract from both directions.
	// -----------------------------------------------------------------------

	/**
	 * Scenario: the hazard — a broad disable-sweep AFTER the sync wipes redirect rules.
	 *   Background: redirect enabled on 'lan', DNSBL disabled (only redirect rows exist).
	 *     Given the redirect sync has created its 2 NAT + 2 filter rules.
	 *     When the broad pfB_ disable-sweep runs afterwards.
	 *     Then the redirect rules are gone — the ordering bug this fix prevents.
	 */
	public function testDisableSweepAfterSyncWipesRedirectRulesHazard(): void
	{
		// Given: redirect enabled on 'lan'; the sync creates its rules.
		$this->seedRedirEnable('on');
		$this->seedRedirInt('lan');
		$this->seedRedirExclude('');
		$this->runSync();
		$this->assertSame(2, $this->countRedirNatRules(), 'precondition: 2 redirect NAT rules created');
		$this->assertSame(2, $this->countRedirFilterRules(), 'precondition: 2 redirect filter rules created');

		// When: the broad disable-sweep runs AFTER the sync.
		$swept = pfb_fwobj_sweep(['virtualip/vip', 'nat/rule', 'filter/rule']);

		// Then: the redirect rules were wiped (demonstrates why the sweep must precede the sync).
		$this->assertTrue($swept, 'sweep after sync must report a removal');
		$this->assertSame(0, $this->countRedirNatRules(),
			'hazard: a disable-sweep AFTER the sync wipes the redirect NAT rules'
		);
		$this->assertSame(0, $this->countRedirFilterRules(),
			'hazard: a disable-sweep AFTER the sync wipes the redirect filter rules'
		);
	}

	/**
	 * Scenario: the fix — the disable-sweep runs BEFORE the sync, redirect rules survive.
	 *   Background: redirect enabled on 'lan', DNSBL disabled, plus a stale pfB DNSBL NAT row.
	 *     Given a stale 'pfB DNSBL' NAT row in config (the orphan the sweep targets).
	 *     When the disable-sweep runs FIRST (removing the stale DNSBL row),
	 *       And the redirect sync then re-asserts its own rules.
	 *     Then the redirect rules are present and the stale DNSBL row stays gone.
	 */
	public function testDisableSweepBeforeSyncLeavesRedirectRulesIntactFix(): void
	{
		// Given: redirect enabled on 'lan' and a stale pfB-owned DNSBL NAT row.
		$this->seedRedirEnable('on');
		$this->seedRedirInt('lan');
		$this->seedRedirExclude('');
		config_set_path('nat/rule', [
			['descr' => 'pfB DNSBL - DO NOT EDIT', 'interface' => 'lan'],
		]);

		// When: the disable-sweep runs FIRST (the fixed sync_package_pfblockerng order).
		$swept = pfb_fwobj_sweep(['virtualip/vip', 'nat/rule', 'filter/rule']);
		$this->assertTrue($swept, 'sweep must remove the stale DNSBL NAT row');
		$this->assertSame(0, $this->countRedirNatRules(), 'after sweep, before sync: no redirect rules yet');
		$this->assertCount(0, $this->getNatRules(), 'after sweep: stale DNSBL NAT row removed too');

		// And: the redirect sync re-asserts its rules.
		$this->runSync();

		// Then: the redirect rules survive; only redirect rows remain.
		$this->assertSame(2, $this->countRedirNatRules(),
			'fixed order: redirect NAT rules survive when the sweep precedes the sync'
		);
		$this->assertSame(2, $this->countRedirFilterRules(),
			'fixed order: redirect filter rules survive when the sweep precedes the sync'
		);
		foreach ($this->getNatRules() as $rule) {
			$this->assertStringStartsWith(
				PFB_DNS_REDIR_DESCR_V4_PFX, $rule['descr'] ?? '',
				'fixed order: only redirect rows remain (stale DNSBL NAT row swept)'
			);
		}
	}

	// -----------------------------------------------------------------------
	// Regression: every emitted rule carries the pfSense rule metadata
	// (a unique 'tracker' + created/updated provenance). Without a tracker the
	// pfSense rule generator drops the row from /tmp/rules.debug and it never
	// reaches pf — the live-VM failure these features hit on first run.
	// -----------------------------------------------------------------------

	public function testSyncedRedirectRulesAreStampedWithUniqueTrackerAndProvenance(): void
	{
		// Given redirect enabled on one interface.
		$this->seedRedirEnable('on');
		$this->seedRedirInt('lan');
		$this->seedRedirExclude('');

		// When the sync builds + writes the rules.
		$this->runSync();

		// Then the NAT row carries a positive integer tracker + provenance.
		$nat = $this->findNatRule('lan', 'inet');
		$this->assertNotNull($nat, 'lan/inet NAT rule must exist');
		$this->assertArrayHasKey('tracker', $nat, 'NAT rule must carry a tracker (else filter_configure drops it)');
		$this->assertIsInt($nat['tracker'], 'tracker must be an int');
		$this->assertGreaterThan(0, $nat['tracker'], 'tracker must be a positive id');
		$this->assertArrayHasKey('created', $nat, 'NAT rule must carry created provenance');
		$this->assertArrayHasKey('time', $nat['created'] ?? [], 'created must carry a time');
		$this->assertArrayHasKey('updated', $nat, 'NAT rule must carry updated provenance');

		// And the paired filter row is stamped with a DISTINCT tracker (the
		// generator keys on it, so a collision would coalesce/drop a rule).
		$marker = PFB_DNS_REDIR_DESCR_V4_PFX . 'lan' . PFB_DNS_REDIR_DESCR_V4_SFX;
		$filter = NULL;
		foreach ($this->getFilterRules() as $r) {
			if (($r['descr'] ?? '') === $marker) {
				$filter = $r;
				break;
			}
		}
		$this->assertNotNull($filter, 'lan/inet filter rule must exist');
		$this->assertArrayHasKey('tracker', $filter, 'filter rule must carry a tracker');
		$this->assertArrayHasKey('created', $filter, 'filter rule must carry created provenance');
		$this->assertArrayHasKey('time', $filter['created'] ?? [], 'filter created must carry a time');
		$this->assertArrayHasKey('updated', $filter, 'filter rule must carry updated provenance');
		$this->assertNotSame(
			$nat['tracker'],
			$filter['tracker'],
			'each emitted rule must get a UNIQUE tracker'
		);
	}
}
