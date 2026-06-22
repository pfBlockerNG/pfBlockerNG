<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-37 Phase 2 — DoT/DoQ block rule lifecycle tests (PHPUnit, off-appliance).
 *
 * Functions under test:
 *   - pfb_sync_dot_block_rules()              — lifecycle: create/reconcile/prune/remove
 *   - pfb_fwobj_init_dot_block_registrations() — ADR-35 registration seam
 *
 * Coverage mandate (CLAUDE.md): every branch, before-and-after assertion, BDD spec for
 * complex multi-step flows.
 *
 * Test inventory (all four mandatory cases from the Phase-2 prompt):
 *
 *   a. Reconcile is idempotent — two syncs with identical settings produce the same
 *      config state (no duplicate rules).
 *   b. Disable removes all pfB_DoT_Block_* rules while a seeded user filter rule survives.
 *   c. Stale-interface prune — enable lan+opt1 → reduce to lan → opt1 rule gone,
 *      lan rule remains.
 *   d. Exception-alias branch — non-empty → negated-alias source; empty → <any/>.
 */
#[CoversFunction('pfb_sync_dot_block_rules')]
#[CoversFunction('pfb_fwobj_init_dot_block_registrations')]
final class DotDoQBlockLifecycleTest extends TestCase
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
		$GLOBALS['config']                      = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	/**
	 * Seed the dnsbl_dot_block toggle in config.xml (stored value 'on' or '').
	 */
	private function seedDotBlockEnable(string $value): void
	{
		config_set_path(self::DNSBL_SETTINGS_PATH . '/dnsbl_dot_block', $value);
	}

	/**
	 * Seed the dnsbl_dot_block_int interfaces string.
	 */
	private function seedDotBlockInt(string $value): void
	{
		config_set_path(self::DNSBL_SETTINGS_PATH . '/dnsbl_dot_block_int', $value);
	}

	/**
	 * Seed the dnsbl_dot_block_exclude exception alias string.
	 */
	private function seedDotBlockExclude(string $value): void
	{
		config_set_path(self::DNSBL_SETTINGS_PATH . '/dnsbl_dot_block_exclude', $value);
	}

	/**
	 * Build a user-owned filter rule with no pfBlockerNG marker — must survive all
	 * pfb_sync_dot_block_rules() calls.
	 *
	 * @return array<string,mixed>
	 */
	private function userFilterRule(): array
	{
		return [
			'descr'     => 'My custom pass rule',
			'type'      => 'pass',
			'interface' => 'wan',
			'protocol'  => 'tcp',
		];
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
	 * Count filter/rule entries whose descr starts with the DoT block prefix.
	 */
	private function countDotBlockFilterRules(): int
	{
		$count = 0;
		foreach ($this->getFilterRules() as $rule) {
			if (str_starts_with($rule['descr'] ?? '', PFB_DOT_BLOCK_DESCR_PFX)) {
				$count++;
			}
		}
		return $count;
	}

	/**
	 * Assert that a filter/rule entry exists for the given interface.
	 */
	private function assertDotBlockRuleExists(string $iface, string $label): void
	{
		$marker = PFB_DOT_BLOCK_DESCR_PFX . $iface;
		$found  = FALSE;
		foreach ($this->getFilterRules() as $rule) {
			if (($rule['descr'] ?? '') === $marker) {
				$found = TRUE;
				break;
			}
		}
		$this->assertTrue($found, "{$label}: DoT block rule for '{$iface}' must exist (marker={$marker})");
	}

	/**
	 * Assert that a filter/rule entry does NOT exist for the given interface.
	 */
	private function assertDotBlockRuleAbsent(string $iface, string $label): void
	{
		$marker = PFB_DOT_BLOCK_DESCR_PFX . $iface;
		foreach ($this->getFilterRules() as $rule) {
			$this->assertNotSame(
				$marker,
				$rule['descr'] ?? '',
				"{$label}: DoT block rule for '{$iface}' must NOT exist (marker={$marker})"
			);
		}
	}

	/**
	 * Find the first filter/rule entry for the given interface.
	 *
	 * @return array<string,mixed>|null
	 */
	private function findDotBlockRule(string $iface): ?array
	{
		$marker = PFB_DOT_BLOCK_DESCR_PFX . $iface;
		foreach ($this->getFilterRules() as $rule) {
			if (($rule['descr'] ?? '') === $marker) {
				return $rule;
			}
		}
		return NULL;
	}

	/**
	 * Run pfb_fwobj_init_dot_block_registrations() + pfb_sync_dot_block_rules()
	 * (mirrors the sync_package_pfblockerng() wiring).
	 *
	 * @return bool  Return value from pfb_sync_dot_block_rules().
	 */
	private function runSync(): bool
	{
		pfb_fwobj_init_dot_block_registrations();
		return pfb_sync_dot_block_rules();
	}

	// -----------------------------------------------------------------------
	// Case (a): Reconcile is idempotent — two syncs produce no duplicates
	//
	// Scenario: idempotent reconcile.
	//   Background: block is enabled with one interface.
	//     Given dnsbl_dot_block='on', dnsbl_dot_block_int='lan', dnsbl_dot_block_exclude=''.
	//     When the sync is called twice with identical settings.
	//     Then the config contains exactly 1 DoT block filter rule after
	//     both the first and second sync (no accumulation of duplicates).
	// -----------------------------------------------------------------------

	public function test_reconcile_is_idempotent(): void
	{
		// Background: enable block on a single interface.
		$this->seedDotBlockEnable('on');
		$this->seedDotBlockInt('lan');
		$this->seedDotBlockExclude('');

		// Before (phase precondition): no DoT block rules in config.
		$this->assertSame(0, $this->countDotBlockFilterRules(),
			'before first sync: 0 DoT block filter rules'
		);

		// When: first sync.
		$changed = $this->runSync();

		// Then: 1 filter rule for 'lan'.
		$this->assertTrue($changed, 'first sync must report a config change');
		$this->assertSame(1, $this->countDotBlockFilterRules(),
			'after first sync: exactly 1 DoT block filter rule (lan)'
		);
		$this->assertDotBlockRuleExists('lan', 'after first sync');

		// When: second sync with identical settings.
		$changed2 = $this->runSync();

		// Then: same count — no duplicates.
		$this->assertFalse($changed2, 'second sync with identical settings must report NO change');
		$this->assertSame(1, $this->countDotBlockFilterRules(),
			'after second sync: still exactly 1 filter rule (idempotent)'
		);
		$this->assertDotBlockRuleExists('lan', 'after second sync (idempotent)');
	}

	// -----------------------------------------------------------------------
	// Case (b): Disable removes all pfB_DoT_Block_* rules
	//
	// Scenario: disable clears pfB_DoT_Block_* rules.
	//   Background: block enabled with one interface.
	//     Given dnsbl_dot_block='on', dnsbl_dot_block_int='lan'.
	//     When sync is called (rule appears).
	//     Then flip to disabled (dnsbl_dot_block='').
	//     When sync is called again.
	//     Then all pfB_DoT_Block_* rules are gone from filter/rule.
	// -----------------------------------------------------------------------

	public function test_disable_removes_all_dot_block_rules(): void
	{
		// Given: block is enabled on 'lan'.
		$this->seedDotBlockEnable('on');
		$this->seedDotBlockInt('lan');
		$this->seedDotBlockExclude('');

		// Before (precondition): no DoT block rules.
		$this->assertSame(0, $this->countDotBlockFilterRules(),
			'before enable sync: 0 DoT block filter rules'
		);

		// When: sync with block enabled.
		$this->runSync();

		// Then: rule appears.
		$this->assertSame(1, $this->countDotBlockFilterRules(),
			'after enable sync: 1 DoT block filter rule'
		);
		$this->assertDotBlockRuleExists('lan', 'after enable sync');

		// When: disable block.
		$this->seedDotBlockEnable('');
		$changed = $this->runSync();

		// Then: all pfB_DoT_Block_* filter rules are gone.
		$this->assertTrue($changed, 'disable sync must report a config change');
		$this->assertSame(0, $this->countDotBlockFilterRules(),
			'after disable sync: 0 DoT block filter rules'
		);
		$this->assertDotBlockRuleAbsent('lan', 'after disable sync');
	}

	// -----------------------------------------------------------------------
	// Case (c): User filter rule survives disable
	//
	// Scenario: a user-owned filter rule is not affected by DoT block sync.
	//   Background: a user filter rule is seeded; block is enabled then disabled.
	//     Given a user filter rule in filter/rule (no pfBlockerNG marker).
	//     And dnsbl_dot_block='on', dnsbl_dot_block_int='lan'.
	//     When sync is called (DoT block rule appears).
	//     Then disable block.
	//     When sync is called again.
	//     Then user rule is still present and unchanged.
	// -----------------------------------------------------------------------

	public function test_user_rule_survives_disable(): void
	{
		// Given: seed a user-owned filter rule.
		config_set_path('filter/rule', [$this->userFilterRule()]);

		// And: block is enabled on 'lan'.
		$this->seedDotBlockEnable('on');
		$this->seedDotBlockInt('lan');
		$this->seedDotBlockExclude('');

		// Before (precondition): user rule present, no DoT block rules.
		$this->assertCount(1, $this->getFilterRules(),
			'before enable sync: 1 rule (user only)'
		);
		$this->assertSame(0, $this->countDotBlockFilterRules(),
			'before enable sync: 0 DoT block filter rules'
		);

		// When: sync with block enabled.
		$this->runSync();

		// Then: DoT block rule appears alongside the user rule.
		$this->assertSame(1, $this->countDotBlockFilterRules(),
			'after enable sync: 1 DoT block filter rule'
		);
		// Total filter rules = 1 user + 1 block.
		$this->assertCount(2, $this->getFilterRules(),
			'after enable sync: 2 total filter rules (1 user + 1 block)'
		);

		// When: disable block.
		$this->seedDotBlockEnable('');
		$changed = $this->runSync();

		// Then: DoT block rules are gone.
		$this->assertTrue($changed, 'disable sync must report a config change');
		$this->assertSame(0, $this->countDotBlockFilterRules(),
			'after disable sync: 0 DoT block filter rules'
		);

		// And: user filter rule is still present, unchanged.
		$filter_rules = $this->getFilterRules();
		$this->assertCount(1, $filter_rules,
			'after disable sync: exactly 1 filter rule (user rule)'
		);
		$this->assertSame('My custom pass rule', $filter_rules[0]['descr'],
			'after disable sync: user filter rule descr unchanged'
		);
		$this->assertSame('pass', $filter_rules[0]['type'],
			'after disable sync: user filter rule type unchanged'
		);
	}

	// -----------------------------------------------------------------------
	// Case (d): Stale-interface prune
	//
	// Scenario: reducing the interface set prunes rules for removed interfaces.
	//   Background: block enabled on lan+opt1, then reduced to lan only.
	// -----------------------------------------------------------------------

	public function test_stale_interface_pruned_on_reconcile(): void
	{
		// Background: enable on two interfaces.
		$this->seedDotBlockEnable('on');
		$this->seedDotBlockInt('lan,opt1');
		$this->seedDotBlockExclude('');

		// Given: before any sync, no rules exist.
		$this->assertSame(0, $this->countDotBlockFilterRules(),
			'before any sync: 0 DoT block filter rules'
		);

		// When: first sync with both interfaces.
		$this->runSync();

		// Then: 2 filter rules (one per interface).
		$this->assertSame(2, $this->countDotBlockFilterRules(),
			'after lan+opt1 sync: 2 DoT block filter rules (lan + opt1)'
		);
		// Assert before-state: both rules present.
		$this->assertDotBlockRuleExists('lan',  'after lan+opt1 sync');
		$this->assertDotBlockRuleExists('opt1', 'after lan+opt1 sync');

		// When: reduce to lan only and sync again.
		$this->seedDotBlockInt('lan');
		$changed = $this->runSync();

		// Then: opt1 rule is gone (stale — pruned).
		$this->assertTrue($changed, 'reducing to lan only must report a config change');
		$this->assertDotBlockRuleAbsent('opt1', 'after stale prune');

		// And: lan rule remains.
		$this->assertDotBlockRuleExists('lan', 'after stale prune');

		// Total = 1 (lan only).
		$this->assertSame(1, $this->countDotBlockFilterRules(),
			'after stale prune: exactly 1 DoT block filter rule (lan only)'
		);
	}

	// -----------------------------------------------------------------------
	// Bonus: exception-alias branch changes source element
	//
	// Scenario: exception alias changes the source element in the filter rule.
	//   Background: block enabled on lan, exception alias toggled.
	//     Given dnsbl_dot_block='on', dnsbl_dot_block_int='lan', dnsbl_dot_block_exclude=''.
	//     When sync: source is <any/>.
	//     Then set dnsbl_dot_block_exclude='DoT_Exceptions', rebuild rules.
	//     Then source is negated-alias (address='DoT_Exceptions', not present).
	//     Then set dnsbl_dot_block_exclude='', rebuild rules.
	//     Then source reverts to <any/>.
	// -----------------------------------------------------------------------

	public function testExceptionAliasBranchChangesSourceElement(): void
	{
		// Background: enable on 'lan', no exception initially.
		$this->seedDotBlockEnable('on');
		$this->seedDotBlockInt('lan');
		$this->seedDotBlockExclude('');

		// When: first sync with empty exception.
		$this->runSync();

		// Then (before): source is <any/> in filter rule.
		$rule_before = $this->findDotBlockRule('lan');
		$this->assertNotNull($rule_before, 'before: lan DoT block rule must exist');
		$this->assertArrayHasKey('any', $rule_before['source'] ?? [],
			'before: source must contain any key when exception empty'
		);
		$this->assertArrayNotHasKey('address', $rule_before['source'] ?? [],
			'before: source must not have address key when exception empty'
		);

		// When: set a non-empty exception alias and rebuild rules.
		// Remove existing rule first so sync must re-add with new source.
		$this->seedDotBlockExclude('DoT_Exceptions');
		pfb_fwobj_remove('filter/rule', PFB_DOT_BLOCK_DESCR_PFX);
		$changed = $this->runSync();

		// Then: source is now negated alias.
		$this->assertTrue($changed, 'setting exception must cause a config change');
		$rule_after = $this->findDotBlockRule('lan');
		$this->assertNotNull($rule_after, 'after: lan DoT block rule must exist with exception');
		$source_after = $rule_after['source'] ?? [];
		$this->assertArrayHasKey('address', $source_after,
			'after: source.address present when exception set'
		);
		$this->assertSame('DoT_Exceptions', $source_after['address'],
			'after: source.address=DoT_Exceptions'
		);
		$this->assertArrayHasKey('not', $source_after,
			'after: source.not present (negated) when exception set'
		);
		$this->assertArrayNotHasKey('any', $source_after,
			'after: source must NOT have any key when exception set'
		);

		// When: clear exception again and rebuild rules.
		$this->seedDotBlockExclude('');
		pfb_fwobj_remove('filter/rule', PFB_DOT_BLOCK_DESCR_PFX);
		$changed2 = $this->runSync();

		// Then: source reverts to <any/>.
		$this->assertTrue($changed2, 'clearing exception must cause a config change');
		$rule_reverted = $this->findDotBlockRule('lan');
		$this->assertNotNull($rule_reverted, 'reverted: lan DoT block rule must exist');
		$source_reverted = $rule_reverted['source'] ?? [];
		$this->assertArrayHasKey('any', $source_reverted,
			'reverted: source must contain any key after exception cleared'
		);
		$this->assertArrayNotHasKey('address', $source_reverted,
			'reverted: source must NOT have address key after exception cleared'
		);
	}

	// -----------------------------------------------------------------------
	// Bonus: pfb_fwobj_init_dot_block_registrations() registers filter/rule
	// -----------------------------------------------------------------------

	/**
	 * Scenario: registration seam covers filter/rule.
	 *   Background: pfb_fwobj_init_dot_block_registrations() called once.
	 *     When called.
	 *     Then pfb_fwobj_registry() contains an entry keyed on PFB_DOT_BLOCK_DESCR_PFX
	 *     for type 'filter'.
	 *     And calling it twice is idempotent (replaces by key, no duplicate entries).
	 */
	public function testRegistrationSeamCoversFilterSection(): void
	{
		// Before: registry is empty (setUp cleared it).
		$registry_before = pfb_fwobj_registry();
		$this->assertArrayNotHasKey(PFB_DOT_BLOCK_DESCR_PFX, $registry_before,
			'before registration: prefix key must not be in registry'
		);

		// When: register once.
		pfb_fwobj_init_dot_block_registrations();

		// Then: registry contains the DoT block entry.
		$registry_after = pfb_fwobj_registry();
		$this->assertArrayHasKey(PFB_DOT_BLOCK_DESCR_PFX, $registry_after,
			'after registration: prefix key must be in registry'
		);

		$entry = $registry_after[PFB_DOT_BLOCK_DESCR_PFX];
		$this->assertSame('filter', $entry['type'],
			'registered entry type must be filter'
		);
		$this->assertSame('filter/rule', $entry['section'],
			'registered entry section must be filter/rule'
		);
		$this->assertSame(PFB_DOT_BLOCK_DESCR_PFX, $entry['marker'],
			'registered entry marker must equal PFB_DOT_BLOCK_DESCR_PFX'
		);
		$this->assertNull($entry['builder'],
			'registered entry builder must be NULL (seam-only)'
		);

		// When: register again (idempotent check).
		pfb_fwobj_init_dot_block_registrations();
		$registry_twice = pfb_fwobj_registry();
		$this->assertArrayHasKey(PFB_DOT_BLOCK_DESCR_PFX, $registry_twice,
			'after second registration: still present'
		);
	}

	// -----------------------------------------------------------------------
	// Bonus: disabled from the start removes nothing and returns FALSE
	// -----------------------------------------------------------------------

	/**
	 * Scenario: sync when already disabled with no rules in config.
	 *   Background: dnsbl_dot_block='' (disabled), no rules exist.
	 *     When sync is called.
	 *     Then FALSE is returned (no config change).
	 *     And filter/rule remains empty.
	 */
	public function testSyncWhenAlreadyDisabledAndNoRulesExistsReturnsFalse(): void
	{
		// Given: disabled block, no existing rules.
		$this->seedDotBlockEnable('');

		// Before: no rules.
		$this->assertSame(0, $this->countDotBlockFilterRules(), 'before: no DoT block filter rules');

		// When.
		$changed = $this->runSync();

		// Then: no change (nothing to remove).
		$this->assertFalse($changed, 'sync when disabled with no rules must return FALSE');
		$this->assertSame(0, $this->countDotBlockFilterRules(), 'after: still no DoT block filter rules');
	}
}
