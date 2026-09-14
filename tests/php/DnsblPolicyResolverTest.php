<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Global policy decoding, legacy group projection, and effective DNSBL mechanisms.
 * Defaults and overrides must preserve explicit choices without copying values.
 */
#[CoversFunction('pfb_dnsbl_mechanism_normalize')]
#[CoversFunction('pfb_dnsbl_group_logging')]
#[CoversFunction('pfb_dnsbl_effective_logging')]
#[CoversFunction('pfb_dnsbl_policy_config')]
final class DnsblPolicyResolverTest extends TestCase
{
	/** The seven concrete DNSBL blocking/logging mechanisms (issue #3288 Constraints: unchanged). */
	private const CONCRETE_MECHANISMS = [
		'enabled', 'disabled_log', 'disabled', 'nxdomain_log', 'nxdomain', 'nodata_log', 'nodata',
	];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// A — PfbDnsblGlobalMode enum (ADR-28 PfbStoredEnum contract)
	// -----------------------------------------------------------------------

	public function testGlobalModeStoresLiteralDefaultAndOverrideTokens(): void
	{
		// Given the two canonical stored tokens.
		// When read through the enum.
		// Then each round-trips to its own case, byte-identical on write.
		$this->assertSame('default', PfbDnsblGlobalMode::Default->toStored());
		$this->assertSame('override', PfbDnsblGlobalMode::Override->toStored());
	}

	public function testGlobalModeFromStoredRecognisesBothTokens(): void
	{
		$this->assertSame(PfbDnsblGlobalMode::Default, PfbDnsblGlobalMode::fromStored('default'));
		$this->assertSame(PfbDnsblGlobalMode::Override, PfbDnsblGlobalMode::fromStored('override'));
	}

	/**
	 * Absent (NULL from a genuinely missing key, mirroring PfbConfig::read()'s NULL
	 * substitution point), '', and any unrecognised junk all fall back to Default --
	 * the fail-safe fallback is the LESS forceful policy (a junk mode must never
	 * accidentally force every group onto the global mechanism).
	 */
	#[DataProvider('junkModeTokenProvider')]
	public function testGlobalModeJunkAndAbsentFallBackToDefault(?string $stored): void
	{
		$this->assertSame(PfbDnsblGlobalMode::Default, PfbDnsblGlobalMode::fromStored($stored));
	}

	/** @return array<string,array{0:string|null}> baseline-safe: plain strings/NULL only. */
	public static function junkModeTokenProvider(): array
	{
		return [
			'null (genuinely absent)' => [null],
			'empty string'            => [''],
			'legacy junk'             => ['enabled'],
			'case variant'            => ['Override'],
			'whitespace'              => [' override'],
		];
	}

	/**
	 * The shared PfbStoredEnumAdapter trait's idempotency guard (ADR-28): an enum fed
	 * back through fromStored() must return itself, not collapse to the default --
	 * this is the exact double-apply footgun CfgAdaptersTest::
	 * testToggleReadIsIdempotentForEnumInput pins for PfbToggle.
	 */
	public function testGlobalModeFromStoredIsIdempotentForEnumInput(): void
	{
		$this->assertSame(PfbDnsblGlobalMode::Override, PfbDnsblGlobalMode::fromStored(PfbDnsblGlobalMode::Override));
		$this->assertSame(PfbDnsblGlobalMode::Default, PfbDnsblGlobalMode::fromStored(PfbDnsblGlobalMode::Default));
	}

	/** A non-scalar stored value (crafted POST array, corrupt config) never reaches tryFrom(). */
	public function testGlobalModeNonScalarFallsBackToDefault(): void
	{
		$this->assertSame(PfbDnsblGlobalMode::Default, PfbDnsblGlobalMode::fromStored(['not', 'a', 'string']));
	}

	// -----------------------------------------------------------------------
	// B — pfb_dnsbl_mechanism_normalize(): the shared 7-token fail-safe normalizer
	// -----------------------------------------------------------------------

	#[DataProvider('concreteMechanismProvider')]
	public function testMechanismNormalizePassesThroughEveryConcreteToken(string $token): void
	{
		$this->assertSame($token, pfb_dnsbl_mechanism_normalize($token));
	}

	/** @return array<string,array{0:string}> */
	public static function concreteMechanismProvider(): array
	{
		$cases = [];
		foreach (self::CONCRETE_MECHANISMS as $token) {
			$cases[$token] = [$token];
		}
		return $cases;
	}

	/** @return array<string,array{0:string}> the six concrete tokens that are NOT the VIP marker 'enabled'. */
	public static function nonVipConcreteMechanismProvider(): array
	{
		$cases = self::concreteMechanismProvider();
		unset($cases['enabled']);
		return $cases;
	}

	/**
	 * Everything that is NOT one of the seven concrete tokens -- absent, '', the
	 * retired alpha-only 'default' sentinel on THIS field (global can never itself be
	 * Default -- issue #3288 Contract), malformed non-scalars, and junk -- fails safe
	 * to 'enabled', the long-standing WebServer/VIP mechanism, never silently to some
	 * OTHER concrete mechanism and never a TypeError.
	 */
	#[DataProvider('nonConcreteMechanismProvider')]
	public function testMechanismNormalizeFailsSafeToEnabled($stored): void
	{
		$this->assertSame('enabled', pfb_dnsbl_mechanism_normalize($stored));
	}

	/** @return array<string,array{0:mixed}> baseline-safe: no enum/class references. */
	public static function nonConcreteMechanismProvider(): array
	{
		return [
			'null (absent)'                 => [null],
			'empty string'                  => [''],
			"'default' (global cannot be Default)" => ['default'],
			'case variant Enabled'          => ['Enabled'],
			'unrecognised junk'             => ['sinkhole'],
			'array (malformed)'             => [['enabled']],
			'int (malformed)'               => [1],
			'bool (malformed)'              => [TRUE],
		];
	}

	// -----------------------------------------------------------------------
	// C — pfb_dnsbl_group_logging(): group-level normalizer (default + 7 concrete)
	// -----------------------------------------------------------------------

	public function testGroupLoggingPassesThroughDefaultToken(): void
	{
		$this->assertSame('default', pfb_dnsbl_group_logging('default'));
	}

	#[DataProvider('concreteMechanismProvider')]
	public function testGroupLoggingPassesThroughEveryConcreteToken(string $token): void
	{
		$this->assertSame($token, pfb_dnsbl_group_logging($token));
	}

	/**
	 * issue #3288 Constraints: "historical absent/empty/Enabled retain VIP as
	 * 'enabled'" -- a group the migration never converted (or a fixture/hand-edit
	 * bypassing it) reads as the concrete mechanism, NOT the new inheritance token.
	 * Conflating the two would silently turn a static VIP choice into live
	 * inheritance the operator never opted into.
	 */
	#[DataProvider('vipMarkerProvider')]
	public function testGroupLoggingHistoricalVipMarkersReadAsEnabledNotDefault($stored): void
	{
		$this->assertSame('enabled', pfb_dnsbl_group_logging($stored));
	}

	/** @return array<string,array{0:mixed}> */
	public static function vipMarkerProvider(): array
	{
		return [
			'null (absent)'    => [null],
			'empty string'     => [''],
			'Enabled (title)'  => ['Enabled'],
			'ENABLED (upper)'  => ['ENABLED'],
			'enabled (lower, already canonical)' => ['enabled'],
		];
	}

	/** Malformed group 'logging' values never TypeError and never silently become 'default'. */
	#[DataProvider('malformedGroupLoggingProvider')]
	public function testGroupLoggingMalformedValuesFailSafeToEnabled($stored): void
	{
		$this->assertSame('enabled', pfb_dnsbl_group_logging($stored));
	}

	/** @return array<string,array{0:mixed}> */
	public static function malformedGroupLoggingProvider(): array
	{
		return [
			'array'  => [['enabled']],
			'int'    => [0],
			'bool'   => [FALSE],
			'junk string' => ['sinkhole'],
		];
	}

	// -----------------------------------------------------------------------
	// D — pfb_dnsbl_effective_logging(): the one resolver every consumer shares
	// -----------------------------------------------------------------------

	/**
	 * Default policy + an explicit group mechanism: the group's OWN choice wins,
	 * completely independent of whatever the global mechanism currently is.
	 */
	#[DataProvider('concreteMechanismProvider')]
	public function testDefaultPolicyExplicitGroupKeepsItsOwnChoice(string $group_token): void
	{
		// A DIFFERENT global mechanism than the group's own, so a wrong resolver that
		// silently prefers global would be caught even when both happen to coincide.
		$global = $group_token === 'nodata' ? 'nxdomain' : 'nodata';

		$effective = pfb_dnsbl_effective_logging($group_token, $global, PfbDnsblGlobalMode::Default);

		$this->assertSame($group_token, $effective);
	}

	/** Default policy + a group on 'default': live inheritance of the CURRENT global mechanism. */
	#[DataProvider('concreteMechanismProvider')]
	public function testDefaultPolicyGroupDefaultInheritsTheGlobalMechanism(string $global_token): void
	{
		$effective = pfb_dnsbl_effective_logging('default', $global_token, PfbDnsblGlobalMode::Default);

		$this->assertSame($global_token, $effective);
	}

	/**
	 * Override policy forces EVERY group -- Default or an explicit mechanism -- onto
	 * the global mechanism. "Override forces same global mechanism but never
	 * overwrites saved group choices" (issue #3288 Contract): the group's STORED
	 * value is untouched by this call (it is a pure function, no write), only the
	 * EFFECTIVE result changes.
	 */
	#[DataProvider('concreteMechanismProvider')]
	public function testOverridePolicyForcesTheGlobalMechanismForAnExplicitGroup(string $group_token): void
	{
		$global = $group_token === 'disabled' ? 'nodata_log' : 'disabled';

		$effective = pfb_dnsbl_effective_logging($group_token, $global, PfbDnsblGlobalMode::Override);

		$this->assertSame($global, $effective);
	}

	public function testOverridePolicyForcesTheGlobalMechanismForADefaultGroup(): void
	{
		$effective = pfb_dnsbl_effective_logging('default', 'nxdomain', PfbDnsblGlobalMode::Override);

		$this->assertSame('nxdomain', $effective);
	}

	/**
	 * Scenario, Given/When/Then: this is the exact transition the issue's Verification
	 * clause names -- "WHEN policy changes to Override THEN all groups use the
	 * selected mechanism; WHEN it returns to Default THEN saved explicit group
	 * choices become effective again." Assert the BEFORE state first so green proves
	 * the toggle causes the change, not merely the final state (testing.md).
	 */
	public function testPolicyTransitionFromOverrideBackToDefaultRestoresTheExplicitChoice(): void
	{
		// Given a group with an explicit, non-global mechanism.
		$group_choice = 'nxdomain_log';
		$global       = 'disabled_log';

		// Before: under Override, the group's own choice is masked.
		$under_override = pfb_dnsbl_effective_logging($group_choice, $global, PfbDnsblGlobalMode::Override);
		$this->assertSame($global, $under_override, 'before: Override must mask the explicit group choice');

		// When policy returns to Default (group's STORED value never changed).
		$under_default = pfb_dnsbl_effective_logging($group_choice, $global, PfbDnsblGlobalMode::Default);

		// Then the explicit choice is effective again.
		$this->assertSame($group_choice, $under_default, 'after: Default must restore the explicit group choice');
	}

	/**
	 * A historical VIP-marker group (never migrated) under Default policy: it
	 * normalizes to 'enabled' (NOT 'default'), so it does NOT inherit -- it reads as
	 * its own explicit 'enabled' choice, exactly like a genuinely migrated group that
	 * explicitly selected VIP would.
	 */
	#[DataProvider('vipMarkerProvider')]
	public function testDefaultPolicyUnmigratedVipMarkerResolvesToEnabledNotGlobal($stored): void
	{
		$effective = pfb_dnsbl_effective_logging($stored, 'disabled_log', PfbDnsblGlobalMode::Default);

		$this->assertSame('enabled', $effective);
	}

	/** Under Override, an unmigrated VIP-marker group is masked exactly like any other -- global wins. */
	#[DataProvider('vipMarkerProvider')]
	public function testOverridePolicyUnmigratedVipMarkerIsStillMaskedByGlobal($stored): void
	{
		$effective = pfb_dnsbl_effective_logging($stored, 'nodata', PfbDnsblGlobalMode::Override);

		$this->assertSame('nodata', $effective);
	}

	// Decode the mode, mechanism, and legacy state as one coherent policy.
	public function testConfigFreshDomainIsDefaultDisabledLogNonLegacy(): void
	{
		$config = pfb_dnsbl_policy_config([], []);

		$this->assertSame(PfbDnsblGlobalMode::Default, $config['mode']);
		$this->assertSame('disabled_log', $config['mechanism']);
		$this->assertFalse($config['legacy']);
	}

	/** Row: "Old no-global-override => Default policy + enabled shared mechanism". */
	#[DataProvider('legacyNoOverrideProvider')]
	public function testConfigLegacyNoOverrideIsDefaultEnabledLegacy(array $dconfig, array $groups): void
	{
		$config = pfb_dnsbl_policy_config($dconfig, $groups);

		$this->assertSame(PfbDnsblGlobalMode::Default, $config['mode']);
		$this->assertSame('enabled', $config['mechanism']);
		$this->assertTrue($config['legacy']);
	}

	/** @return array<string,array{0:array,1:array}> baseline-safe: plain arrays only. */
	public static function legacyNoOverrideProvider(): array
	{
		return [
			'absent global_log, settings has other data' => [['pfb_dnsbl' => 'on'], []],
			'explicit empty global_log'                  => [['pfb_dnsbl' => 'on', 'global_log' => ''], []],
			'settings empty, groups present' => [[], [0 => ['aliasname' => 'X', 'logging' => 'enabled']]],
		];
	}

	/** Row: "Old active global override => Override with same enforced mechanism", verbatim for all 7 tokens. */
	#[DataProvider('concreteMechanismProvider')]
	public function testConfigLegacyActiveOverrideIsOverridePreservedMechanismLegacy(string $token): void
	{
		$config = pfb_dnsbl_policy_config(['pfb_dnsbl' => 'on', 'global_log' => $token], []);

		$this->assertSame(PfbDnsblGlobalMode::Override, $config['mode']);
		$this->assertSame($token, $config['mechanism']);
		$this->assertTrue($config['legacy']);
	}

	/**
	 * Once global_log_mode is present -- migrated, or an operator's later explicit
	 * choice -- it is trusted verbatim and legacy is FALSE, regardless of what the
	 * raw mechanism looks like.
	 */
	#[DataProvider('resolvedModeProvider')]
	public function testConfigResolvedSectionTrustsStoredModeAndMechanismNonLegacy(string $stored_mode): void
	{
		$config = pfb_dnsbl_policy_config(['global_log_mode' => $stored_mode, 'global_log' => 'nxdomain'], []);

		$this->assertSame(
			$stored_mode === 'override' ? PfbDnsblGlobalMode::Override : PfbDnsblGlobalMode::Default,
			$config['mode']
		);
		$this->assertSame('nxdomain', $config['mechanism']);
		$this->assertFalse($config['legacy']);
	}

	/** @return array<string,array{0:string}> */
	public static function resolvedModeProvider(): array
	{
		return [
			'default'  => ['default'],
			'override' => ['override'],
		];
	}

	/** Malformed/non-scalar global_log on a legacy (not fresh, mode absent) section fails safe -- Default/'enabled', never a TypeError. */
	#[DataProvider('nonScalarMalformedProvider')]
	public function testConfigLegacyNonScalarMalformedMechanismFailsSafe($malformed): void
	{
		$config = pfb_dnsbl_policy_config(['pfb_dnsbl' => 'on', 'global_log' => $malformed], []);

		$this->assertSame(PfbDnsblGlobalMode::Default, $config['mode']);
		$this->assertSame('enabled', $config['mechanism']);
		$this->assertTrue($config['legacy']);
	}

	/** @return array<string,array{0:mixed}> only the non-scalar malformed rows. */
	public static function nonScalarMalformedProvider(): array
	{
		return [
			'array' => [['enabled']],
			'int'   => [0],
			'bool'  => [FALSE],
		];
	}

	/** A junk but genuinely non-empty STRING was override evidence under the retired scheme's !empty() precedence -- mirrors pfb_dnsbl_policy_migrate() exactly. */
	public function testConfigLegacyJunkNonEmptyStringMechanismDerivesOverride(): void
	{
		$config = pfb_dnsbl_policy_config(['pfb_dnsbl' => 'on', 'global_log' => 'sinkhole'], []);

		$this->assertSame(PfbDnsblGlobalMode::Override, $config['mode']);
		// 'sinkhole' is not one of the 7 concrete tokens, so mechanism itself still
		// fails safe to 'enabled' -- it is the MODE derivation, not the mechanism
		// value, that reuses the retired scheme's !empty() truthiness.
		$this->assertSame('enabled', $config['mechanism']);
	}

	public function testConfigCurrentPolicyWithoutMechanismUsesTheFreshDefault(): void
	{
		$config = pfb_dnsbl_policy_config(['global_log_mode' => 'default'], []);

		$this->assertSame(PfbDnsblGlobalMode::Default, $config['mode']);
		$this->assertSame('disabled_log', $config['mechanism']);
		$this->assertFalse($config['legacy']);
	}

	// Legacy projection applies only to historical VIP markers, never current choices.

	#[DataProvider('vipMarkerProvider')]
	public function testGroupLoggingLegacyProjectsVipMarkersToDefault($stored): void
	{
		$this->assertSame('default', pfb_dnsbl_group_logging($stored, TRUE));
	}

	/** legacy=FALSE (the parameter's default) is completely unaffected -- unchanged from Section C above. */
	#[DataProvider('vipMarkerProvider')]
	public function testGroupLoggingNonLegacyStillReadsVipMarkersAsEnabled($stored): void
	{
		$this->assertSame('enabled', pfb_dnsbl_group_logging($stored, FALSE));
	}

	/**
	 * An operator's genuine explicit choice -- ANY of the seven concrete mechanisms,
	 * 'enabled' (VIP) included once it is the group's OWN literal stored token, not
	 * an absence/empty/case-variant -- must never be reinterpreted by the legacy
	 * flag. Only the historical ABSENCE-CLASS markers project; an explicit stored
	 * 'enabled' is indistinguishable in storage from the legacy marker by design
	 * (issue #3288 Constraints), so this is intentionally the SAME projection as
	 * the VIP-marker test above for that one token -- documented here to make clear
	 * it is not an oversight.
	 */
	#[DataProvider('concreteMechanismProvider')]
	public function testGroupLoggingLegacyNeverAffectsAnExplicitNonAbsenceToken(string $token): void
	{
		$expected = $token === 'enabled' ? 'default' : $token;

		$this->assertSame($expected, pfb_dnsbl_group_logging($token, TRUE));
	}

	public function testGroupLoggingLegacyLeavesTheDefaultTokenAlone(): void
	{
		$this->assertSame('default', pfb_dnsbl_group_logging('default', TRUE));
	}

	/** Malformed values fail safe to 'enabled' regardless of the legacy flag -- junk is never a historical marker. */
	#[DataProvider('malformedGroupLoggingProvider')]
	public function testGroupLoggingLegacyDoesNotRescueMalformedValues($stored): void
	{
		$this->assertSame('enabled', pfb_dnsbl_group_logging($stored, TRUE));
	}

	/**
	 * The load-bearing scenario itself: under legacy=TRUE, an unmigrated VIP group
	 * under Default policy correctly LIVE-INHERITS the global mechanism -- exactly
	 * as if it had already been converted to 'default' in storage. Effective
	 * behaviour never depends on the migration or facade having run yet.
	 */
	#[DataProvider('vipMarkerProvider')]
	public function testEffectiveLoggingLegacyMakesAnUnmigratedVipGroupInheritTheGlobalMechanism($stored): void
	{
		$effective = pfb_dnsbl_effective_logging($stored, 'disabled_log', PfbDnsblGlobalMode::Default, TRUE);

		$this->assertSame('disabled_log', $effective);
	}

	/**
	 * The regression this closes: WITHOUT the legacy flag (legacy=FALSE, the
	 * default -- what an already-migrated or never-legacy box always uses), that
	 * SAME unmigrated group would resolve to its own literal 'enabled' instead,
	 * never seeing a later global mechanism change. This test documents that this
	 * IS the pre-#3288-review behaviour for legacy=FALSE, so a future edit cannot
	 * silently widen legacy=FALSE into also projecting -- the two call sites
	 * (legacy-aware apply.inc/UI reads vs. anything reading an already-migrated
	 * box) must stay genuinely distinguishable.
	 */
	#[DataProvider('vipMarkerProvider')]
	public function testEffectiveLoggingNonLegacyLeavesAnUnmigratedVipGroupOnItsOwnMechanism($stored): void
	{
		$effective = pfb_dnsbl_effective_logging($stored, 'disabled_log', PfbDnsblGlobalMode::Default, FALSE);

		$this->assertSame('enabled', $effective);
	}

	/** Override policy already forces the global mechanism regardless of the group -- legacy is irrelevant there too. */
	#[DataProvider('vipMarkerProvider')]
	public function testEffectiveLoggingLegacyIsIrrelevantUnderOverridePolicy($stored): void
	{
		$effective = pfb_dnsbl_effective_logging($stored, 'nodata', PfbDnsblGlobalMode::Override, TRUE);

		$this->assertSame('nodata', $effective);
	}

	/** An explicit non-VIP mechanism keeps its own choice under Default policy, legacy or not. */
	#[DataProvider('nonVipConcreteMechanismProvider')]
	public function testEffectiveLoggingLegacyNeverOverridesAnExplicitNonVipChoice(string $token): void
	{
		$global = $token === 'nodata' ? 'nxdomain' : 'nodata';

		$effective = pfb_dnsbl_effective_logging($token, $global, PfbDnsblGlobalMode::Default, TRUE);

		$this->assertSame($token, $effective);
	}

}
