<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1921 — mechanical completeness gate: every pfb_cfg_registry() entry carries its
 * issue #1920 grandfathering decision as a declarative slot.
 *
 * Every entry must carry exactly one of {'grandfather', 'no_grandfather'}, except the two
 * keys listed in self::EXCEPTIONS below, which carry neither. This is a partition, not a
 * suggestion: the check logic lives in pure private helpers that take a registry-shaped
 * array, so a fixture can exercise both the pass and the fail side of the gate.
 *
 * DATA + TEST ONLY (issue #1921 step S1) -- nothing reads these slots yet; the loop that
 * consumes 'grandfather' at install/upgrade is a later step.
 */
final class CfgRegistryGrandfatherGateTest extends TestCase
{
	/**
	 * Registry keys that carry NEITHER 'grandfather' nor 'no_grandfather', with the reason
	 * no per-key classification applies to them.
	 *
	 * @var array<string,string>
	 */
	private const EXCEPTIONS = [
		// The mode instrument itself, recorded by pfb_settings_family_record() -- never a
		// peer row a grandfathering decision could apply to.
		'gen/settings_family' => 'settings-family mode instrument, not operator configuration',
		// PFBL-03 cross-key bespoke seed: this field's value depends on pfb_control PLUS its
		// own run-once marker, not a simple absent/'' -> value map.
		'dnsbl/pfb_control_legacy' => 'PFBL-03 cross-key bespoke seed (depends on pfb_control + a run-once marker)',
	];

	/**
	 * Pinned list of the 14 retired scalar spellings PFB_LEGACY_KEY_RENAMES' scalar half
	 * (pfblockerng.inc) carries -- the multiset of registry 'old_name' values must equal
	 * this set exactly, each appearing exactly once (issue #1921).
	 *
	 * @var list<string>
	 */
	private const RETIRED_SCALAR_SPELLINGS = [
		'alexa_enable',
		'alexa_type',
		'alexa_count',
		'alexa_inclusion',
		'pfb_pytld',
		'pfb_pytld_sort',
		'pfb_pytlds_gtld',
		'pfb_pytlds_cctld',
		'pfb_pytlds_itld',
		'pfb_pytlds_bgtld',
		'pfb_tld',
		'tldblacklist',
		'tldexclusion',
		// issue #1921: the DNSBL whitelist blob's own retired spelling.
		'suppression',
	];

	// -----------------------------------------------------------------------
	// Pure helpers under test -- take a registry-shaped array so fixtures can
	// exercise the fail side without touching the real registry.
	// -----------------------------------------------------------------------

	/**
	 * One violation message per entry that does not carry exactly one of
	 * {'grandfather', 'no_grandfather'}, skipping keys listed in $exceptions.
	 * A present-but-empty 'no_grandfather' reason also fails.
	 *
	 * @param  array<string,array<string,mixed>> $registry
	 * @param  array<string,string>               $exceptions
	 * @return list<string>
	 */
	private static function unclassifiedEntries(array $registry, array $exceptions): array
	{
		$violations = [];
		foreach ($registry as $key => $entry) {
			if (array_key_exists($key, $exceptions)) {
				continue;
			}
			$has_gf = array_key_exists('grandfather', $entry);
			$has_ng = array_key_exists('no_grandfather', $entry);

			if ($has_gf && $has_ng) {
				$violations[] = "{$key}: carries BOTH 'grandfather' and 'no_grandfather'";
				continue;
			}
			if (!$has_gf && !$has_ng) {
				$violations[] = "{$key}: carries NEITHER 'grandfather' nor 'no_grandfather'";
				continue;
			}
			if ($has_ng && (!is_string($entry['no_grandfather']) || $entry['no_grandfather'] === '')) {
				$violations[] = "{$key}: 'no_grandfather' reason must be a non-empty string";
			}
		}
		return $violations;
	}

	/**
	 * One violation message per 'grandfather' map value that is ALSO a non-ABSENT key of
	 * some 'grandfather' map in the registry -- a reinstall-oscillation guard: if a mapped
	 * OUTPUT can be fed back in as an INPUT, a repeated grandfather pass could ping-pong a
	 * value instead of converging.
	 *
	 * @param  array<string,array<string,mixed>> $registry
	 * @return list<string>
	 */
	private static function fixpointViolations(array $registry): array
	{
		$outputs = [];
		$inputs  = [];
		foreach ($registry as $key => $entry) {
			if (!array_key_exists('grandfather', $entry) || !is_array($entry['grandfather'])) {
				continue;
			}
			foreach ($entry['grandfather'] as $from => $to) {
				if ($from !== PFB_GF_ABSENT) {
					$inputs[(string) $from] = TRUE;
				}
				$outputs[(string) $to] = "{$key}: '" . var_export($from, TRUE) . "' => '{$to}'";
			}
		}

		$violations = [];
		foreach ($outputs as $value => $where) {
			if (array_key_exists($value, $inputs)) {
				$violations[] = "map output '{$value}' ({$where}) is also a non-ABSENT map input elsewhere";
			}
		}
		return $violations;
	}

	// -----------------------------------------------------------------------
	// 1 -- totality over the REAL registry
	// -----------------------------------------------------------------------

	public function testEveryEntryIsClassifiedExactlyOnce(): void
	{
		$registry = pfb_cfg_registry();
		$this->assertNotEmpty($registry, 'registry must not be empty (vacuity guard)');

		$violations = self::unclassifiedEntries($registry, self::EXCEPTIONS);
		$this->assertSame([], $violations,
			"every registry entry must carry exactly one of {'grandfather', 'no_grandfather'} "
			. "unless listed in CfgRegistryGrandfatherGateTest::EXCEPTIONS: " . implode('; ', $violations)
		);

		// The two exceptions must actually exist in the registry and carry NO slot at all.
		foreach (self::EXCEPTIONS as $key => $reason) {
			$this->assertArrayHasKey($key, $registry, "exception '{$key}' ({$reason}) must exist in the registry");
			$this->assertArrayNotHasKey('grandfather', $registry[$key], "exception '{$key}' must carry no 'grandfather' slot");
			$this->assertArrayNotHasKey('no_grandfather', $registry[$key], "exception '{$key}' must carry no 'no_grandfather' slot");
		}
	}

	// -----------------------------------------------------------------------
	// 2/3 -- the gate CAN fail (fixtures)
	// -----------------------------------------------------------------------

	public function testUnclassifiedEntryFailsTheGate(): void
	{
		$fixture = [
			'gen/classified' => ['default' => '', 'no_grandfather' => 'reason'],
			'gen/bare_entry' => ['default' => ''],
		];

		$violations = self::unclassifiedEntries($fixture, []);
		$this->assertNotEmpty($violations, 'a bare entry must trip the gate');
		$this->assertStringContainsString('gen/bare_entry', implode('; ', $violations),
			'the violation must name the failing key'
		);
		$this->assertStringNotContainsString('gen/classified', implode('; ', $violations),
			'a correctly classified entry must not appear in the violations'
		);
	}

	public function testDoublyClassifiedEntryFailsTheGate(): void
	{
		$fixture = [
			'gen/double' => [
				'default'        => '',
				'grandfather'    => [PFB_GF_ABSENT => 'on'],
				'no_grandfather' => 'reason',
			],
		];

		$violations = self::unclassifiedEntries($fixture, []);
		$this->assertNotEmpty($violations, 'an entry with both slots must trip the gate');
		$this->assertStringContainsString('gen/double', implode('; ', $violations));
		$this->assertStringContainsString('BOTH', implode('; ', $violations));
	}

	// -----------------------------------------------------------------------
	// 4 -- fixpoint guard (no map output is also a non-ABSENT map input)
	// -----------------------------------------------------------------------

	public function testFixpointNoMapOutputIsAlsoAMapInput(): void
	{
		$registry = pfb_cfg_registry();
		$grandfathered = array_filter($registry, static fn (array $e): bool => array_key_exists('grandfather', $e));
		$this->assertNotEmpty($grandfathered, 'at least one registry entry must carry a grandfather map (vacuity guard)');

		$this->assertSame([], self::fixpointViolations($registry),
			'no grandfather map output may also be a non-ABSENT map input anywhere in the registry (reinstall oscillation guard)'
		);
	}

	public function testFixpointHelperFiresOnAnOscillatingFixture(): void
	{
		$fixture = [
			'gen/oscillates' => [
				'default'     => '',
				'grandfather' => ['on' => 'off', 'off' => 'on'],
			],
		];

		$this->assertNotEmpty(self::fixpointViolations($fixture),
			"a map whose output ('off') is also a non-ABSENT input must trip the fixpoint guard"
		);
	}

	// -----------------------------------------------------------------------
	// 5 -- PFB_GF_ABSENT never used as a map OUTPUT
	// -----------------------------------------------------------------------

	public function testAbsentMarkerNeverUsedAsAMapOutput(): void
	{
		$registry = pfb_cfg_registry();
		$grandfathered = array_filter($registry, static fn (array $e): bool => array_key_exists('grandfather', $e));
		$this->assertNotEmpty($grandfathered, 'at least one registry entry must carry a grandfather map (vacuity guard)');

		foreach ($grandfathered as $key => $entry) {
			foreach ($entry['grandfather'] as $from => $to) {
				$this->assertNotSame(PFB_GF_ABSENT, $to,
					"{$key}: grandfather map must never emit PFB_GF_ABSENT as an output value (from '" . var_export($from, TRUE) . "')"
				);
			}
		}
	}

	// -----------------------------------------------------------------------
	// 6 -- old_name parity with the retired pre-#1898 spellings
	// -----------------------------------------------------------------------

	public function testOldNameParityWithTheRetiredSpellings(): void
	{
		$registry = pfb_cfg_registry();

		$old_names = [];
		foreach ($registry as $key => $entry) {
			if (array_key_exists('old_name', $entry)) {
				$old_names[] = $entry['old_name'];
				$this->assertNotSame($entry['old_name'], substr($key, strpos($key, '/') + 1),
					"{$key}: 'old_name' must differ from the entry's own bare key"
				);
			}
		}

		$this->assertNotEmpty($old_names, 'at least one registry entry must carry an old_name (vacuity guard)');

		sort($old_names);
		$expected = self::RETIRED_SCALAR_SPELLINGS;
		sort($expected);
		$this->assertSame($expected, $old_names,
			"the multiset of registry 'old_name' values must equal the 14 retired scalar spellings exactly, once each"
		);

		// No DNSBL-section bare key may itself be a retired spelling -- a re-registration
		// under an old name would shadow the rename branch. (Scoped to 'dnsbl/': every
		// retired spelling lived in that section; 'suppression' lives on legitimately as
		// the ip/suppression toggle's bare key.)
		foreach ($registry as $key => $entry) {
			if (str_starts_with($key, 'dnsbl/')) {
				$this->assertNotContains(substr($key, strlen('dnsbl/')), self::RETIRED_SCALAR_SPELLINGS,
					"{$key}: a dnsbl-section bare key must never reuse a retired spelling"
				);
			}
		}

		// issue #1921: PFB_LEGACY_KEY_RENAMES no longer carries the scalar-section rows
		// at all -- they moved here, to the registry's own 'old_name' slots, consumed by
		// pfb_registry_pass() (see RegistryPassTest rows 11-16). What remains in
		// PFB_LEGACY_KEY_RENAMES is only the dynamic per-feed row rename
		// (LegacyKeyRenameMigrationTest::testRenameMapIsExactlyTheAuditedRow pins that
		// shape); there is no longer a scalar cross-check to run against it here.
	}

	public function testPslPolicyKeysHaveNoLegacyNameOrGrandfatherSeed(): void
	{
		$registry = pfb_cfg_registry();
		foreach ([
			'dnsbl/pfb_psl_include_private',
			'dnsbl/pfb_psl_allow_private',
			'dnsbl/pfb_psl_feed_private_policy',
			'dnsbl/pfb_psl_feed_icann_policy',
		] as $key) {
			$this->assertArrayHasKey($key, $registry);
			$this->assertArrayNotHasKey('old_name', $registry[$key]);
			$this->assertArrayNotHasKey('grandfather', $registry[$key]);
			$this->assertArrayHasKey('no_grandfather', $registry[$key]);
		}
	}

	// -----------------------------------------------------------------------
	// 7 -- grandfather maps are string -> string with canonical shapes
	// -----------------------------------------------------------------------

	public function testGrandfatherMapsAreStringToStringWithCanonicalShapes(): void
	{
		$registry = pfb_cfg_registry();
		$grandfathered = array_filter($registry, static fn (array $e): bool => array_key_exists('grandfather', $e));
		$this->assertNotEmpty($grandfathered, 'at least one registry entry must carry a grandfather map (vacuity guard)');

		foreach ($grandfathered as $key => $entry) {
			$map = $entry['grandfather'];
			$this->assertIsArray($map, "{$key}: 'grandfather' must be an array");
			$this->assertNotEmpty($map, "{$key}: 'grandfather' map must not be empty");

			foreach ($map as $from => $to) {
				$this->assertIsString($from, "{$key}: grandfather map key must be a string");
				$this->assertTrue($from === '' || $from === PFB_GF_ABSENT,
					"{$key}: grandfather map key must be '' or PFB_GF_ABSENT, got " . var_export($from, TRUE)
				);
				$this->assertIsString($to, "{$key}: grandfather map value must be a string");
				$this->assertNotSame('', $to, "{$key}: grandfather map value must be non-empty");
			}
		}
	}
}
