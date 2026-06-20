<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 3 — Rollback / backward-compat contract.
 *
 * Two invariants, per registered field, for every legacy stored vocabulary token:
 *
 * FORWARD invariant (old store -> new code):
 *   PfbConfig::read($key) on any legacy stored token returns a sane (non-crash,
 *   well-formed) runtime value.  Mirrors ADR-28's existing forward-compat freeze.
 *
 * BACKWARD invariant (new code -> old store -> old code):
 *   PfbConfig::write($key, <runtime_value>) only ever emits a string that is a
 *   member of the field's legacy stored vocabulary.  Because the gateway never
 *   introduces a novel on-disk token, a downgrade leaves older code reading values
 *   it already understands -- no crash, no silent settings-loss.
 *
 * ROLLBACK SAFETY BY CONSTRUCTION:
 *   Every write adapter (pfb_cfg_toggle_write, pfb_cfg_lenient_write) returns a
 *   value whose backing is the exact legacy stored string (ADR-28 SS2.2).  Plain-
 *   string (null-adapter) fields are identity, so they cannot introduce novel tokens
 *   either.  This phase asserts these properties explicitly per field so a future
 *   adapter addition cannot silently break the contract.
 *
 * EXCLUDED FIELDS (not backward-unsafe at the PfbConfig level):
 *   pfb_idn -- uses null/null adapters at PfbConfig level (identity; backward-safe).
 *              The legacy 'on'->'all' normalisation happens only at the pfb_global()
 *              seam, outside PfbConfig.  This exclusion is documented in ADR-29 SS2.3
 *              and mirrors the ADR-28 adapter-adoption exclusion (01_Results.txt).
 *              pfb_idn is included in the plain-string backward test (identity
 *              adapter; any stored value is passed through unchanged).
 *
 * SINCE-VERSION COVERAGE:
 *   The rollback contract applies to every registered key regardless of its
 *   since-version: a downgrade from devel to any prior release that already
 *   knew the key must read values written by devel without confusion.
 *
 * Scenario: rollback safety holds for every registered field.
 *   Background: the registered field vocabulary (pfb_cfg_field_vocab()) defines
 *     every token a pre-ADR-29 release might have persisted for each adapter type.
 *   Given a stored token v from the field's legacy vocabulary.
 *   When PfbConfig::read($key) and PfbConfig::write($key, <result>) are called.
 *   Then (FORWARD) the read result is a well-formed runtime value -- not NULL,
 *     not a crash, and of the correct type.
 *   And (BACKWARD) the write result is a string in the field's legacy vocabulary.
 *   And the since-version field is a non-empty string for every registered field.
 */
final class RollbackContractTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixture
	// -----------------------------------------------------------------------

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// A -- Since-version field populated for every registered key
	// -----------------------------------------------------------------------

	/**
	 * Every registered field has a non-empty 'since' string.
	 *
	 * The since-version convention: the first release that introduced the key
	 * to config.xml.  For legacy keys (pre-registry), the earliest still-shipped
	 * release that used the key is an acceptable baseline.
	 *
	 * Scenario: since-version is populated.
	 *   Background: pfb_cfg_registry() returns all fields.
	 *     Given each registered field entry.
	 *     When inspecting entry['since'].
	 *     Then it is a non-empty string (e.g. '1.0.0', '3.2.0').
	 */
	public function testSinceVersionPopulatedForEveryRegisteredField(): void
	{
		$registry = pfb_cfg_registry();
		$this->assertNotEmpty($registry, 'Registry must not be empty');

		$missing = [];
		foreach ($registry as $key => $entry) {
			if (!is_string($entry['since'] ?? NULL) || $entry['since'] === '') {
				$missing[] = $key;
			}
		}

		$this->assertEmpty(
			$missing,
			'These registered fields are missing a non-empty since-version: '
			. implode(', ', $missing)
		);
	}

	/**
	 * since-version values follow the x.y.z semver-like pattern.
	 *
	 * Scenario:
	 *   Given each registry entry's since value.
	 *   When tested against the x.y.z pattern.
	 *   Then every value matches (no free-text stubs like 'ADR-29-P1' remain).
	 */
	public function testSinceVersionFollowsVersionPattern(): void
	{
		$registry = pfb_cfg_registry();
		$pattern  = '/^\d+\.\d+\.\d+$/';

		$non_semver = [];
		foreach ($registry as $key => $entry) {
			$since = $entry['since'] ?? '';
			if (!preg_match($pattern, (string) $since)) {
				$non_semver[] = $key . '=' . $since;
			}
		}

		$this->assertEmpty(
			$non_semver,
			'These since-version values do not match x.y.z pattern: '
			. implode(', ', $non_semver)
		);
	}

	// -----------------------------------------------------------------------
	// B -- FORWARD invariant: every legacy stored token yields a sane runtime value
	// -----------------------------------------------------------------------

	/**
	 * Toggle-adapted fields: 'on' stored -> PfbToggle::On returned (no crash).
	 *
	 * Scenario:
	 *   Background: toggle field stored vocabulary = {'on', ''}.
	 *     Given stored = 'on'.
	 *     When PfbConfig::read($key) for each toggle-adapted field.
	 *     Then the result is PfbToggle::On (well-formed, non-null enum).
	 */
	public function testForwardToggleFieldsOnYieldsOnEnum(): void
	{
		$toggle_keys = $this->toggleAdaptedKeys();
		$this->assertNotEmpty($toggle_keys, 'Must have at least one toggle-adapted key');

		foreach ($toggle_keys as $key => $path) {
			// Given: 'on' stored.
			config_set_path($path, 'on');

			// Before: raw value confirmed.
			$this->assertSame('on', config_get_path($path), "before forward: {$key} stored='on'");

			// When/Then: read returns PfbToggle::On -- sane, well-formed.
			$result = PfbConfig::read($key);
			$this->assertInstanceOf(PfbToggle::class, $result, "FORWARD: {$key} read('on') must return PfbToggle");
			$this->assertSame(PfbToggle::On, $result, "FORWARD: {$key} read('on') must be PfbToggle::On");
		}
	}

	/**
	 * Toggle-adapted fields: '' stored -> PfbToggle::Off returned (no crash).
	 *
	 * Scenario:
	 *   Background: toggle field stored vocabulary = {'on', ''}.
	 *     Given stored = '' (unchecked / absent-equivalent).
	 *     When PfbConfig::read($key) for each toggle-adapted field.
	 *     Then the result is PfbToggle::Off (well-formed, non-null enum).
	 */
	public function testForwardToggleFieldsOffYieldsOffEnum(): void
	{
		$toggle_keys = $this->toggleAdaptedKeys();

		foreach ($toggle_keys as $key => $path) {
			// Given: '' stored.
			config_set_path($path, '');

			// Before.
			$this->assertSame('', config_get_path($path), "before forward: {$key} stored=''");

			// When/Then.
			$result = PfbConfig::read($key);
			$this->assertInstanceOf(PfbToggle::class, $result, "FORWARD: {$key} read('') must return PfbToggle");
			$this->assertSame(PfbToggle::Off, $result, "FORWARD: {$key} read('') must be PfbToggle::Off");
		}
	}

	/**
	 * Toggle-adapted fields: absent key -> PfbToggle::default() returned (no crash).
	 *
	 * Scenario:
	 *   Background: key entirely absent from config.xml (clean install before save).
	 *     Given no stored value.
	 *     When PfbConfig::read($key).
	 *     Then the result is a PfbToggle enum (registered default kicks in; no crash).
	 */
	public function testForwardToggleFieldsAbsentKeyYieldsToggleEnum(): void
	{
		$toggle_keys = $this->toggleAdaptedKeys();

		foreach ($toggle_keys as $key => $path) {
			// Given: absent (setUp already clears config).
			// Before: absent.
			$this->assertNull(config_get_path($path), "before forward: {$key} must be absent");

			// When/Then: sane default (no crash, returns PfbToggle).
			$result = PfbConfig::read($key);
			$this->assertInstanceOf(PfbToggle::class, $result, "FORWARD: {$key} absent must return PfbToggle enum");
		}
	}

	/**
	 * Lenient field (pfb_dnsbl_lenient): 'on' -> PfbLenient::On (no crash).
	 *
	 * Scenario:
	 *   Background: pfb_dnsbl_lenient vocabulary = {'on', 'off', ''}.
	 *     Given stored = 'on'.
	 *     When PfbConfig::read('pfb_dnsbl_lenient').
	 *     Then PfbLenient::On is returned.
	 */
	public function testForwardLenientFieldOnYieldsOnEnum(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: 'on' stored.
		config_set_path($path, 'on');

		// Before.
		$this->assertSame('on', config_get_path($path));

		// When/Then.
		$result = PfbConfig::read('pfb_dnsbl_lenient');
		$this->assertInstanceOf(PfbLenient::class, $result);
		$this->assertSame(PfbLenient::On, $result, "FORWARD: 'on' must yield PfbLenient::On");
	}

	/**
	 * Lenient field (pfb_dnsbl_lenient): 'off' -> PfbLenient::Off (no crash).
	 */
	public function testForwardLenientFieldOffYieldsOffEnum(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: 'off' stored (canonical disabled value).
		config_set_path($path, 'off');

		// Before.
		$this->assertSame('off', config_get_path($path));

		// When/Then.
		$result = PfbConfig::read('pfb_dnsbl_lenient');
		$this->assertInstanceOf(PfbLenient::class, $result);
		$this->assertSame(PfbLenient::Off, $result, "FORWARD: 'off' must yield PfbLenient::Off");
	}

	/**
	 * Lenient field (pfb_dnsbl_lenient): '' -> PfbLenient::Off (pre-ADR-22 legacy token).
	 *
	 * Scenario:
	 *   Background: '' is the pre-ADR-22 absent state -- a real legacy stored value.
	 *     Given stored = ''.
	 *     When PfbConfig::read('pfb_dnsbl_lenient').
	 *     Then PfbLenient::Off is returned (normalised default -- documented).
	 */
	public function testForwardLenientFieldEmptyYieldsOffEnum(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		// Given: '' stored (pre-ADR-22 install -- legacy token).
		config_set_path($path, '');

		// Before.
		$this->assertSame('', config_get_path($path));

		// When/Then: '' normalises to Off (sane; documented default normalisation).
		$result = PfbConfig::read('pfb_dnsbl_lenient');
		$this->assertInstanceOf(PfbLenient::class, $result);
		$this->assertSame(PfbLenient::Off, $result, "FORWARD: '' must yield PfbLenient::Off (normalised)");
	}

	/**
	 * Plain-string fields: legacy stored value passes through unchanged (no crash).
	 *
	 * Scenario:
	 *   Background: plain (null-adapter) fields -- identity adapter.
	 *     Given a representative canonical stored string for each plain field.
	 *     When PfbConfig::read($key).
	 *     Then the result is the same string (identity; no crash, no type change).
	 */
	public function testForwardPlainStringFieldsPassLegacyTokensUnchanged(): void
	{
		// Representative plain-string fields with canonical legacy stored values.
		$cases = [
			// General section
			'pfb_interval'          => ['installedpackages/pfblockerng/config/0/pfb_interval', '1'],
			'pfb_agg_types'         => ['installedpackages/pfblockerng/config/0/pfb_agg_types', 'Deny'],
			// DNSBL settings section
			'dnsbl_interface'       => ['installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface', 'lo0'],
			'alexa_type'            => ['installedpackages/pfblockerngdnsblsettings/config/0/alexa_type', 'tranco'],
			'alexa_count'           => ['installedpackages/pfblockerngdnsblsettings/config/0/alexa_count', '1000'],
			'action'                => ['installedpackages/pfblockerngdnsblsettings/config/0/action', 'Disabled'],
			'pfb_dnsbl_rule'        => ['installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_rule', 'Disabled'],
			// pfb_idn: excluded from adapter adoption; plain-string (identity).
			'pfb_idn'               => ['installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn', 'all'],
			// SafeSearch section
			'safesearch_enable'     => ['installedpackages/pfblockerngsafesearch/safesearch_enable', 'Disable'],
		];

		foreach ($cases as $key => $spec) {
			[$path, $legacy_value] = $spec;

			// Given.
			config_set_path($path, $legacy_value);

			// Before.
			$this->assertSame($legacy_value, config_get_path($path), "before: {$key} seed");

			// When.
			$result = PfbConfig::read($key);

			// Then: identity -- same string returned; no crash.
			$this->assertIsString($result, "FORWARD: {$key} must return a string");
			$this->assertSame($legacy_value, $result,
				"FORWARD: {$key} read('{$legacy_value}') must pass through unchanged"
			);
		}
	}

	/**
	 * pfb_idn legacy 'on' token passes through unchanged (identity adapter at PfbConfig level).
	 *
	 * This is distinct from pfb_cfg_idn_mode_read() which normalises 'on'->All.
	 * PfbConfig excludes pfb_idn from adapter adoption, so 'on' must round-trip.
	 *
	 * Scenario:
	 *   Background: pfb_idn uses null/null adapters (identity; not PfbIdnMode).
	 *     Given pfb_idn stored as 'on' (legacy).
	 *     When PfbConfig::read('pfb_idn').
	 *     Then 'on' is returned unchanged (identity; NOT 'all').
	 */
	public function testForwardPfbIdnLegacyOnPassesThroughAsIdentity(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';

		// Given: legacy 'on'.
		config_set_path($path, 'on');

		// Before.
		$this->assertSame('on', config_get_path($path));

		// When.
		$result = PfbConfig::read('pfb_idn');

		// Then: identity -- 'on' passes through (no adapter normalisation at PfbConfig level).
		$this->assertSame('on', $result,
			"FORWARD: pfb_idn 'on' must pass through as 'on' (identity adapter; not 'all')"
		);
		$this->assertNotInstanceOf(PfbIdnMode::class, $result,
			"FORWARD: pfb_idn must NOT return a PfbIdnMode enum"
		);
	}

	// -----------------------------------------------------------------------
	// C -- BACKWARD invariant: write only emits legacy vocabulary tokens
	// -----------------------------------------------------------------------

	/**
	 * Toggle-adapted fields: write(On) emits 'on' -- a legacy token.
	 *
	 * Scenario:
	 *   Background: toggle legacy vocabulary = {'on', ''}.
	 *     Given PfbToggle::On.
	 *     When PfbConfig::write($key, PfbToggle::On) for each toggle-adapted field.
	 *     Then config_get_path($path) == 'on' (in vocabulary; no novel token).
	 */
	public function testBackwardToggleFieldsOnEmitsLegacyToken(): void
	{
		$toggle_vocab = pfb_cfg_field_vocab()['toggle'];
		$toggle_keys  = $this->toggleAdaptedKeys();

		foreach ($toggle_keys as $key => $path) {
			// Before: absent.
			$GLOBALS['config'] = [];
			$this->assertNull(config_get_path($path), "before backward On: {$key} absent");

			// When: write On.
			PfbConfig::write($key, PfbToggle::On);

			// Then: stored token is in the legacy vocabulary.
			$stored = (string) config_get_path($path);
			$this->assertContains(
				$stored,
				$toggle_vocab,
				"BACKWARD: {$key} write(On) stored='{$stored}' not in toggle vocab {on,''}"
			);
			$this->assertSame('on', $stored, "BACKWARD: {$key} write(On) must store 'on'");
		}
	}

	/**
	 * Toggle-adapted fields: write(Off) emits '' -- a legacy token.
	 *
	 * Scenario:
	 *   Background: toggle legacy vocabulary = {'on', ''}.
	 *     Given PfbToggle::Off.
	 *     When PfbConfig::write($key, PfbToggle::Off).
	 *     Then stored == '' (in vocabulary; no novel token).
	 */
	public function testBackwardToggleFieldsOffEmitsLegacyToken(): void
	{
		$toggle_vocab = pfb_cfg_field_vocab()['toggle'];
		$toggle_keys  = $this->toggleAdaptedKeys();

		foreach ($toggle_keys as $key => $path) {
			// Before: seed 'on' so we see the write actually changes it.
			config_set_path($path, 'on');
			$this->assertSame('on', config_get_path($path), "before backward Off: {$key} is 'on'");

			// When: write Off.
			PfbConfig::write($key, PfbToggle::Off);

			// Then: stored token is '' -- in the legacy vocabulary.
			$stored = (string) config_get_path($path);
			$this->assertContains(
				$stored,
				$toggle_vocab,
				"BACKWARD: {$key} write(Off) stored='{$stored}' not in toggle vocab"
			);
			$this->assertSame('', $stored, "BACKWARD: {$key} write(Off) must store ''");
		}
	}

	/**
	 * Lenient field: write(On) emits 'on' -- a legacy token.
	 *
	 * Scenario:
	 *   Background: pfb_dnsbl_lenient legacy vocabulary = {'on', 'off', ''}.
	 *     Given PfbLenient::On.
	 *     When PfbConfig::write('pfb_dnsbl_lenient', PfbLenient::On).
	 *     Then stored == 'on' (in vocabulary; no novel token).
	 *
	 * Note: the gateway writes 'on'/'off' -- it does NOT re-emit '' (the pre-ADR-22
	 * absent-key state is a LEGACY READ token, not a WRITE target). Older releases
	 * that check for 'on' to enable and 'off'/'missing' for disabled correctly
	 * interpret 'off' -- no unknown token introduced.
	 */
	public function testBackwardLenientFieldOnEmitsLegacyToken(): void
	{
		$path         = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';
		$lenient_vocab = pfb_cfg_field_vocab()['lenient'];

		// Before: absent.
		$this->assertNull(config_get_path($path), "before backward lenient On: absent");

		// When: write On.
		PfbConfig::write('pfb_dnsbl_lenient', PfbLenient::On);

		// Then.
		$stored = (string) config_get_path($path);
		$this->assertContains($stored, $lenient_vocab,
			"BACKWARD: lenient write(On) stored='{$stored}' not in vocab"
		);
		$this->assertSame('on', $stored, "BACKWARD: lenient write(On) must store 'on'");
	}

	/**
	 * Lenient field: write(Off) emits 'off' -- a legacy token.
	 *
	 * Scenario:
	 *   Background: pfb_dnsbl_lenient legacy vocabulary = {'on', 'off', ''}.
	 *     Given PfbLenient::Off.
	 *     When PfbConfig::write('pfb_dnsbl_lenient', PfbLenient::Off).
	 *     Then stored == 'off' (in vocabulary; pre-existing legacy token).
	 */
	public function testBackwardLenientFieldOffEmitsLegacyToken(): void
	{
		$path         = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';
		$lenient_vocab = pfb_cfg_field_vocab()['lenient'];

		// Before: seed 'on'.
		config_set_path($path, 'on');
		$this->assertSame('on', config_get_path($path), "before backward lenient Off: is 'on'");

		// When: write Off.
		PfbConfig::write('pfb_dnsbl_lenient', PfbLenient::Off);

		// Then: 'off' -- a legacy token (not a novel string).
		$stored = (string) config_get_path($path);
		$this->assertContains($stored, $lenient_vocab,
			"BACKWARD: lenient write(Off) stored='{$stored}' not in vocab"
		);
		$this->assertSame('off', $stored, "BACKWARD: lenient write(Off) must store 'off'");
	}

	/**
	 * Plain-string fields: write($str) emits $str (identity -- no novel token possible).
	 *
	 * Scenario:
	 *   Background: plain fields use null write_adapter (identity).
	 *     Given a canonical stored string.
	 *     When PfbConfig::write($key, $str).
	 *     Then stored == $str (the adapter cannot introduce any novel token).
	 */
	public function testBackwardPlainStringFieldsIdentityAdapterCannotIntroduceNovelTokens(): void
	{
		$cases = [
			'pfb_interval'      => ['installedpackages/pfblockerng/config/0/pfb_interval', '6'],
			'dnsbl_interface'   => ['installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface', 'lo0'],
			'alexa_type'        => ['installedpackages/pfblockerngdnsblsettings/config/0/alexa_type', 'tranco'],
			'safesearch_enable' => ['installedpackages/pfblockerngsafesearch/safesearch_enable', 'Disable'],
			'pfb_idn'           => ['installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn', 'all'],
		];

		foreach ($cases as $key => $spec) {
			[$path, $value] = $spec;

			// Before: absent.
			$GLOBALS['config'] = [];
			$this->assertNull(config_get_path($path), "before backward plain: {$key} absent");

			// When: write the canonical value.
			PfbConfig::write($key, $value);

			// Then: identity -- stored matches the input; no transformation.
			$stored = config_get_path($path);
			$this->assertSame($value, $stored,
				"BACKWARD: {$key} write('{$value}') must store exactly '{$value}' (identity)"
			);
		}
	}

	/**
	 * pfb_idn: write of ANY canonical stored value is identity.
	 * 'on'/'all'/'confusable'/'off'/'' all pass through unchanged.
	 * Backward-safe: no novel token introduced at the PfbConfig level.
	 *
	 * Scenario:
	 *   Background: pfb_idn is excluded from adapter adoption; uses identity adapter.
	 *     Given each canonical or legacy pfb_idn stored value.
	 *     When PfbConfig::write('pfb_idn', $v).
	 *     Then stored == $v (round-trip; no novel token).
	 */
	public function testBackwardPfbIdnAllCanonicalTokensRoundTripAsIdentity(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';
		// All tokens an existing install might have (including legacy 'on').
		$tokens = ['on', 'all', 'confusable', 'off', ''];

		foreach ($tokens as $token) {
			// Reset.
			$GLOBALS['config'] = [];

			// When: write each token.
			PfbConfig::write('pfb_idn', $token);

			// Then: same token stored (identity).
			$stored = config_get_path($path);
			$this->assertSame($token, $stored,
				"BACKWARD: pfb_idn write('{$token}') must store exactly '{$token}'"
			);
		}
	}

	// -----------------------------------------------------------------------
	// D -- Adapter-type helper API
	// -----------------------------------------------------------------------

	/**
	 * pfb_cfg_field_adapter_type() returns a valid type for every registry entry.
	 *
	 * Scenario:
	 *   Background: helper is used by tests to select the vocabulary for a field.
	 *     Given each registry entry.
	 *     When pfb_cfg_field_adapter_type($entry).
	 *     Then the result is 'toggle', 'lenient', or 'plain'.
	 */
	public function testAdapterTypeHelperReturnsValidTypeForEveryRegisteredField(): void
	{
		$registry    = pfb_cfg_registry();
		$valid_types = ['toggle', 'lenient', 'plain'];

		foreach ($registry as $key => $entry) {
			$type = pfb_cfg_field_adapter_type($entry);
			$this->assertContains(
				$type,
				$valid_types,
				"pfb_cfg_field_adapter_type({$key}) returned unknown type: '{$type}'"
			);
		}
	}

	/**
	 * pfb_cfg_field_adapter_type() assigns 'lenient' only to pfb_dnsbl_lenient.
	 *
	 * Scenario:
	 *   Background: only pfb_dnsbl_lenient uses the lenient adapter.
	 *     Given the full registry.
	 *     When collecting all fields whose type is 'lenient'.
	 *     Then only 'pfb_dnsbl_lenient' appears.
	 */
	public function testAdapterTypeHelperLenientAssignedOnlyToPfbDnsblLenient(): void
	{
		$registry       = pfb_cfg_registry();
		$lenient_fields = [];
		foreach ($registry as $key => $entry) {
			if (pfb_cfg_field_adapter_type($entry) === 'lenient') {
				$lenient_fields[] = $key;
			}
		}

		$this->assertSame(
			['pfb_dnsbl_lenient'],
			$lenient_fields,
			'Only pfb_dnsbl_lenient should have adapter type "lenient"'
		);
	}

	/**
	 * pfb_cfg_field_vocab() returns non-empty string arrays for all three adapter types.
	 *
	 * Scenario:
	 *   Given pfb_cfg_field_vocab().
	 *   When inspecting 'toggle', 'lenient', 'plain' keys.
	 *   Then each is a non-empty list of strings.
	 */
	public function testFieldVocabHelperReturnsNonEmptyVocabularyForAllTypes(): void
	{
		$vocab = pfb_cfg_field_vocab();

		$this->assertArrayHasKey('toggle',  $vocab, "vocab must have 'toggle' key");
		$this->assertArrayHasKey('lenient', $vocab, "vocab must have 'lenient' key");
		$this->assertArrayHasKey('plain',   $vocab, "vocab must have 'plain' key");

		foreach ($vocab as $type => $tokens) {
			$this->assertIsArray($tokens, "vocab[{$type}] must be an array");
			$this->assertNotEmpty($tokens, "vocab[{$type}] must not be empty");
			foreach ($tokens as $token) {
				$this->assertIsString($token, "vocab[{$type}] each token must be a string");
			}
		}
	}

	// -----------------------------------------------------------------------
	// E -- Comprehensive per-field rollback (forward + backward) for all fields
	// -----------------------------------------------------------------------

	/**
	 * Every toggle-adapted field satisfies both invariants for every vocab token.
	 *
	 * Scenario:
	 *   Background: toggle vocabulary = {'on', ''}.
	 *     Given each toggle-adapted field and each legacy token.
	 *     When PfbConfig::read($key) and PfbConfig::write($key, runtime).
	 *     Then (FORWARD) result is PfbToggle enum.
	 *     And (BACKWARD) stored result is in {'on', ''}.
	 */
	public function testAllToggleFieldsForwardAndBackwardForEveryVocabToken(): void
	{
		$vocab       = pfb_cfg_field_vocab()['toggle'];
		$toggle_keys = $this->toggleAdaptedKeys();
		$this->assertNotEmpty($toggle_keys, 'Must have toggle-adapted keys to test');

		foreach ($toggle_keys as $key => $path) {
			foreach ($vocab as $token) {
				// Reset.
				$GLOBALS['config'] = [];

				// GIVEN: legacy token stored.
				config_set_path($path, $token);

				// BEFORE: raw value confirmed.
				$this->assertSame(
					$token,
					config_get_path($path),
					"before forward+backward: {$key} token='{$token}'"
				);

				// FORWARD: read yields PfbToggle enum.
				$runtime = PfbConfig::read($key);
				$this->assertInstanceOf(PfbToggle::class, $runtime,
					"FORWARD: {$key} token='{$token}' must yield PfbToggle"
				);

				// BACKWARD: write(runtime) stored value is in vocabulary.
				PfbConfig::write($key, $runtime);
				$stored = (string) config_get_path($path);
				$this->assertContains($stored, $vocab,
					"BACKWARD: {$key} token='{$token}' write(read) stored='{$stored}' not in vocab"
				);
			}
		}
	}

	/**
	 * pfb_dnsbl_lenient satisfies both invariants for all three legacy tokens.
	 *
	 * Scenario:
	 *   Background: lenient vocabulary = {'on', 'off', ''}.
	 *     Given each token.
	 *     When read + write.
	 *     Then FORWARD: PfbLenient enum.
	 *     And BACKWARD: stored value is in {'on', 'off', ''}.
	 *     Note: '' (pre-ADR-22) read->Off; write->Off emits 'off'; 'off' in vocab -> BACKWARD passes.
	 */
	public function testLenientFieldForwardAndBackwardForEveryVocabToken(): void
	{
		$vocab = pfb_cfg_field_vocab()['lenient'];
		$path  = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient';

		foreach ($vocab as $token) {
			// Reset.
			$GLOBALS['config'] = [];
			config_set_path($path, $token);

			// BEFORE.
			$this->assertSame($token, config_get_path($path),
				"before forward+backward: pfb_dnsbl_lenient token='{$token}'"
			);

			// FORWARD.
			$runtime = PfbConfig::read('pfb_dnsbl_lenient');
			$this->assertInstanceOf(PfbLenient::class, $runtime,
				"FORWARD: pfb_dnsbl_lenient token='{$token}' must yield PfbLenient"
			);

			// BACKWARD: write(runtime) stored value is in vocabulary.
			PfbConfig::write('pfb_dnsbl_lenient', $runtime);
			$stored = (string) config_get_path($path);
			$this->assertContains($stored, $vocab,
				"BACKWARD: pfb_dnsbl_lenient token='{$token}' write(read) stored='{$stored}' not in vocab"
			);
		}
	}

	// -----------------------------------------------------------------------
	// F -- ADR-30 log_rotate_<type> rollback contract
	// -----------------------------------------------------------------------

	/**
	 * Data provider — all 10 log_rotate_<type> keys × all 4 vocabulary tokens.
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function logRotateVocabularyProvider(): array
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];
		$vocab     = ['off', 'daily', 'weekly', 'monthly'];
		$cases     = [];
		foreach ($log_types as $type) {
			foreach ($vocab as $token) {
				$cases["log_rotate_{$type}/{$token}"] = ["log_rotate_{$type}", $token];
			}
		}
		return $cases;
	}

	/**
	 * log_rotate_<type>: FORWARD invariant — every vocabulary token yields a string (no crash).
	 * log_rotate_<type>: BACKWARD invariant — write(read(v)) stores exactly v (identity).
	 *
	 * Scenario:
	 *   Background: log_rotate_<type> uses null/null adapters (plain-string identity).
	 *     Given a stored vocabulary token v ∈ {'off','daily','weekly','monthly'}.
	 *     When PfbConfig::read($key).
	 *     Then (FORWARD) result is a string — not NULL, not a crash.
	 *     And (BACKWARD) PfbConfig::write($key, result) stores the same string v.
	 */
	#[DataProvider('logRotateVocabularyProvider')]
	public function testLogRotateFieldForwardAndBackwardForEveryVocabToken(
		string $key,
		string $token
	): void {
		$path = 'installedpackages/pfblockerng/config/0/' . $key;

		// GIVEN: legacy token stored.
		config_set_path($path, $token);

		// BEFORE: raw value confirmed.
		$this->assertSame($token, config_get_path($path),
			"before forward+backward: {$key} token='{$token}'"
		);

		// FORWARD: read returns a well-formed string (no crash, correct type).
		$runtime = PfbConfig::read($key);
		$this->assertIsString($runtime,
			"FORWARD: {$key} token='{$token}' must return a string"
		);
		$this->assertSame($token, $runtime,
			"FORWARD: {$key} token='{$token}' identity adapter must return token unchanged"
		);

		// BACKWARD: write(runtime) stores exactly the same string (in vocabulary; no novel token).
		PfbConfig::write($key, $runtime);
		$stored = config_get_path($path);
		$this->assertSame($token, $stored,
			"BACKWARD: {$key} token='{$token}' write(read) must store '{$token}' (identity)"
		);
	}

	/**
	 * log_rotate_<type>: absent key returns 'off' (FORWARD — sane default, no crash).
	 *
	 * Scenario:
	 *   Background: key absent from config.xml (clean install / field never written).
	 *     Given no stored value.
	 *     When PfbConfig::read($key).
	 *     Then 'off' is returned (registered default; no crash).
	 */
	public function testLogRotateFieldAbsentKeyReturnsOffDefault(): void
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];

		foreach ($log_types as $type) {
			$key  = 'log_rotate_' . $type;
			$path = 'installedpackages/pfblockerng/config/0/' . $key;

			// GIVEN: absent (setUp cleared config).
			// BEFORE: confirm absent.
			$this->assertNull(config_get_path($path),
				"before: {$key} must be absent"
			);

			// FORWARD: read returns the registered default 'off' — no crash.
			$result = PfbConfig::read($key);
			$this->assertSame('off', $result,
				"FORWARD: {$key} absent must return 'off' (registered default)"
			);
		}
	}

	// -----------------------------------------------------------------------
	// G -- ADR-30 amendment: log_reset_keep_<type> rollback contract
	// -----------------------------------------------------------------------

	/**
	 * Data provider — all 10 log_reset_keep_<type> keys × canonical numeric tokens.
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function logResetKeepVocabularyProvider(): array
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];
		$vocab  = ['0', '100', '500'];
		$cases  = [];
		foreach ($log_types as $type) {
			foreach ($vocab as $token) {
				$cases["log_reset_keep_{$type}/{$token}"] = ["log_reset_keep_{$type}", $token];
			}
		}
		return $cases;
	}

	/**
	 * log_reset_keep_<type>: FORWARD invariant — every token yields a string (no crash).
	 * log_reset_keep_<type>: BACKWARD invariant — write(read(v)) stores exactly v (identity).
	 *
	 * Scenario:
	 *   Background: log_reset_keep_<type> uses null/null adapters (plain-string identity).
	 *     Given a stored token v ∈ {'0','100','500'}.
	 *     When PfbConfig::read($key).
	 *     Then (FORWARD) result is a string — not NULL, not a crash.
	 *     And (BACKWARD) PfbConfig::write($key, result) stores the same string v.
	 */
	#[DataProvider('logResetKeepVocabularyProvider')]
	public function testLogResetKeepFieldForwardAndBackwardForEveryVocabToken(
		string $key,
		string $token
	): void {
		$path = 'installedpackages/pfblockerng/config/0/' . $key;

		// GIVEN: token stored.
		config_set_path($path, $token);

		// BEFORE: raw value confirmed.
		$this->assertSame($token, config_get_path($path),
			"before forward+backward: {$key} token='{$token}'"
		);

		// FORWARD: read returns a well-formed string (no crash, correct type).
		$runtime = PfbConfig::read($key);
		$this->assertIsString($runtime,
			"FORWARD: {$key} token='{$token}' must return a string"
		);
		$this->assertSame($token, $runtime,
			"FORWARD: {$key} token='{$token}' identity adapter must return token unchanged"
		);

		// BACKWARD: write(runtime) stores exactly the same string (no novel token).
		PfbConfig::write($key, $runtime);
		$stored = config_get_path($path);
		$this->assertSame($token, $stored,
			"BACKWARD: {$key} token='{$token}' write(read) must store '{$token}' (identity)"
		);
	}

	/**
	 * log_reset_keep_<type>: absent key returns '0' (FORWARD — sane default, no crash).
	 *
	 * Scenario:
	 *   Background: key absent from config.xml (clean install / field never written).
	 *     Given no stored value.
	 *     When PfbConfig::read($key).
	 *     Then '0' is returned (registered default; no crash).
	 */
	public function testLogResetKeepFieldAbsentKeyReturnsZeroDefault(): void
	{
		$log_types = [
			'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
			'ip_matchlog', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
		];

		foreach ($log_types as $type) {
			$key  = 'log_reset_keep_' . $type;
			$path = 'installedpackages/pfblockerng/config/0/' . $key;

			// GIVEN: absent (setUp cleared config).
			// BEFORE: confirm absent.
			$this->assertNull(config_get_path($path),
				"before: {$key} must be absent"
			);

			// FORWARD: read returns the registered default '0' — no crash.
			$result = PfbConfig::read($key);
			$this->assertSame('0', $result,
				"FORWARD: {$key} absent must return '0' (registered default)"
			);
		}
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Return all toggle-adapted keys with their full config.xml paths.
	 *
	 * @return array<string,string>  key => full config path
	 */
	private function toggleAdaptedKeys(): array
	{
		$registry = pfb_cfg_registry();
		$result   = [];
		foreach ($registry as $key => $entry) {
			if (pfb_cfg_field_adapter_type($entry) === 'toggle') {
				$result[$key] = $entry['section'] . '/' . $key;
			}
		}
		return $result;
	}
}
