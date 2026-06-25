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
 *   member of the field's legacy stored vocabulary or a behaviour-equivalent token.
 *   Because the gateway never introduces a novel on-disk token that changes behaviour,
 *   a downgrade leaves older code reading values it already understands -- no crash,
 *   no silent settings-loss.
 *
 * ROLLBACK SAFETY BY CONSTRUCTION:
 *   Toggle/lenient write adapters return the exact legacy stored string.  Plain-
 *   string (null-adapter) fields are identity.  The idn-mode adapter (pfb_idn)
 *   emits only 'on'/'confusable'/'off' -- all tokens a pre-ADR-08 release already
 *   handled (older code treats 'on' as block-all, 'confusable'/'off' as off).
 *   This phase asserts these properties explicitly per field so a future adapter
 *   addition cannot silently break the contract.
 *
 * pfb_idn (ADR-28 reframe): now uses the PfbIdnMode adapter (NOT null/null).
 *   PfbIdnMode::All backing value is 'on' — the original pre-ADR-08 block-all token, so
 *   an older release reading 'on' still blocks all IDN (downgrade-safe). The 4.0.0-alpha
 *   'all' token is dropped (unrecognised -> Off -> 'off'). Backward vocabulary: {'on',
 *   'confusable', 'off'} — no novel token; see testPfbIdnModeAdapterForwardAndBackward().
 *
 * NOTE on pfb_cfg_field_adapter_type():
 *   It classifies pfb_idn ('pfb_cfg_idn_mode_read' adapter) as type 'idn', so it is
 *   naturally excluded from the toggle-only forward/backward tests (which assert
 *   instanceof PfbToggle). pfb_idn is covered by the dedicated idn-mode tests.
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
 *   And (BACKWARD) the write result is a string in the field's legacy vocabulary
 *     or a behaviour-equivalent canonical token.
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
	 * pfb_keep (lenient adapter, #484 fix): 'on' -> PfbLenient::On (no crash).
	 *
	 * Scenario:
	 *   Background: pfb_keep vocabulary = {'on', 'off', ''} ('' = pre-#484 legacy).
	 *     Given stored = 'on'.
	 *     When PfbConfig::read('pfb_keep').
	 *     Then PfbLenient::On is returned.
	 */
	public function testForwardPfbKeepOnYieldsOnEnum(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: 'on' stored (keep=enabled — retain settings on uninstall).
		config_set_path($path, 'on');

		// Before.
		$this->assertSame('on', config_get_path($path));

		// When/Then.
		$result = PfbConfig::read('pfb_keep');
		$this->assertInstanceOf(PfbLenient::class, $result);
		$this->assertSame(PfbLenient::On, $result, "FORWARD: pfb_keep 'on' must yield PfbLenient::On");
	}

	/**
	 * pfb_keep (lenient adapter, #484 fix): 'off' -> PfbLenient::Off (no crash).
	 *
	 * Scenario:
	 *   Background: 'off' is the canonical disabled value written by the GUI after #484.
	 *     Given stored = 'off'.
	 *     When PfbConfig::read('pfb_keep').
	 *     Then PfbLenient::Off is returned.
	 */
	public function testForwardPfbKeepOffYieldsOffEnum(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: 'off' stored (new canonical value for unchecked-save after #484 fix).
		config_set_path($path, 'off');

		// Before.
		$this->assertSame('off', config_get_path($path));

		// When/Then.
		$result = PfbConfig::read('pfb_keep');
		$this->assertInstanceOf(PfbLenient::class, $result);
		$this->assertSame(PfbLenient::Off, $result, "FORWARD: pfb_keep 'off' must yield PfbLenient::Off");
	}

	/**
	 * pfb_keep (lenient adapter, #484 fix): '' -> PfbLenient::Off (pre-#484 legacy empty).
	 *
	 * Scenario:
	 *   Background: '' is the old toggle-OFF value written by the GUI before the #484 fix.
	 *     Given stored = '' (pre-#484 install — toggle::Off empty string).
	 *     When PfbConfig::read('pfb_keep').
	 *     Then PfbLenient::Off is returned (normalised; same as 'off').
	 *
	 * Backward-safety: pfb['keep'] != 'on' in the deinstall gate covers both 'off' and ''.
	 */
	public function testForwardPfbKeepLegacyEmptyYieldsOffEnum(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Given: '' stored (pre-#484 toggle-OFF value).
		config_set_path($path, '');

		// Before.
		$this->assertSame('', config_get_path($path));

		// When/Then: '' normalises to Off — the deinstall gate (keep != 'on') fires correctly.
		$result = PfbConfig::read('pfb_keep');
		$this->assertInstanceOf(PfbLenient::class, $result);
		$this->assertSame(PfbLenient::Off, $result, "FORWARD: pfb_keep '' must yield PfbLenient::Off (legacy token)");
	}

	/**
	 * Plain-string fields: legacy stored value passes through unchanged (no crash).
	 *
	 * Scenario:
	 *   Background: plain (null-adapter) fields -- identity adapter.
	 *     Given a representative canonical stored string for each plain field.
	 *     When PfbConfig::read($key).
	 *     Then the result is the same string (identity; no crash, no type change).
	 *
	 * Note: pfb_idn is now adapted via PfbIdnMode (NOT plain-string). See
	 * testPfbIdnModeAdapterForwardAndBackward() for pfb_idn coverage.
	 */
	public function testForwardPlainStringFieldsPassLegacyTokensUnchanged(): void
	{
		// Representative plain-string fields with canonical legacy stored values.
		// pfb_idn is intentionally excluded: it uses the PfbIdnMode adapter (not
		// null/null) so it returns a PfbIdnMode enum, not a plain string.
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
	 * pfb_idn 'on' token: now adapted via PfbIdnMode — read returns PfbIdnMode::All.
	 *
	 * ADR-28 reframe: pfb_idn is no longer excluded from adapter adoption.
	 * PfbIdnMode::All.value == 'on' (the backing value reuses the canonical token),
	 * so 'on' both reads as PfbIdnMode::All and writes back as 'on' — perfect identity.
	 *
	 * Scenario:
	 *   Background: pfb_idn now uses the PfbIdnMode read/write adapters.
	 *     Given pfb_idn stored as 'on' (canonical = block-all-IDN).
	 *     When PfbConfig::read('pfb_idn').
	 *     Then PfbIdnMode::All is returned (adapter normalises; 'on' is the canonical token).
	 */
	public function testForwardPfbIdnCanonicalOnYieldsAllEnum(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';

		// Given: canonical 'on'.
		config_set_path($path, 'on');

		// Before.
		$this->assertSame('on', config_get_path($path));

		// When.
		$result = PfbConfig::read('pfb_idn');

		// Then: PfbIdnMode::All (adapter IS wired; returns enum, not plain string).
		$this->assertInstanceOf(PfbIdnMode::class, $result,
			"FORWARD: pfb_idn must return a PfbIdnMode enum"
		);
		$this->assertSame(PfbIdnMode::All, $result,
			"FORWARD: pfb_idn 'on' -> PfbIdnMode::All (canonical backing value)"
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
	 * pfb_keep (lenient, #484 fix): write(On) emits 'on' -- a legacy token.
	 *
	 * Scenario:
	 *   Background: pfb_keep legacy vocabulary = {'on', 'off', ''}.
	 *     Given PfbLenient::On.
	 *     When PfbConfig::write('pfb_keep', PfbLenient::On).
	 *     Then stored == 'on' (in vocabulary; no novel token).
	 */
	public function testBackwardPfbKeepOnEmitsLegacyToken(): void
	{
		$path          = 'installedpackages/pfblockerng/config/0/pfb_keep';
		$lenient_vocab = pfb_cfg_field_vocab()['lenient'];

		// Before: absent.
		$this->assertNull(config_get_path($path), "before backward pfb_keep On: absent");

		// When: write On.
		PfbConfig::write('pfb_keep', PfbLenient::On);

		// Then: 'on' -- in vocabulary; no novel token.
		$stored = (string) config_get_path($path);
		$this->assertContains($stored, $lenient_vocab,
			"BACKWARD: pfb_keep write(On) stored='{$stored}' not in vocab"
		);
		$this->assertSame('on', $stored, "BACKWARD: pfb_keep write(On) must store 'on'");
	}

	/**
	 * pfb_keep (lenient, #484 fix): write(Off) emits 'off' -- a legacy token.
	 *
	 * Scenario:
	 *   Background: pfb_keep legacy vocabulary = {'on', 'off', ''}.
	 *     Given PfbLenient::Off.
	 *     When PfbConfig::write('pfb_keep', PfbLenient::Off).
	 *     Then stored == 'off' (in vocabulary; backward-safe — older releases treat 'off'
	 *     as "disabled", which is the correct interpretation for pfb_keep=Off).
	 */
	public function testBackwardPfbKeepOffEmitsLegacyToken(): void
	{
		$path          = 'installedpackages/pfblockerng/config/0/pfb_keep';
		$lenient_vocab = pfb_cfg_field_vocab()['lenient'];

		// Before: seed 'on' so we see the write actually changes it.
		config_set_path($path, 'on');
		$this->assertSame('on', config_get_path($path), "before backward pfb_keep Off: is 'on'");

		// When: write Off.
		PfbConfig::write('pfb_keep', PfbLenient::Off);

		// Then: 'off' -- in the legacy vocabulary (no novel token introduced).
		// Older releases read '' for PfbToggle::Off (disable path). 'off' was previously
		// stored by pfb_feed_internal_filter — a pre-existing legacy vocabulary member.
		$stored = (string) config_get_path($path);
		$this->assertContains($stored, $lenient_vocab,
			"BACKWARD: pfb_keep write(Off) stored='{$stored}' not in vocab"
		);
		$this->assertSame('off', $stored, "BACKWARD: pfb_keep write(Off) must store 'off'");
	}

	/**
	 * Plain-string fields: write($str) emits $str (identity -- no novel token possible).
	 *
	 * Scenario:
	 *   Background: plain fields use null write_adapter (identity).
	 *     Given a canonical stored string.
	 *     When PfbConfig::write($key, $str).
	 *     Then stored == $str (the adapter cannot introduce any novel token).
	 *
	 * Note: pfb_idn is now adapted via PfbIdnMode (NOT plain-string). See
	 * testPfbIdnModeAdapterForwardAndBackward() for pfb_idn backward coverage.
	 */
	public function testBackwardPlainStringFieldsIdentityAdapterCannotIntroduceNovelTokens(): void
	{
		// pfb_idn is intentionally excluded: it now uses the PfbIdnMode write adapter,
		// which normalises to the canonical vocabulary ('on'|'confusable'|'off') rather
		// than emitting identity for every input (e.g. the dropped alpha 'all' -> 'off').
		// See testPfbIdnModeAdapterForwardAndBackward().
		$cases = [
			'pfb_interval'      => ['installedpackages/pfblockerng/config/0/pfb_interval', '6'],
			'dnsbl_interface'   => ['installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface', 'lo0'],
			'alexa_type'        => ['installedpackages/pfblockerngdnsblsettings/config/0/alexa_type', 'tranco'],
			'safesearch_enable' => ['installedpackages/pfblockerngsafesearch/safesearch_enable', 'Disable'],
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
	 * pfb_idn FORWARD + BACKWARD: PfbIdnMode adapter — every legacy token yields a
	 * sane enum and write emits only downgrade-safe tokens.
	 *
	 * ADR-28 reframe: pfb_idn now uses the PfbIdnMode adapter. PfbIdnMode::All
	 * backing value is 'on' (canonical; reuses the original block-all token so older
	 * releases reading 'on' still block all IDN — downgrade-safe). The 4.0.0-alpha
	 * 'all' token is dropped (unrecognised -> Off -> 'off').
	 *
	 * Backward vocabulary (tokens an older release might have stored / might read back):
	 *   'on'         -> All -> 'on'  (canonical identity; downgrade-safe)
	 *   'all'        -> Off -> 'off' (dropped 4.0.0-alpha token; unrecognised)
	 *   'confusable' -> Confusable -> 'confusable' (identity; new token, old code treats
	 *                                               as off — acceptable, same as unset)
	 *   'off'        -> Off  -> 'off' (identity)
	 *   ''           -> Off  -> 'off' (normalised default; '' -> Off -> 'off')
	 *
	 * Scenario:
	 *   Background: pfb_idn uses the PfbIdnMode read/write adapters.
	 *     Given each canonical or legacy pfb_idn stored token.
	 *     When PfbConfig::read('pfb_idn').
	 *     Then (FORWARD) result is a PfbIdnMode enum — not NULL, not a crash.
	 *     And (BACKWARD) PfbConfig::write('pfb_idn', result) stores a downgrade-safe
	 *     token that older code already understands.
	 */
	public function testPfbIdnModeAdapterForwardAndBackward(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn';

		// All tokens an existing install might have stored (full vocabulary).
		$cases = [
			// stored       => [expected_enum,         expected_stored_after_write]
			'on'         => [PfbIdnMode::All,        'on'],         // canonical block-all; identity
			'confusable' => [PfbIdnMode::Confusable, 'confusable'], // identity
			'off'        => [PfbIdnMode::Off,        'off'],        // identity
			''           => [PfbIdnMode::Off,        'off'],        // absent/disabled -> Off
			'all'        => [PfbIdnMode::Off,        'off'],        // 4.0.0-alpha-only token, dropped -> Off
		];

		foreach ($cases as $token => [$expected_enum, $expected_stored]) {
			// Reset.
			$GLOBALS['config'] = [];
			config_set_path($path, $token);

			// BEFORE: raw token confirmed.
			$this->assertSame($token, config_get_path($path),
				"before forward+backward: pfb_idn token='{$token}'"
			);

			// FORWARD: read yields PfbIdnMode enum.
			$runtime = PfbConfig::read('pfb_idn');
			$this->assertInstanceOf(PfbIdnMode::class, $runtime,
				"FORWARD: pfb_idn token='{$token}' must yield PfbIdnMode"
			);
			$this->assertSame($expected_enum, $runtime,
				"FORWARD: pfb_idn token='{$token}' must yield {$expected_enum->name}"
			);

			// BACKWARD: write(runtime) stores a downgrade-safe token.
			PfbConfig::write('pfb_idn', $runtime);
			$stored = config_get_path($path);
			$this->assertSame($expected_stored, $stored,
				"BACKWARD: pfb_idn token='{$token}' write(read) must store '{$expected_stored}'"
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
		$valid_types = ['toggle', 'lenient', 'idn', 'plain', 'alias_delta_mode'];

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
	 * Every adapter type a registered field can resolve to (toggle / lenient / idn)
	 * has a non-empty vocabulary in pfb_cfg_field_vocab(). Guards against a missing or
	 * empty entry (e.g. the 'idn' vocabulary added with the PfbIdnMode adoption).
	 */
	public function testFieldVocabNonEmptyForEveryAdapterTypeInUse(): void
	{
		$vocab = pfb_cfg_field_vocab();
		foreach (pfb_cfg_registry() as $key => $entry) {
			$type = pfb_cfg_field_adapter_type($entry);
			$this->assertArrayHasKey($type, $vocab, "no vocabulary for adapter type '{$type}' (field {$key})");
			$this->assertNotEmpty($vocab[$type], "vocabulary for adapter type '{$type}' is empty (field {$key})");
		}
		// The 'idn' adoption must contribute its canonical write tokens.
		$this->assertSame(['on', 'confusable', 'off'], $vocab['idn']);
	}

	/**
	 * pfb_cfg_field_adapter_type() assigns 'lenient' to pfb_keep and pfb_dnsbl_lenient.
	 *
	 * Scenario:
	 *   Background: pfb_keep (#484 fix) and pfb_dnsbl_lenient use the lenient adapter.
	 *     Given the full registry.
	 *     When collecting all fields whose type is 'lenient'.
	 *     Then exactly 'pfb_keep' and 'pfb_dnsbl_lenient' appear (registry insertion order).
	 */
	public function testAdapterTypeHelperLenientAssignedToPfbKeepAndPfbDnsblLenient(): void
	{
		$registry       = pfb_cfg_registry();
		$lenient_fields = [];
		foreach ($registry as $key => $entry) {
			if (pfb_cfg_field_adapter_type($entry) === 'lenient') {
				$lenient_fields[] = $key;
			}
		}

		$this->assertContains('pfb_keep',        $lenient_fields, 'pfb_keep must be lenient (#484 fix)');
		$this->assertContains('pfb_dnsbl_lenient', $lenient_fields, 'pfb_dnsbl_lenient must be lenient');
		$this->assertCount(2, $lenient_fields, 'Exactly two lenient fields: pfb_keep + pfb_dnsbl_lenient');
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

	/**
	 * pfb_keep (lenient, #484 fix) satisfies both invariants for all three legacy tokens.
	 *
	 * Scenario:
	 *   Background: pfb_keep vocabulary = {'on', 'off', ''} ('' = pre-#484 legacy).
	 *     Given each token.
	 *     When read + write.
	 *     Then FORWARD: PfbLenient enum.
	 *     And BACKWARD: stored value is in {'on', 'off', ''}.
	 *     Note: '' (pre-#484) read->Off; write->Off emits 'off'; 'off' in vocab -> BACKWARD passes.
	 */
	public function testPfbKeepForwardAndBackwardForEveryVocabToken(): void
	{
		$vocab = pfb_cfg_field_vocab()['lenient'];
		$path  = 'installedpackages/pfblockerng/config/0/pfb_keep';

		foreach ($vocab as $token) {
			// Reset.
			$GLOBALS['config'] = [];
			config_set_path($path, $token);

			// BEFORE.
			$this->assertSame($token, config_get_path($path),
				"before forward+backward: pfb_keep token='{$token}'"
			);

			// FORWARD.
			$runtime = PfbConfig::read('pfb_keep');
			$this->assertInstanceOf(PfbLenient::class, $runtime,
				"FORWARD: pfb_keep token='{$token}' must yield PfbLenient"
			);

			// BACKWARD: write(runtime) stored value is in vocabulary.
			PfbConfig::write('pfb_keep', $runtime);
			$stored = (string) config_get_path($path);
			$this->assertContains($stored, $vocab,
				"BACKWARD: pfb_keep token='{$token}' write(read) stored='{$stored}' not in vocab"
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
	// H -- ADR-38 Amendment 1: log_syslog (toggle only — facility/priority removed)
	// -----------------------------------------------------------------------

	/**
	 * log_syslog satisfies both rollback invariants for both toggle vocabulary tokens.
	 *
	 * Note: log_syslog is a toggle-adapted field and is automatically covered by
	 * testAllToggleFieldsForwardAndBackwardForEveryVocabToken() via toggleAdaptedKeys().
	 * This test explicitly pins the field to make ADR-38 coverage visible.
	 *
	 * Scenario:
	 *   Background: log_syslog vocabulary = {'on', ''}.
	 *     Given stored token 'on' then ''.
	 *     When PfbConfig::read('log_syslog') and PfbConfig::write('log_syslog', result).
	 *     Then (FORWARD) result is PfbToggle enum.
	 *     And (BACKWARD) stored value is in {'on', ''}.
	 */
	public function testLogSyslogForwardAndBackwardForEveryVocabToken(): void
	{
		$path  = 'installedpackages/pfblockerng/config/0/log_syslog';
		$vocab = pfb_cfg_field_vocab()['toggle'];

		foreach ($vocab as $token) {
			// Reset.
			$GLOBALS['config'] = [];
			config_set_path($path, $token);

			// BEFORE: raw value confirmed.
			$this->assertSame($token, config_get_path($path),
				"before forward+backward: log_syslog token='{$token}'"
			);

			// FORWARD: read returns PfbToggle enum.
			$runtime = PfbConfig::read('log_syslog');
			$this->assertInstanceOf(PfbToggle::class, $runtime,
				"FORWARD: log_syslog token='{$token}' must yield PfbToggle"
			);

			// BACKWARD: write(runtime) stored value is in vocabulary.
			PfbConfig::write('log_syslog', $runtime);
			$stored = (string) config_get_path($path);
			$this->assertContains($stored, $vocab,
				"BACKWARD: log_syslog token='{$token}' write(read) stored='{$stored}' not in vocab"
			);
		}
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Return all toggle-adapted keys with their full config.xml paths.
	 *
	 * pfb_idn is excluded here because pfb_cfg_field_adapter_type() classifies it as
	 * type 'idn' (its 'pfb_cfg_idn_mode_read' adapter), not 'toggle' — so the type
	 * filter below skips it naturally. pfb_idn returns a PfbIdnMode enum (not a
	 * PfbToggle) and is covered by testPfbIdnModeAdapterForwardAndBackward() instead.
	 *
	 * @return array<string,string>  key => full config path
	 */
	private function toggleAdaptedKeys(): array
	{
		$registry = pfb_cfg_registry();
		$result   = [];
		foreach ($registry as $key => $entry) {
			// pfb_idn (adapter type 'idn') is naturally excluded by the type filter;
			// it is covered by testPfbIdnModeAdapterForwardAndBackward().
			if (pfb_cfg_field_adapter_type($entry) === 'toggle') {
				$result[$key] = $entry['section'] . '/' . $key;
			}
		}
		return $result;
	}
}
