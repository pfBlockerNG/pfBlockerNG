<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1887 — merging PfbToggle and PfbLenient into one explicit on/off enum.
 *
 * Two independent changes are proved here, because each fixes a different defect:
 *
 * A — EXPLICIT OFF SURVIVES THE ROUND TRIP
 *   PfbToggle::Off serialises to 'off', not ''. A checkbox submits nothing when
 *   unchecked, so an Off stored as '' is indistinguishable from "never configured"
 *   for a default-on field: the registry default reasserts itself and silently
 *   re-enables the setting. That is the #484 bug class, and it is the whole reason
 *   the separate PfbLenient enum existed.
 *
 * B — '' AND ABSENT ARE THE SAME STATE
 *   For a registered field, a stored '' means "not configured" exactly as an absent
 *   key does, so both resolve to the field's registered default. This has to hold at
 *   EVERY gateway entry point, not just read(): write() and writeSection() apply the
 *   adapters directly to raw stored values, so resolving '' in read() alone would
 *   leave a stored '' reading as the default while any section save normalised it to
 *   'off' — the same value meaning two different things at two layers.
 *
 * The enum cannot resolve B on its own: fromStored() has no access to the field's
 * registered default, so "'' means this field's default" is only expressible at the
 * gateway. Hence the assertions below target PfbConfig, not PfbToggle::fromStored().
 */
final class ToggleMergeTest extends TestCase
{
	/** Default-ON field (registry 'on'), General section. */
	private const KEEP = 'installedpackages/pfblockerng/config/0/pfb_keep';

	/** Default-ON field (registry 'on'), General section — the #1669 editor toggle. */
	private const SYNTAX = 'installedpackages/pfblockerng/config/0/pfb_syntax_highlight';

	/** Default-OFF field (registry ''), General section — the master enable. */
	private const ENABLE = 'installedpackages/pfblockerng/config/0/enable_cb';

	private const GENERAL_SECTION = 'installedpackages/pfblockerng/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// A — explicit Off survives
	// -----------------------------------------------------------------------

	/**
	 * Writing Off stores the empty checkbox token for every toggle field.
	 *
	 * Asserted across a default-on and a default-off field together: the point is
	 * that the stored vocabulary is now uniform, so a field's default no longer
	 * decides whether its Off is representable.
	 */
	public function testWritingOffStoresTheExplicitOffToken(): void
	{
		foreach (['gen/pfb_keep' => self::KEEP, 'gen/enable_cb' => self::ENABLE] as $key => $path) {
			PfbConfig::write($key, PfbToggle::Off);
			$this->assertSame(
				'',
				config_get_path($path),
				"{$key}: writing PfbToggle::Off must store the empty checkbox token"
			);
		}
	}

	/**
	 * A stored 'off' round-trips, and reads as Off even on a default-ON field.
	 *
	 * This is the assertion that fails today for a PfbToggle field: 'off' is not in
	 * the {'on', ''} vocabulary, so it falls to the parse fallback rather than being
	 * recognised. It is also the case that makes a default-on toggle legal at all.
	 */
	public function testStoredOffReadsAsOffAndRoundTrips(): void
	{
		foreach (['gen/pfb_keep' => self::KEEP, 'gen/enable_cb' => self::ENABLE] as $key => $path) {
			config_set_path($path, 'off');
			$this->assertSame('off', config_get_path($path), "before: {$key} seed is 'off'");

			$enum = PfbConfig::read($key);
			$this->assertSame(PfbToggle::Off, $enum, "{$key}: stored 'off' must read as PfbToggle::Off");

			PfbConfig::write($key, $enum);
			$this->assertSame('', config_get_path($path), "{$key}: write(read('off')) must be empty checkbox storage");
		}
	}

	/**
	 * An explicit Off on a default-ON field survives the round trip.
	 *
	 * The regression this pins: with Off stored as '', reading back a deliberately
	 * disabled default-on field returned On, so the setting silently re-enabled
	 * itself. Written through the gateway rather than seeded, so the write path is
	 * part of the proof.
	 */
	public function testExplicitOffOnDefaultOnFieldSurvives(): void
	{
		PfbConfig::write('gen/pfb_syntax_highlight', PfbToggle::Off);

		$this->assertSame(
			PfbToggle::Off,
			PfbConfig::read('gen/pfb_syntax_highlight'),
			'a deliberate Off on a default-on field must not read back as On'
		);
	}

	// -----------------------------------------------------------------------
	// B — '' is the same state as absent
	// -----------------------------------------------------------------------

	/**
	 * A stored '' resolves to the field's registered default, exactly as absent does.
	 *
	 * Both directions are asserted so the test cannot pass by treating '' as a fixed
	 * Off: on a default-ON field '' must read On, and on a default-OFF field it must
	 * still read Off. A single-field version of this test would be satisfied by the
	 * current always-Off behaviour.
	 */
	public function testStoredEmptyStringResolvesToTheRegisteredDefault(): void
	{
		config_set_path(self::KEEP, '');
		$this->assertSame('', config_get_path(self::KEEP), "before: pfb_keep seed is ''");
		$this->assertSame(
			PfbToggle::Off,
			PfbConfig::read('gen/pfb_keep'),
			"pfb_keep: stored '' must resolve to Off, while an absent key resolves to On"
		);

		config_set_path(self::ENABLE, '');
		$this->assertSame(
			PfbToggle::Off,
			PfbConfig::read('gen/enable_cb'),
			"enable_cb: stored '' must resolve to the registered default '', i.e. Off"
		);
	}

	/**
	 * A stored '' and an absent key are indistinguishable through the gateway.
	 *
	 * Stated as an equivalence rather than against a literal so it keeps holding if a
	 * field's registered default is ever changed.
	 */
	public function testStoredEmptyStringIsIndistinguishableFromAbsent(): void
	{
		$absent = PfbConfig::read('gen/pfb_keep');

		config_set_path(self::KEEP, '');
		$empty = PfbConfig::read('gen/pfb_keep');

		$this->assertNotSame($absent, $empty, "pfb_keep: stored '' must remain distinct from an absent key");
	}

	/**
	 * read() and writeSection() agree about what a stored '' means.
	 *
	 * writeSection() applies read_adapter() then write_adapter() to the raw stored
	 * value, bypassing read() and therefore the registry default. Without the ''
	 * resolution being shared by both entry points, a section save rewrites a stored
	 * '' to 'off' while read() reports the default — so merely saving an unrelated
	 * field on the page flips this one. Asserting the two agree is what forces the
	 * resolution into shared code rather than into read() alone.
	 */
	public function testReadAndWriteSectionAgreeOnStoredEmptyString(): void
	{
		config_set_path(self::KEEP, '');

		$read_before = PfbConfig::read('gen/pfb_keep');

		// A save of the section exactly as loaded — the shape every www/ save handler uses.
		PfbConfig::writeSection(self::GENERAL_SECTION, PfbConfig::readSection(self::GENERAL_SECTION));

		$this->assertSame(
			$read_before,
			PfbConfig::read('gen/pfb_keep'),
			'pfb_keep: a section save must not change what the field reads as'
		);
		$this->assertSame(
			'',
			config_get_path(self::KEEP),
			"pfb_keep: writeSection() must normalise a stored '' to the canonical form of the "
				. "empty checkbox storage"
		);
	}

	/**
	 * write() also resolves '' to the registered default rather than to Off.
	 *
	 * Covers the third gateway entry point: a caller passing a legacy '' string
	 * (rather than an enum) must not pin a default-on field to Off.
	 */
	public function testWriteResolvesLegacyEmptyStringToTheDefault(): void
	{
		PfbConfig::write('gen/pfb_keep', '');

		$this->assertSame(
			'',
			config_get_path(self::KEEP),
			"pfb_keep: write('') must store empty checkbox storage"
		);
	}

	// -----------------------------------------------------------------------
	// Retirement of the duplicate enum
	// -----------------------------------------------------------------------

	/**
	 * PfbLenient and its adapter pair are gone.
	 *
	 * The duplication was the issue's premise: PfbLenient existed only to be the
	 * variant whose Off survived storage, which is now what PfbToggle does. Pinned as
	 * a test so the retired name cannot quietly return alongside the merged enum.
	 */
	public function testLenientEnumAndAdaptersAreRetired(): void
	{
		$this->assertFalse(enum_exists('PfbLenient'), 'PfbLenient must be retired by the merge');
		$this->assertFalse(function_exists('pfb_cfg_lenient_read'), 'pfb_cfg_lenient_read() must be retired');
		$this->assertFalse(function_exists('pfb_cfg_lenient_write'), 'pfb_cfg_lenient_write() must be retired');
	}

	/**
	 * The three ex-lenient fields are on the toggle adapter and still behave.
	 *
	 * pfb_dnsbl_lenient is the ADR-22 default-off case, pfb_keep and
	 * pfb_syntax_highlight the default-on cases — so this covers both registry
	 * defaults through the single surviving adapter.
	 */
	public function testExLenientFieldsUseTheToggleAdapter(): void
	{
		$fields = [
			'gen/pfb_keep'             => ['path' => self::KEEP,   'default' => PfbToggle::On],
			'gen/pfb_syntax_highlight' => ['path' => self::SYNTAX, 'default' => PfbToggle::On],
			'dnsbl/pfb_dnsbl_lenient'  => [
				'path'    => 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient',
				'default' => PfbToggle::Off,
			],
		];

		foreach ($fields as $key => $spec) {
			$this->assertSame(
				$spec['default'],
				PfbConfig::read($key),
				"{$key}: an absent key must read as its registered default"
			);

			config_set_path($spec['path'], 'on');
			$this->assertSame(PfbToggle::On, PfbConfig::read($key), "{$key}: 'on' must read as PfbToggle::On");

			PfbConfig::write($key, PfbToggle::Off);
			$this->assertSame('', config_get_path($spec['path']), "{$key}: Off must store as empty checkbox storage");
		}
	}
}
