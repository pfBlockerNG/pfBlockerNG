<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1887/#2120 — merging PfbToggle and PfbLenient while preserving canonical
 * empty Off storage and legacy 'off' read compatibility.
 *
 * Two independent changes are proved here, because each fixes a different defect:
 *
 * A — EXPLICIT OFF SURVIVES THE ROUND TRIP
 *   PfbToggle::Off serialises to ''. A present empty token is an explicit Off,
 *   while an absent key resolves to the registered default on default-on fields.
 *
 * B — EMPTY AND ABSENT ARE DISTINCT STATES
 *   For adapter-backed fields, a present '' reads as Off while an absent key reads
 *   as the field's registered default. All gateway entry points preserve that
 *   distinction and writeSection() keeps present empty byte-identical.
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
	// B — '' is explicit Off; absence resolves to the registered default
	// -----------------------------------------------------------------------

	/**
	 * A stored '' is explicit Off; absent uses the field's registered default.
	 */
	public function testStoredEmptyStringResolvesToOff(): void
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
	 * A stored '' and an absent key remain distinguishable through the gateway.
	 */
	public function testStoredEmptyStringRemainsDistinctFromAbsent(): void
	{
		$absent = PfbConfig::read('gen/pfb_keep');

		config_set_path(self::KEEP, '');
		$empty = PfbConfig::read('gen/pfb_keep');

		$this->assertNotSame($absent, $empty, "pfb_keep: stored '' must remain Off while absent defaults On");
	}

	/**
	 * read() and writeSection() agree about what a stored '' means.
	 *
	 * writeSection() applies read_adapter() then write_adapter() to the raw stored
	 * value, bypassing read() and therefore the registry default. Without the ''
	 * resolution being shared by both entry points, a section save rewrites a stored
	 * '' to a different token while read() reports Off — so merely saving an unrelated
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
	 * write() preserves a present empty string as explicit Off.
	 *
	 * Covers the third gateway entry point: a caller passing the canonical empty
	 * checkbox token (rather than an enum) must pin the field to Off.
	 */
	public function testWritePreservesExplicitEmptyOff(): void
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
