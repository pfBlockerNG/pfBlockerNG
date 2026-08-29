<?php

use PHPUnit\Framework\TestCase;

/**
 * Issue #1895 — PfbConfig write-authorization tests.
 *
 * write()/writeSection() must enforce a per-field write_priv page privilege via
 * isAllowedPage(), fail-closed. writeSystem()/writeSectionSystem() are the explicit
 * escape hatch for legitimate no-session system callers (cron/install/migrations/
 * CLI/core hooks), where isAllowedPage() is undefined or meaningless.
 *
 * Coverage matrix rows A-L (see the issue #1895 step-1 brief, and the delta-aware
 * addendum found reviewing #1895 against pfblockerng_general.php's read-modify-write
 * composition -- rows J-L):
 *   A - write() blocked by the default privilege: exception + stored value unchanged.
 *   B - write() allowed by the default privilege: succeeds, canonical token stored.
 *   C - write() consults the per-field write_priv override, not the default.
 *   D - write() succeeds once the per-field override is allowed.
 *   E - writeSection() blocked: exception, and the WHOLE section is unmodified
 *       (fixture is a REAL value change, not merely a present field, so the
 *       delta-aware gate below still enforces refusal).
 *   F - writeSection() allowed: same normalisation/pass-through as before the change.
 *   G - writeSystem() bypasses the check even with every page disallowed.
 *   H - writeSectionSystem() bypasses the check even with every page disallowed.
 *   I - parity: writeSystem() stores byte-identical value to an allowed write().
 *   J - writeSection() delta-aware pass-through: an unrelated field changes, a
 *       privilege-gated field rides along UNCHANGED -- must succeed (the composition
 *       bug this addendum fixes: a General-page save must not trip on
 *       pfb_software_check's pass-through value).
 *   K - same seeding as J, but the privilege-gated field's value actually CHANGES --
 *       enforcement is retained: exception, section unmodified.
	 *   L - deletion subtlety: stored ABSENT and incoming NULL are the same no-op state;
	 *       deleting an explicit value remains an authorization event.
 */
final class CfgWriteAuthorizationTest extends TestCase
{
	private const GEN = 'installedpackages/pfblockerng/config/0';
	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;

	protected function setUp(): void
	{
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		unset($GLOBALS['pfb_test_allowed_pages']);
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_allowed_pages']);
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	// -----------------------------------------------------------------------
	// A - write() blocked by the default page privilege.
	// -----------------------------------------------------------------------

	public function testWriteBlockedByDefaultPrivilegeThrowsAndLeavesStoredValueUnchanged(): void
	{
		$path = self::GEN . '/pfb_keep';
		config_set_path($path, 'on');

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
		];

		try {
			PfbConfig::write('gen/pfb_keep', PfbToggle::Off);
			$this->fail('expected RuntimeException, none thrown');
		} catch (RuntimeException $e) {
			$this->assertStringContainsString('pfb_keep', $e->getMessage(),
				'exception message must name the key'
			);
		}

		$this->assertSame('on', config_get_path($path),
			'blocked write must leave the stored value unchanged'
		);
	}

	// -----------------------------------------------------------------------
	// B - write() allowed by the default page privilege.
	// -----------------------------------------------------------------------

	public function testWriteAllowedByDefaultPrivilegeSucceeds(): void
	{
		$path = self::GEN . '/pfb_keep';
		config_set_path($path, 'on');

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
		];

		PfbConfig::write('gen/pfb_keep', PfbToggle::Off);

		$this->assertSame('', config_get_path($path),
			'allowed write must persist the canonical stored token'
		);
	}

	// -----------------------------------------------------------------------
	// C - write() consults the per-field write_priv override, not the default.
	// -----------------------------------------------------------------------

	public function testWriteConsultsPerFieldPrivilegeOverrideNotDefault(): void
	{
		$path = self::GEN . '/pfb_software_check';
		config_set_path($path, 'on');

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'               => false,
		];

		try {
			PfbConfig::write('gen/pfb_software_check', PfbToggle::Off);
			$this->fail('expected RuntimeException, none thrown');
		} catch (RuntimeException $e) {
			$this->assertStringContainsString('pfb_software_check', $e->getMessage(),
				'exception message must name the key'
			);
		}

		$this->assertSame('on', config_get_path($path),
			'blocked write must leave the stored value unchanged'
		);
	}

	// -----------------------------------------------------------------------
	// D - write() succeeds once the per-field override is allowed.
	// -----------------------------------------------------------------------

	public function testWriteSucceedsWhenPerFieldPrivilegeOverrideAllowed(): void
	{
		$path = self::GEN . '/pfb_software_check';
		config_set_path($path, 'on');

		// The default page is deliberately disallowed here -- if write() consulted
		// the default instead of the field's own override, this would (wrongly) throw.
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
			'pkg_mgr_installed.php'               => true,
		];

		PfbConfig::write('gen/pfb_software_check', PfbToggle::Off);

		$this->assertSame('', config_get_path($path),
			'write must succeed and persist the canonical stored token'
		);
	}

	public function testWriteAllowedNullDeletesStoredAdapterKey(): void
	{
		$path = self::GEN . '/pfb_software_check';
		config_set_path($path, 'on');
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pkg_mgr_installed.php' => true,
		];

		PfbConfig::write('gen/pfb_software_check', NULL);

		$this->assertNull(config_get_path($path), 'public write(NULL) must delete the adapted key');
	}

	// -----------------------------------------------------------------------
	// E - writeSection() blocked: whole section unmodified.
	// -----------------------------------------------------------------------

	public function testWriteSectionBlockedByPrivilegeLeavesEntireSectionUnmodified(): void
	{
		$baseline = [
			'pfb_keep'           => 'on',
			'pfb_software_check' => 'on',
			'enable_cb'          => 'on',
		];
		config_set_path(self::GEN, $baseline);

		// General page allowed (pfb_keep/enable_cb would pass), but the
		// pfb_software_check override is blocked -- the whole section write must
		// still be refused, and none of it -- not even pfb_keep -- may land.
		//
		// NOTE (delta-aware addendum): pfb_software_check's incoming value below
		// ('off') is a REAL change from its stored baseline ('on') -- this is
		// deliberate. The delta-aware gate (assertWriteAllowedOnChange()) only
		// skips the privilege assertion for an UNCHANGED pass-through value; a
		// fixture where the denied field's incoming value equalled its stored
		// value would now (correctly) succeed instead of pinning refusal, which
		// would silently defeat this test. See rows J/K/L below for the
		// pass-through/real-change split this addendum adds.
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'               => false,
		];

		try {
			PfbConfig::writeSection(self::GEN, [
				'pfb_keep'           => 'off',
				'pfb_software_check' => 'off',
				'enable_cb'          => 'off',
			]);
			$this->fail('expected RuntimeException, none thrown');
		} catch (RuntimeException $e) {
			$this->assertStringContainsString('pfb_software_check', $e->getMessage());
		}

		$this->assertSame($baseline, config_get_path(self::GEN),
			'blocked writeSection() must leave the ENTIRE section unmodified'
		);
	}

	// -----------------------------------------------------------------------
	// F - writeSection() allowed: normalisation/pass-through unchanged by the refactor.
	// -----------------------------------------------------------------------

	public function testWriteSectionAllowedNormalisesRegisteredFieldsAndPassesThroughForeignKeys(): void
	{
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'                => true,
		];

		// Oracle: single-key write() on a fresh slate.
		$GLOBALS['config'] = [];
		PfbConfig::write('gen/pfb_keep', 'junk');
		$expected_keep = config_get_path(self::GEN . '/pfb_keep');

		// Under test: writeSection() with the same field plus an unregistered/foreign key.
		$GLOBALS['config'] = [];
		PfbConfig::writeSection(self::GEN, [
			'pfb_keep'          => 'junk',
			'some_foreign_key'  => 'untouched-value',
		]);

		$this->assertSame($expected_keep, config_get_path(self::GEN . '/pfb_keep'),
			'writeSection() must normalise a registered field exactly as write() would'
		);
		$this->assertSame('untouched-value', config_get_path(self::GEN . '/some_foreign_key'),
			'writeSection() must pass an unregistered/foreign key through byte-identical'
		);
	}

	// -----------------------------------------------------------------------
	// G - writeSystem() bypasses the check even with every page disallowed.
	// -----------------------------------------------------------------------

	public function testWriteSystemBypassesPrivilegeCheckEvenWhenAllPagesDisallowed(): void
	{
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
			'pkg_mgr_installed.php'                => false,
		];

		PfbConfig::writeSystem('gen/pfb_keep', PfbToggle::On);
		PfbConfig::writeSystem('gen/pfb_software_check', PfbToggle::On);

		$this->assertSame('on', config_get_path(self::GEN . '/pfb_keep'),
			'writeSystem() must succeed and persist the canonical token regardless of privilege'
		);
		$this->assertSame('on', config_get_path(self::GEN . '/pfb_software_check'),
			'writeSystem() must succeed and persist the canonical token regardless of the field write_priv override'
		);
	}

	// -----------------------------------------------------------------------
	// H - writeSectionSystem() bypasses the check even with every page disallowed.
	// -----------------------------------------------------------------------

	public function testWriteSectionSystemBypassesPrivilegeCheckEvenWhenAllPagesDisallowed(): void
	{
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
			'pkg_mgr_installed.php'                => false,
		];

		// Oracle: what an ALLOWED writeSection() would normalise this to (same
		// normalisation contract as row F, just proven again for writeSectionSystem()).
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'                => true,
		];
		PfbConfig::writeSection(self::GEN, ['pfb_keep' => 'junk', 'some_foreign_key' => 'v']);
		$expected_keep    = config_get_path(self::GEN . '/pfb_keep');
		$expected_foreign = config_get_path(self::GEN . '/some_foreign_key');

		// Under test: writeSectionSystem() with every page disallowed.
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
			'pkg_mgr_installed.php'                => false,
		];
		PfbConfig::writeSectionSystem(self::GEN, ['pfb_keep' => 'junk', 'some_foreign_key' => 'v']);

		$this->assertSame($expected_keep, config_get_path(self::GEN . '/pfb_keep'),
			'writeSectionSystem() must normalise exactly as an allowed writeSection() would'
		);
		$this->assertSame($expected_foreign, config_get_path(self::GEN . '/some_foreign_key'),
			'writeSectionSystem() must pass foreign keys through byte-identical, privilege notwithstanding'
		);
	}

	// -----------------------------------------------------------------------
	// I - parity: writeSystem() stores byte-identical value to an allowed write().
	// -----------------------------------------------------------------------

	public function testWriteSystemStoresByteIdenticalValueToAllowedWrite(): void
	{
		$path = self::GEN . '/pfb_keep';

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
		];
		PfbConfig::write('gen/pfb_keep', PfbToggle::On);
		$expected = config_get_path($path);

		$GLOBALS['config'] = [];
		unset($GLOBALS['pfb_test_allowed_pages']);
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
		];
		PfbConfig::writeSystem('gen/pfb_keep', PfbToggle::On);
		$actual = config_get_path($path);

		$this->assertSame($expected, $actual,
			'writeSystem() must store the same value an allowed write() would, byte-identical'
		);
	}

	// -----------------------------------------------------------------------
	// J - writeSection() delta-aware pass-through: THE composition-bug regression.
	// -----------------------------------------------------------------------

	public function testWriteSectionUnchangedPrivilegedFieldPassesThroughOnUnrelatedEdit(): void
	{
		$baseline = [
			'pfb_keep'           => 'on',
			'pfb_software_check' => 'on',
		];
		config_set_path(self::GEN, $baseline);

		// A scoped operator: allowed on the General page, denied on the Software page.
		// pfb_software_check's write_priv override ('pkg_mgr_installed.php') is denied.
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'                => false,
		];

		// The real General-page shape: whole-section readSection() -> modify ONE
		// unrelated field -> writeSection(). pfb_software_check rides along unchanged.
		$data              = PfbConfig::readSection(self::GEN);
		$data['pfb_keep']  = 'off';

		PfbConfig::writeSection(self::GEN, $data);

		$this->assertSame('', config_get_path(self::GEN . '/pfb_keep'),
			'the unrelated, actually-changed field must persist canonically'
		);
		$this->assertSame('on', config_get_path(self::GEN . '/pfb_software_check'),
			'an UNCHANGED pass-through of a privilege-gated field must not trip its '
			. 'write_priv gate -- the #1895 composition bug this addendum fixes'
		);
	}

	// -----------------------------------------------------------------------
	// K - same seeding as J, but the privilege-gated field's value actually changes.
	// -----------------------------------------------------------------------

	public function testWriteSectionRealChangeOfPrivilegedFieldStillEnforcesGate(): void
	{
		$baseline = [
			'pfb_keep'           => 'on',
			'pfb_software_check' => 'on',
		];
		config_set_path(self::GEN, $baseline);

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'                => false,
		];

		// This time the operator (or a crafted POST) actually flips pfb_software_check.
		$data                       = PfbConfig::readSection(self::GEN);
		$data['pfb_software_check'] = 'off';

		try {
			PfbConfig::writeSection(self::GEN, $data);
			$this->fail('expected RuntimeException, none thrown');
		} catch (RuntimeException $e) {
			$this->assertStringContainsString('pfb_software_check', $e->getMessage(),
				'exception message must name the key'
			);
		}

		$this->assertSame($baseline, config_get_path(self::GEN),
			'a REAL change to a privilege-gated field must still refuse the whole section '
			. 'write -- enforcement is retained, the delta-aware gate only skips unchanged values'
		);
	}

	// -----------------------------------------------------------------------
	// L - deletion subtlety: stored ABSENT canonicalises identical to incoming NULL.
	// -----------------------------------------------------------------------

	public function testWriteSectionAbsentStoredFieldEqualsIncomingDefaultIsPassThrough(): void
	{
		// pfb_software_check is entirely ABSENT from the stored section -- never saved
		// on this box before. An incoming NULL is the same deletion/no-op state.
		config_set_path(self::GEN, ['pfb_keep' => 'on']);

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'                => false,
		];

		PfbConfig::writeSection(self::GEN, [
			'pfb_keep'           => 'off',
			// NULL means delete; absent -> NULL is a no-op and needs no privilege.
			'pfb_software_check' => NULL,
		]);

		$this->assertSame('', config_get_path(self::GEN . '/pfb_keep'),
			'the unrelated, actually-changed field must persist canonically'
		);
		$this->assertNull(config_get_path(self::GEN . '/pfb_software_check'),
			'absent-stored must canonicalise identically to incoming NULL and remain absent'
		);
	}

	public function testWriteSectionDefaultValueToNullRequiresPrivilegeAndLeavesSectionUnchanged(): void
	{
		$baseline = [
			'pfb_keep'           => 'on',
			'pfb_software_check' => 'on',
		];
		config_set_path(self::GEN, $baseline);
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'                => false,
		];

		try {
			PfbConfig::writeSection(self::GEN, [
				'pfb_keep'           => 'on',
				'pfb_software_check' => NULL,
			]);
			$this->fail('expected RuntimeException, none thrown');
		} catch (RuntimeException $e) {
			$this->assertStringContainsString('pfb_software_check', $e->getMessage());
		}

		$this->assertSame($baseline, config_get_path(self::GEN),
			'blocked deletion must leave the whole section unchanged'
		);
	}

	public function testWriteSectionAbsentValueToNullIsNoOpWithoutPrivilege(): void
	{
		$baseline = ['pfb_keep' => 'on'];
		config_set_path(self::GEN, $baseline);
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => true,
			'pkg_mgr_installed.php'                => false,
		];

		PfbConfig::writeSection(self::GEN, [
			'pfb_keep'           => 'on',
			'pfb_software_check' => NULL,
		]);

		$this->assertSame($baseline, config_get_path(self::GEN),
			'absent deletion must remain a no-op without privilege'
		);
	}

	// -----------------------------------------------------------------------
	// M - non-scalar values under a plain (adapter-less) registered key must
	//     compare by SHAPE in the delta gate, not by PHP's string cast: a
	//     (string) cast collapses every array to 'Array' (warning + two
	//     different arrays comparing "unchanged" while writeSectionRaw()
	//     persists them verbatim) -- CodeRabbit finding on PR #1903.
	// -----------------------------------------------------------------------

	public function testWriteSectionNonScalarChangeUnderPlainKeyIsAnAuthorizationEvent(): void
	{
		// A crafted-POST array riding a plain registered key (pfb_schedule_hour has
		// NULL/NULL adapters). Stored and incoming arrays DIFFER, so this is a
		// real change: the delta gate must consult the privilege and refuse.
		config_set_path(self::GEN, ['pfb_schedule_hour' => ['a']]);

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
		];

		try {
			PfbConfig::writeSection(self::GEN, ['pfb_schedule_hour' => ['b']]);
			$this->fail('expected RuntimeException, none thrown');
		} catch (RuntimeException $e) {
			$this->assertStringContainsString('pfb_schedule_hour', $e->getMessage(),
				'exception message must name the key'
			);
		}

		$this->assertSame(['a'], config_get_path(self::GEN . '/pfb_schedule_hour'),
			'refused non-scalar change must leave the stored value unchanged'
		);
	}

	public function testWriteSectionIdenticalNonScalarPassThroughEmitsNoWarning(): void
	{
		// Identical arrays are a pass-through; the comparison must not raise
		// "Array to string conversion" (the cast would, on BOTH tests here --
		// PHPUnit converts warnings to errors under failOnWarning, and this
		// closure-based handler catches it regardless of that setting).
		config_set_path(self::GEN, ['pfb_schedule_hour' => ['a']]);

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
		];

		$warnings = [];
		set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
			$warnings[] = $msg;
			return true;
		}, E_WARNING | E_NOTICE);
		try {
			PfbConfig::writeSection(self::GEN, ['pfb_schedule_hour' => ['a']]);
		} finally {
			restore_error_handler();
		}

		$this->assertSame([], $warnings,
			'the delta comparison must not string-cast non-scalars'
		);
		$this->assertSame(['a'], config_get_path(self::GEN . '/pfb_schedule_hour'),
			'identical non-scalar pass-through must persist verbatim'
		);
	}
}
