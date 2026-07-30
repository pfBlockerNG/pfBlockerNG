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
 * Coverage matrix rows A-I (see the issue #1895 step-1 brief):
 *   A - write() blocked by the default privilege: exception + stored value unchanged.
 *   B - write() allowed by the default privilege: succeeds, canonical token stored.
 *   C - write() consults the per-field write_priv override, not the default.
 *   D - write() succeeds once the per-field override is allowed.
 *   E - writeSection() blocked: exception, and the WHOLE section is unmodified.
 *   F - writeSection() allowed: same normalisation/pass-through as before the change.
 *   G - writeSystem() bypasses the check even with every page disallowed.
 *   H - writeSectionSystem() bypasses the check even with every page disallowed.
 *   I - parity: writeSystem() stores byte-identical value to an allowed write().
 */
final class CfgWriteAuthorizationTest extends TestCase
{
	private const GEN = 'installedpackages/pfblockerng/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		unset($GLOBALS['pfb_test_allowed_pages']);
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_allowed_pages']);
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
			PfbConfig::write('pfb_keep', PfbToggle::Off);
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

		PfbConfig::write('pfb_keep', PfbToggle::Off);

		$this->assertSame('off', config_get_path($path),
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
			PfbConfig::write('pfb_software_check', PfbToggle::Off);
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

		PfbConfig::write('pfb_software_check', PfbToggle::Off);

		$this->assertSame('off', config_get_path($path),
			'write must succeed and persist the canonical stored token'
		);
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
		PfbConfig::write('pfb_keep', 'junk');
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

		PfbConfig::writeSystem('pfb_keep', PfbToggle::On);
		PfbConfig::writeSystem('pfb_software_check', PfbToggle::On);

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
		PfbConfig::write('pfb_keep', PfbToggle::On);
		$expected = config_get_path($path);

		$GLOBALS['config'] = [];
		unset($GLOBALS['pfb_test_allowed_pages']);
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => false,
		];
		PfbConfig::writeSystem('pfb_keep', PfbToggle::On);
		$actual = config_get_path($path);

		$this->assertSame($expected, $actual,
			'writeSystem() must store the same value an allowed write() would, byte-identical'
		);
	}
}
