<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2371 — the full install-order interaction: pfb_run_migrations() ->
 * pfb_registry_pass() -> the #2371 post-pass seed, proving the deviation from
 * pfb_migration_registry() (see pfb_psl_feed_policy_is_fresh_install()'s docblock,
 * pfblockerng.inc, and tests/php/PslFeedPolicySeedTest.php for the predicate's own
 * unit tests) is load-bearing and not just theoretical.
 */
#[CoversFunction('pfb_psl_feed_policy_is_fresh_install')]
#[CoversFunction('pfb_install_psl_feed_policy_seed')]
#[CoversFunction('pfb_registry_pass')]
#[CoversFunction('pfb_run_migrations')]
final class PslFeedPolicyPipelineOrderingTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	/**
	 * RE-IMPLEMENTS pfblockerng_install.inc's documented call order for a
	 * genuinely fresh install (capture freshness BEFORE any mutation, run
	 * migrations, run the registry pass, THEN apply the #2371 seed only if
	 * freshness was TRUE) -- it does not execute the installer file, which
	 * cannot be include()'d off-appliance. The real file's ordering is pinned
	 * separately by testInstallerCallsTheSeamAfterRegistryWriteback below;
	 * only the two together prove ordering safety.
	 */
	private function runInstallSequence(): array
	{
		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$fresh = pfb_psl_feed_policy_is_fresh_install($sections[self::DNSBL_SECTION]);
		$modes = pfb_registry_section_modes($sections);

		pfb_run_migrations();

		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		foreach (pfb_registry_pass($sections, NULL, $modes) as $section => $blob) {
			PfbConfig::writeSectionRawSystem($section, $blob);
		}

		// The REAL seam pfblockerng_install.inc calls -- not a hand-copied
		// reimplementation, so a mutation to its body is caught here too.
		pfb_install_psl_feed_policy_seed($fresh);

		return PfbConfig::readSection(self::DNSBL_SECTION);
	}

	/**
	 * Row 3: a genuinely fresh install (nothing configured beforehand) ends with both
	 * keys 'apex' after the full pipeline runs.
	 */
	public function testFreshInstallEndsWithBothKeysApex(): void
	{
		$dnsbl = $this->runInstallSequence();

		$this->assertSame('apex', $dnsbl['pfb_psl_feed_private_policy'] ?? NULL);
		$this->assertSame('apex', $dnsbl['pfb_psl_feed_icann_policy'] ?? NULL);
	}

	/**
	 * The load-bearing regression guard for keeping this seed OUT of
	 * pfb_migration_registry(): a genuinely fresh install must not corrupt a SIBLING
	 * registered dnsbl/* field's own NEWCFG default. dnsbl/pfb_dnsbl_lenient carries a
	 * grandfather map (ABSENT -> 'on') that only an OLDCFG (existing-install) section
	 * may apply; its correct fresh-install value is the registered default 'off'.
	 */
	public function testFreshInstallDoesNotCorruptSiblingFieldGrandfatherMode(): void
	{
		$dnsbl = $this->runInstallSequence();

		$this->assertSame('off', $dnsbl['pfb_dnsbl_lenient'] ?? NULL,
			'a genuinely fresh install must take the NEWCFG default (off) for pfb_dnsbl_lenient, '
			. 'never the OLDCFG absent-grandfather (on) -- proves the #2371 seed running AFTER '
			. 'the registry pass, not as a pfb_migration_registry() entry, is load-bearing');
	}

	/**
	 * Row 4: an existing install (already has unrelated operator configuration, but
	 * never touched these two keys) ends the pipeline with BOTH keys NEVER seeded
	 * 'apex' -- the #2371 seed does not fire (fresh == FALSE). pfb_registry_pass()
	 * itself DOES materialise its own registered default '' for the two keys once the
	 * section is OLDCFG (absent + no grandfather map -> stable_default, same branch
	 * that seeds every other un-grandfathered field on this section, e.g. top1m_source
	 * -> 'tranco'); '' is not 'apex' and PfbConfig::read() resolves it to Honor exactly
	 * like a genuinely absent key would.
	 */
	public function testUpgradeInstallLeavesBothKeysAbsent(): void
	{
		PfbConfig::writeSectionRawSystem(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on', 'dnsbl_interface' => 'lo0']);

		$dnsbl = $this->runInstallSequence();

		$this->assertNotSame('apex', $dnsbl['pfb_psl_feed_private_policy'] ?? NULL,
			'upgrade must never seed apex -- that seed only fires on a genuinely fresh install');
		$this->assertNotSame('apex', $dnsbl['pfb_psl_feed_icann_policy'] ?? NULL,
			'upgrade must never seed apex -- that seed only fires on a genuinely fresh install');
		$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read('dnsbl/pfb_psl_feed_private_policy'));
		$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read('dnsbl/pfb_psl_feed_icann_policy'));
	}

	/**
	 * Idempotency at the pipeline level: running the WHOLE sequence a second time
	 * (simulating a package reinstall over an already-seeded box) is a no-op for these
	 * two keys -- the section is no longer empty, so freshness reads FALSE and the
	 * seed step never fires again.
	 */
	public function testSecondPipelineRunIsNoOpForAlreadySeededKeys(): void
	{
		$first  = $this->runInstallSequence();
		$second = $this->runInstallSequence();

		$this->assertSame('apex', $first['pfb_psl_feed_private_policy'] ?? NULL);
		$this->assertSame($first['pfb_psl_feed_private_policy'], $second['pfb_psl_feed_private_policy'] ?? NULL);
		$this->assertSame($first['pfb_psl_feed_icann_policy'], $second['pfb_psl_feed_icann_policy'] ?? NULL);
	}

	/**
	 * DI-based unit test of pfb_install_psl_feed_policy_seed() itself (mirrors
	 * InstallPrePassWriteOrderTest::testRegistryWritebackSeamFlushesAfterReturnedSectionWrites()
	 * for pfb_install_registry_writeback()): $fresh == TRUE writes BOTH keys, in order,
	 * THEN flushes exactly once with the documented message.
	 */
	public function testSeamWritesBothKeysThenFlushesWhenFresh(): void
	{
		$order = [];
		pfb_install_psl_feed_policy_seed(
			TRUE,
			static function (string $key, mixed $value) use (&$order): void {
				$order[] = "write:{$key}={$value}";
			},
			static function (string $message) use (&$order): void {
				$order[] = "flush:{$message}";
			}
		);
		$this->assertSame(
			[
				'write:dnsbl/pfb_psl_feed_private_policy=apex',
				'write:dnsbl/pfb_psl_feed_icann_policy=apex',
				'flush:pfBlockerNG: seeded feed-at-suffix PSL policy defaults for fresh install (issue #2371)',
			],
			$order
		);
	}

	/** DI-based unit test: $fresh == FALSE writes and flushes NOTHING. */
	public function testSeamIsNoOpWhenNotFresh(): void
	{
		$order = [];
		pfb_install_psl_feed_policy_seed(
			FALSE,
			static function (string $key, mixed $value) use (&$order): void {
				$order[] = "write:{$key}={$value}";
			},
			static function (string $message) use (&$order): void {
				$order[] = "flush:{$message}";
			}
		);
		$this->assertSame([], $order);
	}

	/**
	 * Wiring proof (mirrors InstallPrePassWriteOrderTest::
	 * testRegistryPassWritebackRunsBeforeFinalConfigFlush()): the REAL installer file
	 * dispatches through this seam exactly once, AFTER pfb_install_registry_writeback().
	 * php_strip_whitespace gives an executable-code pin without comments/docblocks
	 * satisfying the ordering contract; pfblockerng_install.inc cannot be include()'d
	 * safely off-appliance (see InstallPrePassWriteOrderTest's docblock).
	 */
	public function testInstallerCallsTheSeamAfterRegistryWriteback(): void
	{
		$path = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
		$source = php_strip_whitespace($path);
		$this->assertNotSame('', $source, 'installer source must be readable');

		$capture = strpos($source, 'pfb_psl_feed_policy_is_fresh_install(');
		$this->assertNotFalse($capture, 'installer must capture freshness via pfb_psl_feed_policy_is_fresh_install()');

		// Migrations run through pfb_install_settings_family_finalize()'s seam
		// (its $migrations callable defaults to pfb_run_migrations).
		$migrations = strpos($source, 'pfb_install_settings_family_finalize(');
		$this->assertNotFalse($migrations, 'installer must run the migration registry via its finalize seam');
		$this->assertLessThan($migrations, $capture, 'freshness must be captured BEFORE any migration mutates a section');

		$writeback = strpos($source,
			'pfb_install_registry_writeback($pfb_registry_sections, $pfb_registry_modes);');
		$this->assertNotFalse($writeback, 'installer must dispatch its registry pass through the writeback seam');

		$seam = strpos($source, 'pfb_install_psl_feed_policy_seed($pfb_psl_feed_policy_fresh_install);');
		$this->assertNotFalse($seam, 'installer must dispatch the #2371 seed through pfb_install_psl_feed_policy_seed()');
		$this->assertSame(1, substr_count($source, 'pfb_install_psl_feed_policy_seed($pfb_psl_feed_policy_fresh_install);'));
		$this->assertGreaterThan($writeback, $seam, 'the #2371 seed must run AFTER the registry writeback, never before');
	}
}
