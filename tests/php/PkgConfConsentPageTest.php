<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2518 STEP C — the Software page's pkg.conf CA-path consent control.
 *
 * Covers the PHPUnit-reachable rows of the STEP C coverage matrix: the checkbox's posted
 * token (row 1), the cron wiring to pfb_pkgconf_ca_tick() (row 2), the field's round trip
 * through the page's ACTUAL save handler -- pfb_pkgconf_ca_save(), not a replay of it (row 3,
 * fix round finding 1), and its write_priv gate (row 4). The page's CONDITIONAL RENDER
 * (section shown only when pfb_pkgconf_ca_state() !== '') is NOT reachable here:
 * pfb_pkgconf_ca_state() reads the real PFB_PKG_CONF path (/usr/local/etc/pkg.conf), which
 * does not exist off-appliance, so it deterministically returns '' under PHPUnit and the
 * shown branch can never be exercised this way. That branch is Tier A/B smoke UI coverage
 * instead, each seeding a real PKG_ENV block into a VM's guest pkg.conf via
 * test_render_smoke.pkg_conf_ca_block_seeded():
 *   - tests/smoke/ui/test_render_smoke.py::test_software_page_pkgconf_ca_consent_section_present_when_pinned
 *     (Tier A positive; its sibling ::test_software_page_pkgconf_ca_consent_section_absent_on_unpinned_pkgconf
 *     covers the negative/default-CE branch WITHOUT seeding)
 *   - tests/smoke/ui/test_functional.py::test_software_page_pkgconf_ca_consent_toggle_post_roundtrip
 *     (Tier B functional POST round-trip)
 *   - tests/smoke/ui/test_browser_misc.py::test_software_panel_pkgconf_ca_consent_section_screenshot
 *     (Tier B browser/screenshot)
 *
 * Row 3 no longer replays the save filter from scraped source: pfb_pkgconf_ca_save()
 * (pfblockerng.inc) IS the save handler now -- the page's top-level 'save' branch calls it
 * (pinned below by testSaveHandlerCallsPfbPkgconfCaSaveThenApplyAfterWriteConfig(), a wiring
 * assertion only) and does nothing else with the field. Driving pfb_pkgconf_ca_save() and
 * pfb_pkgconf_ca_apply() directly exercises the exact code that runs in production.
 *
 * issue #2518 fix round (B1 / N-write-order): the combined save-and-sync was split in two.
 * pfb_pkgconf_ca_save(array $post): string ONLY persists the posted token -- it never
 * touches pkg.conf, and it writes NOTHING at all unless $post carries the hidden
 * 'pfb_pkg_ca_consent_shown' marker the page renders alongside the checkbox (an absent
 * marker means the consent section was never shown this request, so an absent
 * 'pfb_pkg_ca_consent' key is ambiguous between "unticked" and "not rendered" -- B1). The
 * caller MUST run write_config() next to flush that persist to disk BEFORE calling
 * pfb_pkgconf_ca_apply(string $token, ?string $file, string $ca_path): bool, which is the
 * half that actually syncs pkg.conf and is what the page's $input_errors branch reacts to.
 * Consent is this feature's security boundary, so it has to survive a reboot before pkg.conf
 * is ever mutated on its behalf -- deleting either the PfbConfig::write() inside
 * pfb_pkgconf_ca_save(), or the pfb_pkgconf_ca_sync() call inside pfb_pkgconf_ca_apply(),
 * turns testTickedSaveRoundTripsToOn() RED (see the STEP C fix-round handoff's mutation
 * proof, and the B1/B2/B3 mutation proof in the issue #2518 fix-round handoff).
 */
#[CoversFunction('pfb_pkgconf_ca_tick')]
#[CoversFunction('pfb_pkgconf_ca_save')]
#[CoversFunction('pfb_pkgconf_ca_apply')]
final class PkgConfConsentPageTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_software.php';
	private const CRON = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';
	private const GEN  = 'installedpackages/pfblockerng/config/0';
	private const REAL_CA_DIR = '/etc/ssl/certs';

	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;
	private string $root = '';

	protected function setUp(): void
	{
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];

		// issue #1895: this field's write authorization is the package-manager page (same
		// as pfb_software_check, sharing the Software page's secondary gate), not the
		// package's own general page.
		$GLOBALS['pfb_test_allowed_pages'] = ['pkg_mgr_installed.php' => TRUE];

		$this->root = sys_get_temp_dir() . '/pfb-pkgconf-consent-' . bin2hex(random_bytes(6));
		mkdir($this->root, 0o755, true);
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_allowed_pages']);
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}

		$this->rrmdir($this->root);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach ((scandir($dir) ?: []) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = $dir . '/' . $entry;
			is_dir($path) ? $this->rrmdir($path) : @unlink($path);
		}
		@rmdir($dir);
	}

	private function fixture(string $name): string
	{
		return (string) file_get_contents(dirname(__DIR__, 2) . '/tests/fixtures/pkg_conf/' . $name);
	}

	private function patchedFixtureFor(string $caDir): string
	{
		return str_replace(self::REAL_CA_DIR, $caDir, $this->fixture('plus_patched.conf'));
	}

	private function tempFile(string $content, string $name = 'pkg.conf'): string
	{
		$path = $this->root . '/' . $name;
		file_put_contents($path, $content);
		return $path;
	}

	private function emptyDir(): string
	{
		$dir = $this->root . '/empty_capath';
		if (!is_dir($dir)) {
			mkdir($dir, 0o755, true);
		}
		return $dir;
	}

	private function populatedDir(): string
	{
		$dir = $this->root . '/capath';
		if (!is_dir($dir)) {
			mkdir($dir, 0o755, true);
			file_put_contents($dir . '/x.0', '');
		}
		return $dir;
	}

	// -----------------------------------------------------------------------
	// Row 1 — the checkbox POSTs 'on', never pfSense's 'yes' default (issue #2367).
	// -----------------------------------------------------------------------

	/**
	 * The value the rendered consent checkbox posts when ticked: the Form_Checkbox call's
	 * 5th argument, or pfSense's default when the page omits it.
	 *
	 * Read from the comment-stripped source, same extraction SoftwareCheckPostRoundTripTest
	 * uses for the sibling pfb_software_check checkbox, so a reformat of the call cannot
	 * change the answer.
	 */
	private function postedWhenChecked(): string
	{
		$source = php_strip_whitespace(self::PAGE);
		$found  = preg_match(
			"/new Form_Checkbox\\(\\s*'pfb_pkg_ca_consent'\\s*,((?:[^()]|\\([^()]*\\))*)\\)/",
			$source,
			$m
		);
		$this->assertSame(1, $found, 'the Software page must build the pkg.conf CA-consent checkbox');

		$args = array_map('trim', explode(',', $m[1]));
		if (count($args) < 4 || $args[3] === '') {
			return 'yes'; // pfSense's Form_Checkbox default.
		}

		return trim($args[3], "'\"");
	}

	public function testConsentCheckboxPostsATokenTheFilterAccepts(): void
	{
		$posted = $this->postedWhenChecked();

		$this->assertNotSame(
			'yes',
			$posted,
			"the consent checkbox must pass its value explicitly; pfSense's Form_Checkbox default "
			. "'yes' is rejected by PFB_FILTER_ON_OFF (issue #2367)"
		);
		$this->assertSame('on', $posted, 'the consent checkbox must post the canonical On token');
	}

	// -----------------------------------------------------------------------
	// Row 2 — pfblockerng_cron.inc calls pfb_pkgconf_ca_tick().
	//
	// This is a WIRING assertion only: it proves the call site exists, next to
	// pfb_software_update_check(), inside the same best-effort cron pass. It does NOT
	// prove pfb_pkgconf_ca_tick() behaves correctly when called -- that behaviour
	// (provenance gating, consent branching, notice de-dupe) is PkgConfCaPatchTest's
	// job, exercised directly against the function, never through this textual match.
	// -----------------------------------------------------------------------

	public function testCronCallsPkgconfCaTickBesideSoftwareUpdateCheck(): void
	{
		$cron = php_strip_whitespace(self::CRON);

		$this->assertStringContainsString(
			'pfb_software_update_check();',
			$cron,
			'the modelled cron call site has moved; this wiring test needs updating'
		);
		$this->assertStringContainsString(
			'pfb_pkgconf_ca_tick();',
			$cron,
			'pfblockerng_cron.inc must call pfb_pkgconf_ca_tick() with no arguments -- its other '
			. 'params are test-only seams with production-safe defaults'
		);

		// Same best-effort slot: both calls between the update-cron branch above and the
		// pass-release cleanup below, so a re-apply failure can never affect feed timing.
		// pfb_feed_pass_release() also appears earlier, in an unrelated deferred-lock
		// early-return branch -- strrpos() (the LAST occurrence) is the tail cleanup call
		// that actually follows the tick, not that earlier unrelated one.
		$update_pos  = strpos($cron, 'pfb_software_update_check();');
		$tick_pos    = strpos($cron, 'pfb_pkgconf_ca_tick();');
		$release_pos = strrpos($cron, 'pfb_feed_pass_release();');
		$return_pos  = strpos($cron, 'return $sync_ok;');
		$this->assertNotFalse($update_pos);
		$this->assertNotFalse($tick_pos);
		$this->assertNotFalse($release_pos);
		$this->assertNotFalse($return_pos);
		$this->assertGreaterThan($update_pos, $tick_pos, 'the tick call must sit beside (after) the software-update check');
		$this->assertLessThan($release_pos, $tick_pos, 'the tick call must run inside the locked cron pass, before the tail lock release');
		$this->assertLessThan($return_pos, $tick_pos, 'the tick call must run before the function returns');
	}

	// -----------------------------------------------------------------------
	// Row 3 — the Save handler delegates to pfb_pkgconf_ca_save(), and that function's
	// PfbConfig round trip + pkg.conf sync both actually run.
	//
	// testSaveHandlerCallsPfbPkgconfCaSave() below is a WIRING assertion only (same
	// grep-based house pattern as testCronCallsPkgconfCaTickBesideSoftwareUpdateCheck()
	// above): it proves the page's 'save' branch calls the function, next to
	// write_config(), and nothing else touches the 'pfb_pkg_ca_consent' POST key or config
	// path there. It does NOT prove pfb_pkgconf_ca_save() behaves correctly when called --
	// that is the job of the tests below it, which call the function directly with a POST
	// array and a real pkg.conf fixture, so a regression in either the PfbConfig::write()
	// call or the pfb_pkgconf_ca_sync() call inside pfb_pkgconf_ca_save() fails one of them.
	// -----------------------------------------------------------------------

	public function testSaveHandlerCallsPfbPkgconfCaSaveThenApplyAfterWriteConfig(): void
	{
		$source = php_strip_whitespace(self::PAGE);

		$this->assertStringContainsString(
			'pfb_pkgconf_ca_save($_POST)',
			$source,
			'the Software page must delegate the consent persist to pfb_pkgconf_ca_save() '
			. '(issue #2518 fix-round finding 1) -- the page keeps only the redirect/$input_errors '
			. 'presentation decision built on pfb_pkgconf_ca_apply()\'s return value'
		);
		$this->assertStringNotContainsString(
			"PfbConfig::write('gen/pfb_pkg_ca_consent'",
			$source,
			"the page must not write this field itself anymore -- that write belongs to "
			. 'pfb_pkgconf_ca_save() alone, or this wiring test and the round-trip tests below '
			. 'would both be blind to the same regression'
		);
		$this->assertStringContainsString(
			'pfb_pkgconf_ca_apply(',
			$source,
			'the page must call pfb_pkgconf_ca_apply() to sync pkg.conf (issue #2518 N-write-order)'
		);

		$save_pos   = strpos($source, 'pfb_pkgconf_ca_save($_POST)');
		$config_pos = strpos($source, 'write_config(');
		$apply_pos  = strpos($source, 'pfb_pkgconf_ca_apply(');
		$this->assertNotFalse($save_pos);
		$this->assertNotFalse($config_pos);
		$this->assertNotFalse($apply_pos);
		$this->assertLessThan(
			$config_pos,
			$save_pos,
			'N-write-order: the consent token must be persisted into the in-memory config array '
			. 'before write_config() flushes it'
		);
		$this->assertLessThan(
			$apply_pos,
			$config_pos,
			'N-write-order: write_config() must flush consent to disk BEFORE pkg.conf is ever '
			. 'touched on the admin\'s behalf -- consent is this feature\'s security boundary'
		);
	}

	public function testTickedSaveRoundTripsToOn(): void
	{
		$caDir = $this->populatedDir();
		$file  = $this->tempFile($this->fixture('plus_pinned.conf'));

		$token = pfb_pkgconf_ca_save([
			'pfb_pkg_ca_consent_shown' => '1',
			'pfb_pkg_ca_consent'       => $this->postedWhenChecked(),
		]);
		$this->assertSame('on', $token);
		$this->assertSame(
			PfbToggle::On,
			PfbConfig::read('gen/pfb_pkg_ca_consent'),
			'a Save with the box ticked must persist the On token'
		);

		$ok = pfb_pkgconf_ca_apply($token, $file, $caDir);

		$this->assertTrue($ok, 'a ticked Save against a patchable pkg.conf must report success');
		$this->assertSame(
			$this->patchedFixtureFor($caDir),
			file_get_contents($file),
			'a ticked Save must patch the live pkg.conf -- not just the config token -- with the CA path line'
		);
	}

	public function testUntickedSaveRoundTripsToCanonicalOffToken(): void
	{
		// Start On + patched (config AND file) so a green result below is this save's doing,
		// not the registry default or an untouched fixture.
		$file = $this->tempFile($this->fixture('plus_patched.conf'));
		$seedToken = pfb_pkgconf_ca_save([
			'pfb_pkg_ca_consent_shown' => '1',
			'pfb_pkg_ca_consent'       => $this->postedWhenChecked(),
		]);
		$seedOk = pfb_pkgconf_ca_apply($seedToken, $file, self::REAL_CA_DIR);
		$this->assertTrue($seedOk, 'precondition seed save must succeed');
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_pkg_ca_consent'), 'precondition: consent starts On');
		$this->assertSame($this->fixture('plus_patched.conf'), file_get_contents($file), 'precondition: pkg.conf starts patched');

		// A browser omits an unticked checkbox but the hidden marker still posts -- the
		// section WAS rendered, this is an EXPLICIT off, not an absent marker (B1).
		$token = pfb_pkgconf_ca_save(['pfb_pkg_ca_consent_shown' => '1']);

		$this->assertSame('', $token);
		$this->assertSame(
			PfbToggle::Off,
			PfbConfig::read('gen/pfb_pkg_ca_consent'),
			'an unticked Save must persist the canonical Off token'
		);
		$this->assertSame(
			'',
			config_get_path(self::GEN . '/pfb_pkg_ca_consent'),
			'the canonical Off token stored on disk is the empty string'
		);

		$ok = pfb_pkgconf_ca_apply($token, $file, self::REAL_CA_DIR);

		$this->assertTrue($ok);
		$this->assertSame(
			$this->fixture('plus_pinned.conf'),
			file_get_contents($file),
			'an unticked Save must remove the CA path line from the live pkg.conf'
		);
	}

	public function testAbsentKeyDefaultsToOff(): void
	{
		// The field has never been saved -- config key entirely absent.
		$this->assertArrayNotHasKey('pfb_pkg_ca_consent', config_get_path(self::GEN, []));

		$this->assertSame(
			PfbToggle::Off,
			PfbConfig::read('gen/pfb_pkg_ca_consent'),
			'consent is opt-in: an absent key must default Off, never On'
		);
	}

	// -----------------------------------------------------------------------
	// B1 — an absent 'pfb_pkg_ca_consent_shown' marker means the consent section was never
	// rendered this request (e.g. pkg.conf's shape stopped being recognised mid
	// pfSense-repo-setup rewrite). pfb_pkgconf_ca_save() must then make NO write at all and
	// report the currently persisted token, regardless of anything else present in $post --
	// guessing Off from an absent checkbox key in that situation would silently REVOKE a
	// previously granted consent.
	// -----------------------------------------------------------------------

	public function testSaveWithoutShownMarkerNeverRevokesPersistedConsent(): void
	{
		config_set_path(self::GEN . '/pfb_pkg_ca_consent', 'on');

		// No 'pfb_pkg_ca_consent_shown' key -- as if a foreign/stale 'pfb_pkg_ca_consent' key
		// happened to be present in $_POST too, from some unrelated source.
		$token = pfb_pkgconf_ca_save(['pfb_pkg_ca_consent' => '']);

		$this->assertSame('on', $token, 'an absent marker must return the currently persisted token unchanged');
		$this->assertSame(
			PfbToggle::On,
			PfbConfig::read('gen/pfb_pkg_ca_consent'),
			'B1: a previously granted consent must survive a Save where the consent section was never shown'
		);
	}

	public function testSaveWithoutShownMarkerReturnsPersistedOffWhenNeverGranted(): void
	{
		// No prior consent at all -- the marker-absent path must still report the correct
		// (Off) persisted token, not merely "never write".
		$token = pfb_pkgconf_ca_save([]);

		$this->assertSame('', $token);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_pkg_ca_consent'));
	}

	// -----------------------------------------------------------------------
	// B3 — the page's ok===FALSE branch (the $input_errors render) had zero executed proof
	// at any tier. Drive pfb_pkgconf_ca_apply() to FALSE against a plus_pinned fixture with
	// an EMPTY CA dir, and assert the consent token was still persisted regardless.
	// -----------------------------------------------------------------------

	public function testExplicitOnSaveWithEmptyCaDirFailsButTokenPersists(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));

		$token = pfb_pkgconf_ca_save([
			'pfb_pkg_ca_consent_shown' => '1',
			'pfb_pkg_ca_consent'       => $this->postedWhenChecked(),
		]);
		$this->assertSame('on', $token);
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_pkg_ca_consent'));

		$ok = pfb_pkgconf_ca_apply($token, $file, $this->emptyDir());

		$this->assertFalse($ok, 'B3: apply must report failure when the CA hash dir is empty');
		$this->assertSame(
			PfbToggle::On,
			PfbConfig::read('gen/pfb_pkg_ca_consent'),
			'B3: the consent token must still be persisted even though pkg.conf could not be patched'
		);
		$this->assertSame(
			$this->fixture('plus_pinned.conf'),
			file_get_contents($file),
			'a failed apply must never write'
		);
	}

	// -----------------------------------------------------------------------
	// Finding 2 (retained) — pfb_pkgconf_ca_apply() must not run pfb_pkgconf_ca_sync() at
	// all when pfb_pkgconf_ca_state() is '' (a CE box, or any other file the two never
	// recognise): mirrors pfb_pkgconf_ca_tick()'s own guard, so a transient pkg.conf read
	// glitch on a box that never even rendered the consent section cannot surface the
	// CA-specific error to an admin who only toggled the unrelated "check for new versions"
	// setting.
	// -----------------------------------------------------------------------

	public function testApplyOnUnrecognisedPkgConfNeverFailsRegardlessOfCaPath(): void
	{
		$file = $this->tempFile($this->fixture('ce_unpinned.conf'));
		$before = file_get_contents($file);

		$token = pfb_pkgconf_ca_save([
			'pfb_pkg_ca_consent_shown' => '1',
			'pfb_pkg_ca_consent'       => $this->postedWhenChecked(),
		]);
		$this->assertSame('on', $token, 'the consent token itself must still persist');

		// A CA path that would make pfb_pkgconf_ca_sync() itself return FALSE if it ran
		// (missing/empty directory) -- proves the early return skips the call rather than
		// merely happening to succeed.
		$ok = pfb_pkgconf_ca_apply($token, $file, $this->emptyDir());

		$this->assertTrue(
			$ok,
			'a CE box (no recognised PKG_ENV block) must never surface the CA-sync error, even '
			. 'with a CA path that would make pfb_pkgconf_ca_sync() itself fail'
		);
		$this->assertSame($before, file_get_contents($file), 'an unrecognised pkg.conf must never be written');
	}

	// -----------------------------------------------------------------------
	// Row 4 — write_priv matches the page's secondary gate (issue #1895 model:
	// CfgWriteAuthorizationTest rows C/D, applied to this field).
	// -----------------------------------------------------------------------

	public function testWriteConsultsPkgMgrInstalledPrivilegeNotDefault(): void
	{
		config_set_path(self::GEN . '/pfb_pkg_ca_consent', 'on');

		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => TRUE,
			'pkg_mgr_installed.php'               => FALSE,
		];

		try {
			PfbConfig::write('gen/pfb_pkg_ca_consent', PfbToggle::Off);
			$this->fail('expected RuntimeException, none thrown');
		} catch (RuntimeException $e) {
			$this->assertStringContainsString('pfb_pkg_ca_consent', $e->getMessage(), 'exception message must name the key');
		}

		$this->assertSame(
			'on',
			config_get_path(self::GEN . '/pfb_pkg_ca_consent'),
			'blocked write must leave the stored value unchanged'
		);
	}

	public function testWriteSucceedsWithPkgMgrInstalledPrivilegeEvenWithoutDefault(): void
	{
		config_set_path(self::GEN . '/pfb_pkg_ca_consent', 'on');

		// The default (general-page) privilege is deliberately withheld -- if write()
		// consulted the default instead of this field's own override, this would wrongly throw.
		$GLOBALS['pfb_test_allowed_pages'] = [
			'pfblockerng/pfblockerng_general.php' => FALSE,
			'pkg_mgr_installed.php'               => TRUE,
		];

		PfbConfig::write('gen/pfb_pkg_ca_consent', PfbToggle::Off);

		$this->assertSame('', config_get_path(self::GEN . '/pfb_pkg_ca_consent'), 'write must succeed and persist the canonical token');
	}
}
