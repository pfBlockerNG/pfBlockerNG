<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #2518 — the consented pkg.conf CA-path patch: pure text add/remove of a single
 * SSL_CA_CERT_PATH line inside pfSense-repo-setup's PKG_ENV block, the IO wrappers around
 * them, and the cron-facing re-apply + notify tick.
 *
 * Background (see pfb_pkg_ca_env_prefix()'s docblock, issue #2514): on Plus,
 * pfSense-repo-setup deletes and regenerates /usr/local/etc/pkg.conf and appends a PKG_ENV
 * block pinning SSL_CA_CERT_FILE to a Netgate-only bundle, applied by libpkg with
 * setenv(key, value, 1) -- overwrite. PKG_ENV never sets SSL_CA_CERT_PATH, and libfetch loads
 * both into one store via SSL_CTX_load_verify_locations(ctx, ca_cert_file, ca_cert_path), so
 * an added path survives the pin. Adding that one line is the whole fix.
 *
 * Fixtures (tests/fixtures/pkg_conf/, shared byte-for-byte with the sibling shell step):
 *   plus_pinned.conf  -- a live Plus 26.03.1 box's file, unpatched.
 *   plus_patched.conf -- the same file with our line added (ca_path=/etc/ssl/certs).
 *   ce_unpinned.conf  -- a CE box's file: no PKG_ENV block at all.
 *
 * /etc/ssl/certs is used directly as the "real" populated CA directory in the tests that
 * must byte-match plus_patched.conf (its embedded value is literally that path and the
 * fixture is immutable) -- the CI image genuinely ships it non-empty (ca-certificates),
 * so this exercises the real is_dir()+populated gate rather than bypassing it.
 */
#[CoversFunction('pfb_pkgconf_ca_needed')]
#[CoversFunction('pfb_pkgconf_ca_add')]
#[CoversFunction('pfb_pkgconf_ca_remove')]
#[CoversFunction('pfb_pkgconf_ca_state')]
#[CoversFunction('pfb_pkgconf_ca_sync')]
#[CoversFunction('pfb_pkgconf_ca_tick')]
final class PkgConfCaPatchTest extends TestCase
{
	private const REAL_CA_DIR = '/etc/ssl/certs';
	private const CONSENT_PATH = 'installedpackages/pfblockerng/config/0/pfb_pkg_ca_consent';

	private string $root = '';

	private bool $hadDbdir = false;
	private mixed $savedDbdir = null;
	private bool $hadConfig = false;
	private mixed $savedConfig = null;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb-pkgconf-' . bin2hex(random_bytes(6));
		mkdir($this->root, 0o755, true);

		$this->hadDbdir   = isset($GLOBALS['pfb']) && array_key_exists('dbdir', $GLOBALS['pfb']);
		$this->savedDbdir = $GLOBALS['pfb']['dbdir'] ?? null;
		$GLOBALS['pfb']['dbdir'] = $this->root . '/dbdir';
		mkdir($GLOBALS['pfb']['dbdir'], 0o755, true);

		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? null;
		$GLOBALS['config'] = [];

		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		$this->rrmdir($this->root);

		if ($this->hadDbdir) {
			$GLOBALS['pfb']['dbdir'] = $this->savedDbdir;
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		unset($GLOBALS['pfb_test_file_notices']);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		@chmod($dir, 0o755);
		foreach ((scandir($dir) ?: []) as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$path = $dir . '/' . $entry;
			if (is_link($path)) {
				@unlink($path);
				continue;
			}
			if (is_dir($path)) {
				$this->rrmdir($path);
				continue;
			}
			@chmod($path, 0o644);
			@unlink($path);
		}
		@rmdir($dir);
	}

	private function fixture(string $name): string
	{
		return (string) file_get_contents(dirname(__DIR__, 2) . '/tests/fixtures/pkg_conf/' . $name);
	}

	private function tempFile(string $content, string $name = 'pkg.conf'): string
	{
		$path = $this->root . '/' . $name;
		file_put_contents($path, $content);
		return $path;
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

	private function emptyDir(): string
	{
		$dir = $this->root . '/empty_capath';
		if (!is_dir($dir)) {
			mkdir($dir, 0o755, true);
		}
		return $dir;
	}

	private function skipUnderRoot(): void
	{
		if (!function_exists('posix_getuid') || posix_getuid() === 0) {
			$this->markTestSkipped('root reads mode-0000 files / ignores directory write bits, and without ext-posix the uid is unknown');
		}
	}

	// -------------------------------------------------------------------
	// pfb_pkgconf_ca_needed()
	// -------------------------------------------------------------------

	public function testNeededTrueOnPinnedFixture(): void
	{
		$this->assertTrue(pfb_pkgconf_ca_needed($this->fixture('plus_pinned.conf')));
	}

	public function testNeededFalseOnPatchedFixture(): void
	{
		$this->assertFalse(pfb_pkgconf_ca_needed($this->fixture('plus_patched.conf')));
	}

	public function testNeededFalseOnCeUnpinnedFixture(): void
	{
		$this->assertFalse(pfb_pkgconf_ca_needed($this->fixture('ce_unpinned.conf')));
	}

	public function testNeededFalseWhenBlockHasNoCertFileLine(): void
	{
		$text = "ABI=FreeBSD:16:amd64\nOSVERSION=1600018\nPKG_ENV {\n\tSSL_CLIENT_CERT_FILE=/x\n}\n";
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededFalseWithTwoBlocks(): void
	{
		$text = "PKG_ENV {\n\tSSL_CA_CERT_FILE=/a\n}\nPKG_ENV {\n\tSSL_CA_CERT_FILE=/b\n}\n";
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededFalseWithNoClosingBrace(): void
	{
		$text = "PKG_ENV {\n\tSSL_CA_CERT_FILE=/a\n";
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededFalseWhenPathPresentOutsideBlock(): void
	{
		$text = "SSL_CA_CERT_PATH=/x\nPKG_ENV {\n\tSSL_CA_CERT_FILE=/a\n}\n";
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededFalseOnEmptyAndWhitespaceOnlyText(): void
	{
		$this->assertFalse(pfb_pkgconf_ca_needed(''));
		$this->assertFalse(pfb_pkgconf_ca_needed('   '));
	}

	public function testNeededFalseOnSingleLineForm(): void
	{
		$text = "PKG_ENV { SSL_CA_CERT_FILE=/x }\n";
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededFalseOnCrlfLineEndings(): void
	{
		$text = str_replace("\n", "\r\n", $this->fixture('plus_pinned.conf'));
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededFalseOnIndentedBlockOpen(): void
	{
		$text = "  PKG_ENV {\n\tSSL_CA_CERT_FILE=/a\n}\n";
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededFalseOnCommentedBlockOpen(): void
	{
		$text = "#PKG_ENV {\n\tSSL_CA_CERT_FILE=/a\n}\n";
		$this->assertFalse(pfb_pkgconf_ca_needed($text));
	}

	// -------------------------------------------------------------------
	// pfb_pkgconf_ca_add()
	// -------------------------------------------------------------------

	public function testAddPatchesPinnedFixtureByteIdenticalToPlusPatched(): void
	{
		$patched = pfb_pkgconf_ca_add($this->fixture('plus_pinned.conf'), self::REAL_CA_DIR);
		$this->assertSame($this->fixture('plus_patched.conf'), $patched);
	}

	public function testAddRefusesAlreadyPatchedFixture(): void
	{
		$this->assertSame('', pfb_pkgconf_ca_add($this->fixture('plus_patched.conf'), self::REAL_CA_DIR));
	}

	/** @return array<string,array{0:string}> */
	public static function hostileCaPathProvider(): array
	{
		return [
			'empty'             => [''],
			'relative'          => ['relative/path'],
			'newline injection' => ["/etc/ssl/certs\nEVIL=1"],
			'space'             => ['/etc/ssl/c erts'],
			'brace'             => ['/etc/ssl/certs}'],
			'hash comment'      => ['/etc/ssl/certs#c'],
			'quote'             => ['/etc/ssl/"certs"'],
		];
	}

	#[DataProvider('hostileCaPathProvider')]
	public function testAddRefusesHostileCaPaths(string $ca_path): void
	{
		$this->assertSame('', pfb_pkgconf_ca_add($this->fixture('plus_pinned.conf'), $ca_path));
	}

	public function testAddRefusesRootSlashCaPath(): void
	{
		// The regex requires at least one char after the leading '/' -- pin the refusal so
		// that requirement stays enforced.
		$this->assertSame('', pfb_pkgconf_ca_add($this->fixture('plus_pinned.conf'), '/'));
	}

	public function testAddIsRefusedOnItsOwnOutputIdempotent(): void
	{
		$once = pfb_pkgconf_ca_add($this->fixture('plus_pinned.conf'), self::REAL_CA_DIR);
		$this->assertNotSame('', $once);
		$this->assertSame('', pfb_pkgconf_ca_add($once, self::REAL_CA_DIR));
	}

	public function testAddPatchesWhenFinalBraceHasNoTrailingNewline(): void
	{
		$noTrailingNewline = rtrim($this->fixture('plus_pinned.conf'), "\n");
		$patched = pfb_pkgconf_ca_add($noTrailingNewline, self::REAL_CA_DIR);
		$this->assertSame(rtrim($this->fixture('plus_patched.conf'), "\n"), $patched);
	}

	// -------------------------------------------------------------------
	// pfb_pkgconf_ca_remove()
	// -------------------------------------------------------------------

	public function testRemovePatchedFixtureByteIdenticalToPlusPinned(): void
	{
		$removed = pfb_pkgconf_ca_remove($this->fixture('plus_patched.conf'), self::REAL_CA_DIR);
		$this->assertSame($this->fixture('plus_pinned.conf'), $removed);
	}

	public function testRemoveRefusesPinnedFixture(): void
	{
		$this->assertSame('', pfb_pkgconf_ca_remove($this->fixture('plus_pinned.conf'), self::REAL_CA_DIR));
	}

	public function testRemoveLeavesDifferentPathLineAlone(): void
	{
		$this->assertSame('', pfb_pkgconf_ca_remove($this->fixture('plus_patched.conf'), '/different/path'));
	}

	public function testAddThenRemoveRoundTripsToOriginalBytes(): void
	{
		$original = $this->fixture('plus_pinned.conf');
		$added = pfb_pkgconf_ca_add($original, self::REAL_CA_DIR);
		$removed = pfb_pkgconf_ca_remove($added, self::REAL_CA_DIR);
		$this->assertSame($original, $removed);
	}

	// -------------------------------------------------------------------
	// Hostile inputs
	// -------------------------------------------------------------------

	public function testAddHandlesLargePaddedPinnedFileCorrectly(): void
	{
		$line = "# padding comment line for hostile-size coverage (issue #2518)\n";
		$count = (int) ceil((5 * 1024 * 1024) / strlen($line));
		$padding = str_repeat($line, $count);
		$text = $padding . $this->fixture('plus_pinned.conf');
		$this->assertGreaterThanOrEqual(5 * 1024 * 1024, strlen($text), 'fixture must actually exceed 5MB');

		$this->assertTrue(pfb_pkgconf_ca_needed($text));
		$patched = pfb_pkgconf_ca_add($text, self::REAL_CA_DIR);
		$this->assertSame($padding . $this->fixture('plus_patched.conf'), $patched);
	}

	public function testNeededHandlesNulByteWithoutWarning(): void
	{
		$text = "# pad \x00 with a nul byte\n" . $this->fixture('plus_pinned.conf');
		$this->assertTrue(pfb_pkgconf_ca_needed($text));
	}

	public function testNeededIgnoresQuotedPkgEnvLookalike(): void
	{
		$text = "\tSOME_VAR=\"PKG_ENV {\"\n" . $this->fixture('plus_pinned.conf');
		$this->assertTrue(pfb_pkgconf_ca_needed($text));
	}

	// -------------------------------------------------------------------
	// pfb_pkgconf_ca_state()
	// -------------------------------------------------------------------

	public function testStatePinnedFileIsNeeded(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));
		$this->assertSame('needed', pfb_pkgconf_ca_state($file));
	}

	public function testStatePatchedFileIsPatched(): void
	{
		$file = $this->tempFile($this->fixture('plus_patched.conf'));
		$this->assertSame('patched', pfb_pkgconf_ca_state($file));
	}

	public function testStateCeFileIsEmpty(): void
	{
		$file = $this->tempFile($this->fixture('ce_unpinned.conf'));
		$this->assertSame('', pfb_pkgconf_ca_state($file));
	}

	public function testStateAbsentPathIsEmpty(): void
	{
		$this->assertSame('', pfb_pkgconf_ca_state($this->root . '/does-not-exist.conf'));
	}

	public function testStateDirectoryIsEmpty(): void
	{
		$dir = $this->root . '/adir';
		mkdir($dir, 0o755, true);
		$this->assertSame('', pfb_pkgconf_ca_state($dir));
	}

	public function testStateSymlinkIsEmpty(): void
	{
		$target = $this->tempFile($this->fixture('plus_pinned.conf'), 'target.conf');
		$link = $this->root . '/link.conf';
		symlink($target, $link);
		$this->assertSame('', pfb_pkgconf_ca_state($link));
	}

	public function testStateUnreadableFileIsEmpty(): void
	{
		$this->skipUnderRoot();
		$file = $this->tempFile($this->fixture('plus_pinned.conf'), 'unreadable.conf');
		chmod($file, 0o000);
		$this->assertSame('', pfb_pkgconf_ca_state($file));
	}

	// -------------------------------------------------------------------
	// pfb_pkgconf_ca_sync()
	// -------------------------------------------------------------------

	public function testSyncConsentTrueOnPinnedWithPopulatedDirPatches(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));
		$this->assertTrue(pfb_pkgconf_ca_sync(TRUE, $file, self::REAL_CA_DIR));
		$this->assertSame($this->fixture('plus_patched.conf'), file_get_contents($file));
	}

	public function testSyncConsentTrueWithNonDirectoryCaPathFailsByteUnchanged(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));
		$notADir = $this->tempFile('not a directory', 'notadir');
		$before = file_get_contents($file);

		$this->assertFalse(pfb_pkgconf_ca_sync(TRUE, $file, $notADir));
		$this->assertSame($before, file_get_contents($file));
	}

	public function testSyncConsentTrueWithEmptyCaDirFailsByteUnchanged(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));
		$before = file_get_contents($file);

		$this->assertFalse(pfb_pkgconf_ca_sync(TRUE, $file, $this->emptyDir()));
		$this->assertSame($before, file_get_contents($file));
	}

	public function testSyncConsentTrueOnAlreadyPatchedFileNoWrite(): void
	{
		$file = $this->tempFile($this->fixture('plus_patched.conf'));
		$inodeBefore = fileinode($file);

		$this->assertTrue(pfb_pkgconf_ca_sync(TRUE, $file, self::REAL_CA_DIR));
		clearstatcache(true, $file);
		$this->assertSame($inodeBefore, fileinode($file), 'no write means no rename, so the inode must be unchanged');
		$this->assertSame($this->fixture('plus_patched.conf'), file_get_contents($file));
	}

	public function testSyncConsentFalseOnPatchedFileRestoresPlusPinned(): void
	{
		$file = $this->tempFile($this->fixture('plus_patched.conf'));
		$this->assertTrue(pfb_pkgconf_ca_sync(FALSE, $file, self::REAL_CA_DIR));
		$this->assertSame($this->fixture('plus_pinned.conf'), file_get_contents($file));
	}

	public function testSyncConsentFalseOnPinnedFileByteUnchanged(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));
		$before = file_get_contents($file);

		$this->assertTrue(pfb_pkgconf_ca_sync(FALSE, $file, self::REAL_CA_DIR));
		$this->assertSame($before, file_get_contents($file));
	}

	public function testSyncConsentTrueOnCeFileNothingToDoByteUnchanged(): void
	{
		$file = $this->tempFile($this->fixture('ce_unpinned.conf'));
		$before = file_get_contents($file);

		$this->assertTrue(pfb_pkgconf_ca_sync(TRUE, $file, self::REAL_CA_DIR));
		$this->assertSame($before, file_get_contents($file));
	}

	public function testSyncTargetSymlinkFailsLinkAndTargetIntact(): void
	{
		$target = $this->tempFile($this->fixture('plus_pinned.conf'), 'target2.conf');
		$link = $this->root . '/link2.conf';
		symlink($target, $link);
		$beforeTarget = file_get_contents($target);

		$this->assertFalse(pfb_pkgconf_ca_sync(TRUE, $link, self::REAL_CA_DIR));
		$this->assertTrue(is_link($link), 'the symlink itself must survive, not be replaced');
		$this->assertSame($target, readlink($link));
		$this->assertSame($beforeTarget, file_get_contents($target));
	}

	public function testSyncPreservesFileMode0600(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));
		chmod($file, 0o600);

		$this->assertTrue(pfb_pkgconf_ca_sync(TRUE, $file, self::REAL_CA_DIR));
		clearstatcache(true, $file);
		$this->assertSame(0o600, fileperms($file) & 0o777);
	}

	public function testSyncUnwritableDirectoryFailsNoTempLeftover(): void
	{
		$this->skipUnderRoot();
		$dir = $this->root . '/lockeddir';
		mkdir($dir, 0o755, true);
		$file = $dir . '/pkg.conf';
		file_put_contents($file, $this->fixture('plus_pinned.conf'));
		chmod($dir, 0o555);

		try {
			$before = file_get_contents($file);
			$this->assertFalse(pfb_pkgconf_ca_sync(TRUE, $file, self::REAL_CA_DIR));
			$this->assertSame($before, file_get_contents($file));

			$leftovers = array_values(array_filter(
				scandir($dir) ?: [],
				static fn($entry) => $entry !== '.' && $entry !== '..' && $entry !== 'pkg.conf'
			));
			$this->assertSame([], $leftovers, 'no .tmp leftover in the unwritable directory');
		} finally {
			chmod($dir, 0o755);
		}
	}

	// -------------------------------------------------------------------
	// pfb_pkgconf_ca_tick()
	// -------------------------------------------------------------------

	private function sentinelPath(): string
	{
		return $GLOBALS['pfb']['dbdir'] . '/.pkg_ca_notice';
	}

	public function testTickProvenanceFalseDoesNothing(): void
	{
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));
		$before = file_get_contents($file);

		pfb_pkgconf_ca_tick(FALSE, $file, $this->populatedDir());

		$this->assertSame($before, file_get_contents($file));
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testTickConsentOnNeededPatchesAndNoNotice(): void
	{
		config_set_path(self::CONSENT_PATH, 'on');
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));

		pfb_pkgconf_ca_tick(TRUE, $file, self::REAL_CA_DIR);

		$this->assertSame($this->fixture('plus_patched.conf'), file_get_contents($file));
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
		$this->assertFileDoesNotExist($this->sentinelPath());
	}

	public function testTickConsentOffNeededRaisesExactlyOneNoticeAndSentinel(): void
	{
		config_set_path(self::CONSENT_PATH, '');
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));

		pfb_pkgconf_ca_tick(TRUE, $file, $this->populatedDir());

		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertSame('pfBlockerNG', $notice['id']);
		$this->assertStringContainsString('SSL_CA_CERT_PATH', $notice['notice']);
		$this->assertSame('/pfblockerng/pfblockerng_software.php', $notice['url']);
		$this->assertSame(1, $notice['priority']);
		$this->assertSame($this->fixture('plus_pinned.conf'), file_get_contents($file), 'consent off must never write');
		$this->assertFileExists($this->sentinelPath());
	}

	public function testTickSecondCallWithSentinelPresentStillOneNotice(): void
	{
		config_set_path(self::CONSENT_PATH, '');
		$file = $this->tempFile($this->fixture('plus_pinned.conf'));

		pfb_pkgconf_ca_tick(TRUE, $file, $this->populatedDir());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'tick 1: exactly one notice');

		pfb_pkgconf_ca_tick(TRUE, $file, $this->populatedDir());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'tick 2: de-duped, still one notice');
	}

	public function testTickStateEmptyClearsSentinelAndNoNotice(): void
	{
		touch($this->sentinelPath());
		$this->assertFileExists($this->sentinelPath(), 'precondition: a stale sentinel exists');

		$file = $this->tempFile($this->fixture('ce_unpinned.conf'));
		pfb_pkgconf_ca_tick(TRUE, $file, $this->populatedDir());

		$this->assertFileDoesNotExist($this->sentinelPath());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}
}
