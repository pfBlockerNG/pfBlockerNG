<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1098: purge stale change-detect probe bodies ({header}.md5.raw) at
 * install/upgrade, so a pre-#1072 corrupted probe body left on disk can never be
 * reused verbatim by the next sync ingest (pfb_download's reuse fork trusts any
 * existing .md5.raw — see pfblockerng.inc's "re-utilize instead of downloading
 * twice" branch).
 */
#[CoversFunction('pfb_purge_probe_bodies')]
final class ProbeBodyPurgeTest extends TestCase
{
	private string $dir;
	private string $origdir;
	private string $dnsorigdir;
	private ?string $savedOrigdir;
	private ?string $savedDnsorigdir;

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_probe_purge_test_' . getmypid() . '_' . mt_rand(0, 0xffff);
		$this->dir = $base;
		$this->origdir = "{$base}/original";
		$this->dnsorigdir = "{$base}/dnsblorig";
		if (!mkdir($this->origdir, 0777, TRUE) || !mkdir($this->dnsorigdir, 0777, TRUE)) {
			$this->fail("Could not create temp dirs under: {$base}");
		}

		$this->savedOrigdir = $GLOBALS['pfb']['origdir'] ?? NULL;
		$this->savedDnsorigdir = $GLOBALS['pfb']['dnsorigdir'] ?? NULL;
		$GLOBALS['pfb']['origdir'] = $this->origdir;
		$GLOBALS['pfb']['dnsorigdir'] = $this->dnsorigdir;
	}

	protected function tearDown(): void
	{
		if ($this->savedOrigdir === NULL) {
			unset($GLOBALS['pfb']['origdir']);
		} else {
			$GLOBALS['pfb']['origdir'] = $this->savedOrigdir;
		}
		if ($this->savedDnsorigdir === NULL) {
			unset($GLOBALS['pfb']['dnsorigdir']);
		} else {
			$GLOBALS['pfb']['dnsorigdir'] = $this->savedDnsorigdir;
		}

		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($it as $f) {
			$f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
		}
		rmdir($this->dir);
	}

	/**
	 * R1: a planted {h}.md5.raw in origdir is purged.
	 *
	 *  GIVEN a stale probe body sitting in origdir;
	 *   WHEN pfb_purge_probe_bodies() is called;
	 *   THEN the probe body no longer exists.
	 */
	public function test_purges_stale_probe_body_in_origdir(): void
	{
		$probe = "{$this->origdir}/feedA.md5.raw";
		file_put_contents($probe, 'corrupted probe body bytes');
		$this->assertFileExists($probe, 'Precondition: probe body must exist before purge');

		pfb_purge_probe_bodies();

		$this->assertFileDoesNotExist(
			$probe,
			'pfb_purge_probe_bodies() must remove a stale .md5.raw probe body from origdir'
		);
	}

	/**
	 * R2: a planted {h}.md5.raw in dnsorigdir is purged.
	 *
	 *  GIVEN a stale probe body sitting in dnsorigdir;
	 *   WHEN pfb_purge_probe_bodies() is called;
	 *   THEN the probe body no longer exists.
	 */
	public function test_purges_stale_probe_body_in_dnsorigdir(): void
	{
		$probe = "{$this->dnsorigdir}/feedB.md5.raw";
		file_put_contents($probe, 'corrupted probe body bytes');
		$this->assertFileExists($probe, 'Precondition: probe body must exist before purge');

		pfb_purge_probe_bodies();

		$this->assertFileDoesNotExist(
			$probe,
			'pfb_purge_probe_bodies() must remove a stale .md5.raw probe body from dnsorigdir'
		);
	}

	/**
	 * R3: sibling artifacts survive the purge in both dirs — only the exact
	 * '*.md5.raw' probe-body glob is in scope; the ingest body, the finalised
	 * baseline, and every sidecar format must remain untouched.
	 *
	 *  GIVEN a probe body plus its non-probe siblings (.orig, legacy .md5,
	 *        .xxhash128, .etag, .lastmod, and a bare .raw ingest body) in both
	 *        origdir and dnsorigdir;
	 *   WHEN pfb_purge_probe_bodies() is called;
	 *   THEN every sibling file still exists (only the .md5.raw is gone).
	 */
	public function test_leaves_sibling_artifacts_untouched_in_both_dirs(): void
	{
		$siblingSuffixes = array('.orig', '.md5', '.xxhash128', '.etag', '.lastmod', '.raw');

		foreach (array($this->origdir, $this->dnsorigdir) as $dir) {
			file_put_contents("{$dir}/feedC.md5.raw", 'stale probe body');
			foreach ($siblingSuffixes as $sfx) {
				file_put_contents("{$dir}/feedC{$sfx}", "sibling artifact {$sfx}");
			}
		}

		pfb_purge_probe_bodies();

		foreach (array($this->origdir, $this->dnsorigdir) as $dir) {
			$this->assertFileDoesNotExist(
				"{$dir}/feedC.md5.raw",
				"the probe body in {$dir} must be purged"
			);
			foreach ($siblingSuffixes as $sfx) {
				$this->assertFileExists(
					"{$dir}/feedC{$sfx}",
					"sibling artifact feedC{$sfx} in {$dir} must survive the purge (not a .md5.raw probe body)"
				);
			}
		}
	}

	/**
	 * R4: a nonexistent dir is skipped by the is_dir guard — the purge completes
	 * silently without raising a warning/error.
	 *
	 *  GIVEN origdir points at a path that does not exist on disk;
	 *   WHEN pfb_purge_probe_bodies() is called;
	 *   THEN it completes without raising a warning/error.
	 */
	public function test_nonexistent_dir_completes_without_error(): void
	{
		$GLOBALS['pfb']['origdir'] = "{$this->dir}/does_not_exist";

		$raised = NULL;
		set_error_handler(function (int $errno, string $errstr) use (&$raised): bool {
			$raised = $errstr;
			return TRUE;
		});
		try {
			pfb_purge_probe_bodies();
		} finally {
			restore_error_handler();
		}

		$this->assertNull(
			$raised,
			sprintf('pfb_purge_probe_bodies() must not raise a warning/error for a missing dir, got: %s', $raised)
		);
	}

	/**
	 * R7: an UNSET dir key is skipped silently (no "Undefined array key" warning) and
	 * must not abort the sweep of the other dir — an unset/empty value must never
	 * widen the glob towards '/'.
	 *
	 *  GIVEN $pfb['origdir'] is unset and a stale probe body sits in dnsorigdir;
	 *   WHEN pfb_purge_probe_bodies() is called;
	 *   THEN no warning is raised AND the dnsorigdir probe body is still purged.
	 */
	public function test_unset_dir_key_skipped_and_other_dir_still_purged(): void
	{
		unset($GLOBALS['pfb']['origdir']);
		$probe = "{$this->dnsorigdir}/feedD.md5.raw";
		file_put_contents($probe, 'stale probe body');
		$this->assertFileExists($probe, 'Precondition: probe body must exist before purge');

		$raised = NULL;
		set_error_handler(function (int $errno, string $errstr) use (&$raised): bool {
			$raised = $errstr;
			return TRUE;
		});
		try {
			pfb_purge_probe_bodies();
		} finally {
			restore_error_handler();
		}

		$this->assertNull(
			$raised,
			sprintf('pfb_purge_probe_bodies() must not warn on an unset dir key, got: %s', $raised)
		);
		$this->assertFileDoesNotExist(
			$probe,
			'an unset origdir must not stop the dnsorigdir sweep'
		);
	}

	/**
	 * R5: a hostile filename (embedded space) is purged correctly — glob() and
	 * unlink() take literal paths here, no shell is involved.
	 *
	 *  GIVEN a probe body named with an embedded space;
	 *   WHEN pfb_purge_probe_bodies() is called;
	 *   THEN that file is removed.
	 */
	public function test_purges_probe_body_with_embedded_space_in_filename(): void
	{
		$probe = "{$this->origdir}/weird name.md5.raw";
		file_put_contents($probe, 'stale probe body');
		$this->assertFileExists($probe, 'Precondition: probe body with embedded space must exist before purge');

		pfb_purge_probe_bodies();

		$this->assertFileDoesNotExist(
			$probe,
			'pfb_purge_probe_bodies() must purge a probe body whose filename has an embedded space'
		);
	}

	/**
	 * R8: a glob-metacharacter filename is purged, alongside a coincidental sibling
	 * the bracket pattern would match. Pins the direct-@unlink contract: re-globbing
	 * the resolved path (unlink_if_exists() behaviour) would delete only the sibling
	 * and leave the bracket-named leftover on disk.
	 *
	 *  GIVEN probe bodies 'weird[z].md5.raw' and 'weirdz.md5.raw' in origdir
	 *        ('[' sorts before 'z', so the sweep reaches the bracket name first);
	 *   WHEN pfb_purge_probe_bodies() is called;
	 *   THEN both files are removed.
	 */
	public function test_purges_glob_metachar_filename_and_its_glob_decoy(): void
	{
		$target = "{$this->origdir}/weird[z].md5.raw";
		$decoy  = "{$this->origdir}/weirdz.md5.raw";
		file_put_contents($target, 'stale probe body (bracket name)');
		file_put_contents($decoy, 'stale probe body (decoy)');
		$this->assertFileExists($target, 'Precondition: bracket-named probe body must exist before purge');
		$this->assertFileExists($decoy, 'Precondition: decoy probe body must exist before purge');

		pfb_purge_probe_bodies();

		$this->assertFileDoesNotExist(
			$target,
			'a glob-metachar-named probe body must be unlinked literally, not re-globbed away'
		);
		$this->assertFileDoesNotExist(
			$decoy,
			'the decoy probe body matches *.md5.raw and must be purged too'
		);
	}

	/**
	 * R6: source-pin (install.inc is not loadable by the unit harness — see
	 * InstallDnsblMoveRestartGuardTest). Pins the install-time wiring the harness
	 * cannot execute: a LIVE (uncommented) pfb_purge_probe_bodies() call.
	 *
	 *  GIVEN the pfblockerng_install.inc source;
	 *   THEN a line calls pfb_purge_probe_bodies(); with no comment marker before it.
	 */
	public function test_install_inc_calls_purge_probe_bodies(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
		$src = @file_get_contents($path);
		$this->assertIsString($src, "could not read {$path}");

		$this->assertMatchesRegularExpression(
			'/^[ \t]*pfb_purge_probe_bodies\(\);/m',
			$src,
			'pfblockerng_install.inc must contain a live (uncommented, statement-position) pfb_purge_probe_bodies() call'
		);
	}
}
