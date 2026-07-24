<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfb_validate_filepath() authorizes per-logtype, never on the dir-union (issue #1649).
 *
 * The defect: the validator admitted any file whose dirname was ANY logtype's
 * logdir, ignoring each logtype's own 'ext' filename whitelist and its
 * 'clear'/'download' capability flags. '/usr/local/pkg/pfblockerng/' is a
 * whitelisted logdir (dnsbl_tld / dnsbl_safe, both clear => FALSE), so a holder
 * of the grantable WebCfg pfBlockerNG privilege could clear= (unlink) or
 * download= (read) package source such as pfblockerng.inc.
 *
 * Intent pinned here: a request is authorized only when SOME logtype's whole
 * tuple authorizes it -- its logdir matches the file's directory, the requested
 * action's capability flag is enabled for that logtype, and the filename matches
 * that logtype's 'ext' whitelist (glob "*<ext>", mirroring getlogs()). A logtype
 * carrying an inline 'logs' list has no 'ext' and stays directory-scoped -- the
 * pre-existing behaviour the Tier-B flows (tests/smoke/ui/test_log.py) pin by
 * seeding throwaway basenames under the defaultlogs dir.
 */
final class LogValidateFilepathTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/LogPageLoader.php';
		pfb_test_load_log_page_functions();
	}

	/**
	 * A $pfb_logtypes fixture mirroring the real page's entries for every shape
	 * involved: inline 'logs' lists, scalar and array 'ext', glob patterns, the
	 * shared-package-dir pair (both clear => FALSE), and two logtypes sharing one
	 * logdir with opposite clear flags (masterfiles vs top1m).
	 */
	private function logtypes(): array
	{
		return [
			'defaultlogs' => [
				'logdir'   => '/var/log/pfblockerng/',
				'logs'     => ['pfblockerng.log', 'error.log', 'ip_block.log', 'py_error.log', 'dnsbl.log'],
				'download' => TRUE,
				'clear'    => TRUE,
			],
			'masterfiles' => [
				'logdir'   => '/var/db/pfblockerng/',
				'logs'     => ['masterfile', 'mastercat'],
				'download' => TRUE,
				'clear'    => FALSE,
			],
			'originallogs' => [
				'logdir'   => '/var/db/pfblockerng/original/',
				'ext'      => ['orig', 'raw'],
				'download' => TRUE,
				'clear'    => TRUE,
			],
			'python' => [
				'logdir'   => '/var/unbound/',
				'ext'      => ['pfb_py*.txt'],
				'download' => TRUE,
				'clear'    => FALSE,
			],
			'dnsbl_tld' => [
				'logdir'   => '/usr/local/pkg/pfblockerng/',
				'ext'      => ['dnsbl_tld'],
				'download' => TRUE,
				'clear'    => FALSE,
			],
			'dnsbl_safe' => [
				'logdir'   => '/usr/local/pkg/pfblockerng/',
				'ext'      => ['pfb_dnsbl*.conf'],
				'download' => TRUE,
				'clear'    => FALSE,
			],
			'top1m' => [
				'logdir'   => '/var/db/pfblockerng/',
				'ext'      => ['pfbalexawhitelist.txt'],
				'download' => TRUE,
				'clear'    => TRUE,
			],
		];
	}

	// --- the reported escalation: package source under a whitelisted logdir ---

	public function testDownloadOfPackageSourceUnderWhitelistedDirIsRejected(): void
	{
		$this->assertFalse(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/pfblockerng.inc', $this->logtypes(), 'download'),
			'download of pfblockerng.inc must be rejected: it matches no pkg-dir logtype ext whitelist'
		);
	}

	public function testClearOfPackageSourceUnderWhitelistedDirIsRejected(): void
	{
		$this->assertFalse(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/pfblockerng.inc', $this->logtypes(), 'clear'),
			'clear (unlink) of pfblockerng.inc must be rejected: no pkg-dir logtype allows it'
		);
	}

	public function testLoadOfPackageSourceUnderWhitelistedDirIsRejected(): void
	{
		$this->assertFalse(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/pfblockerng.inc', $this->logtypes(), 'load'),
			'ajax load of pfblockerng.inc must be rejected: it matches no pkg-dir logtype ext whitelist'
		);
	}

	// --- capability flags bind to the matching logtype, not the union ---------

	public function testClearOfDnsblTldFileIsRejectedBecauseItsLogtypeForbidsClear(): void
	{
		// The file itself IS the dnsbl_tld logtype's own file (download works,
		// below) -- but that logtype carries clear => FALSE.
		$this->assertFalse(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/dnsbl_tld', $this->logtypes(), 'clear'),
			'clear of dnsbl_tld must be rejected: its logtype has clear => FALSE'
		);
	}

	public function testClearOfMasterfileIsRejectedWhereASiblingLogtypeSharesTheDir(): void
	{
		// masterfiles (clear => FALSE) and top1m (clear => TRUE) share one
		// logdir; top1m's whitelist does not cover 'masterfile', so no logtype
		// authorizes the clear.
		$this->assertFalse(
			pfb_validate_filepath('/var/db/pfblockerng/masterfile', $this->logtypes(), 'clear'),
			'clear of masterfile must be rejected: masterfiles forbids clear and top1m does not cover the file'
		);
	}

	// --- legitimate requests keep passing --------------------------------------

	public function testDownloadOfDnsblTldFileIsAllowedByItsOwnLogtype(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/dnsbl_tld', $this->logtypes(), 'download'),
			'download of dnsbl_tld must pass: its own logtype matches and allows download'
		);
	}

	public function testDownloadOfSafeSearchConfIsAllowedByItsGlobPattern(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/pfb_dnsbl.conf', $this->logtypes(), 'download'),
			'download of pfb_dnsbl.conf must pass: it matches dnsbl_safe\'s pfb_dnsbl*.conf pattern'
		);
	}

	public function testClearOfDefaultLogIsAllowedByItsOwnLogtype(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/var/log/pfblockerng/ip_block.log', $this->logtypes(), 'clear'),
			'clear of ip_block.log must pass: defaultlogs owns the dir and allows clear'
		);
	}

	public function testClearOfTop1mWhitelistIsAllowedByItsOwnLogtype(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/pfbalexawhitelist.txt', $this->logtypes(), 'clear'),
			'clear of pfbalexawhitelist.txt must pass: top1m matches and allows clear'
		);
	}

	public function testDownloadOfMasterfileIsAllowedByItsOwnLogtype(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/masterfile', $this->logtypes(), 'download'),
			'download of masterfile must pass: masterfiles allows download'
		);
	}

	public function testExtArrayLogtypeAdmitsEachListedExtension(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/original/feed1.orig', $this->logtypes(), 'download'),
			'a .orig file must match originallogs\' first ext entry'
		);
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/original/feed1.raw', $this->logtypes(), 'clear'),
			'a .raw file must match originallogs\' second ext entry'
		);
	}

	public function testLogsListLogtypeAdmitsOnlyItsEnumeratedBasenames(): void
	{
		// A 'logs'-list logtype (defaultlogs) authorizes ONLY the exact basenames
		// it enumerates -- the same set its dropdown offers -- never an arbitrary
		// basename in its dir.
		$this->assertTrue(
			pfb_validate_filepath('/var/log/pfblockerng/py_error.log', $this->logtypes(), 'clear'),
			'an enumerated defaultlogs basename must be admitted'
		);
		$this->assertFalse(
			pfb_validate_filepath('/var/log/pfblockerng/0af1b2c3-py_error.log', $this->logtypes(), 'clear'),
			'an UNlisted basename under the defaultlogs dir must be rejected (logs-list is a basename whitelist, not a dir grant)'
		);
	}

	// --- issue #1649 (CodeRabbit CWE-863): a no-ext logtype's enumerated 'logs'
	// list must not lend blanket access to unlisted files in a SHARED dir. The
	// dbdir (/var/db/pfblockerng/) holds masterfile/mastercat (masterfiles),
	// pfbalexawhitelist.txt (top1m), and sensitive siblings (asn_cache.sqlite,
	// pfbsuppression.txt, ...). masterfiles is download-capable with no ext, so
	// the pre-fix blanket grant admitted download of ANY of them. -----------------

	public function testDownloadOfArbitraryFileUnderSharedDbdirIsRejected(): void
	{
		$this->assertFalse(
			pfb_validate_filepath('/var/db/pfblockerng/random_unlisted_file.txt', $this->logtypes(), 'download'),
			'download of an unlisted basename under a shared dbdir must be rejected, not admitted via masterfiles\' blanket grant'
		);
	}

	public function testDownloadOfSensitiveSqliteUnderSharedDbdirIsRejected(): void
	{
		// The concrete disclosure: masterfiles' blanket grant used to expose the
		// on-box SQLite caches sitting beside masterfile in the dbdir.
		$this->assertFalse(
			pfb_validate_filepath('/var/db/pfblockerng/asn_cache.sqlite', $this->logtypes(), 'download'),
			'download of asn_cache.sqlite must be rejected: no dbdir logtype enumerates or ext-matches it'
		);
	}

	public function testDownloadOfMastercatUnderSharedDbdirIsAllowed(): void
	{
		// The legit counter: masterfiles' OTHER enumerated file must still work.
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/mastercat', $this->logtypes(), 'download'),
			'download of mastercat must pass: it is one of masterfiles\' enumerated basenames'
		);
	}

	// --- the traversal bound stays exactly as it was ---------------------------

	public function testPathOutsideEveryLogdirIsRejectedForEveryAction(): void
	{
		foreach (['load', 'download', 'clear'] as $action) {
			$this->assertFalse(
				pfb_validate_filepath('/etc/passwd', $this->logtypes(), $action),
				"/etc/passwd must be rejected for action '{$action}': its dir is no logtype's logdir"
			);
		}
	}

	public function testUnboundDirNonPfbFileIsStillRejected(): void
	{
		// The pre-existing /var/unbound/ pfb_-prefix guard is untouched.
		$this->assertFalse(
			pfb_validate_filepath('/var/unbound/root.key', $this->logtypes(), 'download'),
			'a non-pfb_ file under /var/unbound/ must stay rejected by the pre-existing guard'
		);
	}

	public function testUnboundDirPythonLogMatchingExtIsAllowed(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/var/unbound/pfb_py_error.txt', $this->logtypes(), 'download'),
			'a pfb_py*.txt file under /var/unbound/ must pass via the python logtype'
		);
	}
}
