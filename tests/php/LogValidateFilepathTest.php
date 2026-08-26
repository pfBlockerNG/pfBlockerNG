<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfb_validate_filepath() authorizes per-logtype, never on the dir-union (issue #1649).
 *
 * The defect: the validator admitted any file whose dirname was ANY logtype's
 * logdir, ignoring each logtype's own 'ext' filename whitelist and its
 * 'clear'/'download' capability flags. '/usr/local/pkg/pfblockerng/' is a
 * whitelisted logdir (dnsbl_psl / dnsbl_safe, both clear => FALSE), so a holder
 * of the grantable WebCfg pfBlockerNG privilege could clear= (unlink) or
 * download= (read) package source such as pfblockerng.inc.
 *
 * Intent pinned here: a request is authorized only when SOME logtype's whole
 * tuple authorizes it -- its logdir matches the file's directory, the requested
 * action's capability flag is enabled for that logtype, and the filename matches
 * that logtype's exact 'logs' basename or 'ext' whitelist (glob "*<ext>",
 * mirroring getlogs()). Live Tier-B flows use only the inactive listed wizard.log;
 * clear-shape coverage for active log basenames stays hermetic below.
 */
final class LogValidateFilepathTest extends TestCase
{
	private string $tmpDir;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/LogPageLoader.php';
		pfb_test_load_log_page_functions();
	}

	protected function setUp(): void
	{
		$this->tmpDir = sys_get_temp_dir() . '/pfb_log_clear_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->tmpDir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->tmpDir . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->tmpDir);
	}

	private function tempLog(string $basename): string
	{
		return $this->tmpDir . '/' . $basename;
	}

	/**
	 * A $pfb_logtypes fixture mirroring the real page's entries for every shape
	 * involved: inline 'logs' lists, scalar ('txt', '.*', '*') and array 'ext',
	 * glob patterns, the shared-package-dir pair (both clear => FALSE), and two
	 * logtypes sharing one logdir with opposite clear flags (masterfiles vs top1m).
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
			'dnsbl_psl' => [
				'logdir'   => '/usr/local/pkg/pfblockerng/',
				'ext'      => ['dnsbl_psl'],
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
			// The page's scalar-'ext' shapes, which outnumber the array ones:
			// denylogs ('txt'), etiprep ('.*') and the dynamically appended DNSBL
			// category feeds ('*'). They reach the same (array) cast, so a fixture
			// of arrays alone leaves the dominant production shape unexercised.
			'denylogs' => [
				'logdir'   => '/var/db/pfblockerng/deny/',
				'ext'      => 'txt',
				'download' => TRUE,
				'clear'    => TRUE,
			],
			'etiprep' => [
				'logdir'   => '/var/db/pfblockerng/et/',
				'ext'      => '.*',
				'download' => TRUE,
				'clear'    => FALSE,
			],
			'feedlogs' => [
				'logdir'   => '/var/db/pfblockerng/feed/',
				'ext'      => '*',
				'download' => TRUE,
				'clear'    => FALSE,
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

	public function testClearOfDnsblPslFileIsRejectedBecauseItsLogtypeForbidsClear(): void
	{
		// The file itself IS the dnsbl_psl logtype's own file (download works,
		// below) -- but that logtype carries clear => FALSE.
		$this->assertFalse(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/dnsbl_psl', $this->logtypes(), 'clear'),
			'clear of dnsbl_psl must be rejected: its logtype has clear => FALSE'
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

	public function testDownloadOfDnsblPslFileIsAllowedByItsOwnLogtype(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/dnsbl_psl', $this->logtypes(), 'download'),
			'download of dnsbl_psl must pass: its own logtype matches and allows download'
		);
	}

	public function testDownloadOfDenyFileIsAllowedByItsScalarExt(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/deny/pfb_deny.txt', $this->logtypes(), 'download'),
			'download of a deny .txt file must pass: denylogs carries the scalar ext "txt"'
		);
	}

	public function testDownloadUnderAScalarExtLogdirStillHonoursThatExt(): void
	{
		// Same logdir as denylogs, but the file matches no "*txt" pattern: the
		// scalar shape must whitelist by extension, never by directory alone.
		$this->assertFalse(
			pfb_validate_filepath('/var/db/pfblockerng/deny/pfb_deny.conf', $this->logtypes(), 'download'),
			'download of a .conf under the deny logdir must be rejected by the scalar ext "txt"'
		);
	}

	public function testDownloadUnderTheDotStarExtRequiresADot(): void
	{
		// etiprep's '.*' becomes fnmatch("*.*", ...), so a dotless name misses.
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/et/rep.list', $this->logtypes(), 'download'),
			'download of a dotted etiprep file must pass its ".*" ext'
		);
		$this->assertFalse(
			pfb_validate_filepath('/var/db/pfblockerng/et/dotless', $this->logtypes(), 'download'),
			'download of a dotless etiprep file must be rejected by the ".*" ext'
		);
	}

	public function testDownloadUnderTheStarExtAcceptsAnyNameInThatLogdirOnly(): void
	{
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/feed/anything', $this->logtypes(), 'download'),
			'download of any file in a category-feed logdir must pass its "*" ext'
		);
		$this->assertFalse(
			pfb_validate_filepath('/var/db/pfblockerng/feed/sub/anything', $this->logtypes(), 'download'),
			'a "*" ext must not reach below its own logdir'
		);
	}

	public function testLoadIsAllowedRegardlessOfTheClearAndDownloadFlags(): void
	{
		// 'load' has no capability flag of its own: matching the logtype's file
		// whitelist is the whole gate, even where clear => FALSE.
		$this->assertTrue(
			pfb_validate_filepath('/var/db/pfblockerng/et/rep.list', $this->logtypes(), 'load'),
			'load must pass on etiprep despite clear => FALSE: load carries no flag'
		);
		$this->assertTrue(
			pfb_validate_filepath('/usr/local/pkg/pfblockerng/dnsbl_psl', $this->logtypes(), 'load'),
			'load must pass on dnsbl_psl despite clear => FALSE: load carries no flag'
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

	// A no-ext logtype's enumerated 'logs'
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

	// Clear behavior is hermetic here; Tier-B smoke coverage stays read-only on active logs.
	public function testClearOfPlainLogUnlinksIt(): void
	{
		$path = $this->tempLog('ip_block.log');
		file_put_contents($path, "plain\n");
		$this->assertFileExists($path, 'plain log must exist before clear');
		$this->assertGreaterThan(0, filesize($path), 'plain log must be non-empty before clear');

		pfb_clear_logfile($path);

		$this->assertFileDoesNotExist($path, 'plain log clear must unlink the file');
	}

	public function testClearOfNonemptyPyErrorLogTruncatesInPlace(): void
	{
		$path = $this->tempLog('py_error.log');
		file_put_contents($path, "python error\n");
		$inode = fileinode($path);
		$this->assertFileExists($path, 'py_error.log must exist before clear');
		$this->assertGreaterThan(0, filesize($path), 'py_error.log must be non-empty before clear');

		pfb_clear_logfile($path);

		$this->assertFileExists($path, 'py_error.log clear must keep the file');
		$this->assertSame(0, filesize($path), 'py_error.log clear must truncate to zero bytes');
		$this->assertSame($inode, fileinode($path), 'py_error.log clear must truncate in place');
	}

	public function testClearOfAbsentPyErrorLogDoesNotCreateOrFatal(): void
	{
		$path = $this->tempLog('py_error.log');
		$this->assertFileDoesNotExist($path, 'py_error.log must be absent before clear');

		pfb_clear_logfile($path);

		$this->assertFileDoesNotExist($path, 'clearing an absent py_error.log must remain a no-op');
	}

	public function testClearOfDnsblLogRetouchesEmptyFile(): void
	{
		$path = $this->tempLog('dnsbl.log');
		file_put_contents($path, "dnsbl\n");
		$this->assertFileExists($path, 'dnsbl.log must exist before clear');
		$this->assertGreaterThan(0, filesize($path), 'dnsbl.log must be non-empty before clear');

		pfb_clear_logfile($path);

		$this->assertFileExists($path, 'dnsbl.log clear must retouch the file');
		$this->assertSame(0, filesize($path), 'dnsbl.log clear must leave an empty file');
	}
}
