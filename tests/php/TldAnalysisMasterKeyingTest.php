<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * tld_analysis() — master-list loader bucket keying.
 *
 * Issue #1068: `strrpos($line, '.')` returns FALSE on a dot-less line;
 * FALSE + 1 coerces to 1, so `substr($line, 1)` drops the first char and
 * buckets the line under the wrong TLD key (e.g. 'com' lands in 'om').
 */
#[CoversFunction('tld_analysis')]
final class TldAnalysisMasterKeyingTest extends TestCase
{
	private string $tmpDir;

	/** Saved bootstrap globals, restored in tearDown (issue #1063 hygiene). */
	private mixed $savedPfb  = null;
	private mixed $savedTlds = null;

	protected function setUp(): void
	{
		global $pfb, $tlds;

		$this->savedPfb  = $pfb ?? null;
		$this->savedTlds = $tlds ?? null;

		$this->tmpDir = sys_get_temp_dir() . '/pfb_tld_keying_' . getmypid() . '_' . mt_rand();
		mkdir($this->tmpDir, 0700, TRUE);
		mkdir("{$this->tmpDir}/dnsdir", 0700, TRUE);

		$tlds = array();
		$pfb['dnsbl_file']	= "{$this->tmpDir}/pfb_dnsbl";
		$pfb['dnsbl_tld_data']	= "{$this->tmpDir}/tld_master";
		$pfb['unbound_py_data']	= "{$this->tmpDir}/pfb_py_data";
		$pfb['unbound_py_zone']	= "{$this->tmpDir}/pfb_py_zone";
		$pfb['dnsdir']		= "{$this->tmpDir}/dnsdir";
		$pfb['dnsbl_tmpdir']	= "{$this->tmpDir}/tmpdir";
		$pfb['dnsbl_tld_txt']	= "{$this->tmpDir}/dnsbl_tld.txt";
		$pfb['dnsbl_tmp']	= "{$this->tmpDir}/dnsbl_tmp";
		$pfb['dnsbl_info']	= "{$this->tmpDir}/dnsbl_info.db";
		$pfb['errlog']		= "{$this->tmpDir}/error.log";
		$pfb['log']		= "{$this->tmpDir}/pfblockerng.log";
		$pfb['domain_max_cnt']	= 100000;
		$pfb['sqlite_timeout']	= 5000;
		$pfb['dnsblconfig']	= array('tldblacklist' => '', 'tldexclusion' => '');
		$pfb['dnsbl_info_stats'] = array();
		$pfb['alias_dnsbl_all']	= array();
		$pfb['tld_update']	= array();

		// Master list: dot-less lines ('com', punycode 'xn--80ak6aa92e'), two
		// dotted lines ('co.om', 'com.ac'), a leading-whitespace real content
		// line (trimmed and keyed clean, not the raw padded value), whitespace-
		// only lines (single space AND tab-mixed) and comment lines (bare and
		// leading-whitespace -- all SKIPPED, issue #1116's Python-mirror
		// contract), a bare '0' TLD and a dotted-to-'0' line (both KEPT -- the
		// !empty() footgun fix), and hostile rows (blank, trailing-dot-only,
		// control-char only) that must never seed a bucket.
		file_put_contents(
			$pfb['dnsbl_tld_data'],
			"com\nco.om\ncom.ac\nxn--80ak6aa92e\n \n\nbad.\n.\n\x01\n"
			. "# comment\n  # leading space comment\n0\nexample.0\n"
			. "\t \t\n indented.example.com\n"
		);

		file_put_contents(
			"{$pfb['dnsbl_file']}.raw",
			pfb_dnsbl_ndjson_emit_domain_row('example-1068.test', '1', 'PlainFeed', 'GroupA')
		);
	}

	protected function tearDown(): void
	{
		global $pfb, $tlds;

		$pfb  = $this->savedPfb;
		$tlds = $this->savedTlds;

		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->tmpDir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($files as $f) {
			$f->isDir() ? rmdir((string) $f) : unlink((string) $f);
		}
		rmdir($this->tmpDir);
	}

	/**
	 * Run tld_analysis() collecting every PHP diagnostic it raises (mirrors
	 * TldAnalysisAbpVerbatimTest's collector): callers assert on the list.
	 *
	 * @return list<string>
	 */
	private function runTldAnalysis(): array
	{
		$warnings = [];
		set_error_handler(
			static function (int $errno, string $errstr) use (&$warnings): bool {
				$warnings[] = $errstr;
				return TRUE;
			}
		);
		try {
			tld_analysis();
		} finally {
			restore_error_handler();
		}
		return $warnings;
	}

	/**
	 * Scenario: the master-list loader buckets a dot-less line.
	 *
	 * Given:  a master list with dot-less lines ('com', punycode
	 *         'xn--80ak6aa92e'), dotted siblings ('co.om', 'com.ac'), a
	 *         leading-whitespace real content line, comment lines, whitespace-
	 *         only lines (space and tab-mixed), a bare '0' TLD, a dotted-to-'0'
	 *         line, and hostile rows that carry no usable TLD
	 * When:   tld_analysis() loads the master list into $tlds
	 * Then:   each dot-less line is keyed under its own full value, not
	 *         truncated ('com' not 'om'); 'co.om' keys under 'om' alone (no
	 *         'com' pollution); the dotted 'com.ac' line still keys under
	 *         'ac'; leading whitespace on real content is trimmed before
	 *         keying; comment and whitespace-only lines seed no bucket; a bare
	 *         '0' line and a dotted-to-'0' line both key under '0' (the
	 *         !empty() footgun fix); the remaining zero-TLD hostile rows seed
	 *         no bucket; and the loader itself raises no diagnostic
	 */
	public function testDotLessMasterLineKeysUnderItsOwnFullValue(): void
	{
		global $tlds;

		$warnings = $this->runTldAnalysis();

		// R1: 'com' must sit under its own bucket, not FALSE+1-truncated 'om'.
		$this->assertTrue(
			isset($tlds['com']['com']),
			"'com' must key under 'com'; got tlds: " . var_export($tlds, TRUE)
		);

		// R2: 'om' holds only the dotted 'co.om' sibling -- no 'com' pollution.
		$this->assertSame(
			array('co.om' => ''),
			$tlds['om'] ?? NULL,
			"'om' bucket must hold only 'co.om'; got: " . var_export($tlds['om'] ?? NULL, TRUE)
		);

		// R2b: leading whitespace on a real content line is trimmed BEFORE
		// keying -- ' indented.example.com' keys as the clean, unpadded value.
		$this->assertTrue(
			isset($tlds['com']['indented.example.com']),
			"leading whitespace must be trimmed before keying; got tlds['com']: "
				. var_export($tlds['com'] ?? NULL, TRUE)
		);

		// R3: dotted-line regression pin -- 'com.ac' keys under 'ac' either way.
		$this->assertTrue(
			isset($tlds['ac']['com.ac']),
			"'com.ac' must key under 'ac'; got tlds: " . var_export($tlds, TRUE)
		);

		// R4a: the dot-less punycode label keys under its own full value too
		// (same loader branch as 'com' -- documents the IDN class).
		$this->assertTrue(
			isset($tlds['xn--80ak6aa92e']['xn--80ak6aa92e']),
			"'xn--80ak6aa92e' must key under its own full value; got tlds: " . var_export($tlds, TRUE)
		);

		// R4b: a whitespace-only line is SKIPPED (Python-mirror `.strip()`
		// contract, issue #1116) -- it must seed no bucket at all. Covers both
		// a single space and a tab-mixed line (CLAUDE.md hostile-input class).
		$this->assertArrayNotHasKey(
			' ',
			$tlds,
			'a whitespace-only line must not seed a bucket; got: ' . var_export($tlds[' '] ?? NULL, TRUE)
		);
		$this->assertArrayNotHasKey(
			"\t \t",
			$tlds,
			'a tab-mixed whitespace-only line must not seed a bucket; got: '
				. var_export($tlds["\t \t"] ?? NULL, TRUE)
		);

		// R4c: zero-TLD rows (blank, 'bad.', '.', control-char-only, and both
		// comment lines) seed no bucket; exact keyset pins the whole load.
		// Note: PHP normalises the canonical-integer string key '0' to int 0.
		$keys = array_keys($tlds);
		sort($keys);
		$this->assertSame(
			array(0, 'ac', 'com', 'om', 'xn--80ak6aa92e'),
			$keys,
			'hostile master-list rows must not create extra buckets; got: ' . var_export($keys, TRUE)
		);

		// R6: the !empty("0") footgun -- a bare '0' line AND a dotted line
		// whose suffix is '0' (e.g. 'example.0') both bucket under key '0'
		// (int 0 per PHP's numeric-string key normalisation).
		$this->assertSame(
			array(0 => '', 'example.0' => ''),
			$tlds['0'] ?? NULL,
			"'0' bucket must hold the bare '0' line and 'example.0'; got: " . var_export($tlds['0'] ?? NULL, TRUE)
		);

		// R5: diagnostic hygiene -- the loader itself raises no PHP warnings.
		// dnsbl_save_stats()/rmdir_recursive() warn on this dev/CI box (no
		// 'unbound' system user, tmpdir not pre-created) -- unrelated to the
		// loader; filtered so a real loader regression still fails this row.
		$tmpDir = $this->tmpDir;
		$isKnownNonLoaderNoise = static function (string $w) use ($tmpDir): bool {
			return str_starts_with($w, 'chown(): Unable to find uid for unbound')
				|| str_starts_with($w, 'chgrp(): Unable to find gid for unbound')
				|| (str_starts_with($w, 'unlink(') && str_contains($w, $tmpDir)
					&& str_contains($w, 'No such file or directory'));
		};
		$loaderWarnings = array_values(array_filter($warnings, static fn (string $w): bool => !$isKnownNonLoaderNoise($w)));
		$this->assertSame(
			[],
			$loaderWarnings,
			'master-list loader must raise no diagnostics; got: ' . var_export($loaderWarnings, TRUE)
		);
	}
}
