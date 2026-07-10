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

		// Master list: a dot-less line ('com'), two dotted lines ('co.om',
		// 'com.ac') and hostile rows (blank, trailing-dot-only, control-char
		// only) that must never seed a bucket either way.
		file_put_contents(
			$pfb['dnsbl_tld_data'],
			"com\nco.om\ncom.ac\n\nbad.\n.\n\x01\n"
		);

		file_put_contents(
			"{$pfb['dnsbl_file']}.raw",
			",example-1068.test,,1,PlainFeed,GroupA\n"
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
	 * Given:  a master list with a dot-less 'com' line, dotted siblings
	 *         ('co.om', 'com.ac'), and hostile rows that carry no usable TLD
	 * When:   tld_analysis() loads the master list into $tlds
	 * Then:   'com' is keyed under its own full value, not truncated to 'om';
	 *         'co.om' keys under 'om' alone (no 'com' pollution); the dotted
	 *         'com.ac' line still keys under 'ac'; the hostile rows seed no
	 *         bucket; and the loader itself raises no diagnostic
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

		// R3: dotted-line regression pin -- 'com.ac' keys under 'ac' either way.
		$this->assertTrue(
			isset($tlds['ac']['com.ac']),
			"'com.ac' must key under 'ac'; got tlds: " . var_export($tlds, TRUE)
		);

		// R4: hostile rows (blank, 'bad.', '.', control-char-only) seed no bucket.
		$keys = array_keys($tlds);
		sort($keys);
		$this->assertSame(
			array('ac', 'com', 'om'),
			$keys,
			'hostile master-list rows must not create extra buckets; got: ' . var_export($keys, TRUE)
		);

		// R5: diagnostic hygiene -- the loader itself raises no PHP warnings.
		// dnsbl_save_stats()/rmdir_recursive() warn on this dev/CI box (no
		// 'unbound' system user, tmpdir not pre-created) -- unrelated to the
		// loader; filtered so a real loader regression still fails this row.
		$isKnownNonLoaderNoise = static function (string $w): bool {
			return str_starts_with($w, 'chown(): Unable to find uid for unbound')
				|| str_starts_with($w, 'chgrp(): Unable to find gid for unbound')
				|| (str_starts_with($w, 'unlink(') && str_contains($w, 'No such file or directory'));
		};
		$loaderWarnings = array_values(array_filter($warnings, static fn (string $w): bool => !$isKnownNonLoaderNoise($w)));
		$this->assertSame(
			[],
			$loaderWarnings,
			'master-list loader must raise no diagnostics; got: ' . var_export($loaderWarnings, TRUE)
		);
	}
}
