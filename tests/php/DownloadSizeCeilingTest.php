<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2658 — nothing bounded how much a feed could pull down or expand to.
 *
 * These tests pin the two ceilings and the free-space precheck that now guard
 * ingest: the fetched body is capped by libcurl, the extracted output is capped
 * by the kernel through the shell that runs every extractor, and an extraction
 * onto a staging filesystem with no room is refused before it writes anything.
 *
 * pfb_download() itself executes archive tools against appliance paths and is
 * not callable off-appliance (ADR-45 §5), so its interior is pinned the way the
 * rest of the suite pins it: against the comment-free source. The helpers the
 * interior delegates to are exercised directly, including one live /bin/sh run
 * proving the ceiling really does stop a writing child.
 */
final class DownloadSizeCeilingTest extends TestCase
{
	private static string $source;
	private static string $downloadBody;

	private string $dir = '';

	public static function setUpBeforeClass(): void
	{
		self::$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		if (self::$source === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng.inc');
		}
		$start = strpos(self::$source, 'function pfb_download(PfbDownloadRequest $request): PfbDownloadResult {');
		$end   = strpos(self::$source, 'function pfb_download_failure(');
		if ($start === FALSE || $end === FALSE || $end <= $start) {
			throw new RuntimeException('test bootstrap: could not bound the pfb_download() body');
		}
		self::$downloadBody = substr(self::$source, $start, $end - $start);
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_size_ceiling_' . uniqid('', TRUE);
		mkdir($this->dir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
	}

	// -----------------------------------------------------------------------
	// The extraction ceiling
	// -----------------------------------------------------------------------

	/**
	 * Scenario: an extraction command carries the write ceiling
	 *
	 * Given  any extraction command line
	 * When   pfb_extract_cmd() wraps it
	 * Then   the wrapped command lowers the shell's file-size limit to the
	 *        configured block count first, and aborts without running the
	 *        extractor at all if that limit cannot be set (fail closed).
	 */
	public function test_extract_cmd_wraps_the_command_in_the_write_ceiling(): void
	{
		$this->assertSame(
			'ulimit -f ' . PFB_EXTRACT_MAX_BLOCKS . ' || exit 1; /usr/bin/gunzip -c a > b',
			pfb_extract_cmd('/usr/bin/gunzip -c a > b')
		);
	}

	/**
	 * Scenario: the ceiling is settable for tests
	 *
	 * Given  an explicit block count
	 * When   pfb_extract_cmd() wraps a command with it
	 * Then   that count replaces the shipped ceiling, so a test can prove the
	 *        guard fires without writing gigabytes.
	 */
	public function test_extract_cmd_accepts_an_explicit_block_count(): void
	{
		$this->assertSame('ulimit -f 2 || exit 1; /bin/true', pfb_extract_cmd('/bin/true', 2));
	}

	/**
	 * Scenario: the ceiling stops a child that writes past it
	 *
	 * Given  a wrapped command whose ceiling is two blocks and whose child
	 *        writes one MiB
	 * When   the command runs through the same exec() the extraction sites use
	 * Then   the child is killed for exceeding the file-size limit, exec()
	 *        reports the nonzero status the extraction gates already reject,
	 *        and the output stops far short of what was asked for.
	 *
	 * The brace group only silences the shell's own "Filesize limit exceeded"
	 * notice so the suite output stays readable; the wrapped command is verbatim.
	 */
	public function test_extract_cmd_ceiling_kills_a_child_that_writes_past_it(): void
	{
		if (!is_executable('/bin/dd')) {
			$this->markTestSkipped('/bin/dd not available on this host');
		}

		$target = $this->dir . '/overflow.bin';
		$output = [];
		$retval = 0;
		exec(
			'{ ' . pfb_extract_cmd('/bin/dd if=/dev/zero of=' . escapeshellarg($target) . ' bs=1024 count=1024', 2) . '; } 2>/dev/null',
			$output,
			$retval
		);

		$this->assertSame(PFB_EXTRACT_SIGXFSZ_EXIT, $retval,
			'a write past the ceiling must surface as the SIGXFSZ exit status');
		$this->assertFalse(pfb_download_extraction_succeeded($retval),
			'the extraction gates must read the capped run as a failure');
		$this->assertLessThan(1024 * 1024, filesize($target),
			'the ceiling must stop the write, not merely report on it');
	}

	/**
	 * Scenario: a run under the ceiling is untouched
	 *
	 * Given  a wrapped command whose child writes well under the ceiling
	 * When   it runs
	 * Then   it succeeds and its full output is on disk — the guard rejects
	 *        nothing legitimate.
	 */
	public function test_extract_cmd_leaves_a_run_under_the_ceiling_alone(): void
	{
		if (!is_executable('/bin/dd')) {
			$this->markTestSkipped('/bin/dd not available on this host');
		}

		$target = $this->dir . '/small.bin';
		$output = [];
		$retval = 1;
		exec(
			pfb_extract_cmd('/bin/dd if=/dev/zero of=' . escapeshellarg($target) . ' bs=1024 count=1 2>/dev/null'),
			$output,
			$retval
		);

		$this->assertSame(0, $retval);
		$this->assertSame(1024, filesize($target));
	}

	/**
	 * Scenario: a capped extraction is logged as a size refusal
	 *
	 * Given  the exit status a child killed for exceeding the ceiling produces
	 * When   the extraction failure is logged
	 * Then   the line names the ceiling, so an operator reads "too large"
	 *        instead of a bare exit code; every other nonzero status keeps the
	 *        existing wording untouched.
	 */
	public function test_extract_cap_note_names_the_ceiling_only_for_the_capped_exit(): void
	{
		$this->assertStringContainsString('ceiling', pfb_extract_cap_note(PFB_EXTRACT_SIGXFSZ_EXIT));
		foreach ([0, 1, 2, 66, 127, 152, 154] as $retval) {
			$this->assertSame('', pfb_extract_cap_note($retval),
				"exit {$retval} is not a ceiling refusal and must not be labelled one");
		}
	}

	// -----------------------------------------------------------------------
	// The free-space precheck
	// -----------------------------------------------------------------------

	/**
	 * Scenario: a staging filesystem without room refuses the extraction
	 *
	 * Given  two staging directories, the second with less free space than the
	 *        extraction needs
	 * When   the precheck runs
	 * Then   it names that directory, so the caller can refuse before writing.
	 */
	public function test_space_shortfall_names_the_directory_without_room(): void
	{
		$free = static fn (string $dir) => $dir === '/b' ? 1024.0 : 1024.0 * 1024 * 1024;
		$this->assertSame('/b', pfb_extract_space_shortfall(['/a', '/b'], 1024 * 1024, $free));
	}

	/**
	 * Scenario: enough room everywhere
	 *
	 * Given  staging directories that all have at least what the extraction needs
	 * When   the precheck runs
	 * Then   it reports no shortfall — including the exact-fit boundary, which
	 *        is room enough and must not be refused.
	 */
	public function test_space_shortfall_passes_when_every_directory_has_room(): void
	{
		$free = static fn (string $dir) => 1024.0 * 1024;
		$this->assertNull(pfb_extract_space_shortfall(['/a', '/b'], 1024 * 1024, $free));
	}

	/**
	 * Scenario: an unreadable filesystem is not a shortfall
	 *
	 * Given  a directory whose free space cannot be read (statfs failed)
	 * When   the precheck runs
	 * Then   it reports no shortfall: an unreadable filesystem is not evidence
	 *        of a full one, and must never refuse a legitimate feed.
	 */
	public function test_space_shortfall_ignores_a_directory_it_cannot_probe(): void
	{
		$free = static fn (string $dir) => FALSE;
		$this->assertNull(pfb_extract_space_shortfall(['/a'], PHP_INT_MAX, $free));
	}

	/**
	 * Scenario: only real staging directories are probed
	 *
	 * Given  a candidate list carrying an empty entry and a relative one (a feed
	 *        name, not a path)
	 * When   the precheck runs
	 * Then   neither is probed, so a feed named like a path cannot make the
	 *        guard measure the wrong filesystem.
	 */
	public function test_space_shortfall_skips_entries_that_are_not_absolute_paths(): void
	{
		$probed = [];
		$free = static function (string $dir) use (&$probed) {
			$probed[] = $dir;
			return 0.0;
		};
		$this->assertNull(pfb_extract_space_shortfall(['', 'somefeed', '.'], 1, $free));
		$this->assertSame([], $probed);
	}

	/**
	 * Scenario: the precheck measures a real filesystem by default
	 *
	 * Given  no injected probe
	 * When   the precheck runs against a real directory asking for one byte
	 * Then   it reports no shortfall, proving the default probe is wired to the
	 *        filesystem rather than returning a constant.
	 */
	public function test_space_shortfall_default_probe_reads_the_real_filesystem(): void
	{
		$this->assertNull(pfb_extract_space_shortfall([$this->dir], 1));
		$this->assertSame($this->dir, pfb_extract_space_shortfall([$this->dir], PHP_INT_MAX));
	}

	// -----------------------------------------------------------------------
	// The download ceiling
	// -----------------------------------------------------------------------

	/**
	 * Scenario: every feed fetch carries the body ceiling
	 *
	 * Given  the cURL options pfb_download() loads for every feed
	 * When   they are read
	 * Then   the large-variant maximum file size is set to the configured
	 *        ceiling, so an over-large body is refused by libcurl itself.
	 */
	public function test_curl_defaults_carry_the_fetched_body_ceiling(): void
	{
		$defaults = $GLOBALS['pfb']['curl_defaults'] ?? [];
		$this->assertArrayHasKey(CURLOPT_MAXFILESIZE_LARGE, $defaults);
		$this->assertSame(PFB_DOWNLOAD_MAX_BYTES, $defaults[CURLOPT_MAXFILESIZE_LARGE]);
	}

	// -----------------------------------------------------------------------
	// Wiring inside pfb_download()
	// -----------------------------------------------------------------------

	/**
	 * Scenario: no extraction escapes the ceiling
	 *
	 * Given  every exec() pfb_download() makes
	 * When   they are enumerated from the comment-free source
	 * Then   each one either runs under pfb_extract_cmd() or is an allow-listed
	 *        call that writes no archive output. A new extraction site added
	 *        without the ceiling fails here.
	 */
	public function test_every_extraction_exec_runs_under_the_ceiling(): void
	{
		$allowed = [
			// Fetches a feed body; writes no archive output. Its own fetch is bounded
			// by neither ceiling (rsync is not a libcurl transfer) -- issue #2667.
			'exec("/usr/local/bin/rsync',
			// Helper-script calls that post-process an ALREADY-extracted text feed.
			'exec("{$pfb[\'script\']} whoisconvert',
			'exec("{$pfb[\'script\']} asn_table',
			'exec("{$pfb[\'script\']} et ',
			// processxlsx() reports success by the output file existing rather than by
			// an exit status, so a child killed at the ceiling would publish a
			// truncated feed as a success. Capping it needs an exit gate first
			// (issue #2666).
			'exec("{$pfb[\'script\']} xlsx',
			// Lists an archive; extracts nothing.
			'exec("/usr/bin/tar -tf',
			// Capped.
			'exec(pfb_extract_cmd(',
		];

		// curl_exec() is not a shell call -- the lookbehind keeps it out.
		$found = preg_match_all('/(?<![A-Za-z0-9_])exec\(/', self::$downloadBody, $m, PREG_OFFSET_CAPTURE);
		$this->assertNotFalse($found);
		$this->assertNotSame(0, $found, 'the pfb_download() body must contain exec() calls');

		foreach ($m[0] as [, $offset]) {
			$call = substr(self::$downloadBody, $offset, 48);
			$ok = FALSE;
			foreach ($allowed as $prefix) {
				if (str_starts_with($call, $prefix)) {
					$ok = TRUE;
					break;
				}
			}
			$this->assertTrue($ok, "unguarded exec() in pfb_download(): {$call}");
		}
	}

	/**
	 * Scenario: no extraction anywhere in the package escapes the ceiling
	 *
	 * Given  every shipped PHP source file, not just pfb_download()
	 * When   each exec() that drives an extraction tool is enumerated
	 * Then   all of them run under pfb_extract_cmd(). The ingest reuse path in
	 *        pfblockerng_apply.inc is the reason this sweep is tree-wide rather
	 *        than scoped to pfb_download(): an expansion bomb does not care which
	 *        function opened the archive.
	 *
	 * Blind spots, verified absent from src/ today rather than assumed: a command
	 * held in a variable or built by a heredoc, a bare `tar` with no path, and the
	 * other process launchers (passthru/shell_exec/system/proc_open/popen). Any of
	 * those forms would need adding here.
	 */
	public function test_no_extraction_exec_anywhere_in_the_package_is_uncapped(): void
	{
		$root = dirname(__DIR__, 2) . '/src';
		$files = new RegexIterator(
			new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)),
			'/\.(inc|php)$/'
		);

		$seen = 0;
		foreach ($files as $file) {
			$path = $file->getPathname();
			$source = php_strip_whitespace($path);
			// -t/-tf only TEST or LIST an archive; they write nothing.
			if (!preg_match_all(
				'/(?<![A-Za-z0-9_])exec\(\s*(?:pfb_extract_cmd\()?[\'"][^\'"]*(?:gunzip|bzip2|\/tar) -(?!t)/',
				$source, $m, PREG_OFFSET_CAPTURE
			)) {
				continue;
			}
			foreach ($m[0] as [$call, $offset]) {
				$seen++;
				$this->assertStringStartsWith('exec(pfb_extract_cmd(', $call,
					'uncapped extraction in ' . basename($path) . ': ' . substr($source, $offset, 64));
			}
		}
		$this->assertGreaterThan(1, $seen,
			'the sweep must actually find extraction calls — a pattern that matches nothing proves nothing');
	}

	/**
	 * Scenario: an over-large body is refused, not retried
	 *
	 * Given  the download retry loop
	 * When   libcurl reports the maximum file size exceeded
	 * Then   the loop refuses the feed immediately with a named reason rather
	 *        than re-fetching the same over-large body twice more and then
	 *        letting a partial response reach MIME validation.
	 */
	public function test_download_loop_refuses_an_over_large_body_without_retrying(): void
	{
		$this->assertStringContainsString('if ($curl_error === CURLE_FILESIZE_EXCEEDED) {', self::$downloadBody);
		$this->assertStringContainsString(
			"pfb_validate_log(\$header, 'size', 'download_too_large'", self::$downloadBody);
	}

	/**
	 * Scenario: the staging filesystem is checked before anything is written
	 *
	 * Given  a downloaded body about to be decompressed
	 * When   the source is read
	 * Then   the free-space precheck runs ahead of the decompression dispatch,
	 *        so a full filesystem refuses the feed instead of being filled.
	 */
	public function test_free_space_precheck_runs_before_the_decompression_dispatch(): void
	{
		$check    = strpos(self::$downloadBody, 'pfb_extract_space_shortfall(');
		$dispatch = strpos(self::$downloadBody, "if (\$file_type == 'application/x-gzip' || \$file_type == 'application/gzip')");
		$this->assertNotFalse($check, 'pfb_download() must run the free-space precheck');
		$this->assertNotFalse($dispatch);
		$this->assertLessThan($dispatch, $check);
		// Archive types only: a plain text feed extracts nothing, so the guard must not
		// stand between it and its publication.
		$this->assertStringContainsString('if (pfb_archive_probe($file_type) !== NULL) {', self::$downloadBody);
		// The requirement is the archive's own size and no fixed floor -- /var is a
		// 60 MiB RAM disk on a default use_mfs_tmpvar install.
		$this->assertStringContainsString(
			'pfb_extract_space_shortfall($extract_dirs, (int) @filesize($file_download))', self::$downloadBody);
	}
}
