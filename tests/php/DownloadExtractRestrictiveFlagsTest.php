<?php

declare(strict_types=1);

require_once __DIR__ . '/StagedDirFixtureTrait.php';

use PHPUnit\Framework\TestCase;

/**
 * issue #2659: extraction runs as root, and the disk-writing tar calls restored
 * whatever the archive asked for -- ownership, permission bits, extended
 * attributes, ACLs and file flags -- into staging trees whose contents are only
 * scraped for tokens and then deleted or swapped into place.
 *
 * Two independent kinds of proof live here, because either alone is weak:
 *
 *  - The source sweeps pin WHICH call sites carry the flag set. They run on every
 *    platform, so a site that loses the flags, or a stdout call that gains them,
 *    fails here whatever tar the host ships.
 *  - The executed case proves the flag set actually STRIPS what an archive
 *    carries. That is a property of tar, not of the argv, and no source pin can
 *    establish it.
 *
 * The executed case is paired with a control extraction that omits the flags: on
 * a host whose tar restores nothing by default (GNU tar carries no xattrs, ACLs
 * or file flags unless asked, and an unprivileged extraction cannot chown), the
 * assertion would pass with the flags removed, so the case skips rather than
 * reporting vacuous coverage. The privileged full-vector proof runs on the
 * appliance in tests/smoke/test_smoke_feeds.py.
 */
final class DownloadExtractRestrictiveFlagsTest extends TestCase
{
	use StagedDirFixtureTrait;

	/** Comment-free source of every shipped PHP file, keyed by path. */
	private static array $sources = array();

	private string $dir = '';

	public static function setUpBeforeClass(): void
	{
		$root = dirname(__DIR__, 2) . '/src';
		$files = new RegexIterator(
			new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)),
			'/\.(inc|php)$/'
		);
		foreach ($files as $file) {
			self::$sources[$file->getPathname()] = php_strip_whitespace($file->getPathname());
		}
		if (self::$sources === array()) {
			throw new RuntimeException('test bootstrap: no shipped PHP sources found');
		}
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_extract_flags_' . getmypid()
			. '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir("{$this->dir}/build", 0755, TRUE));
	}

	protected function tearDown(): void
	{
		// A fixture deliberately carries an immutable file flag; clear it so the
		// tree can be removed whatever the extraction restored.
		if (is_executable('/bin/chflags')) {
			exec('/bin/chflags -R 0 ' . escapeshellarg($this->dir) . ' 2>/dev/null');
		}
		$this->removeTree($this->dir);
	}

	/**
	 * Every `/usr/bin/tar -x…` extraction in the shipped sources, as
	 * [file, option cluster, statement].
	 *
	 * The statement is cut at the `$retval);` every one of these exec() calls
	 * ends with rather than at a fixed width: a fixed window would run past the
	 * end of a short call and read the NEXT call site's flags, which is exactly
	 * the confusion these sweeps exist to catch.
	 *
	 * @return list<array{string, string, string}>
	 */
	private function tarExtractions(): array
	{
		$found = array();
		foreach (self::$sources as $path => $source) {
			if (!preg_match_all('#(?:/usr/bin/tar|\{\$tar_bin\}) -x([a-zA-Z]*)f#', $source, $m, PREG_OFFSET_CAPTURE)) {
				continue;
			}
			foreach ($m[0] as $i => [$call, $offset]) {
				$start = (int) $offset;
				$end = strpos($source, '$retval);', $start);
				$this->assertNotFalse($end,
					'extraction with no exec() result argument in ' . basename($path) . ": {$call}");
				$found[] = array(basename($path), (string) $m[1][$i][0],
					substr($source, $start, (int) $end - $start));
			}
		}
		return $found;
	}

	/**
	 * Scenario: the flag set names every restriction the issue asked for
	 *
	 * Given  the shipped extraction flag set
	 * When   it is read
	 * Then   it is exactly the six restrictions, so dropping one -- --no-fflags
	 *        is the one whose loss no unprivileged behavioural run can see --
	 *        fails here.
	 *
	 * The appliance ships FreeBSD bsdtar, which accepts all six. GNU tar 1.35
	 * rejects --no-fflags outright (exit 64), which is why the executed case
	 * below refuses to run the set on a tar that cannot author the fixture.
	 */
	public function test_the_flag_set_pins_every_restriction(): void
	{
		$this->assertSame(
			'--no-same-owner --no-same-permissions --numeric-owner --no-xattrs --no-acls --no-fflags',
			PFB_TAR_EXTRACT_FLAGS,
			'the disk-writing extractions must refuse owner, mode, xattr, ACL and file-flag restoration'
		);
	}

	/**
	 * Scenario: no disk-writing extraction escapes the flag set
	 *
	 * Given  every tar extraction in the shipped sources
	 * When   the ones that write named files are enumerated from the
	 *        comment-free source
	 * Then   each one carries the flag set, AFTER the archive operand. A new
	 *        disk-writing site added without the flags fails here, so does a site
	 *        that loses them, and so does one that puts them where -f's own
	 *        operand would swallow the first of them as the archive name.
	 *
	 * The five are the GeoIP share extract (gzip and x-tar containers share it),
	 * the Blacklist category extracts on the gzip and x-tar arms, and the zip
	 * arm's GeoIP and top-1M extracts. #2638's x-tar arm is the fifth: the issue
	 * predicted it as future work, and it landed first.
	 */
	public function test_every_disk_writing_tar_extraction_carries_the_flag_set(): void
	{
		$seen = 0;
		foreach ($this->tarExtractions() as [$file, $options, $statement]) {
			if (str_contains($options, 'O')) {
				continue;
			}
			$seen++;
			$this->assertStringContainsString('PFB_TAR_EXTRACT_FLAGS', $statement,
				"disk-writing extraction without the flag set in {$file}: {$statement}");
			// -f takes the NEXT argument as the archive, so everything between the
			// mode word and the flags must be the archive operand -- interpolated
			// or escaped, never just the concatenation punctuation a misplaced
			// flag set leaves behind.
			$operand = substr($statement, 0, (int) strpos($statement, 'PFB_TAR_EXTRACT_FLAGS'));
			$this->assertTrue(
				str_contains($operand, 'escapeshellarg(') || str_contains($operand, '{$'),
				"the flag set must follow the archive operand, not sit between -f and it, in {$file}: {$statement}"
			);
		}
		$this->assertSame(5, $seen,
			'the five disk-writing extractions are the whole class; a sixth must be added here deliberately');
	}

	/**
	 * Scenario: the stdout extractions are left alone
	 *
	 * Given  the tar calls that write to stdout rather than to named files
	 * When   they are enumerated
	 * Then   none of them carries the flag set: they create no directory entry
	 *        for metadata to be restored onto, and the shell redirect that
	 *        captures them already owns the mode of the file it creates.
	 *
	 * Without this, moving the flags onto a -xO call would look like a fix.
	 */
	public function test_the_stdout_extractions_stay_unflagged(): void
	{
		$seen = 0;
		foreach ($this->tarExtractions() as [$file, $options, $statement]) {
			if (!str_contains($options, 'O')) {
				continue;
			}
			$seen++;
			$this->assertStringNotContainsString('PFB_TAR_EXTRACT_FLAGS', $statement,
				"stdout extraction carrying disk-extraction flags in {$file}: {$statement}");
		}
		$this->assertSame(7, $seen,
			'the seven stdout extractions are the whole class; the sweep must not silently match none');
	}

	/**
	 * Scenario: nothing the archive carries survives into the staging tree
	 *
	 * Given  an archive whose member claims a foreign owner, a setuid mode, an
	 *        extended attribute and an immutable file flag
	 * When   the shipped flag set extracts it, in the shipped argument order
	 * Then   none of that metadata is on the extracted file
	 * And    the same extraction WITHOUT the flag set carries at least one of
	 *        them, so the assertion above cannot pass by testing a tar that
	 *        restores nothing in the first place.
	 */
	public function test_the_flag_set_strips_what_the_archive_carries(): void
	{
		$archive = $this->buildForeignArchive();
		$control = $this->extractWith($archive, 'control', '');
		$shipped = $this->extractWith($archive, 'shipped', ' ' . PFB_TAR_EXTRACT_FLAGS);

		$carried = $this->survivingMetadata($control);
		if ($carried === array()) {
			$this->markTestSkipped(
				'this host\'s tar (' . $this->tarVersion() . ') restored none of the fixture metadata even '
				. 'without the flag set as uid ' . getmyuid() . ', so the flagged run proves nothing here; '
				. 'the privileged proof runs on the appliance'
			);
		}

		$this->assertSame(array(), $this->survivingMetadata($shipped),
			'the flag set left archive-supplied metadata on the staged file, which the unflagged control '
			. 'carried as: ' . implode(', ', $carried));
	}

	/** First line of the extracting tar's version, for failure and skip messages. */
	private function tarVersion(): string
	{
		$output = array();
		$retval = 1;
		exec(escapeshellcmd(pfb_test_tar()) . ' --version 2>&1', $output, $retval);
		return $retval === 0 && $output !== array() ? trim((string) $output[0]) : 'unknown tar';
	}

	/**
	 * An archive whose single member claims metadata no staging tree should ever
	 * receive. Everything is authored WITHOUT privilege: the foreign owner comes
	 * from tar's own header-override options, and the mode, attribute and flag
	 * are set on a file this process owns.
	 *
	 * A tar that cannot author the fixture cannot extract the shipped flag set
	 * either (GNU tar rejects both --uid and --no-fflags), so the case skips
	 * there instead of failing on the host's tar rather than on the code.
	 */
	private function buildForeignArchive(): string
	{
		$member = "{$this->dir}/build/member.dat";
		$this->assertNotFalse(file_put_contents($member, "203.0.113.11\n"));
		$this->assertTrue(chmod($member, 04755));
		$escaped = escapeshellarg($member);
		// Best-effort: each of these exists on a different subset of hosts, and
		// the control extraction is what decides whether any of them took.
		exec("/usr/bin/xattr -w user.pfb2659 carried {$escaped} 2>/dev/null");
		exec("/usr/sbin/setextattr user pfb2659 carried {$escaped} 2>/dev/null");
		exec("/bin/chmod +a 'everyone allow read' {$escaped} 2>/dev/null");
		exec("/bin/chflags uchg {$escaped} 2>/dev/null");

		$archive = "{$this->dir}/foreign.tar";
		$output = array();
		$retval = 1;
		exec(escapeshellcmd(pfb_test_tar()) . ' -cf ' . escapeshellarg($archive)
			. ' --uid 12345 --gid 12345 --uname pfbfake --gname pfbfake -C '
			. escapeshellarg("{$this->dir}/build") . ' member.dat 2>/dev/null', $output, $retval);
		if ($retval !== 0) {
			$this->markTestSkipped(
				'this host\'s tar (' . $this->tarVersion() . ') cannot author a foreign-owner fixture, '
				. 'so it cannot run the shipped flag set either'
			);
		}
		return $archive;
	}

	/**
	 * Extract $archive into a fresh directory in the shipped argument order --
	 * flags after the archive operand, where -f's own operand cannot swallow
	 * them -- and return the extracted member's path.
	 */
	private function extractWith(string $archive, string $into, string $flags): string
	{
		$target = "{$this->dir}/{$into}";
		$this->assertTrue(mkdir($target, 0755));
		$output = array();
		$retval = 1;
		exec(pfb_extract_cmd(escapeshellcmd(pfb_test_tar()) . ' -xf ' . escapeshellarg($archive) . $flags . ' -C '
			. escapeshellarg($target) . ' 2>&1'), $output, $retval);
		$this->assertSame(0, $retval,
			"extraction with '{$flags}' failed on " . $this->tarVersion() . ': ' . implode(' ', $output));
		$member = "{$target}/member.dat";
		$this->assertFileExists($member);
		return $member;
	}

	/**
	 * The archive-supplied metadata still on $path.
	 *
	 * Extended attributes, ACLs and file flags are read by re-archiving the file
	 * with the same tar and looking for the pax keywords that carry them: that
	 * needs no per-platform attribute tool, and it reads exactly what the next
	 * tar would carry onward. Only the fixture's own attribute name counts --
	 * macOS stamps com.apple.provenance onto every file it creates, and an
	 * attribute the extraction did not restore is not a finding.
	 *
	 * @return list<string>
	 */
	private function survivingMetadata(string $path): array
	{
		clearstatcache(TRUE, $path);
		$carried = array();
		if (fileowner($path) !== getmyuid()) {
			$carried[] = 'owner';
		}
		if ((fileperms($path) & 04000) !== 0) {
			$carried[] = 'setuid';
		}
		$repacked = $this->repack($path);
		foreach (array('fflags' => 'SCHILY.fflags', 'xattr' => 'pfb2659', 'acl' => 'acl') as $vector => $needle) {
			if (stripos($repacked, $needle) !== FALSE) {
				$carried[] = $vector;
			}
		}
		return $carried;
	}

	/** $path as a fresh archive's raw bytes, metadata keywords included. */
	private function repack(string $path): string
	{
		$probe = "{$this->dir}/repack_" . basename(dirname($path)) . '.tar';
		$output = array();
		$retval = 1;
		exec(escapeshellcmd(pfb_test_tar()) . ' -cf ' . escapeshellarg($probe) . ' -C ' . escapeshellarg(dirname($path))
			. ' ' . escapeshellarg(basename($path)) . ' 2>/dev/null', $output, $retval);
		$this->assertSame(0, $retval, 'the extracted file must be re-archivable for its metadata to be read');
		$bytes = file_get_contents($probe);
		$this->assertNotFalse($bytes);
		return (string) $bytes;
	}
}
