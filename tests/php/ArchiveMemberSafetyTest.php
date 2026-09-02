<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-46: the archive member-name guard that runs before every disk-writing
 * `tar ... -C` extraction in pfb_download(). pfb_archive_unsafe_member() returns
 * the FIRST member name unsafe to extract to disk (absolute path, a '..' path
 * component, a component over 255 bytes = FreeBSD NAME_MAX, or a total name over
 * 1024 bytes = PATH_MAX), a fail-closed sentinel for a NULL (unlistable) list, or
 * NULL when all are safe. Pure -- the full hostile/benign matrix is pinned
 * off-appliance. pfb_archive_member_names() is the thin lister the call sites feed
 * it from -- `unzip -Z1` for application/zip, `tar -tf` for every other container
 * (issue #3068) -- and it returns NULL on a listing failure (rc != 0) so a caller
 * fails closed, and it must NOT drop a member merely because its name begins with
 * "tar: " (stderr is discarded, never merged into the member list).
 */
#[CoversFunction('pfb_archive_unsafe_member')]
#[CoversFunction('pfb_archive_member_names')]
final class ArchiveMemberSafetyTest extends TestCase
{
	// --- pure decision matrix ------------------------------------------------

	/** @return array<string, array{0: list<string>, 1: ?string}> */
	public static function memberMatrix(): array
	{
		$longComponent = str_repeat('a', 256);           // NAME_MAX is 255
		$okComponent   = str_repeat('a', 255);
		// 5x200 'b' + 100 'c' + 5 separators = 1105 bytes total (> PATH_MAX 1024),
		// while every individual component stays legal (<= 255) -- isolates the
		// total-length cap from the per-component cap.
		$longPath = implode('/', array_fill(0, 5, str_repeat('b', 200))) . '/' . str_repeat('c', 100);

		return [
			'benign flat file'            => [['GeoLite2-Country.mmdb'], null],
			'benign nested path'          => [['GeoLite2/GeoLite2-Country.mmdb'], null],
			'benign deep nesting'         => [['a/b/c/d/e/domains'], null],
			'benign dot-prefixed name'    => [['.hidden', 'dir/.also.hidden'], null],
			'benign dot-dot inside name'  => [['weird..name', 'dir/file..txt'], null],
			'benign 255-byte component'   => [[$okComponent], null],
			'empty list'                  => [[], null],
			'absolute path'               => [['/etc/passwd'], '/etc/passwd'],
			'dot-dot escape at start'     => [['../../../etc/passwd'], '../../../etc/passwd'],
			'dot-dot escape mid-path'     => [['safe/../../escape'], 'safe/../../escape'],
			'bare dot-dot'                => [['..'], '..'],
			'over-long component'         => [[$longComponent], $longComponent],
			'over-long total path'        => [[$longPath], $longPath],
			'first unsafe wins'           => [['ok.txt', '/abs', '../esc'], '/abs'],
			'hostile after benign'        => [['a/b', 'c/../../d'], 'c/../../d'],
			// A member whose NAME begins with "tar: " must be judged on its content,
			// never dropped as tool noise -- this is the guard-bypass regression pin.
			// ("tar: ../x" splits to ['tar: ..', 'x'] -- 'tar: ..' is a literal dir, NOT
			// a bare '..', so it is genuinely benign; the real escape needs a bare '..'
			// component, exactly the reviewer's "tar: ../../x" bypass shape.)
			'tar-prefixed benign name'    => [['tar: ../notes.txt'], null],
			'tar-prefixed hostile name'   => [['tar: ../../escape'], 'tar: ../../escape'],
		];
	}

	/** @param list<string> $names */
	#[DataProvider('memberMatrix')]
	public function testUnsafeMemberMatrix(array $names, ?string $expected): void
	{
		$actual = pfb_archive_unsafe_member($names);
		$this->assertSame(
			$expected,
			$actual,
			'pfb_archive_unsafe_member(' . json_encode($names) . ") expected "
			. var_export($expected, TRUE) . ', got ' . var_export($actual, TRUE)
		);
	}

	public function testNullMemberListFailsClosed(): void
	{
		// A NULL list (the lister could not read the archive) is unsafe -- the finder
		// returns a sentinel so every disk-writing caller rejects rather than fail-open
		// extracting an archive the ADR-45 gzip probe never structurally validated.
		$this->assertSame('unlistable-archive', pfb_archive_unsafe_member(NULL));
	}

	// --- the listers (real-tool wiring) --------------------------------------

	public function testMemberNamesListsRealArchiveAndKeepsTarPrefixedMember(): void
	{
		// The tar lister, pinned with a plain .tar so it runs on every host's tar
		// flavour. A member literally named "tar: keep.txt" must survive -- stderr is
		// discarded, so a member name can never be confused with a bsdtar diagnostic.
		$dir  = sys_get_temp_dir() . '/pfb_members_' . uniqid('', TRUE);
		$path = "{$dir}/members.tar";
		mkdir($dir);
		$tar = new PharData($path);
		$tar->addFromString('one.txt', "inert\n");
		$tar->addFromString('dir/two.txt', "inert\n");
		$tar->addFromString('tar: keep.txt', "inert\n");
		unset($tar);

		$members = pfb_archive_member_names($path, 'application/x-tar');
		@unlink($path);
		@rmdir($dir);

		$this->assertNotNull($members, 'a readable archive must list, not fail closed');
		$real = array_values(array_filter($members, static fn (string $m): bool => !str_ends_with($m, '/')));
		sort($real);
		$this->assertSame(
			['dir/two.txt', 'one.txt', 'tar: keep.txt'],
			$real,
			'expected exactly the members incl. the "tar: "-prefixed one (never dropped as noise)'
		);
	}

	/**
	 * Scenario: issue #3068 -- the ZIP leg of the ADR-46 guard, on any host.
	 *   Given  a ZIP whose members include an absolute path and a '..' escape
	 *   When   the lister is asked for its members as application/zip
	 *   Then   it returns every name VERBATIM, so pfb_archive_unsafe_member() sees
	 *          the hostile ones and the guard can refuse them.
	 *
	 * This used to be unrunnable off the appliance: the lister execed `tar -tf` for
	 * every type, and only a libarchive tar reads ZIP, so a GNU-tar host got NULL and
	 * the whole ZIP leg of ADR-46 was proven live-only. Routing ZIP through
	 * /usr/bin/unzip -- present on both platforms -- makes it hermetic everywhere.
	 */
	public function testMemberNamesListsAZipVerbatimIncludingHostileNames(): void
	{
		if (!class_exists('ZipArchive')) {
			$this->markTestSkipped('ZipArchive not available (php-zip extension missing)');
		}
		$dir  = sys_get_temp_dir() . '/pfb_zipmembers_' . uniqid('', TRUE);
		$path = "{$dir}/members.zip";
		mkdir($dir);
		$zip = new ZipArchive();
		$this->assertTrue($zip->open($path, ZipArchive::CREATE) === TRUE);
		$this->assertTrue($zip->addFromString('GeoLite2-Country.mmdb', "inert\n"));
		$this->assertTrue($zip->addFromString('dir/two.txt', "inert\n"));
		$this->assertTrue($zip->addFromString('../pfb3068_escape.txt', "inert\n"));
		$this->assertTrue($zip->addFromString('/pfb3068_absolute.txt', "inert\n"));
		$this->assertTrue($zip->close());

		$members = pfb_archive_member_names($path, 'application/zip');
		@unlink($path);
		@rmdir($dir);

		$this->assertNotNull($members, 'a readable zip must list, not fail closed');
		$real = array_values(array_filter($members, static fn (string $m): bool => !str_ends_with($m, '/')));
		sort($real);
		$this->assertSame(
			['../pfb3068_escape.txt', '/pfb3068_absolute.txt', 'GeoLite2-Country.mmdb', 'dir/two.txt'],
			$real,
			'the zip lister must report hostile member names verbatim, never normalised away'
		);
		// The point of listing them: the ADR-46 guard rejects on the first one.
		$this->assertNotNull(pfb_archive_unsafe_member($members),
			'a zip carrying an escape must be refused by the member guard');
	}

	public function testMemberNamesOnUnreadableArchiveIsNullFailClosed(): void
	{
		// Listing failure returns NULL so the caller fails CLOSED -- for the gzip/UT1
		// sites the ADR-45 probe is only `gunzip -t` (stream integrity, not the inner
		// tar), so a corrupt-inner archive that passed the probe must be rejected here,
		// never fail-open extracted.
		$this->assertNull(pfb_archive_member_names(
			sys_get_temp_dir() . '/pfb_members_does_not_exist.tar', 'application/x-tar'));
	}

	/**
	 * The same fail-closed contract on the ZIP lister: a missing file, and a file that
	 * is not a zip at all, both list as NULL so the caller refuses the archive rather
	 * than extracting something it could not read.
	 *
	 * Deliberately NOT a truncated zip: Info-ZIP rejects one (rc 9) while bsdunzip
	 * still lists it (rc 0), so pinning that fixture would pass on the appliance and
	 * fail on a plain Debian host -- the exact trap issue #3068 is about.
	 */
	public function testZipMemberNamesFailClosedOnSomethingThatIsNotAZip(): void
	{
		$dir = sys_get_temp_dir() . '/pfb_zipmembers_neg_' . uniqid('', TRUE);
		mkdir($dir);
		$notAZip = "{$dir}/feed.tar.gz";
		$this->assertNotFalse(file_put_contents($notAZip, gzencode(str_repeat("\0", 1024))));

		$this->assertNull(pfb_archive_member_names($notAZip, 'application/zip'),
			'a gzip stream is not a zip: the zip lister must fail closed, never fall back to tar');
		$this->assertNull(pfb_archive_member_names("{$dir}/absent.zip", 'application/zip'));

		@unlink($notAZip);
		@rmdir($dir);
	}
}
