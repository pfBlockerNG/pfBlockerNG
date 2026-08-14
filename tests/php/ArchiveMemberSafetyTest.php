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
 * off-appliance. pfb_archive_member_names() is the thin bsdtar lister the call
 * sites feed it from; it returns NULL on a listing failure (rc != 0) so a caller
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

	// --- bsdtar lister (real-tool wiring, skip-guarded) ----------------------

	public function testMemberNamesListsRealArchiveAndKeepsTarPrefixedMember(): void
	{
		// A plain .tar, NOT a zip: a dev host whose /usr/bin/tar is GNU tar cannot read
		// zip at all (the CI image now supplies bsdtar there, as the appliance does, but a
		// bare Linux host still does not). A .tar pins the same lister behaviour on every
		// host; the zip leg is live-proven by the ADR-46 smoke cases.
		// A member literally named "tar: keep.txt" must survive -- stderr is discarded,
		// so a member name can never be confused with a bsdtar diagnostic.
		$dir  = sys_get_temp_dir() . '/pfb_members_' . uniqid('', TRUE);
		$path = "{$dir}/members.tar";
		mkdir($dir);
		$tar = new PharData($path);
		$tar->addFromString('one.txt', "inert\n");
		$tar->addFromString('dir/two.txt', "inert\n");
		$tar->addFromString('tar: keep.txt', "inert\n");
		unset($tar);

		$members = pfb_archive_member_names($path);
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

	public function testMemberNamesOnUnreadableArchiveIsNullFailClosed(): void
	{
		// Listing failure returns NULL so the caller fails CLOSED -- for the gzip/UT1
		// sites the ADR-45 probe is only `gunzip -t` (stream integrity, not the inner
		// tar), so a corrupt-inner archive that passed the probe must be rejected here,
		// never fail-open extracted.
		$this->assertNull(pfb_archive_member_names(sys_get_temp_dir() . '/pfb_members_does_not_exist.tar'));
	}
}
