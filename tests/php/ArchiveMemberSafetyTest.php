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
 * 1024 bytes = PATH_MAX) or NULL when all are safe; pfb_archive_members_safe() is
 * the boolean predicate over it. Both are pure -- the full hostile/benign matrix
 * is pinned off-appliance. pfb_zip_member_names() is the thin bsdtar lister the
 * call sites feed them from; its noise-line filtering is pinned against a real
 * archive (a noise line returned as a "member name" would false-trip the guard).
 */
#[CoversFunction('pfb_archive_unsafe_member')]
#[CoversFunction('pfb_archive_members_safe')]
#[CoversFunction('pfb_zip_member_names')]
final class ArchiveMemberSafetyTest extends TestCase
{
	// --- pure decision matrix ------------------------------------------------

	/** @return array<string, array{0: list<string>, 1: ?string}> */
	public static function memberMatrix(): array
	{
		$longComponent = str_repeat('a', 256);           // NAME_MAX is 255
		$okComponent   = str_repeat('a', 255);
		// 5 x 200 chars + 4 separators = 1004 bytes total, every component legal.
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

	/** @param list<string> $names */
	#[DataProvider('memberMatrix')]
	public function testSafePredicateAgreesWithUnsafeMember(array $names, ?string $expected): void
	{
		// The predicate is definitionally the NULL-check over the finder -- pin the
		// agreement so the two cannot drift apart.
		$this->assertSame($expected === NULL, pfb_archive_members_safe($names));
	}

	// --- bsdtar lister (real-tool wiring, skip-guarded) ----------------------

	public function testMemberNamesListsRealZipWithoutNoiseLines(): void
	{
		if (!class_exists('ZipArchive')) {
			$this->markTestSkipped('ZipArchive extension unavailable on this host');
		}
		$path = tempnam(sys_get_temp_dir(), 'pfb_members_') . '.zip';
		$zip = new ZipArchive();
		$this->assertTrue($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE));
		$zip->addFromString('one.txt', "inert\n");
		$zip->addFromString('dir/two.txt', "inert\n");
		$zip->close();

		$members = pfb_zip_member_names($path);
		@unlink($path);

		sort($members);
		$this->assertSame(['dir/two.txt', 'one.txt'], $members, 'expected exactly the archive members, no bsdtar noise lines');
		foreach ($members as $m) {
			$this->assertStringStartsNotWith('tar: ', $m, "bsdtar noise line leaked into the member list: <{$m}>");
		}
	}

	public function testMemberNamesOnUnreadableArchiveIsEmptyFailOpen(): void
	{
		// Listing failure returns [] (guard passes): the archive already passed the
		// ADR-45 structural probe, and the extraction itself fails as before -- the
		// guard must never turn a listing hiccup into a new reject class.
		$this->assertSame([], pfb_zip_member_names(sys_get_temp_dir() . '/pfb_members_does_not_exist.zip'));
	}
}
