<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4037 (slice 8c): the Outpost's cursor file, /var/db/pfblockerng/pfb_apply_cursors.json, holds per resource the
 * generation, digest and entries the Outpost applied. A file that is missing, a symbolic link, oversized, truncated or of an
 * unknown format means "no cursors": it is reported and never trusted, so every table is answered full. It is written whole,
 * by a temporary file and a rename, only while this process holds the apply lock (the feed-pass lock).
 */
#[CoversFunction('pfb_outpost_cursors_read')]
#[CoversFunction('pfb_outpost_cursor_advance')]
#[CoversFunction('pfb_outpost_cursor_drop')]
final class OutpostCursorFileTest extends TestCase
{
	private const DIGEST = '0123456789abcdef0123456789abcdef';

	private string $dir = '';

	private string $file = '';

	private string $savedDbdir = '';

	protected function setUp(): void
	{
		global $pfb;
		$this->dir = sys_get_temp_dir() . '/pfbcursor' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
		$this->savedDbdir = (string) ($pfb['dbdir'] ?? '');
		$pfb['dbdir'] = $this->dir;
		$this->file = "{$this->dir}/pfb_apply_cursors.json";
	}

	protected function tearDown(): void
	{
		global $pfb;
		pfb_feed_pass_release();
		$pfb['dbdir'] = $this->savedDbdir;
		rmdir_recursive($this->dir);
	}

	private function lock(): void
	{
		$this->assertTrue(pfb_feed_pass_acquire(), 'the apply lock could not be taken');
	}

	public function testAMissingFileIsNoCursorsAndIsReported(): void
	{
		$read = pfb_outpost_cursors_read();

		$this->assertSame([], $read['cursors']);
		$this->assertIsString($read['error']);
	}

	public function testAnAdvancedCursorIsWrittenWholeInTheDatabaseFolderAndReadBack(): void
	{
		$this->lock();
		$this->assertNull(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 15234));
		$this->assertNull(pfb_outpost_cursor_advance('geo-catalog', '3', str_repeat('f', 32), 0));

		$this->assertSame(['schema' => 1, 'resources' => [
			'geo-catalog'       => ['generation' => '3', 'digest' => str_repeat('f', 32), 'entries' => 0],
			'ip-set/Abuse/ipv4' => ['generation' => '42', 'digest' => self::DIGEST, 'entries' => 15234],
		]], json_decode((string) file_get_contents($this->file), TRUE), 'the cursor file is not the documented format');
		$this->assertSame(0600, fileperms($this->file) & 0777);
		$this->assertSame(['cursors' => [
			'geo-catalog'       => ['generation' => '3', 'digest' => str_repeat('f', 32), 'entries' => 0],
			'ip-set/Abuse/ipv4' => ['generation' => '42', 'digest' => self::DIGEST, 'entries' => 15234],
		], 'error' => NULL], pfb_outpost_cursors_read());
		$this->assertSame(['pfb_apply_cursors.json', 'pfb_feed_pass.lock'], array_values(array_diff(scandir($this->dir), ['.', '..'])),
			'the write left a temporary file');
	}

	/**
	 * The cursor file is created 0600, not made so after it was written under a wider umask; the process umask is left as it
	 * was (review of slice 8c, L10). The creation mode itself cannot be observed from here without a race: the review recorded
	 * it with strace.
	 */
	public function testUnderAUmaskOf022TheFileIsModeSixHundredAndTheUmaskIsKept(): void
	{
		$this->lock();
		$saved = umask(022);
		try {
			$this->assertNull(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1));
			$this->assertSame(022, umask(), 'the write changed the process umask');
		} finally {
			umask($saved);
		}
		$this->assertSame(0600, fileperms($this->file) & 0777);
	}

	public function testAdvancingAResourceAgainReplacesOnlyItsCursor(): void
	{
		$this->lock();
		pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1);
		pfb_outpost_cursor_advance('ip-set/Top/ipv6', '7', self::DIGEST, 2);
		$this->assertNull(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '43', str_repeat('a', 32), 3));

		$this->assertSame([
			'ip-set/Abuse/ipv4' => ['generation' => '43', 'digest' => str_repeat('a', 32), 'entries' => 3],
			'ip-set/Top/ipv6'   => ['generation' => '7', 'digest' => self::DIGEST, 'entries' => 2],
		], pfb_outpost_cursors_read()['cursors']);
	}

	public function testDroppingARemovedResourceKeepsTheOthers(): void
	{
		$this->lock();
		pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1);
		pfb_outpost_cursor_advance('ip-set/Top/ipv6', '7', self::DIGEST, 2);
		$this->assertSame(2, count(pfb_outpost_cursors_read()['cursors']));

		$this->assertNull(pfb_outpost_cursor_drop('ip-set/Abuse/ipv4'));
		$this->assertSame(['ip-set/Top/ipv6' => ['generation' => '7', 'digest' => self::DIGEST, 'entries' => 2]],
			pfb_outpost_cursors_read()['cursors']);
		$this->assertNull(pfb_outpost_cursor_drop('ip-set/Never/ipv4'), 'dropping a resource that holds no cursor is not a failure');
	}

	public function testNothingIsWrittenWithoutTheApplyLock(): void
	{
		$this->lock();
		pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1);
		$before = file_get_contents($this->file);
		pfb_feed_pass_release();

		$this->assertIsString(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '43', self::DIGEST, 1));
		$this->assertIsString(pfb_outpost_cursor_drop('ip-set/Abuse/ipv4'));
		$this->assertSame($before, file_get_contents($this->file));
	}

	/** @return array<string, array{string, string, int}> */
	public static function badCursors(): array
	{
		return [
			'an id that is not a resource id' => ['ip-set/../ipv4', '1', 0],
			'a generation that is not digits' => ['geo-catalog', '1.5', 0],
			'a generation over 64 bits'       => ['geo-catalog', '18446744073709551616', 0],
			'an empty generation'             => ['geo-catalog', '', 0],
			'a digest of another shape'       => ['geo-catalog', '1', 'ABC'],
			'negative entries'                => ['geo-catalog', '1', -1],
		];
	}

	#[DataProvider('badCursors')]
	public function testACursorOfTheWrongShapeIsNeverWritten(string $id, string $generation, int|string $digestOrEntries): void
	{
		$this->lock();
		$digest = is_string($digestOrEntries) ? $digestOrEntries : self::DIGEST;
		$entries = is_int($digestOrEntries) ? $digestOrEntries : 0;

		$this->assertIsString(pfb_outpost_cursor_advance($id, $generation, $digest, $entries));
		$this->assertFileDoesNotExist($this->file);
	}

	/** @return array<string, array{string}> */
	public static function untrustedFiles(): array
	{
		$good = ['schema' => 1, 'resources' => ['geo-catalog' => ['generation' => '3', 'digest' => self::DIGEST, 'entries' => 1]]];
		$entry = $good['resources']['geo-catalog'];
		$with = static fn (array $e): string => (string) json_encode(['schema' => 1, 'resources' => ['geo-catalog' => $e]]);
		$whole = (string) json_encode($good);
		return [
			'truncated'                    => [substr($whole, 0, -7)],
			'empty'                        => [''],
			'not JSON'                     => ['cursors'],
			'a JSON list'                  => ['[1,2]'],
			'another schema'               => [(string) json_encode(['schema' => 2] + $good)],
			'no schema'                    => [(string) json_encode(['resources' => $good['resources']])],
			'resources is a list'          => [(string) json_encode(['schema' => 1, 'resources' => [$entry]])],
			'an id that is no resource id' => [(string) json_encode(['schema' => 1, 'resources' => ['geo-catalog/x' => $entry]])],
			'a numeric generation'         => [$with(['generation' => 3] + $entry)],
			'an upper-case digest'         => [$with(['digest' => strtoupper(self::DIGEST)] + $entry)],
			'entries as a string'          => [$with(['entries' => '1'] + $entry)],
			'an entry missing its digest'  => [$with(['generation' => '3', 'entries' => 1])],
			'oversized'                    => [$whole . str_repeat(' ', 1 << 20)],
		];
	}

	#[DataProvider('untrustedFiles')]
	public function testAFileThatCannotBeTrustedIsNoCursorsAndIsReported(string $content): void
	{
		file_put_contents($this->file, $content);
		$read = pfb_outpost_cursors_read();

		$this->assertSame([], $read['cursors'], 'an untrusted cursor file was trusted');
		$this->assertIsString($read['error']);
	}

	public function testTheFileAsWrittenIsTrustedSoTheUntrustedRowsFailForTheirOwnReason(): void
	{
		file_put_contents($this->file, json_encode(['schema' => 1, 'resources' => ['geo-catalog' => ['generation' => '3', 'digest' => self::DIGEST,
			'entries' => 1]]]));

		$this->assertSame(['cursors' => ['geo-catalog' => ['generation' => '3', 'digest' => self::DIGEST, 'entries' => 1]], 'error' => NULL],
			pfb_outpost_cursors_read());
	}

	public function testAnUntrustedFileIsReplacedWholeByTheNextAdvance(): void
	{
		file_put_contents($this->file, '{"schema":1,"resources":{"geo-catalog":');
		$this->lock();

		$this->assertNull(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1));
		$this->assertSame(['ip-set/Abuse/ipv4' => ['generation' => '42', 'digest' => self::DIGEST, 'entries' => 1]],
			pfb_outpost_cursors_read()['cursors']);
	}

	public function testAFileThatIsASymbolicLinkIsNeitherTrustedNorFollowed(): void
	{
		$target = "{$this->dir}/elsewhere.json";
		$content = (string) json_encode(['schema' => 1, 'resources' => ['geo-catalog' => ['generation' => '3', 'digest' => self::DIGEST, 'entries' => 1]]]);
		file_put_contents($target, $content);
		$this->assertTrue(symlink($target, $this->file));

		$read = pfb_outpost_cursors_read();
		$this->assertSame([], $read['cursors'], 'a linked cursor file was trusted');
		$this->assertIsString($read['error']);

		$this->lock();
		$this->assertNull(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1));
		$this->assertFalse(is_link($this->file), 'the link was not replaced');
		$this->assertSame($content, file_get_contents($target), 'the link target was written through');
	}

	public function testALeftoverTemporaryFileThatIsALinkIsNotFollowed(): void
	{
		$target = "{$this->dir}/elsewhere";
		file_put_contents($target, 'keep');
		$this->assertTrue(symlink($target, "{$this->file}.tmp"));
		$this->lock();

		$this->assertNull(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1));
		$this->assertSame('keep', file_get_contents($target));
		$this->assertSame(1, count(pfb_outpost_cursors_read()['cursors']));
	}

	public function testADirectoryInPlaceOfTheFileIsNoCursorsAndAnAdvanceFails(): void
	{
		$this->assertTrue(mkdir($this->file));
		$read = pfb_outpost_cursors_read();
		$this->assertSame([], $read['cursors']);
		$this->assertIsString($read['error']);

		$this->lock();
		$this->assertIsString(pfb_outpost_cursor_advance('ip-set/Abuse/ipv4', '42', self::DIGEST, 1));
		$this->assertDirectoryExists($this->file);
		$this->assertFileDoesNotExist("{$this->file}.tmp");
	}

	public function testAnExplicitPathIsHonoured(): void
	{
		$path = "{$this->dir}/other.json";
		$this->lock();

		$this->assertNull(pfb_outpost_cursor_advance('geo-catalog', '1', self::DIGEST, 1, $path));
		$this->assertFileDoesNotExist($this->file);
		$this->assertSame(['geo-catalog'], array_keys(pfb_outpost_cursors_read($path)['cursors']));
		$this->assertNull(pfb_outpost_cursor_drop('geo-catalog', $path));
		$this->assertSame([], pfb_outpost_cursors_read($path)['cursors']);
	}
}
