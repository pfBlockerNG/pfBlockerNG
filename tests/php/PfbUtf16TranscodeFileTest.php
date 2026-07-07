<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_utf16_transcode_file() — issue #946.
 *
 * A UTF-16/UTF-32-BOM-marked text feed reaches the byte-oriented DNSBL parser
 * undecoded: every line fails (default installs) or the ADR-49 opt-in sanity
 * scan rejects the whole feed as 'nul_bytes'. This function transcodes such a
 * file to UTF-8 IN PLACE, atomically (temp file in the same directory +
 * rename()), preserving the original mtime -- fail-open (returns FALSE, file
 * untouched) for every path that is not BOM-marked UTF-16/UTF-32, unreadable,
 * or fails conversion.
 */
#[CoversFunction('pfb_utf16_transcode_file')]
#[CoversFunction('pfb_utf16_bom_encoding')]
#[CoversFunction('pfb_utf16_sample_to_utf8')]
final class PfbUtf16TranscodeFileTest extends TestCase
{
	/** @var string */
	private string $dir;

	protected function setUp(): void
	{
		$dir = sys_get_temp_dir() . '/pfb_u16_test_' . bin2hex(random_bytes(8));
		if (!mkdir($dir) && !is_dir($dir)) {
			$this->fail('Could not create temp dir');
		}
		$this->dir = $dir;
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
	}

	private function path(string $name): string
	{
		return $this->dir . '/' . $name;
	}

	// -- BOM-marked encodings decode correctly, mtime preserved --------------------------

	/** @return array<string, array{0: string}> */
	public static function bomEncodings(): array
	{
		return [
			'UTF-16LE' => ['UTF-16LE'],
			'UTF-16BE' => ['UTF-16BE'],
			'UTF-32LE' => ['UTF-32LE'],
			'UTF-32BE' => ['UTF-32BE'],
		];
	}

	#[DataProvider('bomEncodings')]
	public function test_bom_marked_file_is_transcoded_to_utf8_and_mtime_preserved(string $enc): void
	{
		$text = "0.0.0.0 example.com\n# comment\n";
		$boms = [
			'UTF-16LE' => "\xFF\xFE",
			'UTF-16BE' => "\xFE\xFF",
			'UTF-32LE' => "\xFF\xFE\x00\x00",
			'UTF-32BE' => "\x00\x00\xFE\xFF",
		];
		$path = $this->path('feed_' . $enc . '.txt');
		file_put_contents($path, $boms[$enc] . mb_convert_encoding($text, $enc, 'UTF-8'));

		// GIVEN a known, non-current mtime -- so "preserved" is provably the ORIGINAL
		// stamp, not merely "unchanged because nothing touched it".
		$knownMtime = time() - 100000;
		touch($path, $knownMtime);
		clearstatcache(TRUE, $path);
		$this->assertSame($knownMtime, filemtime($path), 'setup drift: mtime priming failed');

		$result = pfb_utf16_transcode_file($path);

		$this->assertTrue($result, "{$enc}: expected TRUE (file transcoded)");
		$this->assertSame($text, file_get_contents($path), "{$enc}: content must be the exact UTF-8 string");
		clearstatcache(TRUE, $path);
		$this->assertSame($knownMtime, filemtime($path), "{$enc}: mtime must survive the transcode");
	}

	// -- Non-BOM / benign inputs: FALSE, byte-identical ----------------------------------

	public function test_plain_ascii_file_is_untouched(): void
	{
		$path = $this->path('ascii.txt');
		$original = "0.0.0.0 example.com\n";
		file_put_contents($path, $original);

		$this->assertFalse(pfb_utf16_transcode_file($path));
		$this->assertSame($original, file_get_contents($path));
	}

	public function test_utf8_bom_file_is_untouched(): void
	{
		// The UTF-8 BOM is handled line-level inside pfb_text_sanity()/the parser, not
		// file-level here -- this function only reacts to UTF-16/UTF-32 BOMs.
		$path = $this->path('utf8bom.txt');
		$original = "\xEF\xBB\xBF0.0.0.0 example.com\n";
		file_put_contents($path, $original);

		$this->assertFalse(pfb_utf16_transcode_file($path));
		$this->assertSame($original, file_get_contents($path));
	}

	public function test_empty_file_is_untouched(): void
	{
		$path = $this->path('empty.txt');
		file_put_contents($path, '');

		$this->assertFalse(pfb_utf16_transcode_file($path));
		$this->assertSame('', file_get_contents($path));
	}

	public function test_bom_less_nul_interleaved_binary_is_untouched(): void
	{
		$path = $this->path('binary.bin');
		$original = "\x01\x00\x02\x00garbage\x00\xFF";
		file_put_contents($path, $original);

		$this->assertFalse(pfb_utf16_transcode_file($path));
		$this->assertSame($original, file_get_contents($path));
	}

	public function test_nonexistent_path_returns_false_without_warning(): void
	{
		// is_readable()/@ guard: no warning-spam for a path that simply doesn't exist.
		$this->assertFalse(pfb_utf16_transcode_file($this->path('does-not-exist.txt')));
	}

	// -- Pinned edge cases: deterministic, non-crashing observed behaviour ---------------

	public function test_bom_only_utf16le_file(): void
	{
		// Exactly the 2-byte UTF-16LE BOM, no payload: BOM strips to an empty remainder,
		// mb_convert_encoding('', 'UTF-8', 'UTF-16LE') === '' (not FALSE), so the observed
		// outcome is TRUE + an empty UTF-8 file.
		$path = $this->path('bom_only_16le.bin');
		file_put_contents($path, "\xFF\xFE");

		$result = pfb_utf16_transcode_file($path);

		$this->assertTrue($result, 'BOM-only UTF-16LE: observed outcome is TRUE (empty remainder converts cleanly)');
		$this->assertSame('', file_get_contents($path));
	}

	public function test_bom_only_utf32le_file(): void
	{
		// Exactly the 4-byte UTF-32LE BOM ("\xFF\xFE\x00\x00") -- this is the load-bearing
		// detection-order case: it must be read as UTF-32LE (checked FIRST), not UTF-16LE
		// plus two stray NUL bytes.
		$path = $this->path('bom_only_32le.bin');
		file_put_contents($path, "\xFF\xFE\x00\x00");

		$result = pfb_utf16_transcode_file($path);

		$this->assertTrue($result, 'BOM-only UTF-32LE: observed outcome is TRUE (empty remainder converts cleanly)');
		$this->assertSame('', file_get_contents($path));
	}

	public function test_odd_length_utf16le_payload_does_not_crash(): void
	{
		// BOM + an odd number of trailing bytes (a truncated UTF-16LE code unit). The
		// only hard requirement is no crash and a deterministic outcome -- pin PHP's
		// actual mb_convert_encoding() behaviour (a '?' replacement for the dangling byte).
		$path = $this->path('odd_16le.bin');
		file_put_contents($path, "\xFF\xFE" . mb_convert_encoding('AB', 'UTF-16LE', 'UTF-8') . "\x41");

		$result = pfb_utf16_transcode_file($path);

		$this->assertTrue($result);
		$this->assertSame('AB?', file_get_contents($path), 'pinned observed mb_convert_encoding behaviour for a dangling odd byte');
	}

	public function test_bom_only_utf16be_and_utf32be_files(): void
	{
		// BE siblings of the LE BOM-only pins above -- the conversion path is shared,
		// and these rows pin that the BE byte orders behave identically (PR #951 review).
		$path16 = $this->path('bom_only_16be.bin');
		file_put_contents($path16, "\xFE\xFF");
		$this->assertTrue(pfb_utf16_transcode_file($path16));
		$this->assertSame('', file_get_contents($path16));

		$path32 = $this->path('bom_only_32be.bin');
		file_put_contents($path32, "\x00\x00\xFE\xFF");
		$this->assertTrue(pfb_utf16_transcode_file($path32));
		$this->assertSame('', file_get_contents($path32));
	}

	public function test_odd_length_utf16be_and_utf32_payloads_do_not_crash(): void
	{
		// BE / UTF-32 siblings of the odd-length pin: a dangling partial code unit is
		// substituted with '?' identically across byte orders (PR #951 review).
		$path16 = $this->path('odd_16be.bin');
		file_put_contents($path16, "\xFE\xFF" . mb_convert_encoding('AB', 'UTF-16BE', 'UTF-8') . "\x41");
		$this->assertTrue(pfb_utf16_transcode_file($path16));
		$this->assertSame('AB?', file_get_contents($path16));

		$path32le = $this->path('odd_32le.bin');
		file_put_contents($path32le, "\xFF\xFE\x00\x00" . mb_convert_encoding('AB', 'UTF-32LE', 'UTF-8') . "\x41");
		$this->assertTrue(pfb_utf16_transcode_file($path32le));
		$this->assertSame('AB?', file_get_contents($path32le));

		$path32be = $this->path('odd_32be.bin');
		file_put_contents($path32be, "\x00\x00\xFE\xFF" . mb_convert_encoding('AB', 'UTF-32BE', 'UTF-8') . "\x41");
		$this->assertTrue(pfb_utf16_transcode_file($path32be));
		$this->assertSame('AB?', file_get_contents($path32be));
	}

	public function test_transcode_preserves_permission_bits(): void
	{
		// tempnam() creates 0600 files; without an explicit chmod the rename would
		// silently narrow the .orig's mode (PR #951 review, Copilot). Pin that a
		// distinctive pre-existing mode survives the atomic rewrite.
		$path = $this->path('perms.bin');
		file_put_contents($path, "\xFF\xFE" . mb_convert_encoding("0.0.0.0 example.com\n", 'UTF-16LE', 'UTF-8'));
		chmod($path, 0644);

		$this->assertTrue(pfb_utf16_transcode_file($path));

		clearstatcache();
		$this->assertSame(
			'644',
			decoct(fileperms($path) & 0777),
			'permission bits must survive the tempnam()+rename() rewrite'
		);
	}
}
