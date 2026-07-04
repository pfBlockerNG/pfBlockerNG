<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Source pin for issue #823: a PHP filesystem builtin (or unlink_if_exists())
 * must never receive an `*_esc` variable — by repo convention those hold
 * escapeshellarg()-quoted strings, so the literal path probed on disk carries
 * the surrounding single quotes and never exists. The call silently no-ops
 * (pfb_download()'s gzip GeoIP/ASN branches left the downloaded .raw behind).
 *
 * The escaped form belongs in shell command lines (exec/shell_exec) only;
 * filesystem calls take the raw path (the `trim($x_esc, "'")` companions,
 * e.g. $file_download in pfb_download()).
 *
 * pfb_download() itself is not off-appliance unit-testable (curl/exec — see
 * ArchiveValidateWiringTest), so this pins the defect statically across all
 * shipped PHP: red on the pre-fix source (two hits), red again if the
 * pattern is reintroduced anywhere.
 */
final class EscapedPathFilesystemCallTest extends TestCase
{
	/**
	 * Filesystem calls that take a path argument. Shell-exec functions are
	 * deliberately absent — _esc is correct there. rename()/copy() get a
	 * second alternative for their destination-path (second) argument.
	 */
	private const FS_CALL_PATTERN =
		'/\b(?:unlink_if_exists|unlink|file_exists|is_file|is_dir|is_link|touch|rename|copy'
		. '|filesize|filemtime|file_get_contents|file_put_contents|readfile|fopen|mkdir|rmdir'
		. '|rmdir_recursive|safe_mkdir)\s*\(\s*\$[A-Za-z0-9_]*_esc\b'
		. '|\b(?:rename|copy)\s*\([^,)]*,\s*\$[A-Za-z0-9_]*_esc\b/';

	/**
	 * Scenario: the pattern catches an _esc path in either path argument
	 *
	 * Given  representative call shapes — an _esc first argument, an _esc
	 *        destination (second) argument of rename()/copy(), and a
	 *        legitimate shell-exec interpolation
	 * When   each is matched against FS_CALL_PATTERN
	 * Then   the filesystem calls match and the shell-exec line does not —
	 *        so the src/ scan below cannot silently under-detect.
	 */
	public function test_pattern_catches_escaped_path_in_either_argument(): void
	{
		$mustMatch = [
			'unlink_if_exists($file_dwn_esc);',
			"unlink_if_exists(\n\t\$file_dwn_esc\n);",
			'rename($src, $dst_esc);',
			'copy("/tmp/a", $dst_esc);',
		];
		foreach ($mustMatch as $snippet) {
			$this->assertSame(1, preg_match(self::FS_CALL_PATTERN, $snippet),
				"FS_CALL_PATTERN must match: {$snippet}");
		}
		$this->assertSame(0, preg_match(self::FS_CALL_PATTERN, 'exec("/usr/bin/tar -xzf {$file_dwn_esc}");'),
			'Shell-exec interpolation is the legitimate use of _esc and must not match');
	}

	/**
	 * Scenario: no shipped PHP passes an escapeshellarg()-quoted variable to a
	 * filesystem call
	 *
	 * Given  every tracked .php/.inc file under src/
	 * When   each is scanned for a filesystem call whose first argument is an
	 *        `$…_esc` variable
	 * Then   no file matches — a match means the quoted string is being used
	 *        as an on-disk path, which can never exist.
	 */
	public function test_no_filesystem_call_receives_escaped_path(): void
	{
		$root = dirname(__DIR__, 2);
		$violations = [];

		$iter = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator("{$root}/src", FilesystemIterator::SKIP_DOTS)
		);
		foreach ($iter as $file) {
			if (!in_array($file->getExtension(), ['php', 'inc'], TRUE)) {
				continue;
			}
			$source = file_get_contents($file->getPathname());
			$this->assertNotFalse($source, "Failed to read {$file->getPathname()}");
			$count = preg_match_all(self::FS_CALL_PATTERN, $source, $m, PREG_OFFSET_CAPTURE);
			// FALSE = regex-engine error, which must fail loud — not read as "no match".
			$this->assertNotFalse($count, "preg_match_all failed on {$file->getPathname()}");
			if ($count) {
				foreach ($m[0] as [$match, $offset]) {
					$line = substr_count($source, "\n", 0, $offset) + 1;
					$rel  = substr($file->getPathname(), strlen($root) + 1);
					$violations[] = "{$rel}:{$line}: {$match}";
				}
			}
		}

		$this->assertSame([], $violations,
			"Filesystem call(s) passed an escapeshellarg()-quoted (_esc) variable — the quoted\n"
			. "literal is never a real path, so the call silently no-ops. Pass the raw path\n"
			. "(its trim(…, \"'\") companion) instead:\n  " . implode("\n  ", $violations)
		);
	}
}
