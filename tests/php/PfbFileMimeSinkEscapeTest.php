<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filter() FILE_MIME / FILE_MIME_COMPRESSED — the file-type probe argument is
 * escaped AT the sink, so a metacharacter-bearing path is rendered inert (passed
 * to /usr/bin/file as a single literal argument) and cannot start a second command.
 *
 * The probe runs the real /usr/bin/file against a real on-disk file, so these tests
 * use actual temp files. Both branches are pinned:
 *   - a benign path probes correctly (mime returned unchanged for valid input);
 *   - a path whose NAME contains shell metacharacters does NOT execute the injected
 *     command (no sentinel side effect) — proving the sink, not the caller, escapes.
 */
#[CoversFunction('pfb_filter')]
final class PfbFileMimeSinkEscapeTest extends TestCase
{
	private string $dir;
	private string $cwd;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_mime_' . uniqid('', true);
		mkdir($this->dir);
		// Work from inside the dir so a metacharacter-bearing filename (which may
		// not itself contain '/') and its sentinel are addressed by bare name.
		$this->cwd = (string) getcwd();
		chdir($this->dir);
		$this->saved['mime_types'] = array_key_exists('mime_types', $GLOBALS['pfb'] ?? [])
			? $GLOBALS['pfb']['mime_types']
			: FALSE;

		// FILE_MIME accepts the probed type only when it is a known mime_type.
		$GLOBALS['pfb']['mime_types'] = ['text/plain' => 1];
	}

	protected function tearDown(): void
	{
		chdir($this->cwd);
		foreach (glob($this->dir . '/*') ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
	}

	public function testBenignPathProbesMimeUnchanged(): void
	{
		// Given a plain-text file with an ordinary name (addressed by bare name; cwd
		// is the test dir).
		file_put_contents('benign.txt', "127.0.0.1 example\n");

		// When FILE_MIME validates it ($input[1] is the raw path, escaped at the sink).
		$result = pfb_filter(["'unused'", 'benign.txt', 'http://feed.example/'], PFB_FILTER_FILE_MIME, 'test');

		// Then the probed mime-type is returned unchanged — valid input is untouched.
		$this->assertSame('text/plain', $result);
	}

	public function testMetacharacterPathIsInertAtSink(): void
	{
		// Given a real file whose NAME embeds a command-injection attempt, and a
		// sentinel that the injected command would create if the arg were unescaped.
		// The filename cannot contain '/', so both file and sentinel are bare names.
		$evilName = 'evil; touch SENTINEL #.txt';
		file_put_contents($evilName, "data\n");

		// Sanity (before-state): the sentinel does not exist yet.
		$this->assertFileDoesNotExist('SENTINEL');

		// When FILE_MIME validates the metacharacter-bearing path.
		pfb_filter(["'unused'", $evilName, 'http://feed.example/'], PFB_FILTER_FILE_MIME, 'test');

		// Then the embedded command never ran: escaping at the sink rendered it inert.
		$this->assertFileDoesNotExist('SENTINEL');
	}

	public function testCompressedMetacharacterPathIsInertAtSink(): void
	{
		// Same guarantee for the COMPRESSED case (file -bZ).
		$evilName = 'evilz; touch SENTINEL_Z #.gz';
		file_put_contents($evilName, "data\n");

		$this->assertFileDoesNotExist('SENTINEL_Z');

		pfb_filter(["'unused'", $evilName, 'http://feed.example/'], PFB_FILTER_FILE_MIME_COMPRESSED, 'test');

		$this->assertFileDoesNotExist('SENTINEL_Z');
	}
}
