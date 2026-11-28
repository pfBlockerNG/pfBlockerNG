<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-40 Phase 3 — the last-applied alias mirror writer.
 *
 *   pfb_write_canonical_alias(string $path, array $canonical_set): bool
 *     Writes the canonical set to the given path (one entry per line, trailing
 *     newline), and reports whether the whole file was written.
 *
 * The PHP reload gate that compared a set against this mirror
 * (pfb_alias_set_different(), pfb_cross_list_scope(), pfb_supp_update_active())
 * left with the PHP Update pass in the Go cutover (#3977), with its tests.
 */
#[CoversFunction('pfb_write_canonical_alias')]
final class AliasContentGateTest extends TestCase
{
	/** @var string Per-test temp dir for mirror files. */
	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_adr40_p3_' . getmypid() . '_' . uniqid();
		@mkdir($this->tmp, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->tmp}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->tmp);
	}

	// -----------------------------------------------------------------------
	// Scenario F — pfb_write_canonical_alias writes correct format
	// -----------------------------------------------------------------------

	/**
	 * Scenario F: pfb_write_canonical_alias writes the provided canonical set as-is.
	 *
	 * pfb_write_canonical_alias() writes caller-supplied entries verbatim, one per
	 * line with a trailing newline.  The CALLER is responsible for providing a
	 * canonical (sorted, unique) set; the writer does NOT re-sort or de-duplicate.
	 * This matches the ADR-40 design: pfb_canonical_alias_set() canonicalises
	 * before handing off to the writer.
	 *
	 * The input here is already sorted so the assertion is unambiguous: the file
	 * must contain exactly these entries in exactly this order.
	 */
	public function testWriteCanonicalAliasProducesCanonicalFormat(): void
	{
		$path = "{$this->tmp}/pfB_Format_v4.txt";
		// Pre-sorted canonical set (as pfb_canonical_alias_set() would return it).
		$set  = ['10.0.0.1', '192.0.2.1', '192.0.2.3'];

		pfb_write_canonical_alias($path, $set);

		$this->assertFileExists(
			$path,
			"mirror file must be created by pfb_write_canonical_alias\n" .
			"path: {$path}"
		);

		$written = file_get_contents($path);
		// Writer must preserve caller order and append a trailing newline.
		$lines = array_filter(explode("\n", rtrim($written)));
		$this->assertSame(
			$set,
			array_values($lines),
			"written file must contain exactly the canonical set entries, one per line\n" .
			"set:     " . implode(', ', $set) . "\n" .
			"written: " . json_encode($written)
		);
		$this->assertStringEndsWith(
			"\n",
			$written,
			"written file must end with a newline\n" .
			"written: " . json_encode($written)
		);
	}

	/**
	 * Issue #4191: the mirror is replaced whole, never rewritten in place. pfctl -T replace -f (the tick's retry, outside the
	 * Update's lock) and the alias URL read it without a lock, so a reader that opened it before a write keeps reading the old
	 * set whole, and the new set is published only complete, readable by the alias URL's reader (0644).
	 */
	public function testWriteCanonicalAliasReplacesTheMirrorWholeUnderAnOpenReader(): void
	{
		$path = "{$this->tmp}/pfB_Whole_v4.txt";
		file_put_contents($path, "10.0.0.1\n10.0.0.2\n10.0.0.3\n");
		$reader = fopen($path, 'rb');

		$this->assertTrue(pfb_write_canonical_alias($path, ['192.0.2.1']));

		$this->assertSame("10.0.0.1\n10.0.0.2\n10.0.0.3\n", stream_get_contents($reader), 'an open reader still sees the old set whole');
		fclose($reader);
		$this->assertSame("192.0.2.1\n", file_get_contents($path));
		$this->assertSame('0644', sprintf('%04o', fileperms($path) & 0777));
		$this->assertSame(['pfB_Whole_v4.txt'], array_values(array_diff(scandir($this->tmp), ['.', '..'])), 'no staged file is left');
	}

	/** Issue #4191: a mirror that cannot be replaced (a folder in its place) is reported, and nothing is left staged. */
	public function testWriteCanonicalAliasThatCannotReplaceTheMirrorSaysSo(): void
	{
		$path = "{$this->tmp}/pfB_Blocked_v4.txt";
		mkdir($path);

		$this->assertFalse(pfb_write_canonical_alias($path, ['192.0.2.1']));
		$this->assertDirectoryExists($path);
		$this->assertSame(['pfB_Blocked_v4.txt'], array_values(array_diff(scandir($this->tmp), ['.', '..'])));
		rmdir($path);
	}

	/**
	 * Run $call in a forked child whose file writes stop after $bytes (RLIMIT_FSIZE, SIGXFSZ ignored), as a full disk cuts
	 * them short; the child dies without running shutdown handlers. @return string what $call returned (var_export)
	 */
	private static function cutShort(int $bytes, callable $call): string
	{
		$pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
		$pid = pcntl_fork();
		if ($pid === -1) {
			throw new RuntimeException('fork failed');
		}
		if ($pid === 0) {
			pcntl_alarm(30);
			fclose($pair[0]);
			pcntl_signal(SIGXFSZ, SIG_IGN);
			posix_setrlimit(POSIX_RLIMIT_FSIZE, $bytes, $bytes);
			fwrite($pair[1], var_export($call(), TRUE));
			posix_kill(posix_getpid(), SIGKILL);
		}
		fclose($pair[1]);
		$out = (string) stream_get_contents($pair[0]);
		pcntl_waitpid($pid, $status);
		return $out;
	}

	/** Issue #4191: a write a full disk cuts short publishes nothing: the previous mirror stays whole and nothing is left staged. */
	public function testWriteCanonicalAliasCutShortKeepsThePreviousMirror(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_setrlimit')) {
			$this->markTestSkipped('pcntl and posix are required to cut a write short.');
		}
		$path = "{$this->tmp}/pfB_Full_v4.txt";
		file_put_contents($path, "10.0.0.1\n");
		$set = [];
		for ($i = 0; $i < 2000; $i++) {
			$set[] = '192.0.' . intdiv($i, 250) . '.' . ($i % 250);
		}

		$this->assertSame('false', self::cutShort(4096, static fn (): bool => pfb_write_canonical_alias($path, $set)));

		$this->assertSame("10.0.0.1\n", file_get_contents($path));
		$this->assertSame(['pfB_Full_v4.txt'], array_values(array_diff(scandir($this->tmp), ['.', '..'])));
	}

	/** Issue #4191: the apply writes no list into the alias folder itself; every mirror goes through pfb_write_canonical_alias(). */
	public function testTheApplyCopiesNoListIntoTheAliasFolderInPlace(): void
	{
		$apply = (string) php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertSame(0, preg_match_all('/\b(?:copy|file_put_contents|fopen)\s*\([^;]*aliasdir/', $apply));
	}
}
