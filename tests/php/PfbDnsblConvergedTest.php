<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 3 — pfb_dnsbl_converged() truth table.
 *
 * TRUE iff (a) the sentinel/applied generation markers agree (or neither has
 * ever been written -- both default to 0), (b) is_process_running('unbound'),
 * AND (c) unbound.conf still references pfb_unbound.py. The function
 * short-circuits on the first failing condition, so a mismatch on (a) makes
 * (b)/(c) irrelevant to the result -- each collapsed case below is exercised
 * with the LATER conditions deliberately left passing, to prove the EARLIER
 * failing condition alone forces FALSE.
 *
 * Also covers pfb_unbound_py_marker_generation()'s remaining return-0 shapes
 * DIRECTLY (issue #1024): the truth table above only reaches it through the
 * "neither marker file exists" case. Of the four input shapes named in #1024
 * (absent, unreadable, blank, non-digit), only "non-digit" is independently
 * observable via a return-value assertion -- "absent"/"unreadable"/"blank" all
 * funnel through the SAME downstream ctype_digit('')-is-FALSE catch-all, so no
 * assertion can attribute their shared 0 result to one specific guard over another
 * (each still gets its own regression-pinning test below, honestly scoped as such).
 *
 * Functions under test: pfb_dnsbl_converged(): bool,
 * pfb_unbound_py_marker_generation(string $path): int (pfblockerng.inc).
 */
#[CoversFunction('pfb_dnsbl_converged')]
#[CoversFunction('pfb_unbound_py_marker_generation')]
final class PfbDnsblConvergedTest extends TestCase
{
	private string $dir;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $savedPfb = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_dnsbl_converged_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		foreach (['dnsbldir'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		$GLOBALS['pfb']['dnsbldir'] = $this->dir;

		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		$this->savedPfb = [];
		unset($GLOBALS['pfb_test_process_running']);

		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function writeSentinel(int $gen): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload", "{$gen}\n");
	}

	private function writeApplied(int $gen): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "{$gen}\n");
	}

	private function writeUnboundConf(bool $referencesPfbUnbound): void
	{
		$body = $referencesPfbUnbound ? "module-config: \"python validator iterator\"\npython-script: \"/var/unbound/pfb_unbound.py\"\n"
			: "module-config: \"validator iterator\"\n";
		file_put_contents("{$this->dir}/unbound.conf", $body);
	}

	public function testSentinelEqualsAppliedRunningAndConfReferenced_returnsTrue(): void
	{
		$this->writeSentinel(3);
		$this->writeApplied(3);
		$this->writeUnboundConf(TRUE);

		$this->assertTrue(pfb_dnsbl_converged(), 'matching non-zero generations + live + wired must converge');
	}

	public function testNeitherMarkerFileExists_defaultsToZeroEqualsZero_convergedWhenRunningAndConfOk(): void
	{
		// Neither pfb_py_reload nor .applied exists yet (DNSBL never flipped this boot) --
		// the shared "0 == 0" baseline both markers' read helper defaults to.
		$this->writeUnboundConf(TRUE);

		$this->assertTrue(pfb_dnsbl_converged(), 'a never-flipped sentinel/applied pair (both absent) must read as converged');
	}

	public function testSentinelNotEqualApplied_returnsFalseRegardlessOfOtherConditions(): void
	{
		$this->writeSentinel(5);
		$this->writeApplied(3);
		// Running + wired both deliberately TRUE -- proves the generation mismatch ALONE forces FALSE.
		$this->writeUnboundConf(TRUE);

		$this->assertFalse(pfb_dnsbl_converged(), 'a sentinel/applied generation mismatch must never converge');
	}

	public function testUnboundNotRunning_returnsFalseEvenWhenGenerationsMatch(): void
	{
		$this->writeSentinel(2);
		$this->writeApplied(2);
		$this->writeUnboundConf(TRUE);
		$GLOBALS['pfb_test_process_running']['unbound'] = FALSE;

		$this->assertFalse(pfb_dnsbl_converged(), 'Unbound not running must never converge, even with matching generations');
	}

	public function testUnboundConfMissing_returnsFalse(): void
	{
		$this->writeSentinel(1);
		$this->writeApplied(1);
		// No unbound.conf written at all.

		$this->assertFalse(pfb_dnsbl_converged(), 'an absent unbound.conf must never converge');
	}

	public function testUnboundConfDoesNotReferencePfbUnboundPy_returnsFalse(): void
	{
		$this->writeSentinel(1);
		$this->writeApplied(1);
		$this->writeUnboundConf(FALSE);

		$this->assertFalse(pfb_dnsbl_converged(), 'an unbound.conf that no longer wires pfb_unbound.py must never converge');
	}

	public function testUnboundConfExistsButUnreadable_returnsFalseInsteadOfCrashing(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions -- cannot simulate an unreadable file.');
		}

		$this->writeSentinel(1);
		$this->writeApplied(1);
		$this->writeUnboundConf(TRUE);
		chmod("{$this->dir}/unbound.conf", 0000);

		try {
			// file_exists() sees the file (TOCTOU-style: present but unreadable), so
			// file_get_contents() returns FALSE -- a bare strpos(FALSE, ...) call would
			// TypeError in PHP 8+. Must degrade to FALSE, not throw.
			$this->assertFalse(pfb_dnsbl_converged(), 'an existing-but-unreadable unbound.conf must read as not converged, never crash');
		} finally {
			chmod("{$this->dir}/unbound.conf", 0644);
		}
	}

	// -----------------------------------------------------------------------
	// pfb_unbound_py_marker_generation() -- direct branch coverage (issue #1024)
	// -----------------------------------------------------------------------

	// issue #1024: "unreadable file" and "blank/whitespace first line" have no test of
	// their own beyond regression-pinning below. Both funnel through the SAME downstream
	// ctype_digit('')-is-FALSE catch-all as every other degenerate shape -- confirmed via
	// mutation that no return-value assertion can attribute the 0 result to one guard over
	// another, so a "this specific branch" claim here would be coverage theater.

	public function testMarkerGenerationUnreadableFile_returnsZeroInsteadOfCrashing(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions -- cannot simulate an unreadable file.');
		}

		$path = "{$this->dir}/unreadable_marker";
		file_put_contents($path, "5\n");
		chmod($path, 0000);

		try {
			$this->assertSame(0, pfb_unbound_py_marker_generation($path),
				'an existing-but-unreadable marker (file_get_contents() FALSE) must read as generation 0, never crash');
		} finally {
			chmod($path, 0644);
		}
	}

	public function testMarkerGenerationBlankFirstLine_returnsZero(): void
	{
		$empty = "{$this->dir}/empty_marker";
		file_put_contents($empty, '');

		$whitespace = "{$this->dir}/whitespace_marker";
		file_put_contents($whitespace, "   \n");

		$this->assertSame(0, pfb_unbound_py_marker_generation($empty),
			'a zero-byte marker file must read as generation 0');
		$this->assertSame(0, pfb_unbound_py_marker_generation($whitespace),
			'a whitespace-only first line must trim() to empty and read as generation 0');
	}

	public function testMarkerGenerationNonDigitFirstLine_returnsZero(): void
	{
		// Leading-digit-run input ("12abc"): a naive (int) cast without the ctype_digit()
		// guard would silently yield 12, not 0 -- this fixture actually discriminates the
		// guard, unlike a purely alphabetic string (which casts to 0 either way).
		$path = "{$this->dir}/non_digit_marker";
		file_put_contents($path, "12abc\n");

		$this->assertSame(0, pfb_unbound_py_marker_generation($path),
			'a non-digit first line must fail ctype_digit() and read as generation 0, never a garbage leading-digit int cast');
	}

	public function testMarkerGenerationValidDigitFirstLine_returnsParsedInt(): void
	{
		$path = "{$this->dir}/valid_marker";
		file_put_contents($path, "42\nstray second line\n");

		$this->assertSame(42, pfb_unbound_py_marker_generation($path),
			'a valid digit first line must parse to its integer value, ignoring any later lines');
	}
}
