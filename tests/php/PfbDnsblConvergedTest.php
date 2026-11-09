<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 3 — pfb_dnsbl_converged() truth table.
 *
 * TRUE iff (a) the sentinel/applied generation markers agree (or neither has
 * ever been written -- both default to 0) AND (b) the DNS proxy hosts the module
 * (pfB-DNS owns the Resolver with DNSBL on) and is running: Unbound never hosts it
 * (issue #3770). The function short-circuits on the first failing condition, so a
 * mismatch on (a) makes (b) irrelevant to the result -- that case is exercised
 * with (b) deliberately left passing, to prove the mismatch alone forces FALSE.
 *
 * Also covers pfb_unbound_py_marker_generation()'s remaining return-0 shapes
 * DIRECTLY (issue #1024): the truth table above only reaches it through the
 * "neither marker file exists" case. Of the four input shapes named in #1024
 * (absent, unreadable, blank, non-digit), only "non-digit" is independently
 * observable via a return-value assertion -- "absent"/"unreadable"/"blank" all
 * funnel through the SAME downstream ctype_digit('')-is-FALSE catch-all, so no
 * assertion can attribute their shared 0 result to one specific guard over another.
 * "unreadable" and "blank" each still get an honestly-scoped regression-pinning test
 * below; "absent" continues to rely on the truth table's own indirect coverage above.
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
	private bool $hadConfig = FALSE;
	private array $savedConfig = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_dnsbl_converged_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		foreach (['dnsbldir', 'enable', 'dnsbl'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		$GLOBALS['pfb']['dnsbldir'] = $this->dir;
		$GLOBALS['pfb']['enable'] = $GLOBALS['pfb']['dnsbl'] = PfbToggle::On;

		// pfB-DNS owns the Resolver (a snapshot) and its proxy runs: the module host
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['config'] ??= [];
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl' => ['present' => FALSE, 'value' => NULL],
			'custom_options' => ['present' => FALSE, 'value' => NULL],
		])));
		$GLOBALS['pfb_test_valid_pids'] = ['/var/run/pfb_dns_proxy.pid' => TRUE];
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
		unset($GLOBALS['pfb_test_valid_pids']);
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}

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

	public function testSentinelEqualsAppliedAndTheProxyRuns_returnsTrue(): void
	{
		$this->writeSentinel(3);
		$this->writeApplied(3);

		$this->assertTrue(pfb_dnsbl_converged(), 'matching non-zero generations + a running module host must converge');
	}

	public function testNeitherMarkerFileExists_defaultsToZeroEqualsZero_convergedWhenTheProxyRuns(): void
	{
		// Neither pfb_py_reload nor .applied exists yet (DNSBL never flipped this boot) --
		// the shared "0 == 0" baseline both markers' read helper defaults to.
		$this->assertTrue(pfb_dnsbl_converged(), 'a never-flipped sentinel/applied pair (both absent) must read as converged');
	}

	public function testSentinelNotEqualApplied_returnsFalseRegardlessOfOtherConditions(): void
	{
		$this->writeSentinel(5);
		$this->writeApplied(3);
		// The proxy runs -- proves the generation mismatch ALONE forces FALSE.

		$this->assertFalse(pfb_dnsbl_converged(), 'a sentinel/applied generation mismatch must never converge');
	}

	public function testTheProxyNotRunning_returnsFalseEvenWhenGenerationsMatch(): void
	{
		$this->writeSentinel(2);
		$this->writeApplied(2);
		$GLOBALS['pfb_test_valid_pids']['/var/run/pfb_dns_proxy.pid'] = FALSE;

		$this->assertFalse(pfb_dnsbl_converged(), 'a stopped module host must never converge, even with matching generations');
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

		$path = "{$this->dir}/unreadable_marker";
		file_put_contents($path, "5\n");
		chmod($path, 0000);

		try {
			$this->assertSame(0, pfb_test_as_unprivileged(
				fn () => pfb_unbound_py_marker_generation($path),
				[$this->dir]
			), 'an existing-but-unreadable marker (file_get_contents() FALSE) must read as generation 0, never crash');
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

	public function testMarkerGenerationSignPrefixedFirstLine_returnsZero(): void
	{
		// ctype_digit() is strict digits-only, unlike the looser is_numeric() (which
		// accepts a sign/exponent) -- this fixture would survive an accidental
		// ctype_digit() -> is_numeric() swap if it only asserted "12abc" above.
		$positive = "{$this->dir}/plus_marker";
		file_put_contents($positive, "+5\n");

		$negative = "{$this->dir}/minus_marker";
		file_put_contents($negative, "-3\n");

		$this->assertSame(0, pfb_unbound_py_marker_generation($positive),
			'a sign-prefixed first line must fail ctype_digit() and read as generation 0');
		$this->assertSame(0, pfb_unbound_py_marker_generation($negative),
			'a negative first line must fail ctype_digit() and read as generation 0');
	}

	public function testMarkerGenerationValidDigitFirstLine_returnsParsedInt(): void
	{
		$path = "{$this->dir}/valid_marker";
		file_put_contents($path, "42\nstray second line\n");

		$this->assertSame(42, pfb_unbound_py_marker_generation($path),
			'a valid digit first line must parse to its integer value, ignoring any later lines');
	}
}
