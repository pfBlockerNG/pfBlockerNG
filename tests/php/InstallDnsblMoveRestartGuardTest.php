<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Regression guard: the "Move dnsbl_*.sqlite -> /var/unbound" migration block in
 * pfblockerng_install.inc must reset its Unbound-restart guard ($ufound) before the
 * block, so a TRUE left by an EARLIER migration block (e.g. the pfBlockerNGSuppress
 * alias upgrade) cannot leak through and trigger a spurious pfb_stop_start_unbound()
 * on a plain pkg upgrade.
 *
 * The bug: the reset was misspelled `$u_found = FALSE;` (an orphan that is assigned
 * but never read), so `$ufound` was NOT reset and carried the prior block's value
 * into the `if ($ufound) { pfb_stop_start_unbound('') }` guard.
 *
 * install.inc is a procedural migration script (host-absolute requires, sqlite,
 * exec, real Unbound control) and is not loadable by the unit harness, so this pins
 * the invariant at the source level — the same approach as the custom-sniff tests.
 */
final class InstallDnsblMoveRestartGuardTest extends TestCase
{
	private static function installSource(): string
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
		$src = @file_get_contents($path);
		self::assertIsString($src, "could not read {$path}");
		return $src;
	}

	/**
	 * Given the dnsbl-sqlite-move block, the restart guard it tests ($ufound) is reset
	 * to FALSE before the move attempts — so the restart fires iff THIS block moved a file.
	 */
	public function testDnsblMoveBlockResetsRestartGuardBeforeUse(): void
	{
		$src = self::installSource();

		// The section runs from its "Move dnsbl_levent.sqlite" header to the guarded
		// pfb_stop_start_unbound() call. NOTE: this header string is load-bearing — it
		// bounds the window this test inspects; testNoOrphanUfoundTypo() is the
		// header-independent backstop for the exact regression class.
		$start = strpos($src, '// Move dnsbl_levent.sqlite');
		$this->assertNotFalse($start, 'the "Move dnsbl_levent.sqlite" migration block is missing');
		$guard = strpos($src, 'pfb_stop_start_unbound', $start);
		$this->assertNotFalse($guard, 'the dnsbl-move block no longer guards a pfb_stop_start_unbound() call');

		$section = substr($src, $start, $guard - $start);

		// Before: $ufound = FALSE; reset must appear at the top of the block, ahead of
		// the conditional `$ufound = TRUE;` move flags — else a prior block's TRUE leaks
		// into the restart guard.
		$reset = strpos($section, '$ufound = FALSE;');
		$this->assertNotFalse($reset, 'the dnsbl-move block does not reset $ufound before its restart guard');
		$firstSet = strpos($section, '$ufound = TRUE;');
		$this->assertNotFalse($firstSet, 'expected the dnsbl-move block to set $ufound = TRUE on a move');
		$this->assertLessThan(
			$firstSet,
			$reset,
			'$ufound must be reset to FALSE BEFORE the move flags set it TRUE'
		);
	}

	/**
	 * No orphaned `$u_found` (a typo of `$ufound`) anywhere in install.inc: such a
	 * variable is assigned but never read and silently breaks the restart-guard reset.
	 */
	public function testNoOrphanUfoundTypo(): void
	{
		$this->assertStringNotContainsString(
			'$u_found',
			self::installSource(),
			'install.inc assigns $u_found — a typo of $ufound that leaves the Unbound-restart guard unreset'
		);
	}
}
