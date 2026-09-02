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
	 * exec, real Unbound control) and is not loadable by the unit harness. The pin therefore
	 * scans executable tokens only; comments/docblocks cannot satisfy it.
 */
final class InstallDnsblMoveRestartGuardTest extends TestCase
{
	private static function installSource(): string
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
		$src = @php_strip_whitespace($path);
		self::assertNotSame('', $src, "could not read {$path}");
		return $src;
	}

	/**
	 * Given the dnsbl-sqlite-move block, the restart guard it tests ($ufound) is reset
	 * to FALSE before the move attempts — so the restart fires iff THIS block moved a file.
	 */
	public function testDnsblMoveBlockResetsRestartGuardBeforeUse(): void
	{
		$src = self::installSource();

		$start = strpos($src, "\$ufound = FALSE; if (file_exists('/var/db/pfblockerng/dnsbl_levent.sqlite')");
		$this->assertNotFalse($start, 'the dnsbl-move migration guard reset is missing');
		$guard = strpos($src, 'pfb_stop_start_unbound', $start);
		$this->assertNotFalse($guard, 'the dnsbl-move block no longer guards a restart call');

		$section = substr($src, $start, $guard - $start);

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
	/**
	 * issue #3094: the restart's return value must be READ.
	 *
	 * `$final = pfb_stop_start_unbound('')` was assigned and never used again in that
	 * scope, so a package install could finish "successfully" with the resolver never
	 * restarted -- the refusal (#3055) surfacing only in the pfBlockerNG log. install.inc
	 * is not loadable by the harness and the update_status() double records nothing, so
	 * this is pinned the way this file pins its siblings: executable tokens only.
	 */
	public function testInstallReportsARestartThatDidNotHappen(): void
	{
		$src = self::installSource();

		$call = strpos($src, 'pfb_stop_start_unbound(\'\');');
		$this->assertNotFalse($call, 'the install restart call is missing');

		$tail = substr($src, $call);
		$read = strpos($tail, '[\'retval\']');
		$this->assertNotFalse($read,
			'the install restart return value must be read, not just assigned (#3094)');
		$report = strpos($tail, 'update_status', $read);
		$this->assertNotFalse($report,
			'a restart that did not happen must be reported to the installing user');
		$this->assertLessThan(200, $read,
			'the retval check must sit at the call site, not drift into an unrelated block');
	}
}
