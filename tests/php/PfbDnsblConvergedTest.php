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
 * Function under test: pfb_dnsbl_converged(): bool (pfblockerng.inc).
 */
#[CoversFunction('pfb_dnsbl_converged')]
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
}
