<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3515 -- a package removal must stop while pfB-DNS still holds the Resolver.
 *
 * When the Resolver cannot be put back (another config save holds the lock, config.xml cannot be re-read, or the proxy
 * outlived its stop), the Resolver stays moved and its snapshot is the only way back. The rest of the removal destroys
 * the recovery path: the pending-changes marker, the generated files and (Keep Settings off) the whole package config,
 * snapshot included, and pkg then deletes the proxy and observer code the moved Resolver depends on.
 *
 * pfSense ignores what the hook returns (rc.packages runs it through eval_once() and exits 0), and pkg(8) only logs a
 * failed DEINSTALL script and removes the files anyway; the one status that makes pkg abandon the removal is 3
 * (libpkg pkg_script_run_child()). So the hook returns FALSE and the package XML exits with PFB_PKG_REMOVAL_ABORT.
 *
 * Each case runs the shipped hook in a private child process (support/PackageRemovalWorker.php) through the XML text that
 * pfSense evaluates, and observes what survives. The `none` case proves the observations can fail: with the Resolver
 * restored the same removal destroys them. The staged observer files are removed by `pfblockerng.sh dnsbl_cache teardown`,
 * an absolute path that cannot be sandboxed here: it comes after the pending-changes clear this test observes.
 */
final class DnsProxyUninstallAbortTest extends TestCase
{
	/** The status pkg(8) treats as "stop, leave the package installed". */
	private const PKG_ABORT = 3;

	/** @return array{returned:bool,snapshot:bool,interface:?string,sections:list<string>,pending:bool,dbCanary:bool,logCanary:bool,rcScript:bool,lockHeld:bool,notices:list<string>,exit:int} */
	private function removal(string $failure, string $keep): array
	{
		$dir = sys_get_temp_dir() . '/pfb_removal_abort_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([
				PHP_BINARY, __DIR__ . '/support/PackageRemovalWorker.php',
				(string) json_encode(['failure' => $failure, 'keep' => $keep]), $result,
			], 120.0);
			$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}");
			return ['exit' => $process['exit']] + json_decode((string) file_get_contents($result), TRUE, 512, JSON_THROW_ON_ERROR);
		} finally {
			@unlink($result);
			@rmdir($dir);
		}
	}

	/** @return array<string,array{string,string}> */
	public static function unrestorableResolver(): array
	{
		$cases = [];
		foreach (['lock' => 'config.xml is locked by another save', 'read' => 'config.xml cannot be re-read', 'survivor' => 'the proxy outlived its stop'] as $failure => $why) {
			foreach (['on' => 'Keep Settings on', 'off' => 'Keep Settings off'] as $keep => $label) {
				$cases["{$why}, {$label}"] = [$failure, $keep];
			}
		}
		return $cases;
	}

	#[DataProvider('unrestorableResolver')]
	public function testRemovalStopsWithPkgsAbortStatusAndKeepsEverythingTheMovedResolverNeeds(string $failure, string $keep): void
	{
		$removal = $this->removal($failure, $keep);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the package hook exits with the one status that makes pkg abandon the removal');
		$this->assertFalse($removal['returned'], 'and never returns into the rest of the removal');
		$this->assertTrue($removal['snapshot'], 'the Resolver snapshot is kept');
		$this->assertSame('lo0', $removal['interface'], 'the Resolver is untouched: still moved');
		$this->assertContains('pfblockerngdns', $removal['sections'], 'the section holding the snapshot is not wiped');
		$this->assertContains('pfblockerngipsettings', $removal['sections'], 'nor any other package section');
		$this->assertTrue($removal['pending'], 'the pending-changes marker, the first thing the teardown clears, is still there');
		$this->assertTrue($removal['dbCanary'], 'the package data directory is kept');
		$this->assertTrue($removal['logCanary'], 'so is the log directory');
		$this->assertTrue($removal['rcScript'], 'the proxy\'s rc script is kept');
		$this->assertFalse($removal['lockHeld'], 'no config lock is left held');
		$this->assertNotSame([], array_filter($removal['notices'], static fn (string $notice): bool => str_contains($notice, 'removal was stopped')
			&& str_contains($notice, 'remove the package again')), 'the operator is told the removal stopped and what to do: ' . json_encode($removal['notices']));
	}

	/** @return array<string,array{string}> */
	public static function keepSettings(): array
	{
		return ['Keep Settings on' => ['on'], 'Keep Settings off' => ['off']];
	}

	#[DataProvider('keepSettings')]
	public function testRemovalOfARestorableResolverStillTearsDownAndExitsCleanly(string $keep): void
	{
		$removal = $this->removal('none', $keep);

		$this->assertSame(0, $removal['exit'], 'a removal that restored the Resolver is not aborted');
		$this->assertTrue($removal['returned']);
		$this->assertFalse($removal['snapshot'], 'the snapshot was used and cleared');
		$this->assertNotSame('lo0', $removal['interface'], 'the Resolver is back on the user\'s interfaces');
		$this->assertFalse($removal['pending'], 'the teardown ran: the pending-changes marker is cleared');
		$this->assertFalse($removal['rcScript'], 'the proxy\'s rc script is removed');
		$this->assertSame($keep === 'on', $removal['dbCanary'], 'the data directory goes only with Keep Settings off');
		$this->assertSame($keep === 'on', $removal['logCanary'], 'so does the log directory');
		$this->assertSame($keep === 'on', in_array('pfblockerngipsettings', $removal['sections'], TRUE), 'and the package config sections');
		$this->assertSame([], $removal['notices'], 'no notice: nothing went wrong');
	}
}
