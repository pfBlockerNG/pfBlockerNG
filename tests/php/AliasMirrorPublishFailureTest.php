<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * Issues #4191 and #4213: an alias mirror that cannot be published must not pass for one that was. The ADR-40 gate the IP
 * lists and the GeoIP continents share (pfb_alias_mirror_gate()) queues an alias only once its mirror is written, the
 * continent pass keeps a failed continent detectable for the next pass, and a stage that tempnam() could not create beside
 * its target is refused before anything is written to it.
 */
final class AliasMirrorPublishFailureTest extends TestCase
{
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_alias_publish_' . bin2hex(random_bytes(6));
		foreach (['orig', 'folder', 'alias'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0777, TRUE));
		}
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/** @var array<string, mixed> */
	private array $savedPfb = [];

	/** The gate and the pfctl reads go through the global $pfb: point it at the sandbox and a pfctl that lists $count entries. */
	private function useSandbox(int $count): void
	{
		$this->savedPfb = ['aliasdir' => $GLOBALS['pfb']['aliasdir'] ?? NULL, 'pfctl' => $GLOBALS['pfb']['pfctl'] ?? NULL];
		$shim = "{$this->dir}/pfctl";
		file_put_contents($shim, "#!/bin/sh\n" . str_repeat("echo 192.0.2.250\n", $count));
		chmod($shim, 0755);
		$GLOBALS['pfb']['aliasdir'] = "{$this->dir}/alias";
		$GLOBALS['pfb']['pfctl']    = $shim;
	}

	private function restorePfb(): void
	{
		foreach ($this->savedPfb as $key => $value) {
			$GLOBALS['pfb'][$key] = $value;
		}
	}

	/** Issue #4213: a set that differs from the mirror is written and the alias queued, with the previous set for the delta. */
	public function testTheGateWritesAChangedSetAndQueuesTheAliasWithItsPreviousSet(): void
	{
		$this->useSandbox(1);
		file_put_contents("{$this->dir}/alias/pfB_Test_v4.txt", "192.0.2.1\n");
		$prev = $changed = [];

		$this->assertTrue(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.2\n192.0.2.1\n", 1, $prev, $changed));
		$this->restorePfb();

		$this->assertSame("192.0.2.1\n192.0.2.2\n", file_get_contents("{$this->dir}/alias/pfB_Test_v4.txt"));
		$this->assertSame(['pfB_Test_v4'], $changed);
		$this->assertSame(['pfB_Test_v4' => ['192.0.2.1']], $prev);
	}

	/** Issue #4213: a set the mirror already holds, with a loaded table, is neither written nor queued. */
	public function testTheGateLeavesAnUnchangedSetAlone(): void
	{
		$this->useSandbox(1);
		file_put_contents("{$this->dir}/alias/pfB_Test_v4.txt", "192.0.2.1\n");
		$inode = fileinode("{$this->dir}/alias/pfB_Test_v4.txt");
		$prev = $changed = [];

		$this->assertTrue(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.1\n", 1, $prev, $changed));
		$this->restorePfb();

		clearstatcache();
		$this->assertSame($inode, fileinode("{$this->dir}/alias/pfB_Test_v4.txt"), 'not rewritten');
		$this->assertSame([], $changed);
		$this->assertSame([], $prev);
	}

	/** Issue #4213 (#468): an empty kernel table is queued even for an unchanged set, with no previous set: a full replace. */
	public function testTheGateQueuesAnEmptyTableForAFullReplace(): void
	{
		$this->useSandbox(0);
		file_put_contents("{$this->dir}/alias/pfB_Test_v4.txt", "192.0.2.1\n");
		$prev = $changed = [];

		$this->assertTrue(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.1\n", 0, $prev, $changed));
		$this->restorePfb();

		$this->assertSame(['pfB_Test_v4'], $changed);
		$this->assertSame(['pfB_Test_v4' => []], $prev);
	}

	/** Issue #4191: an alias whose mirror still holds the previous set is not reported as updated. */
	public function testTheGateDoesNotQueueAnAliasWhoseMirrorCannotBeWritten(): void
	{
		$this->useSandbox(1);
		$this->assertTrue(mkdir("{$this->dir}/alias/pfB_Test_v4.txt"), 'setup: a folder in the mirror\'s place makes its write fail');
		$prev = $changed = [];

		$this->assertFalse(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.1\n", 1, $prev, $changed));
		$this->restorePfb();

		$this->assertSame([], $changed);
	}

	/**
	 * Runs the apply's continent pass over one continent alias whose members (the GeoIP block's output) hold a new network.
	 *
	 * @param list<string> $feedChanged the aliases the download loop changed this pass
	 * @return array<string, mixed>
	 */
	private function continentPass(int $kernelEntries, array $feedChanged): array
	{
		file_put_contents("{$this->dir}/folder/pfB_Europe_v4.txt", "192.0.2.0/24\n198.51.100.0/24\n");
		file_put_contents("{$this->dir}/orig/pfB_Europe_v4.orig", "192.0.2.0/24\n198.51.100.0/24\n");
		$this->useSandbox($kernelEntries);
		try {
			return pfb_test_page_eval(
				pfb_test_page_region(self::APPLY, 'foreach ($pfb_geoip_mirrors as $alias => $geoip) {', '#########################################################################'),
				[
					'pfb_geoip_mirrors'   => ['pfB_Europe_v4' => ['members' => "{$this->dir}/folder/pfB_Europe_v4.txt", 'orig' => "{$this->dir}/orig/pfB_Europe_v4.orig"]],
					'pfb_cross_list'      => FALSE,
					'final_alias_old'     => $feedChanged,
					'pfb_alias_prev_sets' => [],
					'pfb_alias_lists'     => [],
				]
			);
		} finally {
			$this->restorePfb();
		}
	}

	/** Issue #4213: a continent the GeoIP block changed this pass is published and queued for reload; its baseline stays. */
	public function testAChangedContinentIsPublishedAndQueuedForReload(): void
	{
		file_put_contents("{$this->dir}/alias/pfB_Europe_v4.txt", "192.0.2.0/24\n");

		$scope = $this->continentPass(1, ['pfB_Europe_v4']);

		$this->assertSame(['pfB_Europe_v4'], $scope['pfb_alias_lists']);
		$this->assertSame(['pfB_Europe_v4' => ['192.0.2.0/24']], $scope['pfb_alias_prev_sets']);
		$this->assertSame("192.0.2.0/24\n198.51.100.0/24\n", file_get_contents("{$this->dir}/alias/pfB_Europe_v4.txt"));
		$this->assertFileExists("{$this->dir}/orig/pfB_Europe_v4.orig");
	}

	/**
	 * Issue #4191, kept by #4213: a continent mirror that cannot be written drops the GeoIP baseline, so the next pass finds
	 * the data changed and publishes again.
	 */
	public function testAContinentMirrorThatCannotBeWrittenLeavesItsChangeDetectable(): void
	{
		$this->assertTrue(mkdir("{$this->dir}/alias/pfB_Europe_v4.txt"), 'setup: a folder in the mirror\'s place makes its write fail');

		$scope = $this->continentPass(1, ['pfB_Europe_v4']);

		$this->assertSame([], $scope['pfb_alias_lists']);
		$this->assertFileDoesNotExist("{$this->dir}/orig/pfB_Europe_v4.orig", 'a baseline for an unpublished mirror hides the change from the next pass');
	}

	/** Issue #4213: a continent outside this pass's scope (unchanged, its table loaded, no cross-list work) is left alone. */
	public function testAContinentOutsideThePassScopeIsLeftAlone(): void
	{
		file_put_contents("{$this->dir}/alias/pfB_Europe_v4.txt", "192.0.2.0/24\n");

		$scope = $this->continentPass(1, []);

		$this->assertSame([], $scope['pfb_alias_lists']);
		$this->assertSame("192.0.2.0/24\n", file_get_contents("{$this->dir}/alias/pfB_Europe_v4.txt"));
	}

	/**
	 * tempnam() falls back to the system temporary folder when it cannot create the stage beside the target (a missing or
	 * inode-exhausted folder); a rename from there would be a copy over the target. Such a stage is refused before the
	 * extractor writes to it, as pfb_stage_publish_dir_merge() refuses one.
	 */
	public function testAStageOutsideTheTargetsFolderIsRefusedBeforeAnythingIsWrittenToIt(): void
	{
		$written = [];

		$ok = pfb_stage_publish("{$this->dir}/missing/pfB_Test_v4.txt", static function (string $staged) use (&$written): int {
			$written[] = $staged;
			return 0;
		});

		$this->assertFalse($ok);
		$this->assertSame([], $written, 'the extractor ran on a stage outside the target\'s folder');
	}
}
