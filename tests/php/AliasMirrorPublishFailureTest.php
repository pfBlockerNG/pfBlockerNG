<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * Issues #4191 and #4213: an alias mirror that cannot be published must not pass for one that was. The ADR-40 gate the IP
 * lists and the GeoIP continents share (pfb_alias_mirror_gate()) queues an alias only once its mirror is written, the
 * GeoIP block keeps a continent it could not publish detectable for the next pass, and a stage that tempnam() could not create beside
 * its target is refused before anything is written to it.
 */
final class AliasMirrorPublishFailureTest extends TestCase
{
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private string $dir;

	/** @var array{0: bool, 1: mixed} whether the global $pfb had an aliasdir, and its value */
	private array $savedAliasdir;

	/** The gate writes through the global $pfb['aliasdir']: point it at the sandbox for each test. */
	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_alias_publish_' . bin2hex(random_bytes(6));
		foreach (['orig', 'folder', 'alias'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0777, TRUE));
		}
		$this->savedAliasdir = [array_key_exists('aliasdir', $GLOBALS['pfb'] ?? []), $GLOBALS['pfb']['aliasdir'] ?? NULL];
		$GLOBALS['pfb']['aliasdir'] = "{$this->dir}/alias";
	}

	protected function tearDown(): void
	{
		if ($this->savedAliasdir[0]) {
			$GLOBALS['pfb']['aliasdir'] = $this->savedAliasdir[1];
		} else {
			unset($GLOBALS['pfb']['aliasdir']);
		}
		rmdir_recursive($this->dir);
	}

	/** Issue #4213: a set that differs from the mirror is written and the alias queued, with the previous set for the delta. */
	public function testTheGateWritesAChangedSetAndQueuesTheAliasWithItsPreviousSet(): void
	{
		file_put_contents("{$this->dir}/alias/pfB_Test_v4.txt", "192.0.2.1\n");
		$prev = $changed = [];

		$this->assertTrue(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.2\n192.0.2.1\n", 1, $prev, $changed));

		$this->assertSame("192.0.2.1\n192.0.2.2\n", file_get_contents("{$this->dir}/alias/pfB_Test_v4.txt"));
		$this->assertSame(['pfB_Test_v4'], $changed);
		$this->assertSame(['pfB_Test_v4' => ['192.0.2.1']], $prev);
	}

	/** Issue #4213: a set the mirror already holds, with a loaded table, is neither written nor queued. */
	public function testTheGateLeavesAnUnchangedSetAlone(): void
	{
		file_put_contents("{$this->dir}/alias/pfB_Test_v4.txt", "192.0.2.1\n");
		$inode = fileinode("{$this->dir}/alias/pfB_Test_v4.txt");
		$prev = $changed = [];

		$this->assertTrue(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.1\n", 1, $prev, $changed));

		clearstatcache();
		$this->assertSame($inode, fileinode("{$this->dir}/alias/pfB_Test_v4.txt"), 'not rewritten');
		$this->assertSame([], $changed);
		$this->assertSame([], $prev);
	}

	/** Issue #4213 (#468): an empty kernel table is queued even for an unchanged set, with no previous set: a full replace. */
	public function testTheGateQueuesAnEmptyTableForAFullReplace(): void
	{
		file_put_contents("{$this->dir}/alias/pfB_Test_v4.txt", "192.0.2.1\n");
		$prev = $changed = [];

		$this->assertTrue(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.1\n", 0, $prev, $changed));

		$this->assertSame(['pfB_Test_v4'], $changed);
		$this->assertSame(['pfB_Test_v4' => []], $prev);
	}

	/** Issue #4191: an alias whose mirror still holds the previous set is not reported as updated. */
	public function testTheGateDoesNotQueueAnAliasWhoseMirrorCannotBeWritten(): void
	{
		$this->assertTrue(mkdir("{$this->dir}/alias/pfB_Test_v4.txt"), 'setup: a folder in the mirror\'s place makes its write fail');
		$prev = $changed = [];

		$this->assertFalse(pfb_alias_mirror_gate('pfB_Test_v4', "192.0.2.1\n", 1, $prev, $changed));

		$this->assertSame([], $changed);
	}

	/**
	 * Runs the GeoIP block's publication of continent alias pfB_Europe_v4, whose baseline has just advanced to a set with a
	 * new network.
	 *
	 * @param list<string> $queued the aliases the pass has queued so far (the GeoIP block queues a changed continent)
	 * @return array<string, mixed>
	 */
	private function continentPublish(int $kernelEntries, array $queued): array
	{
		file_put_contents("{$this->dir}/orig/pfB_Europe_v4.orig", "192.0.2.0/24\n198.51.100.0/24\n");
		return pfb_test_page_eval(
			pfb_test_page_region(self::APPLY, 'if (in_array($cc_alias, $pfb_alias_lists, TRUE)) {', '// Create alias config'),
			[
				'cc_alias'            => 'pfB_Europe_v4',
				'pfbfolder'           => "{$this->dir}/folder",
				'pfborig'             => "{$this->dir}/orig",
				'pfctlck'             => $kernelEntries,
				'pfb_alias_lists'     => $queued,
				'pfb_geoip_prev_sets' => [],
				'pfb_geoip_changed'   => [],
			]
		);
	}

	/** The GeoIP block's output for pfB_Europe_v4: its members with the new network. */
	private function givenMembers(): void
	{
		file_put_contents("{$this->dir}/folder/pfB_Europe_v4.txt", "192.0.2.0/24\n198.51.100.0/24\n");
	}

	/** Issue #4213: a continent the GeoIP block changed is published and queued for reload; its baseline stays. */
	public function testAChangedContinentIsPublishedAndQueuedForReload(): void
	{
		$this->givenMembers();
		file_put_contents("{$this->dir}/alias/pfB_Europe_v4.txt", "192.0.2.0/24\n");

		$scope = $this->continentPublish(1, ['pfB_Europe_v4']);

		$this->assertSame(['pfB_Europe_v4'], $scope['pfb_geoip_changed']);
		$this->assertSame(['pfB_Europe_v4' => ['192.0.2.0/24']], $scope['pfb_geoip_prev_sets']);
		$this->assertSame("192.0.2.0/24\n198.51.100.0/24\n", file_get_contents("{$this->dir}/alias/pfB_Europe_v4.txt"));
		$this->assertFileExists("{$this->dir}/orig/pfB_Europe_v4.orig");
	}

	/** Issue #4213 (#468): a continent queued for its empty kernel table is reloaded in full, even with its set unchanged. */
	public function testAContinentWithAnEmptyTableIsQueuedForAFullReplace(): void
	{
		$this->givenMembers();
		file_put_contents("{$this->dir}/alias/pfB_Europe_v4.txt", "192.0.2.0/24\n198.51.100.0/24\n");

		$scope = $this->continentPublish(0, ['pfB_Europe_v4']);

		$this->assertSame(['pfB_Europe_v4'], $scope['pfb_geoip_changed']);
		$this->assertSame(['pfB_Europe_v4' => []], $scope['pfb_geoip_prev_sets']);
	}

	/**
	 * Issue #4191, kept by #4213: a continent mirror that cannot be written drops the GeoIP baseline, so the next pass finds
	 * the data changed and publishes again.
	 */
	public function testAContinentMirrorThatCannotBeWrittenLeavesItsChangeDetectable(): void
	{
		$this->givenMembers();
		$this->assertTrue(mkdir("{$this->dir}/alias/pfB_Europe_v4.txt"), 'setup: a folder in the mirror\'s place makes its write fail');

		$scope = $this->continentPublish(1, ['pfB_Europe_v4']);

		$this->assertSame([], $scope['pfb_geoip_changed']);
		$this->assertFileDoesNotExist("{$this->dir}/orig/pfB_Europe_v4.orig", 'a baseline for an unpublished mirror hides the change from the next pass');
	}

	/** Issue #4213: members that cannot be read are not taken for an empty continent; the change stays for the next pass. */
	public function testContinentMembersThatCannotBeReadEmptyNoTable(): void
	{
		file_put_contents("{$this->dir}/alias/pfB_Europe_v4.txt", "192.0.2.0/24\n");

		$scope = $this->continentPublish(1, ['pfB_Europe_v4']);

		$this->assertSame([], $scope['pfb_geoip_changed']);
		$this->assertSame("192.0.2.0/24\n", file_get_contents("{$this->dir}/alias/pfB_Europe_v4.txt"), 'the mirror was emptied');
		$this->assertFileDoesNotExist("{$this->dir}/orig/pfB_Europe_v4.orig");
	}

	/** Issue #4213: a continent the GeoIP block did not queue (unchanged, its table loaded) is left alone. */
	public function testAContinentThePassDidNotQueueIsLeftAlone(): void
	{
		$this->givenMembers();
		file_put_contents("{$this->dir}/alias/pfB_Europe_v4.txt", "192.0.2.0/24\n");

		$scope = $this->continentPublish(1, []);

		$this->assertSame([], $scope['pfb_geoip_changed']);
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
