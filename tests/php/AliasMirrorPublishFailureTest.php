<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * Issue #4191 (CodeRabbit on PR #4207): an alias mirror that cannot be published must not pass for one that was. The GeoIP
 * branch keeps its change detectable for the next pass, the ADR-40 branch does not queue the alias for a reload, and a stage
 * that tempnam() could not create beside its target is refused before anything is written to it.
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

	/** Runs the GeoIP branch that publishes changed continent data, with new data staged at geoip_tmp. @return array<string, mixed> */
	private function publishGeoip(): array
	{
		$tmp = "{$this->dir}/geoip_tmp";
		file_put_contents($tmp, "192.0.2.0/24\n");
		file_put_contents("{$this->dir}/orig/pfB_Europe_v4.orig", "198.51.100.0/24\n");
		return pfb_test_page_eval(
			pfb_test_page_region(self::APPLY, "if (\$continent != 'md5_0') {", '// Check if file exists and is > 0 in size and save alias file'),
			[
				'continent' => 'new md5', 'cc_alias' => 'pfB_Europe_v4', 'vtype' => '_v4', 'elog' => '', 'pfbadv' => FALSE,
				'pfborig' => "{$this->dir}/orig", 'pfbfolder' => "{$this->dir}/folder",
				'pfb' => ['geoip_tmp' => $tmp, 'aliasdir' => "{$this->dir}/alias", 'agg' => PfbToggle::Off, 'script' => '/nonexistent'],
			]
		);
	}

	public function testAGeoipMirrorPublishedKeepsTheNewBaseline(): void
	{
		$this->publishGeoip();

		$this->assertSame("192.0.2.0/24\n", file_get_contents("{$this->dir}/orig/pfB_Europe_v4.orig"));
		$this->assertSame("192.0.2.0/24\n", file_get_contents("{$this->dir}/alias/pfB_Europe_v4.txt"));
	}

	/**
	 * The baseline the next pass compares the GeoIP data with must not vouch for data the alias mirror never received: it is
	 * dropped, so the next pass finds the data changed and publishes again.
	 */
	public function testAGeoipMirrorThatCannotBePublishedLeavesItsChangeDetectable(): void
	{
		$this->assertTrue(mkdir("{$this->dir}/alias/pfB_Europe_v4.txt"), 'setup: a folder in the mirror\'s place makes its publication fail');

		$this->publishGeoip();

		$this->assertFileDoesNotExist("{$this->dir}/orig/pfB_Europe_v4.orig", 'a baseline for unpublished data hides the change from the next pass');
	}

	/** Runs the ADR-40 branch for one alias whose set differs from its mirror. @return array<string, mixed> */
	private function applyCanonicalSet(string $mirror): array
	{
		return pfb_test_page_eval(
			pfb_test_page_region(self::APPLY, '$canonical_set = pfb_canonical_alias_set($alias_ips);', '// When set is unchanged: aliasdir file is already correct; no reload needed.'),
			[
				'alias_ips' => "192.0.2.1\n192.0.2.2\n", 'alias_mirror' => $mirror, 'pfctlck' => '2', 'alias' => 'pfB_Test_v4',
				'pfb_alias_prev_sets' => [], 'pfb_alias_lists' => [],
			]
		);
	}

	public function testAnAliasWhoseMirrorIsWrittenIsQueuedForReload(): void
	{
		$mirror = "{$this->dir}/alias/pfB_Test_v4.txt";
		file_put_contents($mirror, "192.0.2.1\n");

		$scope = $this->applyCanonicalSet($mirror);

		$this->assertSame(['pfB_Test_v4'], $scope['pfb_alias_lists']);
		$this->assertSame("192.0.2.1\n192.0.2.2\n", file_get_contents($mirror));
	}

	/** An alias whose mirror still holds the previous set is not reported as updated. */
	public function testAnAliasWhoseMirrorCannotBeWrittenIsNotQueuedForReload(): void
	{
		$mirror = "{$this->dir}/alias/pfB_Test_v4.txt";
		$this->assertTrue(mkdir($mirror), 'setup: a folder in the mirror\'s place makes its write fail');

		$scope = $this->applyCanonicalSet($mirror);

		$this->assertSame([], $scope['pfb_alias_lists']);
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
