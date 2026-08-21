<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_unbound_py_teardown_raw_set')]
final class Top1mTeardownDirectoryTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private bool $hadPfb = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->tmp = sys_get_temp_dir() . '/pfb_top1m_teardown_' . uniqid('', TRUE);
		$this->assertTrue(mkdir("{$this->tmp}/db", 0777, TRUE));
		$this->assertTrue(mkdir("{$this->tmp}/unbound", 0777, TRUE));
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'unbound_py_count'   => "{$this->tmp}/pfb_py_count",
			'unbound_py_regex_count' => "{$this->tmp}/pfb_py_regex_count",
			'unbound_py_reject_stats' => "{$this->tmp}/pfb_py_reject_stats.json",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'unbound_py_top1m'   => "{$this->tmp}/unbound/pfb_py_top1m.txt",
			'dbdir'              => "{$this->tmp}/db",
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		rmdir_recursive($this->tmp);
	}

	public function testTeardownRemovesTop1mDirectoriesFilesAndLinksWithoutTouchingLiveData(): void
	{
		$base = "{$GLOBALS['pfb']['dbdir']}/top-1m.csv.zip";
		$fixed = $GLOBALS['pfb']['unbound_py_top1m'];
		$exactArtifacts = [
			$fixed,
			"{$base}.orig",
			"{$base}.xxhash128",
			"{$base}.md5",
			"{$base}.source",
			"{$base}.orig.etag",
			"{$base}.orig.lastmod",
			"{$GLOBALS['pfb']['dbdir']}/.pfbtop1m_active_file",
			dirname($fixed) . '/.pfbtop1m_prev_file',
		];
		foreach ($exactArtifacts as $artifact) {
			$this->assertNotFalse(file_put_contents($artifact, 'owned'), "seed {$artifact}");
		}

		$dbStage = "{$GLOBALS['pfb']['dbdir']}/.pfbtop1m_base_nonempty";
		$fixedStage = dirname($fixed) . '/.pfbtop1m_stage_nonempty';
		$this->assertTrue(mkdir("{$dbStage}/nested", 0777, TRUE));
		$this->assertNotFalse(file_put_contents("{$dbStage}/nested/raw", 'owned'));
		$this->assertTrue(mkdir($fixedStage, 0777, TRUE));
		$this->assertNotFalse(file_put_contents("{$fixedStage}/candidate", 'owned'));

		$linkTarget = "{$this->tmp}/link-target";
		$this->assertTrue(mkdir($linkTarget));
		$this->assertNotFalse(file_put_contents("{$linkTarget}/keep", 'keep'));
		$link = "{$GLOBALS['pfb']['dbdir']}/.pfbtop1m_link";
		$this->assertTrue(symlink($linkTarget, $link));

		$preserved = [
			"{$GLOBALS['pfb']['dbdir']}/top-1m.csv",
			"{$GLOBALS['pfb']['dbdir']}/pfbalexawhitelist.txt",
			"{$GLOBALS['pfb']['dbdir']}/top-1m.csv.zip.orig.neighbor",
			"{$GLOBALS['pfb']['dbdir']}/pfbtop1m_decoy",
			"{$this->tmp}/.pfbtop1m_outside",
		];
		foreach ($preserved as $path) {
			$this->assertNotFalse(file_put_contents($path, 'keep'), "seed {$path}");
		}

		$this->assertDirectoryExists($dbStage, 'before-state: db staging directory');
		$this->assertDirectoryExists($fixedStage, 'before-state: fixed-file staging directory');
		$this->assertTrue(is_link($link), 'before-state: narrow symlink');
		$this->assertTrue(pfb_unbound_py_teardown_raw_set(), 'teardown must remove every narrow TOP1M artifact');

		foreach ($exactArtifacts as $artifact) {
			$this->assertFalse(file_exists($artifact) || is_link($artifact), "removed {$artifact}");
		}
		$this->assertDirectoryDoesNotExist($dbStage);
		$this->assertDirectoryDoesNotExist($fixedStage);
		$this->assertFalse(file_exists($link) || is_link($link), 'symlink removed without following it');
		$this->assertSame('keep', file_get_contents("{$linkTarget}/keep"), 'symlink target preserved');
		foreach ($preserved as $path) {
			$this->assertSame('keep', file_get_contents($path), "preserved {$path}");
		}
		$this->assertTrue(pfb_unbound_py_teardown_raw_set(), 'second teardown is idempotent');
	}

	/**
	 * issue #2607: every pfb_py_* artifact Python emits describes the generation the manifest
	 * defines, and Python rewrites them only for a build that produced a snapshot — so none of
	 * them may survive the manifest's teardown. Left behind, each is read back as live:
	 * pfb_py_count by the update log and by pfb_unbound_py_swap_fits_ram(), which sizes the
	 * zero-downtime swap's RAM projection from it; pfb_py_reject_stats by
	 * pfb_emit_entry_reject_stats(), which replays a dead generation's stage=entries lines;
	 * pfb_py_regex_count by the DNSBL_Regex alias count. After a `pkg delete` + reinstall all
	 * three describe a snapshot that is no longer loaded.
	 */
	public function testTeardownRemovesEveryEmittedArtifactAlongsideTheManifest(): void
	{
		$manifest = $GLOBALS['pfb']['unbound_py_sources'];
		$emitted = [
			'count' => $GLOBALS['pfb']['unbound_py_count'],
			'regex count' => $GLOBALS['pfb']['unbound_py_regex_count'],
			'reject tally' => $GLOBALS['pfb']['unbound_py_reject_stats'],
		];
		$this->assertNotFalse(file_put_contents($manifest, '{"feeds":[]}'), "seed {$manifest}");
		$this->assertNotFalse(file_put_contents($emitted['count'], "11732\n"));
		$this->assertNotFalse(file_put_contents($emitted['regex count'], "4\n"));
		$this->assertNotFalse(file_put_contents($emitted['reject tally'],
			'[{"feed":"StaleFeed","group":"StaleGroup","shape":3}]'));

		foreach ($emitted as $label => $path) {
			$this->assertFileExists($path, "before-state: the emitted {$label} is on disk");
		}
		$this->assertTrue(pfb_unbound_py_teardown_raw_set());

		$this->assertFileDoesNotExist($manifest, 'the teardown removes the manifest');
		foreach ($emitted as $label => $path) {
			$this->assertFileDoesNotExist($path,
				"the emitted {$label} must not outlive the manifest generation it describes");
		}
	}
}
