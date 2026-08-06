<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_download() publishes an extracted blacklist category through a staging
 * directory, so a failed extraction cannot destroy the category contents already
 * in service (issue #2172).
 *
 * pfb_download() itself is not off-appliance unit-testable (ADR §5), so the
 * behaviour is covered at the pfb_stage_publish_dir() boundary and the call site
 * is pinned by source inspection.
 */
#[CoversFunction('pfb_stage_publish_dir')]
final class DownloadStagePublishDirTest extends TestCase
{
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb stagedir; ' . getmypid() . " 'fixture'";
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->dir);
	}

	private function removeTree(string $path): void
	{
		foreach ($this->entries($path) as $name) {
			$child = "{$path}/{$name}";
			is_dir($child) && !is_link($child) ? $this->removeTree($child) : @unlink($child);
		}
		@rmdir($path);
	}

	/**
	 * Staging and backup directories are dot-named, and glob() never returns dot
	 * entries -- a litter assertion spelled with glob() cannot fail on leftovers.
	 */
	private function entries(string $path): array
	{
		return array_values(array_diff(scandir($path) ?: array(), array('.', '..')));
	}

	public function testSuccessfulExtractionPublishesTheStagedDirectory(): void
	{
		$target = "{$this->dir}/category";
		$this->assertTrue(pfb_stage_publish_dir($target, static function (string $staged): int {
			file_put_contents("{$staged}/cat_ads", "fresh\n");
			return 0;
		}));

		$this->assertSame("fresh\n", file_get_contents("{$target}/cat_ads"));
	}

	/** The defect: the category was wiped before anyone knew the archive extracts. */
	public function testFailedExtractionKeepsThePreviousCategoryContents(): void
	{
		$target = "{$this->dir}/category";
		$this->assertTrue(mkdir($target, 0755));
		$this->assertNotFalse(file_put_contents("{$target}/cat_ads", "last-good\n"));

		$this->assertFalse(pfb_stage_publish_dir($target, static function (string $staged): int {
			file_put_contents("{$staged}/cat_ads", 'trunc');
			return 1;
		}));

		$this->assertSame("last-good\n", file_get_contents("{$target}/cat_ads"));
	}

	public function testFailedExtractionWithNoPriorCategoryPublishesNothing(): void
	{
		$target = "{$this->dir}/category";
		$this->assertFalse(pfb_stage_publish_dir($target, static function (string $staged): int {
			file_put_contents("{$staged}/cat_ads", 'partial');
			return 1;
		}));

		$this->assertDirectoryDoesNotExist($target);
	}

	public function testFailedExtractionLeavesNoStagingDirectoryBehind(): void
	{
		$target = "{$this->dir}/category";
		pfb_stage_publish_dir($target, static function (string $staged): int {
			file_put_contents("{$staged}/cat_ads", 'partial');
			return 1;
		});

		$this->assertSame([], $this->entries($this->dir));
	}

	public function testSuccessfulPublicationLeavesNoStagingDirectoryBehind(): void
	{
		$target = "{$this->dir}/category";
		$this->assertTrue(mkdir($target, 0755));
		$this->assertNotFalse(file_put_contents("{$target}/cat_ads", "last-good\n"));

		$this->assertTrue(pfb_stage_publish_dir($target, static function (string $staged): int {
			file_put_contents("{$staged}/cat_news", "fresh\n");
			return 0;
		}));

		// Only the published category survives: no staging or backup directory is
		// left in the database directory, and the replaced contents are gone.
		$this->assertSame(['category'], $this->entries($this->dir));
		$this->assertFileDoesNotExist("{$target}/cat_ads");
	}

	/**
	 * The previous category moves aside so the staged one can take its name; if that
	 * second step does not complete, the category that was in service comes back.
	 * Driven by an extraction that reports success while leaving no staging directory
	 * to publish, which is the one way the swap fails without the backup step failing
	 * first.
	 */
	public function testAFailedSwapRestoresThePreviousCategoryContents(): void
	{
		$target = "{$this->dir}/category";
		$this->assertTrue(mkdir($target, 0755));
		$this->assertNotFalse(file_put_contents("{$target}/cat_ads", "last-good\n"));

		$this->assertFalse(pfb_stage_publish_dir($target, static function (string $staged): int {
			file_put_contents("{$staged}/cat_ads", "fresh\n");
			@unlink("{$staged}/cat_ads");
			@rmdir($staged);
			return 0;
		}));

		$this->assertSame("last-good\n", file_get_contents("{$target}/cat_ads"));
		$this->assertSame(['category'], $this->entries($this->dir),
			'the moved-aside category must not be left behind under its backup name');
	}

	/** Staging beside the target is what makes the publication a same-filesystem rename. */
	public function testStagedDirectorySitsBesideTheTargetAndIsNotTheTarget(): void
	{
		$target = "{$this->dir}/category";
		$seen = '';
		pfb_stage_publish_dir($target, static function (string $staged) use (&$seen): int {
			$seen = $staged;
			return 0;
		});

		// realpath() on both sides -- macOS resolves sys_get_temp_dir() through a
		// /var -> /private/var symlink and tempnam() hands back the resolved path,
		// so the raw strings differ on the prefix while naming the same directory
		// (issue #2192).
		$this->assertSame(realpath($this->dir), realpath(dirname($seen)));
		$this->assertNotSame($target, $seen);
	}

	/** The extractor is handed a directory that already exists, as tar -C requires. */
	public function testExtractorReceivesAnExistingEmptyDirectory(): void
	{
		$target = "{$this->dir}/category";
		$seen = '';
		pfb_stage_publish_dir($target, static function (string $staged) use (&$seen): int {
			$seen = $staged;
			return 0;
		});

		$this->assertDirectoryDoesNotExist($seen, 'the staging directory must be renamed into place');
		$this->assertDirectoryExists($target);
		$this->assertSame([], $this->entries($target));
	}

	/** A category published at tempnam's 0600 would hide the feed from its readers. */
	public function testPublishedDirectoryIsWorldReadable(): void
	{
		$target = "{$this->dir}/category";
		$this->assertTrue(pfb_stage_publish_dir($target, static function (string $staged): int {
			file_put_contents("{$staged}/cat_ads", "data\n");
			return 0;
		}));

		$this->assertSame('0755', substr(sprintf('%o', fileperms($target)), -4));
	}

	/**
	 * The category directory is never emptied before the extraction reports success,
	 * so the last-good contents survive an ENOSPC or a killed tar.
	 */
	public function testBlacklistBranchNoLongerWipesTheCategoryBeforeExtracting(): void
	{
		$source = file_get_contents(self::INC);
		$this->assertNotFalse($source);

		// Counted, never matched against the haystack: this file is ~700 KB and a
		// containment matcher would dump all of it into the failure output.
		$this->assertSame(0, preg_match_all('/rmdir_recursive\("\{\$pfb\[\'dbdir\'\]\}\/\{\$filename\}/', $source),
			'the blacklist branch still wipes the live category directory before extracting');
		$this->assertSame(0, preg_match_all('/-C \{\$filename_esc\}/', $source),
			'the blacklist branch still extracts straight into the live category directory');
	}

	/**
	 * Preserving the last-good category means a failed extraction no longer leaves an
	 * empty directory behind, so the branch must fail the download itself rather than
	 * falling through onto the stale category as a successful update.
	 */
	public function testEveryStagedDirectoryPublicationSitsInAFailureGuard(): void
	{
		$source = file_get_contents(self::INC);
		$this->assertNotFalse($source);

		// One occurrence is the definition; every other must be a guarded call.
		$occurrences = substr_count($source, 'pfb_stage_publish_dir(');
		$this->assertGreaterThan(1, $occurrences,
			'expected the blacklist branch to publish through pfb_stage_publish_dir()');
		$this->assertSame($occurrences - 1, substr_count($source, 'if (!pfb_stage_publish_dir('),
			'every pfb_stage_publish_dir() call must sit directly in a failure guard');
	}
}
