<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_download() publishes decompressed feed output through a staged file, so a
 * failed extraction cannot truncate the publication already in service.
 *
 * pfb_download() itself is not off-appliance unit-testable (ADR §5), so the
 * behaviour is covered at the pfb_stage_publish() boundary and the call sites are
 * pinned by source inspection.
 */
#[CoversFunction('pfb_stage_publish')]
final class DownloadStagePublishTest extends TestCase
{
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb stage; ' . getmypid() . " 'fixture'";
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testSuccessfulExtractionPublishesTheStagedContent(): void
	{
		$target = "{$this->dir}/feed.orig";
		$this->assertTrue(pfb_stage_publish($target, static function (string $staged): int {
			file_put_contents($staged, "fresh-data\n");
			return 0;
		}));

		$this->assertSame("fresh-data\n", file_get_contents($target));
	}

	public function testFailedExtractionKeepsThePublicationInService(): void
	{
		$target = "{$this->dir}/feed.orig";
		$this->assertNotFalse(file_put_contents($target, "last-good\n"));
		$this->assertSame("last-good\n", file_get_contents($target));

		$this->assertFalse(pfb_stage_publish($target, static function (string $staged): int {
			file_put_contents($staged, 'truncated-gar');
			return 1;
		}));

		$this->assertSame("last-good\n", file_get_contents($target));
	}

	public function testFailedExtractionWithNoPriorPublicationWritesNothing(): void
	{
		$target = "{$this->dir}/fresh.orig";
		$this->assertFalse(pfb_stage_publish($target, static function (string $staged): int {
			file_put_contents($staged, 'partial');
			return 1;
		}));

		$this->assertFileDoesNotExist($target);
	}

	public function testFailedExtractionLeavesNoStagedFileBehind(): void
	{
		$target = "{$this->dir}/litter.orig";
		pfb_stage_publish($target, static function (string $staged): int {
			file_put_contents($staged, 'partial');
			return 1;
		});

		$this->assertSame([], glob("{$this->dir}/*"));
	}

	/** Staging beside the target is what makes the publication a same-filesystem rename. */
	public function testStagedPathSitsBesideTheTargetAndIsNotTheTarget(): void
	{
		$target = "{$this->dir}/feed.orig";
		$seen = '';
		pfb_stage_publish($target, static function (string $staged) use (&$seen): int {
			$seen = $staged;
			file_put_contents($staged, "x\n");
			return 0;
		});

		// realpath() on both sides -- macOS resolves sys_get_temp_dir() through a
		// /var -> /private/var symlink and tempnam() hands back the resolved path,
		// so the raw strings differ on the prefix while naming the same directory
		// (issue #2192).
		$this->assertSame(realpath($this->dir), realpath(dirname($seen)));
		$this->assertNotSame($target, $seen);
	}

	/**
	 * The same-filesystem invariant is about the directory, never about how the
	 * caller spelled it. Reaching the target through a symlink makes the resolved
	 * and unresolved forms differ on EVERY platform, so this pins the comparison
	 * that macOS was the only platform to fail (issue #2192).
	 */
	public function testStagedPathSitsBesideATargetReachedThroughASymlink(): void
	{
		$link = "{$this->dir}/via-symlink";
		$this->assertTrue(symlink($this->dir, $link));

		$target = "{$link}/feed.orig";
		$seen   = '';
		$this->assertTrue(pfb_stage_publish($target, static function (string $staged) use (&$seen): int {
			$seen = $staged;
			file_put_contents($staged, "x\n");
			return 0;
		}));

		// The vacuity guard: without it the assertion below could pass on a fixture
		// whose two spellings were already identical, pinning nothing. Compared
		// against $link, never $this->dir -- $this->dir is already canonical on a
		// Linux runner, which would let an unresolved comparison pass there.
		$this->assertNotSame($link, dirname($seen),
			'setup: the symlinked target must spell its directory differently from the staged path');
		$this->assertSame(realpath($link), realpath(dirname($seen)));
	}

	/** A staged file published at tempnam's 0600 would hide the feed from its readers. */
	public function testPublishedFileIsWorldReadable(): void
	{
		$target = "{$this->dir}/perm.orig";
		$this->assertTrue(pfb_stage_publish($target, static function (string $staged): int {
			file_put_contents($staged, "data\n");
			return 0;
		}));

		$this->assertSame('0644', substr(sprintf('%o', fileperms($target)), -4));
	}

	public function testExtractorReturningSuccessWithoutOutputStillPublishes(): void
	{
		$target = "{$this->dir}/empty.orig";
		$this->assertTrue(pfb_stage_publish($target, static function (string $staged): int {
			file_put_contents($staged, '');
			return 0;
		}));

		$this->assertSame('', file_get_contents($target));
	}

	/**
	 * The ZIP inner-content gate unlinks whatever it probes, so the piped SFS/hpHosts
	 * branch must probe its staged copy: probing after publication would delete the
	 * publication the staging exists to protect.
	 */
	public function testPipedZipBranchValidatesContentBeforePublishing(): void
	{
		$source = file_get_contents(self::INC);
		$this->assertNotFalse($source);

		$open = strpos($source, 'if (!pfb_stage_publish($orig_download,'
			. "\n\t\t\t\t    static function (string \$staged) use (\$file_dwn_esc, \$list_download,");
		$this->assertNotFalse($open,
			'the piped ZIP branch no longer stages with the list URL in scope for its MIME probe');

		$close = strpos($source, '})) {', $open);
		$this->assertNotFalse($close);
		$callback = substr($source, $open, $close - $open);

		// The probe's VERDICT must gate the publication. Asserting only that the
		// constant appears passes while the call's result is computed and discarded,
		// which republishes the rejected content and loses the previous file.
		$this->assertMatchesRegularExpression(
			'/if \(!pfb_filter\(\s*array\(escapeshellarg\(\$staged\), \$staged, \$list_download\),'
			. '\s*PFB_FILTER_FILE_MIME[^)]*\)\) \{\s*\$inner_rejected = TRUE;\s*return [^;]+;\s*\}/',
			$callback,
			'the piped ZIP branch must reject the staged content before it is published, '
			. 'not merely probe it');
	}

	/**
	 * Preserving the last-good file means a failed extraction no longer leaves an
	 * empty one for the downstream MIME gate to reject, so each branch must fail the
	 * download itself rather than falling through onto the stale publication.
	 */
	public function testEveryStagedPublicationSitsInAFailureGuard(): void
	{
		$source = file_get_contents(self::INC);
		$this->assertNotFalse($source);

		// One occurrence is the definition; every other must be a guarded call.
		$occurrences = substr_count($source, 'pfb_stage_publish(');
		$this->assertGreaterThan(1, $occurrences,
			'expected the decompress branches to publish through pfb_stage_publish()');
		$this->assertSame($occurrences - 1, substr_count($source, 'if (!pfb_stage_publish('),
			'every pfb_stage_publish() call must sit directly in a failure guard');
	}

	/**
	 * The decompress branches no longer redirect onto a live publication. The
	 * gunzip-to-header form survives exactly once: the TOP1M branch, which
	 * reassigns that variable to its own staged path first (issue #1542).
	 */
	public function testDecompressBranchesNoLongerRedirectOntoLiveFiles(): void
	{
		$source = file_get_contents(self::INC);
		$this->assertNotFalse($source);

		// Counted, never matched against the haystack: this file is ~700 KB and a
		// containment matcher would dump all of it into the failure output. Matched
		// with \s* so respacing the redirect cannot smuggle one of these back in.
		$this->assertSame(0, preg_match_all('/>\s*\{\$file_org_esc\}/', $source),
			'a decompress branch still redirects onto the live .orig publication');
		$this->assertSame(1, preg_match_all('/>\s*\{\$header_esc\}/', $source),
			'expected exactly one redirect onto {$header_esc}: the TOP1M branch, which '
			. 'reassigns that variable to its own staged path first');
	}
}
