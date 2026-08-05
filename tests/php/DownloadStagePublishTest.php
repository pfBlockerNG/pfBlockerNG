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

		$this->assertSame($this->dir, dirname($seen));
		$this->assertNotSame($target, $seen);
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
		// containment matcher would dump all of it into the failure output.
		$this->assertSame(0, substr_count($source, '> {$file_org_esc}'),
			'a decompress branch still redirects onto the live .orig publication');
		$this->assertSame(1, substr_count($source, '> {$header_esc}'),
			'expected exactly one redirect onto {$header_esc}: the TOP1M branch, which '
			. 'reassigns that variable to its own staged path first');
	}
}
