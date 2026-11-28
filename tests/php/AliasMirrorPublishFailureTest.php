<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issues #4191 and #4213: an alias mirror that cannot be published must not pass for one that was. A stage that tempnam()
 * could not create beside its target is refused before anything is written to it.
 */
final class AliasMirrorPublishFailureTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_alias_publish_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0777, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
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
