<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #4262 -- PHP's folder publication meets a blacklist category the Core Updater published: the category is a link
 * to its current generation (.<name>.<pid>.<8 hex>), beside its previous generation and its .<name>.lock, and possibly a
 * real folder an interrupted Go publication left aside under .pfbstagebak2_<name> (go/pfb_core/feedfetch replaceDir).
 *
 * pfb_stage_publish_dir() and pfb_stage_publish_dir_recover() run only on PHP's download path, which the cutover (#3977)
 * removes; until then the Core Updater publishes nothing. They are kept as they are: over a Go publication both refuse,
 * and neither removes, replaces or writes through anything of it.
 */
#[CoversFunction('pfb_stage_publish_dir')]
#[CoversFunction('pfb_stage_publish_dir_recover')]
final class StagePublishDirGoLayoutTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_go_layout_' . bin2hex(random_bytes(6));
		foreach (['.blacklists.123.0123abcd/adult', '.blacklists.99.89abcdef/adult', '.pfbstagebak2_blacklists/adult'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0755, TRUE));
		}
		file_put_contents("{$this->dir}/.blacklists.123.0123abcd/adult/domains", "current.example\n");
		file_put_contents("{$this->dir}/.blacklists.99.89abcdef/adult/domains", "previous.example\n");
		file_put_contents("{$this->dir}/.pfbstagebak2_blacklists/adult/domains", "set-aside.example\n");
		file_put_contents("{$this->dir}/.blacklists.lock", '');
		$this->assertTrue(symlink('.blacklists.123.0123abcd', "{$this->dir}/blacklists"));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/** @return array<string,string> every entry under the folder: a file's content, a link's target, a folder as "dir" */
	private function layout(): array
	{
		$out = [];
		$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::SELF_FIRST);
		foreach ($it as $entry) {
			$rel = substr($entry->getPathname(), strlen($this->dir) + 1);
			if ($entry->isLink()) {
				$out[$rel] = '-> ' . readlink($entry->getPathname()); // not walked into: no FOLLOW_SYMLINKS
			} else {
				$out[$rel] = $entry->isDir() ? 'dir' : (string) file_get_contents($entry->getPathname());
			}
		}
		ksort($out);
		return $out;
	}

	public function testThePublicationRefusesAGoCategoryAndLeavesItWhole(): void
	{
		$before = $this->layout();
		$extracted = FALSE;

		$ok = pfb_stage_publish_dir("{$this->dir}/blacklists", function (string $staged) use (&$extracted): int {
			$extracted = TRUE;
			mkdir("{$staged}/adult");
			file_put_contents("{$staged}/adult/domains", "php.example\n");
			return 0;
		});

		$this->assertFalse($ok, 'a recovery that cannot settle the set-aside folder stops the publication');
		$this->assertSame($before, $this->layout(), 'the Go publication, its generations, its lock and the set-aside folder stay');
		$this->assertFalse($extracted, 'nothing is extracted');
	}

	public function testThePublicationRefusesAGoLinkWithNothingSetAside(): void
	{
		rmdir_recursive("{$this->dir}/.pfbstagebak2_blacklists");
		$before = $this->layout();

		$ok = pfb_stage_publish_dir("{$this->dir}/blacklists", static function (string $staged): int {
			mkdir("{$staged}/adult");
			file_put_contents("{$staged}/adult/domains", "php.example\n");
			return 0;
		});

		$this->assertFalse($ok);
		$this->assertSame($before, $this->layout(), 'nothing replaces or writes through the link, and no staging folder stays');
	}

	public function testTheRecoveryLeavesAGoCategoryAndWhatItSetAside(): void
	{
		$before = $this->layout();

		$this->assertFalse(pfb_stage_publish_dir_recover($this->dir), 'a folder set aside behind a link is not settled');
		$this->assertSame($before, $this->layout());
	}
}
