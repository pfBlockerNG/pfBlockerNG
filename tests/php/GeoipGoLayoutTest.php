<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #4261 -- the Outpost reads the GeoIP share and its country folder as the Core Updater publishes them
 * (go/pfb_core/geoip Conversion.publish, go/pfb_core/feedfetch mergeIntoDir): the country folder `cc` is a link to its
 * current generation `.cc.<pid>.<8 hex>`, published under the lock `.cc.lock` beside the link, with the ISO list inside
 * it as `.geoip_isos`; a MaxMind archive merged into the share leaves each member as a link `.<archive>/<member>` to its
 * archive's generation. Until the cutover PHP publishes the country folder as a real folder, locked on
 * `cc/.pfb_generation.lock`, with the ISO list at `<db>/geoip.txt`; every reader works on both.
 */
#[CoversFunction('pfb_geoip_generation_read_lock')]
#[CoversFunction('pfb_geoip_isos_path')]
#[CoversFunction('pfb_geoip_retire_php_isos')]
#[CoversFunction('pfb_stage_publish_dir_merge_swap')]
final class GeoipGoLayoutTest extends TestCase
{
	private string $dir;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_geoip_go_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir("{$this->dir}/share/.cc.123.0123abcd", 0755, TRUE));
		$this->assertTrue(mkdir("{$this->dir}/db", 0755));
		file_put_contents("{$this->dir}/share/.cc.123.0123abcd/.geoip_isos", 'AU [ Australia ],AU_rep [ Australia ],');
		file_put_contents("{$this->dir}/share/.cc.123.0123abcd/AU_v4.txt", "192.0.2.0/24\n");
		$this->assertTrue(symlink('.cc.123.0123abcd', "{$this->dir}/share/cc"));
		$GLOBALS['pfb']['ccdir'] = "{$this->dir}/share/cc";
		$GLOBALS['pfb']['dbdir'] = "{$this->dir}/db";
	}

	protected function tearDown(): void
	{
		if (isset($GLOBALS['pfb_geoip_generation_read_lock']) && is_resource($GLOBALS['pfb_geoip_generation_read_lock'])) {
			fclose($GLOBALS['pfb_geoip_generation_read_lock']);
		}
		unset($GLOBALS['pfb_geoip_generation_read_lock'], $GLOBALS['pfb_geoip_generation_read_depth']);
		$GLOBALS['pfb'] = $this->savedPfb;
		exec('rm -rf ' . escapeshellarg($this->dir));
	}

	/** @return resource the publisher's lock file, held exclusively */
	private function publisherHolds(string $path)
	{
		$lock = fopen($path, 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX | LOCK_NB));
		return $lock;
	}

	public function testAReaderTakesTheGoPublishersLockBesideTheLink(): void
	{
		$publisher = $this->publisherHolds("{$this->dir}/share/.cc.lock");
		$this->assertFalse(pfb_geoip_generation_read_lock(), 'a reader runs while the Core Updater publishes');
		flock($publisher, LOCK_UN);

		$lock = pfb_geoip_generation_read_lock();
		$this->assertIsResource($lock, 'with the publication over, the reader takes its lock');
		$this->assertFalse(flock($publisher, LOCK_EX | LOCK_NB), "the reader's lock is not the one the Core Updater takes");
		pfb_geoip_generation_read_unlock($lock);
		$this->assertTrue(flock($publisher, LOCK_EX | LOCK_NB), 'the unlock released it');
		fclose($publisher);
		$this->assertFileDoesNotExist("{$this->dir}/share/.cc.123.0123abcd/.pfb_generation.lock",
			'nothing is written into a Go generation');
	}

	public function testOnPhpsLayoutAReaderStillTakesTheLockInTheFolder(): void
	{
		unlink("{$this->dir}/share/cc");
		$this->assertTrue(mkdir("{$this->dir}/share/cc"));
		$publisher = $this->publisherHolds("{$this->dir}/share/cc/.pfb_generation.lock");

		$this->assertFalse(pfb_geoip_generation_read_lock());
		fclose($publisher);
	}

	public function testTheIsoListIsTheGoGenerationsOnGosLayoutAndGeoipTxtOnPhps(): void
	{
		$this->assertSame("{$this->dir}/share/cc/.geoip_isos", pfb_geoip_isos_path("{$this->dir}/share/cc", "{$this->dir}/db"));
		unlink("{$this->dir}/share/cc");
		$this->assertTrue(mkdir("{$this->dir}/share/cc"));
		$this->assertSame("{$this->dir}/db/geoip.txt", pfb_geoip_isos_path("{$this->dir}/share/cc", "{$this->dir}/db"));
	}

	public function testOnceGoPublishesPhpsIsoListsGo(): void
	{
		foreach (['geoip.txt', 'geoip.txt.new.123.0123abcd', 'geoip.txt.keep'] as $name) {
			file_put_contents("{$this->dir}/db/{$name}", 'x');
		}

		pfb_geoip_retire_php_isos("{$this->dir}/share/cc", "{$this->dir}/db");

		$this->assertSame(['geoip.txt.keep'], array_values(array_diff(scandir("{$this->dir}/db"), ['.', '..'])));
	}

	public function testWhilePhpPublishesItsIsoListStays(): void
	{
		unlink("{$this->dir}/share/cc");
		$this->assertTrue(mkdir("{$this->dir}/share/cc"));
		file_put_contents("{$this->dir}/db/geoip.txt", 'x');

		pfb_geoip_retire_php_isos("{$this->dir}/share/cc", "{$this->dir}/db");

		$this->assertFileExists("{$this->dir}/db/geoip.txt");
	}

	public function testPhpsShareMergeNeverReplacesAGoArchivesMemberLink(): void
	{
		$share = "{$this->dir}/share";
		$this->assertTrue(mkdir("{$share}/..GeoLite2-Country.tar.gz.7.89abcdef"));
		file_put_contents("{$share}/..GeoLite2-Country.tar.gz.7.89abcdef/GeoLite2-Country.mmdb", 'go');
		$this->assertTrue(symlink('..GeoLite2-Country.tar.gz.7.89abcdef', "{$share}/.GeoLite2-Country.tar.gz"));
		$this->assertTrue(symlink('.GeoLite2-Country.tar.gz/GeoLite2-Country.mmdb', "{$share}/GeoLite2-Country.mmdb"));
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/GeoLite2-Country.mmdb", 'php');

		$this->assertFalse(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertTrue(is_link("{$share}/GeoLite2-Country.mmdb"), 'the member link stays a link');
		$this->assertSame('go', file_get_contents("{$share}/GeoLite2-Country.mmdb"));
	}

	public function testALinkThatNamesNoGoGenerationIsNoMemberLinkOfTheCoreUpdater(): void
	{
		// an administrator's layout: the Core Updater would replace such a link too (feedfetch entryLink)
		$share = "{$this->dir}/share";
		$this->assertTrue(mkdir("{$this->dir}/elsewhere"));
		file_put_contents("{$this->dir}/elsewhere/GeoLite2-ASN.mmdb", 'admin');
		$this->assertTrue(symlink("{$this->dir}/elsewhere", "{$share}/.custom"));
		$this->assertTrue(symlink('.custom/GeoLite2-ASN.mmdb', "{$share}/GeoLite2-ASN.mmdb"));
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/GeoLite2-ASN.mmdb", 'php');

		$this->assertTrue(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertSame('php', file_get_contents("{$share}/GeoLite2-ASN.mmdb"));
	}

	public function testPhpsShareMergeNeverReplacesAGoArchiveLink(): void
	{
		// a staged entry named like an archive link would leave every member link of it dangling (feedfetch mergeable)
		$share = "{$this->dir}/share";
		$this->assertTrue(mkdir("{$share}/..A.1.0123abcd"));
		file_put_contents("{$share}/..A.1.0123abcd/m", 'go');
		$this->assertTrue(symlink('..A.1.0123abcd', "{$share}/.A"));
		$this->assertTrue(symlink('.A/m', "{$share}/m"));
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/.A", 'php');

		$this->assertFalse(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertTrue(is_link("{$share}/.A"));
		$this->assertSame('go', file_get_contents("{$share}/m"));
	}

	public function testPhpsShareMergeNeverStagesADotEntry(): void
	{
		// what the Core Updater names its own (archive links, their generations, locks); a dangling archive link included
		$share = "{$this->dir}/share";
		$this->assertTrue(symlink('..A.1.0123abcd', "{$share}/.A"));
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/.A", 'php');

		$this->assertFalse(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertTrue(is_link("{$share}/.A"));
	}

	public function testPhpsShareMergeStillPublishesADotMemberOfItsOwn(): void
	{
		// an archive made on a Mac carries ._* and .DS_Store members: today's merge publishes them, and still does
		$share = "{$this->dir}/share";
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/.DS_Store", 'mac');
		file_put_contents("{$this->dir}/staged/GeoLite2-Country.mmdb", 'php');

		$this->assertTrue(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertSame('mac', file_get_contents("{$share}/.DS_Store"));
		$this->assertSame('php', file_get_contents("{$share}/GeoLite2-Country.mmdb"));
	}

	public function testPhpsShareMergeNeverReplacesTheGoCountryFolderLink(): void
	{
		$share = "{$this->dir}/share";
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/cc", 'php');

		$this->assertFalse(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertTrue(is_link("{$share}/cc"));
	}

	public function testALinkNamingAnotherMemberIsNoMemberLinkOfIt(): void
	{
		$share = "{$this->dir}/share";
		$this->assertTrue(mkdir("{$share}/..A.1.0123abcd"));
		file_put_contents("{$share}/..A.1.0123abcd/other", 'go');
		$this->assertTrue(symlink('..A.1.0123abcd', "{$share}/.A"));
		$this->assertTrue(symlink('.A/other', "{$share}/m"));
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/m", 'php');

		$this->assertTrue(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertSame('php', file_get_contents("{$share}/m"));
	}

	public function testPhpsShareMergeStillReplacesItsOwnFiles(): void
	{
		$share = "{$this->dir}/share";
		file_put_contents("{$share}/GeoLite2-Country.mmdb", 'old');
		$this->assertTrue(mkdir("{$this->dir}/staged"));
		file_put_contents("{$this->dir}/staged/GeoLite2-Country.mmdb", 'php');

		$this->assertTrue(pfb_stage_publish_dir_merge_swap("{$this->dir}/staged", $share));

		$this->assertSame('php', file_get_contents("{$share}/GeoLite2-Country.mmdb"));
	}
}
