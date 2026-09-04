<?php

declare(strict_types=1);

require_once __DIR__ . '/StagedDirFixtureTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * The two direct-write GeoIP extraction branches publish through a staging
 * directory, so an extraction that fails part-way leaves the GeoIP share already
 * in service byte-identical (issue #2668).
 *
 * The share is a MERGE target, never a replaceable directory: $pfb['ccdir'] --
 * the published country-code generation and the file every generation lock is
 * taken on -- lives inside it, and the ASN feeds publish their databases into the
 * same directory. pfb_stage_publish_dir()'s whole-directory swap would delete all
 * of that, so the members are published individually instead, and staging happens
 * INSIDE the share so no publication rename can cross a filesystem boundary.
 */
#[CoversFunction('pfb_stage_publish_dir_merge')]
#[CoversFunction('pfb_geoip_extract_tar_to_share')]
final class DownloadGeoipStagePublishTest extends TestCase
{
	use StagedDirFixtureTrait;

	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private array $originalPfb = [];
	private string $dir = '';
	private string $share = '';
	private string $build = '';

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		// Shell-clean on purpose: a fixture path carrying metacharacters would make
		// every failure ambiguous. The escaping the generated staged target needs is
		// pinned by its own case below.
		$this->dir = sys_get_temp_dir() . '/pfb_geoip_stage_' . getmypid();
		$this->share = "{$this->dir}/GeoIP";
		$this->build = "{$this->dir}/build";
		$this->assertTrue(mkdir("{$this->share}/cc", 0755, TRUE));
		$this->assertTrue(mkdir($this->build, 0755, TRUE));
		$GLOBALS['pfb']['geoipshare'] = $this->share;
		$GLOBALS['pfb']['ccdir'] = "{$this->share}/cc";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		// A fixture deliberately drops write permission on the share; restore it so
		// the tree can be removed whatever the test did to it.
		exec('/bin/chmod -R u+rwx ' . escapeshellarg($this->dir) . ' 2>/dev/null');
		$this->removeTree($this->dir);
	}

	/**
	 * Every entry under $path as relative-path => md5, dot entries included.
	 * Directories carry their own key: an empty one adds no file, so without it a
	 * refused publication could leave its staging directory in the share and every
	 * byte-identity assertion would still pass.
	 */
	private function snapshot(string $path, string $prefix = ''): array
	{
		$seen = array();
		foreach ($this->entries($path) as $name) {
			$child = "{$path}/{$name}";
			$label = "{$prefix}{$name}";
			if (is_link($child)) {
				$seen[$label] = 'symlink:' . (string) readlink($child);
			} elseif (is_dir($child)) {
				$seen["{$label}/"] = 'dir';
				$seen += $this->snapshot($child, "{$label}/");
			} else {
				$seen[$label] = (string) md5_file($child);
			}
		}
		return $seen;
	}

	/**
	 * The GeoIP share as an appliance actually holds it: the MaxMind members this
	 * branch publishes, the ASN databases a different branch publishes into the same
	 * directory, and the country-code generation directory that carries the lock.
	 */
	private function seedServedShare(): array
	{
		$this->assertNotFalse(file_put_contents("{$this->share}/GeoLite2-Country.mmdb", "last-good-mmdb\n"));
		$this->assertNotFalse(file_put_contents("{$this->share}/COPYRIGHT.txt", "last-good-copyright\n"));
		$this->assertNotFalse(file_put_contents("{$this->share}/asn.mmdb", "last-good-asn\n"));
		$this->assertNotFalse(file_put_contents("{$this->share}/cc/Africa_v4.txt", "Africa networks\n"));
		$this->assertNotFalse(file_put_contents("{$this->share}/cc/.pfb_generation.lock", ''));
		return $this->snapshot($this->share);
	}

	/**
	 * A gzip container shaped like MaxMind's: one top-level directory the branch
	 * strips, holding $members as relative paths => contents.
	 */
	private function buildArchive(array $members, string $name = 'feed.tar.gz'): string
	{
		$root = "{$this->build}/GeoLite2-Country_20260801";
		foreach ($members as $relative => $contents) {
			$path = "{$root}/{$relative}";
			$this->assertTrue(is_dir(dirname($path)) || mkdir(dirname($path), 0755, TRUE));
			$this->assertNotFalse(file_put_contents($path, $contents));
		}
		$archive = "{$this->dir}/{$name}";
		$retval = 1;
		$output = array();
		exec('cd ' . escapeshellarg($this->build) . ' && ' . escapeshellcmd(pfb_test_tar()) . ' -czf ' . escapeshellarg($archive)
			. ' ' . escapeshellarg('GeoLite2-Country_20260801'), $output, $retval);
		$this->assertSame(0, $retval, 'the fixture archive must be built');
		return $archive;
	}

	/**
	 * The shipped extraction command's ceiling and staging wiring, so these cases
	 * never invent their own tar call.
	 *
	 * Deliberately WITHOUT issue #2659's PFB_TAR_EXTRACT_FLAGS: GNU tar has no
	 * --no-fflags and exits 64 on it, so carrying the appliance's flag set here
	 * would make every case below fail on the Linux CI runner rather than on the
	 * appliance's bsdtar. The flag set has its own executed proof in
	 * DownloadExtractRestrictiveFlagsTest, which refuses to run on a tar that
	 * cannot express it.
	 */
	private function extractCmd(string $archive, string $into, int $blocks): string
	{
		return pfb_extract_cmd(escapeshellcmd(pfb_test_tar()) . ' -xf ' . escapeshellarg($archive) . ' --strip=1 -C '
			. escapeshellarg($into) . ' >/dev/null 2>&1', $blocks);
	}

	/**
	 * The same ceiling wiring for a ZIP fixture. ZIP is not a tar container, and no
	 * unzip implementation has a --strip equivalent (-j junks EVERY component, not
	 * one), so the staged tree keeps the archive's own top-level directory. That is
	 * irrelevant to the cases that use this: what they assert is that a failing
	 * extraction publishes nothing and leaves the served share byte-identical, and
	 * the shape of the staged tree never reaches the share.
	 */
	private function extractZipCmd(string $archive, string $into, int $blocks): string
	{
		return pfb_extract_cmd('/usr/bin/unzip -o -q ' . escapeshellarg($archive) . ' -d '
			. escapeshellarg($into) . ' >/dev/null 2>&1', $blocks);
	}

	/**
	 * Exit status of the SHIPPED extraction argv (issue #2659's PFB_TAR_EXTRACT_FLAGS)
	 * run by this host's /usr/bin/tar against a real one-member tar.
	 *
	 * Deliberately the real argv against a real archive, never a version-string parse:
	 * what matters is whether this tar ACCEPTS the flags the branch execs, and only
	 * running them answers that.
	 */
	private function shippedExtractionFlagsExitCode(): int
	{
		$probe = "{$this->dir}/tarcap_" . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir("{$probe}/src", 0755, TRUE));
		$this->assertTrue(mkdir("{$probe}/out", 0755, TRUE));
		$this->assertNotFalse(file_put_contents("{$probe}/src/probe.txt", "probe\n"));
		$output = array();
		$retval = 1;
		exec(escapeshellcmd(pfb_test_tar()) . ' -cf ' . escapeshellarg("{$probe}/probe.tar") . ' -C '
			. escapeshellarg("{$probe}/src") . ' probe.txt 2>/dev/null', $output, $retval);
		$this->assertSame(0, $retval, 'the capability probe must be able to build a one-member tar');
		exec(escapeshellcmd(pfb_test_tar()) . ' -xf ' . escapeshellarg("{$probe}/probe.tar") . ' ' . PFB_TAR_EXTRACT_FLAGS
			. ' -C ' . escapeshellarg("{$probe}/out") . ' 2>/dev/null', $output, $retval);
		if ($retval === 0) {
			$this->assertFileExists("{$probe}/out/probe.txt",
				'a tar that accepted the flag set must also have extracted the member');
		}
		return $retval;
	}

	/** First line of /usr/bin/tar --version, for skip and failure messages. */
	private function tarVersion(): string
	{
		$version = array();
		exec(escapeshellcmd(pfb_test_tar()) . ' --version 2>&1', $version);
		return trim((string) ($version[0] ?? 'unknown tar'));
	}

	/**
	 * Issue #3068: skip unless this host's /usr/bin/tar can actually run the shipped
	 * extraction, which every case reaching pfb_geoip_extract_tar_to_share() does.
	 *
	 * GNU tar rejects --no-fflags outright with exit 64 -- a usage error, raised before
	 * it reads one byte of the archive. A case that runs anyway is not testing the
	 * branch: it reports "extraction failed" for a reason the appliance can never
	 * produce, which is a manufactured red at best and a vacuous green at worst. The
	 * appliance ships bsdtar and CI installs it (test.yml diverts GNU tar and symlinks
	 * /usr/bin/tar -> bsdtar), so this gate closes only on a dev host that has not done
	 * the same -- and its message says how.
	 */
	private function skipUnlessTarRunsTheShippedExtractionFlags(): void
	{
		$retval = $this->shippedExtractionFlagsExitCode();
		if ($retval !== 0) {
			$this->markTestSkipped(
				'The archiver on this host (' . $this->tarVersion() . ') rejects the shipped '
				. 'PFB_TAR_EXTRACT_FLAGS with exit ' . $retval . ' -- it is not libarchive. The appliance '
				. 'ships bsdtar; install libarchive-tools to run this case.'
			);
		}
	}

	/**
	 * Scenario: the gate above must not be able to swallow the cases it guards.
	 *   Given  this host's /usr/bin/tar, whatever it is
	 *   When   the shipped flag set is run against a real archive
	 *   Then   a libarchive tar accepts it -- so the gate stays OPEN and all five
	 *          guarded cases really run on the appliance's toolchain and in CI
	 *   And    a tar that is not libarchive rejects it -- so when the gate closes, it
	 *          closes for the stated reason and not by accident.
	 *
	 * Without this, a gate that closed unconditionally -- a typo in the flag constant, a
	 * probe that can never succeed -- would delete five cases from the CI run while the
	 * suite still read green. That is exactly the issue #2356 class the skip allowlist
	 * exists for, and an allowlisted id cannot distinguish "skipped for its reason" from
	 * "skipped because the probe broke".
	 *
	 * The version string picks WHICH outcome to demand; the assertion is always on the
	 * executed exit status. This case itself never skips, on any host.
	 */
	public function testTheExtractionFlagGateTracksWhetherTheHostTarIsLibarchive(): void
	{
		$version    = $this->tarVersion();
		$libarchive = stripos($version, 'bsdtar') !== FALSE || stripos($version, 'libarchive') !== FALSE;
		$retval     = $this->shippedExtractionFlagsExitCode();

		if ($libarchive) {
			$this->assertSame(0, $retval,
				"this host's tar ({$version}) is libarchive, so it must accept the shipped "
				. 'PFB_TAR_EXTRACT_FLAGS and leave the gate open; exit ' . $retval . ' means the five '
				. 'guarded cases are silently skipping on the appliance toolchain and in CI');
			return;
		}
		$this->assertNotSame(0, $retval,
			"this host's tar ({$version}) is not libarchive, so it cannot accept --no-fflags; "
			. 'a clean exit here means the probe is not running the shipped flag set at all, and the '
			. 'gate would let the guarded cases run against an extractor that cannot express them');
	}

	/**
	 * Scenario: the failure issue #2658 introduced a new way to reach.
	 *   Given  a GeoIP share already in service
	 *   And    an archive whose member is larger than the extraction ceiling
	 *   When   the real tar runs under the real ceiling through the staged publish
	 *   Then   the extraction is killed, nothing is published, and every served
	 *          byte is exactly what it was.
	 *
	 * The ceiling is injected through pfb_extract_cmd()'s own $blocks parameter --
	 * the shipped value is 2 GiB -- which is how DownloadSizeCeilingTest proves the
	 * ceiling fires without writing gigabytes.
	 */
	public function testCeilingKilledExtractionLeavesTheServedShareByteIdentical(): void
	{
		$before = $this->seedServedShare();
		$archive = $this->buildArchive(array(
			'GeoLite2-Country.mmdb' => "fresh-mmdb\n",
			'GeoLite2-Country-Blocks-IPv4.csv' => str_repeat("192.0.2.0/24,6252001\n", 4096),
		));
		$retval = pfb_download_initial_retval();
		$output = array();

		$published = pfb_stage_publish_dir_merge($this->share,
			function (string $staged) use ($archive, &$output, &$retval): int {
				exec($this->extractCmd($archive, $staged, 2), $output, $retval);
				return $retval;
			});

		$this->assertFalse($published, 'a killed extraction must not publish');
		$this->assertFalse(pfb_download_extraction_succeeded($retval),
			"the ceiling kill must surface as a failing exit status (saw {$retval})");
		$this->assertSame($before, $this->snapshot($this->share),
			'the served GeoIP share must be byte-identical after a killed extraction');
	}

	/**
	 * A two-member ZIP whose SECOND member's stored bytes no longer match its
	 * recorded CRC. Header-only listing still succeeds, so the branch's member guard
	 * passes and the extraction runs; inflating the second member is where it fails,
	 * with the first member already written. That is the "corrupt archive" shape --
	 * a tail-truncated ZIP is not one, because libarchive streams local headers and
	 * both lists and extracts it.
	 */
	private function buildCorruptArchive(): string
	{
		$path = "{$this->dir}/corrupt.zip";
		$zip = new ZipArchive();
		$this->assertTrue($zip->open($path, ZipArchive::CREATE) === TRUE);
		$this->assertTrue($zip->addFromString('GeoLite2-Country_20260801/COPYRIGHT.txt', "fresh-copyright\n"));
		$this->assertTrue($zip->addFromString('GeoLite2-Country_20260801/GeoLite2-Country.mmdb', "fresh-mmdb-bytes\n"));
		$this->assertTrue($zip->setCompressionName('GeoLite2-Country_20260801/COPYRIGHT.txt', ZipArchive::CM_STORE));
		$this->assertTrue($zip->setCompressionName('GeoLite2-Country_20260801/GeoLite2-Country.mmdb', ZipArchive::CM_STORE));
		$this->assertTrue($zip->close());
		$raw = file_get_contents($path);
		$this->assertNotFalse($raw);
		$at = strpos($raw, 'fresh-mmdb-bytes');
		$this->assertNotFalse($at, 'the stored member body must be findable to corrupt it');
		$raw[$at + 4] = chr(ord($raw[$at + 4]) ^ 0xFF);
		$this->assertNotFalse(file_put_contents($path, $raw));
		return $path;
	}

	/**
	 * Scenario: the failure mode that has always been reachable.
	 *   Given  a GeoIP share already in service
	 *   And    a corrupt archive that lists cleanly but fails part-way through
	 *          extraction, with one member already written
	 *   When   it extracts through the staged publish
	 *   Then   nothing is published and every served byte is exactly what it was.
	 *
	 * Both the listing and the extraction go through ZIP tools rather than tar
	 * (issue #3068). Listing a ZIP with `tar -tf` only ever worked because the
	 * appliance's /usr/bin/tar is bsdtar; on a GNU-tar host the lister returned NULL,
	 * the case died on the assertion below, and even had it survived, GNU tar would
	 * have "failed" the extraction because it cannot read a ZIP at all -- not because
	 * the member's CRC is wrong. The whole point of the fixture is WHICH failure it
	 * produces, so the extractor has to be one that can read the container.
	 */
	public function testCorruptArchiveThatListsCleanlyLeavesTheServedShareByteIdentical(): void
	{
		$before = $this->seedServedShare();
		$archive = $this->buildCorruptArchive();
		$this->assertNotNull(pfb_archive_member_names($archive, 'application/zip'),
			'the archive must list cleanly, or the branch refuses it before extracting');
		$retval = pfb_download_initial_retval();
		$output = array();

		$published = pfb_stage_publish_dir_merge($this->share,
			function (string $staged) use ($archive, &$output, &$retval): int {
				exec($this->extractZipCmd($archive, $staged, PFB_EXTRACT_MAX_BLOCKS), $output, $retval);
				return $retval;
			});

		$this->assertFalse($published, 'a corrupt archive must not publish');
		$this->assertFalse(pfb_download_extraction_succeeded($retval),
			"the corrupt member must surface as a failing exit status (saw {$retval})");
		$this->assertSame($before, $this->snapshot($this->share),
			'the served GeoIP share must be byte-identical after a corrupt archive');
	}

	/**
	 * Scenario: the defect, through the shipped branch helper.
	 *   Given  a GeoIP share already in service that contains a dangling symlink
	 *   And    an archive that lists cleanly but whose second member's path runs
	 *          through that symlink
	 *   When   the GeoIP tar branch extracts
	 *   Then   the download fails AND the served share is byte-identical.
	 *
	 * The symlink is what made the PRE-fix run fail part-way: extraction went
	 * straight into the share, so libarchive refused the second member -- the
	 * refusal ADR-46 relies on -- with the first member already written over the
	 * served .mmdb. Staged, tar writes into a fresh directory that has no such
	 * symlink, and the publication is what refuses: the staged `sub` directory
	 * cannot replace the live symlink -- so at head tar exits 0 and the publication
	 * is the refusal. Either way the update lands part-way or not at all, and the
	 * served bytes are the assertion.
	 */
	public function testExtractionThatFailsPartWayLeavesTheServedShareByteIdentical(): void
	{
		$this->skipUnlessTarRunsTheShippedExtractionFlags();
		$this->assertTrue(symlink('/nonexistent/pfb2668', "{$this->share}/sub"));
		$before = $this->seedServedShare();
		// Only the leaf is archived, so no directory member replaces the symlink
		// before tar tries to write through it.
		$root = "{$this->build}/GeoLite2-Country_20260801";
		$this->assertTrue(mkdir("{$root}/sub", 0755, TRUE));
		$this->assertNotFalse(file_put_contents("{$root}/GeoLite2-Country.mmdb", "fresh-mmdb\n"));
		$this->assertNotFalse(file_put_contents("{$root}/sub/two.csv", "two\n"));
		$archive = "{$this->dir}/feed.tar.gz";
		$retval = 1;
		$output = array();
		exec('cd ' . escapeshellarg($this->build) . ' && ' . escapeshellcmd(pfb_test_tar()) . ' -czf ' . escapeshellarg($archive)
			. ' GeoLite2-Country_20260801/GeoLite2-Country.mmdb GeoLite2-Country_20260801/sub/two.csv',
			$output, $retval);
		$this->assertSame(0, $retval);
		$this->assertNotNull(pfb_archive_member_names($archive, 'application/x-tar'),
			'the archive must list cleanly, or the branch refuses it before extracting');

		$result = pfb_geoip_extract_tar_to_share('GeoIP', $archive, escapeshellarg($archive), $retval);

		$this->assertFalse($result->success, 'a part-way extraction must fail the download');
		$this->assertSame($before, $this->snapshot($this->share),
			'the served GeoIP share must be byte-identical after a part-way extraction');
	}

	/**
	 *   Given  a GeoIP share already in service
	 *   When   a healthy archive extracts through the GeoIP tar branch
	 *   Then   every member is published and the download reports success.
	 */
	public function testSuccessfulExtractionPublishesEveryMemberIntoTheLiveShare(): void
	{
		$this->skipUnlessTarRunsTheShippedExtractionFlags();
		$this->seedServedShare();
		$archive = $this->buildArchive(array(
			'GeoLite2-Country.mmdb' => "fresh-mmdb\n",
			'COPYRIGHT.txt' => "fresh-copyright\n",
			'LICENSE.txt' => "fresh-licence\n",
		));
		$retval = pfb_download_initial_retval();

		$result = pfb_geoip_extract_tar_to_share('GeoIP', $archive, escapeshellarg($archive), $retval);

		$this->assertTrue($result->success);
		$this->assertSame("fresh-mmdb\n", file_get_contents("{$this->share}/GeoLite2-Country.mmdb"));
		$this->assertSame("fresh-copyright\n", file_get_contents("{$this->share}/COPYRIGHT.txt"));
		$this->assertSame("fresh-licence\n", file_get_contents("{$this->share}/LICENSE.txt"));
		$this->assertFileDoesNotExist($archive, 'the consumed download must be unlinked');
		// Only published members and the untouched siblings: no staging litter.
		$this->assertSame(
			array('COPYRIGHT.txt', 'GeoLite2-Country.mmdb', 'LICENSE.txt', 'asn.mmdb', 'cc'),
			$this->sorted($this->entries($this->share))
		);
	}

	private function sorted(array $values): array
	{
		sort($values);
		return $values;
	}

	/**
	 * Scenario: the hazard issue #2668 named -- the GeoIP publication lock.
	 *   Given  a publication lock held on the generation directory inside the share
	 *   When   a healthy GeoIP archive publishes
	 *   Then   the generation directory, its contents and the very file the lock is
	 *          held on are untouched down to the inode, the ASN databases a
	 *          different branch published there survive, and releasing the lock
	 *          still releases the file the holder took it on.
	 *
	 * The inode is the assertion that matters: a whole-directory swap leaves a
	 * holder flock()ing an unlinked inode while every later caller opens a different
	 * file, so mutual exclusion breaks silently while both calls still "succeed".
	 */
	public function testPublicationLeavesTheGenerationLockFileAndItsDirectoryUntouched(): void
	{
		$this->skipUnlessTarRunsTheShippedExtractionFlags();
		$this->seedServedShare();
		$lockFile = "{$this->share}/cc/.pfb_generation.lock";
		$inodeBefore = stat($lockFile)['ino'];
		$lock = pfb_geoip_generation_publication_lock("{$this->share}/cc");
		$this->assertNotFalse($lock, 'the fixture must hold the real publication lock');
		$archive = $this->buildArchive(array('GeoLite2-Country.mmdb' => "fresh-mmdb\n"));
		$retval = pfb_download_initial_retval();

		$result = pfb_geoip_extract_tar_to_share('GeoIP', $archive, escapeshellarg($archive), $retval);

		$this->assertTrue($result->success);
		$this->assertSame("fresh-mmdb\n", file_get_contents("{$this->share}/GeoLite2-Country.mmdb"));
		$this->assertFileExists($lockFile, 'the generation lock file must survive the publication');
		$this->assertSame($inodeBefore, stat($lockFile)['ino'],
			'the publication must not replace the file the generation lock is held on');
		$this->assertSame("Africa networks\n", file_get_contents("{$this->share}/cc/Africa_v4.txt"),
			'the published country-code generation must survive a GeoIP member publication');
		$this->assertSame("last-good-asn\n", file_get_contents("{$this->share}/asn.mmdb"),
			'the ASN databases published into the same share must survive');
		pfb_geoip_generation_publication_unlock($lock);
		$reacquired = pfb_geoip_generation_publication_lock("{$this->share}/cc");
		$this->assertNotFalse($reacquired, 'the released lock must be re-acquirable on the same file');
		pfb_geoip_generation_publication_unlock($reacquired);
	}

	/**
	 *   Given  an archive member whose name collides with the live generation
	 *          directory
	 *   When   the publication runs
	 *   Then   it is refused whole, before the first member is moved, so the
	 *          generation directory cannot be replaced by a feed member.
	 */
	public function testPublicationRefusesToReplaceALiveDirectory(): void
	{
		$before = $this->seedServedShare();

		$published = pfb_stage_publish_dir_merge($this->share, static function (string $staged): int {
			file_put_contents("{$staged}/GeoLite2-Country.mmdb", "fresh-mmdb\n");
			file_put_contents("{$staged}/cc", "a member named like the generation directory\n");
			return 0;
		});

		$this->assertFalse($published);
		$this->assertSame($before, $this->snapshot($this->share),
			'a refused publication must move no member at all');
	}

	/**
	 *   Given  a staged member that is a directory whose live counterpart is a file
	 *   And    a publishable member that sorts BEFORE it, so dropping the precheck
	 *          would move that one first and leave a part-way publication
	 *   When   the publication runs
	 *   Then   it is refused whole, because rename() cannot replace a file with a
	 *          directory and the refusal is decided before any member moves.
	 */
	public function testPublicationRefusesADirectoryMemberOverALiveFileBeforeMovingAnything(): void
	{
		$before = $this->seedServedShare();

		$published = pfb_stage_publish_dir_merge($this->share, static function (string $staged): int {
			// Sorts before COPYRIGHT.txt, so scandir() hands it over first.
			file_put_contents("{$staged}/AAA-GeoLite2-Country.mmdb", "fresh-mmdb\n");
			mkdir("{$staged}/COPYRIGHT.txt", 0755);
			file_put_contents("{$staged}/COPYRIGHT.txt/nested", "nested\n");
			return 0;
		});

		$this->assertFalse($published);
		$this->assertSame($before, $this->snapshot($this->share),
			'a refused publication must move no member at all');
	}

	/**
	 * Staging inside the share is what makes every publication rename
	 * same-filesystem: a directory just created there cannot be a mount point, so
	 * no member can be published across a device boundary.
	 */
	public function testStagingSitsInsideTheShareSoNoSwapCrossesAFilesystem(): void
	{
		$this->seedServedShare();
		$seen = '';

		pfb_stage_publish_dir_merge($this->share, static function (string $staged) use (&$seen): int {
			$seen = $staged;
			return 0;
		});

		// realpath() on both sides: macOS resolves sys_get_temp_dir() through a
		// /var -> /private/var symlink and tempnam() hands back the resolved path
		// (issue #2192).
		$this->assertSame(realpath($this->share), realpath(dirname($seen)));
		$this->assertSame(stat($this->share)['dev'], stat(dirname($seen))['dev'],
			'the staging directory must sit on the share own filesystem');
	}

	/**
	 * The staged target is a generated path, so the extraction command must escape
	 * it -- unlike the hardcoded share literal it replaces. A share directory whose
	 * name carries shell metacharacters therefore still publishes.
	 */
	public function testStagedExtractionEscapesItsTargetSoAMetacharacterShareStillPublishes(): void
	{
		$share = "{$this->dir}/GeoIP share; [odd] 'quoted'";
		$this->assertTrue(mkdir($share, 0755));
		$this->assertNotFalse(file_put_contents("{$share}/GeoLite2-Country.mmdb", "last-good-mmdb\n"));
		$archive = $this->buildArchive(array('GeoLite2-Country.mmdb' => "fresh-mmdb\n"));
		$retval = pfb_download_initial_retval();
		$output = array();

		$published = pfb_stage_publish_dir_merge($share,
			function (string $staged) use ($archive, &$output, &$retval): int {
				exec($this->extractCmd($archive, $staged, PFB_EXTRACT_MAX_BLOCKS), $output, $retval);
				return $retval;
			});

		$this->assertTrue($published, "the staged extraction must survive a metacharacter path (tar exit {$retval})");
		$this->assertSame("fresh-mmdb\n", file_get_contents("{$share}/GeoLite2-Country.mmdb"));
	}

	/**
	 * tempnam() silently falls back to the system temp directory when the requested
	 * directory is not writable, which is the one way staging can land on another
	 * filesystem. Publishing from there is a copy, not an atomic rename -- PHP's
	 * rename() has no cross-device fallback for a directory and degrades to a
	 * non-atomic copy for a file -- so the escape is refused BEFORE the extractor
	 * runs. Asserting the extractor never ran is what makes the guard falsifiable:
	 * the publication is refused either way once the target is unwritable, but only
	 * the guard stops an extraction from being spent on a foreign filesystem.
	 */
	public function testStagingThatEscapesTheShareRefusesBeforeExtracting(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses the directory permissions this fixture relies on');
		}
		$before = $this->seedServedShare();
		$this->assertTrue(chmod($this->share, 0555));
		$seen = NULL;

		$published = pfb_stage_publish_dir_merge($this->share, static function (string $staged) use (&$seen): int {
			$seen = $staged;
			file_put_contents("{$staged}/GeoLite2-Country.mmdb", "fresh-mmdb\n");
			return 0;
		});

		$this->assertTrue(chmod($this->share, 0755));
		$this->assertFalse($published, 'staging outside the share must refuse the publication');
		$this->assertNull($seen,
			'the extractor must not run against a staging directory outside the target');
		$this->assertSame($before, $this->snapshot($this->share));
	}

	/**
	 * A complete staged tree still publishes nothing when the extractor exits
	 * nonzero: the exit status is the gate, not the staged tree looking finished.
	 */
	public function testNonZeroExtractorExitPublishesNothingEvenWhenTheStagedTreeIsComplete(): void
	{
		$before = $this->seedServedShare();

		$published = pfb_stage_publish_dir_merge($this->share, static function (string $staged): int {
			file_put_contents("{$staged}/GeoLite2-Country.mmdb", "fresh-mmdb\n");
			file_put_contents("{$staged}/COPYRIGHT.txt", "fresh-copyright\n");
			return 1;
		});

		$this->assertFalse($published);
		$this->assertSame($before, $this->snapshot($this->share));
	}


	/**
	 * A staged merge can fail with the extractor's status still zero: the members
	 * were refused, not the archive. Reporting that as "tar exit 0" tells an
	 * operator the opposite of what happened, so the two outcomes read differently.
	 */
	public function testAPublicationRefusalIsNotLoggedAsATarFailure(): void
	{
		$this->skipUnlessTarRunsTheShippedExtractionFlags();
		$this->seedServedShare();
		$this->assertTrue(mkdir("{$this->build}/GeoLite2-Country_20260801", 0755));
		// A member named like the live generation directory: tar extracts it
		// cleanly into staging, and the publication refuses to replace cc/.
		$archive = $this->buildArchive(array('cc' => "not the generation directory\n"));
		$retval = pfb_download_initial_retval();

		$result = pfb_geoip_extract_tar_to_share('GeoIP', $archive, escapeshellarg($archive), $retval);

		$this->assertFalse($result->success);
		$this->assertSame(0, $retval, 'the extractor must have exited clean for this case to mean anything');
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringContainsString('geoip publication failed', $log);
		$this->assertStringNotContainsString('extraction failed (tar exit 0)', $log,
			'a clean tar must never be reported as the reason a publication was refused');
	}

	/**
	 * A ceiling kill must still be named as one. The wrapper composes the extractor
	 * wording with pfb_extract_cap_note(), and dropping that composition loses the
	 * "too large" the operator reads instead of a bare exit code (issue #2658).
	 */
	public function testTheFailureNoteStillNamesTheExtractionCeiling(): void
	{
		$this->assertStringContainsString('ceiling',
			pfb_stage_publish_failure_note(PFB_EXTRACT_SIGXFSZ_EXIT),
			'a child killed at the ceiling must be reported as too large, not as a bare exit code');
		$this->assertStringContainsString((string) PFB_EXTRACT_SIGXFSZ_EXIT,
			pfb_stage_publish_failure_note(PFB_EXTRACT_SIGXFSZ_EXIT));
		$this->assertSame('publication failed', pfb_stage_publish_failure_note(0),
			'a clean extractor status means the publication refused, and carries no ceiling note');
		foreach (array(1, 2, 127) as $retval) {
			$this->assertSame("extraction failed (tar exit {$retval})",
				pfb_stage_publish_failure_note($retval),
				"exit {$retval} is not a ceiling refusal and must not be labelled one");
		}
	}

	/** The converse: a real extractor failure keeps naming its exit status. */
	public function testAnExtractorFailureStillNamesItsExitStatus(): void
	{
		$this->skipUnlessTarRunsTheShippedExtractionFlags();
		$this->seedServedShare();
		$archive = $this->buildCorruptArchive();
		$retval = pfb_download_initial_retval();

		$result = pfb_geoip_extract_tar_to_share('GeoIP', $archive, escapeshellarg($archive), $retval);

		$this->assertFalse($result->success);
		$this->assertNotSame(0, $retval);
		$this->assertStringContainsString("geoip extraction failed (tar exit {$retval})",
			(string) file_get_contents($GLOBALS['pfb']['log']));
	}

	public function testFailedExtractionLeavesNoStagingDirectoryBehind(): void
	{
		$before = $this->seedServedShare();

		pfb_stage_publish_dir_merge($this->share, static function (string $staged): int {
			file_put_contents("{$staged}/GeoLite2-Country.mmdb", 'partial');
			return 1;
		});

		$this->assertSame($this->sorted(array_keys($before)),
			$this->sorted(array_keys($this->snapshot($this->share))),
			'the served share must be exactly what it was');
		$this->assertSame(array('COPYRIGHT.txt', 'GeoLite2-Country.mmdb', 'asn.mmdb', 'cc'),
			$this->sorted($this->entries($this->share)),
			'no staging directory may be left in the share');
	}

	/**
	 * Issue #2668: the gzip and uncompressed x-tar GeoIP arms share one helper, and
	 * it must extract into staging rather than straight into the live share.
	 * Comments and docblocks are never extraction boundaries.
	 */
	public function testGeoipShareExtractionRunsUnderTheStagedPublishHelper(): void
	{
		$body = $this->functionBody('pfb_geoip_extract_tar_to_share');

		$this->assertStringContainsString('pfb_stage_publish_dir_merge($pfb[\'geoipshare\']', $body,
			'the GeoIP tar extraction must publish through the staged merge helper');
		$this->assertStringNotContainsString('-C {$pfb[\'geoipshare\']}', $body,
			'the GeoIP tar extraction must not write straight into the live share');
		$this->assertStringNotContainsString('-C {$header_esc}', $body,
			'issue #2638 B7: the GeoIP extraction target is never the .mmdb $header path');
		$this->assertStringContainsString('pfb_archive_unsafe_member', $body,
			'ADR-46: a disk-writing extraction still rejects hostile member names first');
	}

	/**
	 * Issue #2668: the zip container's multi-member GeoIP arm was the second
	 * direct-write branch. It publishes to its CALLER's target rather than to
	 * $pfb['geoipshare'] -- pinned by GeoipZipPublicationTest end to end -- so it
	 * stages against that target instead of sharing the gzip arm's helper.
	 */
	public function testZipMultiMemberGeoipArmStagesAgainstItsCallerTarget(): void
	{
		$source = file_get_contents(self::INC);
		$this->assertNotFalse($source);
		$zip = strpos($source, "elseif (\$file_type == 'application/zip') {");
		$this->assertNotFalse($zip);
		$top1m = strpos($source, "if (\$type == 'top1m') {", $zip);
		$this->assertNotFalse($top1m);
		$scope = substr($source, $zip, $top1m - $zip);

		$this->assertStringContainsString('if (!pfb_stage_publish_dir_merge($head_download,', $scope,
			'the multi-member zip GeoIP arm must publish through the staged merge helper');
		$this->assertStringNotContainsString('--strip=1 -C {$header_esc}', $scope,
			'the multi-member zip GeoIP arm must not extract straight into the live target');
	}

	/**
	 * The class, swept tree-wide: no extraction anywhere in the package may name the
	 * live GeoIP share as its -C target. Scoped to the share literal, because the
	 * TOP1M zip arm legitimately reassigns $header_esc to its OWN staging directory
	 * before extracting into it. Counted, never matched against the haystack --
	 * these files are hundreds of KB and a containment matcher would dump them into
	 * the failure output.
	 */
	public function testNoExtractionInThePackageWritesStraightIntoTheLiveShare(): void
	{
		$root = dirname(__DIR__, 2) . '/src';
		$files = new RegexIterator(
			new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)),
			'/\.(php|inc)$/'
		);
		$offenders = array();
		foreach ($files as $file) {
			$source = (string) file_get_contents($file->getPathname());
			$hits = preg_match_all('/-C \{\$pfb\[\x27geoipshare\x27\]\}/', $source);
			if ($hits > 0) {
				$offenders[str_replace("{$root}/", '', $file->getPathname())] = $hits;
			}
		}

		$this->assertSame(array(), $offenders,
			'every extraction must write into staging, never straight onto a live publication');
	}

	/** A publication whose failure is ignored would report a stale share as fresh. */
	public function testEveryStagedMergePublicationSitsInAFailureGuard(): void
	{
		$source = file_get_contents(self::INC);
		$this->assertNotFalse($source);

		// One occurrence is the definition; every other must be a guarded call.
		$occurrences = substr_count($source, 'pfb_stage_publish_dir_merge(');
		$this->assertGreaterThan(1, $occurrences,
			'expected the GeoIP branch to publish through pfb_stage_publish_dir_merge()');
		$this->assertSame($occurrences - 1, substr_count($source, 'if (!pfb_stage_publish_dir_merge('),
			'every pfb_stage_publish_dir_merge() call must sit directly in a failure guard');
	}

	private function functionBody(string $name): string
	{
		$this->assertTrue(function_exists($name), "{$name}() must exist");
		$reflection = new ReflectionFunction($name);
		$source = file(self::INC);
		$this->assertNotFalse($source);
		return implode('', array_slice($source, $reflection->getStartLine() - 1,
			$reflection->getEndLine() - $reflection->getStartLine() + 1));
	}
}
