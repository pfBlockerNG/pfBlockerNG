<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Missing-archive saves must neither race generation publication nor stage code before the old fingerprint. */
final class DnsblCacheSnapshotTest extends TestCase
{
	private string $dir;
	private array $saved;

	protected function setUp(): void
	{
		$this->saved = [$GLOBALS['pfb'], $GLOBALS['config'] ?? NULL, $GLOBALS['pfb_test_write_config_calls'] ?? NULL];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$this->dir = sys_get_temp_dir() . '/pfb_snapshot_' . bin2hex(random_bytes(6));
		foreach (['chroot', 'pkg', 'db', 'etc'] as $sub) {
			mkdir("{$this->dir}/{$sub}", 0777, TRUE);
		}
		$GLOBALS['config'] = [];
		config_set_path('system/use_mfs_tmpvar', '');
		config_set_path('system/earlyshellcmd', ['/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache restore']);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], [
			'unbound_py_sources' => "{$this->dir}/chroot/pfb_py_sources.json",
			'dnsblarchive' => "{$this->dir}/etc/cache.tar",
			'script' => "{$this->dir}/save.sh",
			'log' => "{$this->dir}/pfb.log", 'errlog' => "{$this->dir}/error.log",
			'enable' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'pfb_dns' => PfbToggle::Off,
		]);
		mkdir("{$this->dir}/chroot/pfb_py_raw.old");
		file_put_contents("{$this->dir}/chroot/pfb_py_raw.old/feed.raw", 'old.example');
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"feeds":[{"raw":"pfb_py_raw.old/feed.raw"}]}');
		$this->wrapper(pfb_test_tar());
	}

	protected function tearDown(): void
	{
		[$GLOBALS['pfb'], $GLOBALS['config'], $GLOBALS['pfb_test_write_config_calls']] = $this->saved;
		if ($GLOBALS['config'] === NULL) {
			unset($GLOBALS['config']);
		}
		if ($GLOBALS['pfb_test_write_config_calls'] === NULL) {
			unset($GLOBALS['pfb_test_write_config_calls']);
		}
		rmdir_recursive($this->dir);
	}

	private function executable(string $path, string $body): void
	{
		file_put_contents($path, $body);
		chmod($path, 0755);
	}

	private function wrapper(string $tar): void
	{
		$source = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.sh';
		$body = "#!/bin/sh\nPFB_SOURCED=1\n. " . escapeshellarg($source) . "\n";
		foreach (['pathtar' => $tar, 'pfbchroot' => "{$this->dir}/chroot", 'pfbpkgdir' => "{$this->dir}/pkg",
			'pfbdb' => "{$this->dir}/db", 'dnsblarchive' => $GLOBALS['pfb']['dnsblarchive']] as $name => $value) {
			$body .= $name . '=' . escapeshellarg($value) . "\n";
		}
		$body .= 'dnsbl_cache "$2"' . "\n";
		$this->executable("{$this->dir}/save.sh", $body);
	}

	private function archive(): string
	{
		$base = $GLOBALS['pfb']['dnsblarchive'];
		$path = is_file("{$base}.zst") ? "{$base}.zst" : "{$base}.bz2";
		$this->assertFileExists($path, 'saving the snapshot must publish an archive');
		return $path;
	}

	public function testPublicationCannotReplaceManifestBetweenEnumerationAndTar(): void
	{
		// Given a publisher that attempts the real publication flock when tar starts, after the shell expanded its file set
		$publisher = <<<'PHP'
<?php
$d = $argv[1];
$lock = fopen("$d/chroot/pfb_py_sources.lock", 'c');
if (flock($lock, LOCK_EX | LOCK_NB)) {
    mkdir("$d/chroot/pfb_py_raw.new");
    file_put_contents("$d/chroot/pfb_py_raw.new/feed.raw", 'new.example');
    file_put_contents("$d/chroot/pfb_py_sources.json", '{"feeds":[{"raw":"pfb_py_raw.new/feed.raw"}]}');
    file_put_contents("$d/publisher", 'published');
} else {
    file_put_contents("$d/publisher", 'blocked');
}
fclose($lock);
PHP;
		file_put_contents("{$this->dir}/publish.php", $publisher);
		$tar = "{$this->dir}/tar.sh";
		$this->executable($tar, "#!/bin/sh\n" . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("{$this->dir}/publish.php") . ' ' . escapeshellarg($this->dir)
			. "\nexec " . escapeshellarg(pfb_test_tar()) . ' "$@"' . "\n");
		$this->wrapper($tar);

		// When a save races publication at exactly the tar boundary
		pfb_dnsbl_cache('save');

		// Then the archived manifest still names the raw generation that was enumerated
		$manifest = shell_exec(escapeshellarg(pfb_test_tar()) . ' -xOf ' . escapeshellarg($this->archive()) . ' '
			. escapeshellarg($GLOBALS['pfb']['unbound_py_sources']) . ' 2>/dev/null');
		$this->assertSame('{"feeds":[{"raw":"pfb_py_raw.old/feed.raw"}]}', $manifest, 'publication must not swap the manifest during capture');
		$this->assertSame('blocked', file_get_contents("{$this->dir}/publisher"), 'the publisher must contend on the same flock');
		$this->assertLockReleased();
	}

	public function testMissingArchiveSaveLeavesShippedHstsForTheNormalPassToStage(): void
	{
		// Given different shipped and currently staged HSTS data, before the old fingerprint is taken
		file_put_contents("{$this->dir}/pkg/pfb_py_hsts.txt", 'new.example');
		file_put_contents("{$this->dir}/chroot/pfb_py_hsts.txt", 'old.example');

		// When conf fills a missing archive
		pfb_dnsbl_cache('conf');

		// Then capture has not changed the old fingerprint input; the normal DNSBL stage still copies the new data
		$this->archive();
		$this->assertSame('old.example', file_get_contents("{$this->dir}/chroot/pfb_py_hsts.txt"), 'capture must not mask the HSTS change before fingerprinting');
		exec(escapeshellarg("{$this->dir}/save.sh") . ' dnsbl_cache stage 2>/dev/null');
		$this->assertSame('new.example', file_get_contents("{$this->dir}/chroot/pfb_py_hsts.txt"), 'normal staging must still install the shipped HSTS');
	}

	public function testStopEntryPointUsesTheLockedSave(): void
	{
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertSame(1, preg_match("~\\belseif \\(\\\$argv\\[1\\] == 'dnsbl_cache'\\) \\{(.*?)\\bexit\\(0\\);\\s*\\}~s", $source, $arm),
			'the stop must enter through the publication-locked PHP save');
		(static function () use ($arm): void { eval($arm[1]); })();
		$this->archive();
		$this->assertLockReleased();
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'shutdown capture must not register restore hooks or write config.xml');
	}

	public function testUnavailablePublicationLockDoesNotSave(): void
	{
		// Given a real lock-path failure, not an injected exception
		mkdir("{$this->dir}/chroot/pfb_py_sources.lock");
		pfb_dnsbl_cache('save');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsblarchive'] . '.zst', 'an unlocked snapshot must never be published');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsblarchive'] . '.bz2', 'fallback must not bypass the publication lock');
	}

	public function testFailedCompressionReleasesPublicationLock(): void
	{
		$tar = "{$this->dir}/fail.sh";
		$this->executable($tar, "#!/bin/sh\nexit 2\n");
		$this->wrapper($tar);
		pfb_dnsbl_cache('save');
		$this->assertLockReleased();
	}

	private function assertLockReleased(): void
	{
		$lock = fopen("{$this->dir}/chroot/pfb_py_sources.lock", 'c');
		try {
			$this->assertTrue(flock($lock, LOCK_EX | LOCK_NB), 'capture must release the publication lock on success and failure');
		} finally {
			fclose($lock);
		}
	}
}
