<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/** Issue #1542: TOP1M is a fixed sidecar file, not manifest-embedded data. */
final class Top1mFixedFileManifestTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_top1m_fixed_' . getmypid() . '_' . uniqid();
		mkdir("{$this->tmp}/dnsbl", 0777, TRUE);
		mkdir("{$this->tmp}/db", 0777, TRUE);
		$this->originalPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'unbound_py_top1m'   => "{$this->tmp}/pfb_py_top1m.txt",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_tld_wildcard' => '',
			'dnsblconfig'        => ['tldblacklist' => '', 'tldexclusion' => '', 'suppression' => ''],
		]);
		file_put_contents("{$this->tmp}/dnsbl/feed.txt", "{\"kind\":\"domain\",\"domain\":\"blocked.example\"}\n");
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$this->removeTree($this->tmp);
	}

	public function testDisabledOmitsTop1mFileRequirementAndEmbeddedList(): void
	{
		$manifest = pfb_unbound_python_sources([
			['header' => 'feed', 'group' => 'g', 'log' => '1', 'provenance' => 'feed'],
		]);

		$this->assertIsArray($manifest);
		$this->assertFalse($manifest['config']['top1m_enabled']);
		$this->assertArrayNotHasKey('top1m_list', $manifest['config']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['unbound_py_top1m']);
	}

	public function testEnabledPublishesFixedFileBeforeManifestAndPreservesBytes(): void
	{
		$source = "one.example\r\n\r\n two.example \r\none.example\r\n";
		file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", $source);
		$GLOBALS['pfb']['dnsbl_top1m'] = 'on';
		$manifest = pfb_unbound_python_sources([
			['header' => 'feed', 'group' => 'g', 'log' => '1', 'provenance' => 'feed'],
		], [
			'top1m_atomic' => $this->successfulOwnershipOps(),
		]);

		$this->assertIsArray($manifest);
		$this->assertTrue($manifest['config']['top1m_enabled']);
		$this->assertArrayNotHasKey('top1m_list', $manifest['config']);
		$this->assertSame($source, file_get_contents($GLOBALS['pfb']['unbound_py_top1m']));
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_sources']);
	}

	public function testEnabledPublicationFailureLeavesPreviousFileAndManifest(): void
	{
		$target = $GLOBALS['pfb']['unbound_py_top1m'];
		file_put_contents($target, "old.example\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"old":true}');
		file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", "new.example\n");
		$GLOBALS['pfb']['dnsbl_top1m'] = 'on';

		$manifest = pfb_unbound_python_sources([], [
			'top1m_atomic' => [
				'write' => static fn($stream, string $bytes): int => strlen($bytes),
				'flush' => static fn($stream): bool => FALSE,
				'fsync'  => static fn($stream): bool => TRUE,
			] + $this->successfulOwnershipOps(),
		]);

		$this->assertFalse($manifest);
		$this->assertSame("old.example\n", file_get_contents($target));
		$this->assertSame('{"old":true}', file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
	}

	public function testCopyFailureKeepsOldTargetVisibleAndDoesNotRestore(): void
	{
		$target = $GLOBALS['pfb']['unbound_py_top1m'];
		file_put_contents($target, "old.example\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"old":true}');
		file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", "new.example\n");
		$GLOBALS['pfb']['dnsbl_top1m'] = 'on';
		$copy_observed = [];
		$restore_called = FALSE;

		$result = pfb_unbound_python_sources([], [
			'top1m_atomic' => [
				'write' => static fn($stream, string $bytes): int => strlen($bytes),
				'flush' => static fn($stream): bool => TRUE,
				'fsync'  => static fn($stream): bool => TRUE,
				'rename' => function (string $from, string $to) use (&$copy_observed): bool {
					$copy_observed[] = [file_exists($to), file_get_contents($to)];
					return FALSE;
				},
				'restore' => static function (string $from, string $to) use (&$restore_called): bool {
					$restore_called = TRUE;
					return FALSE;
				},
			] + $this->successfulOwnershipOps(),
			'manifest_atomic' => [
				'rename' => static fn(string $from, string $to): bool => FALSE,
			],
		]);

		$this->assertFalse($result);
		$this->assertSame([[TRUE, "old.example\n"]], $copy_observed);
		$this->assertFalse($restore_called);
		$this->assertSame("old.example\n", file_get_contents($target));
		$this->assertSame('{"old":true}', file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
		$this->assertSame([], glob("{$this->tmp}/.pfbtop1m_prev_*") ?: []);
	}

	public function testManifestFailureRollsBackTop1mViaAtomicRename(): void
	{
		$target = $GLOBALS['pfb']['unbound_py_top1m'];
		file_put_contents($target, "old.example\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"old":true}');
		file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", "new.example\n");
		$GLOBALS['pfb']['dnsbl_top1m'] = 'on';
		$restore_observed = [];

		$result = pfb_unbound_python_sources([], [
			'top1m_atomic' => [
				'restore' => function (string $from, string $to) use (&$restore_observed): bool {
					$restore_observed[] = [file_exists($to), file_get_contents($to)];
					return rename($from, $to);
				},
			] + $this->successfulOwnershipOps(),
			'manifest_atomic' => [
				'rename' => static fn(string $from, string $to): bool => FALSE,
			],
		]);

		$this->assertFalse($result);
		$this->assertSame([[TRUE, "new.example\n"]], $restore_observed);
		$this->assertSame("old.example\n", file_get_contents($target));
		$this->assertSame('{"old":true}', file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
	}

	public function testMetadataFailureAbortsFixedFilePublication(): void
	{
		$source = "{$this->tmp}/source.txt";
		$target = "{$this->tmp}/target.txt";
		file_put_contents($source, "source.example\n");
		$ops = $this->successfulOwnershipOps();
		$ops['metadata'] = static fn(string $file): bool => FALSE;

		$this->assertFalse(pfb_unbound_py_atomic_copy($source, $target, $ops));
		$this->assertFileDoesNotExist($target);
	}

	public static function ownershipFailureCallbacks(): array
	{
		return [
			'chown' => ['chown'],
			'chgrp' => ['chgrp'],
			'chmod' => ['chmod'],
		];
	}

	#[DataProvider('ownershipFailureCallbacks')]
	public function testOwnershipFailureAbortsFixedFilePublication(string $failed_callback): void
	{
		$source = "{$this->tmp}/source.txt";
		$target = "{$this->tmp}/target.txt";
		file_put_contents($source, "source.example\n");
		$ops = $this->successfulOwnershipOps();
		$ops[$failed_callback] = static fn(string $file, $value): bool => FALSE;

		$this->assertFalse(pfb_unbound_py_atomic_copy($source, $target, $ops));
		$this->assertFileDoesNotExist($target);
	}

	private function successfulOwnershipOps(): array
	{
		return [
			'chown' => static fn(string $file, string $owner): bool => TRUE,
			'chgrp' => static fn(string $file, string $group): bool => TRUE,
			'chmod' => static fn(string $file, int $mode): bool => TRUE,
		];
	}

	private function removeTree(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($it as $entry) {
			$entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
		}
		rmdir($dir);
	}
}
