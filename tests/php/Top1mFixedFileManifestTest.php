<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

final class Top1mChangingSourceStream
{
	public $context;
	public static int $opens = 0;
	private string $bytes = '';
	private int $offset = 0;

	public static function reset(): void
	{
		self::$opens = 0;
	}

	public function stream_open(string $path, string $mode, int $options, ?string &$opened_path): bool
	{
		self::$opens++;
		$this->bytes = self::$opens === 1
			? "canonical.example\n"
			: ".legacy.example,,\n,legacy.example,,\n,www.legacy.example,,\n";
		$this->offset = 0;
		return TRUE;
	}

	public function stream_read(int $count): string
	{
		$bytes = substr($this->bytes, $this->offset, $count);
		$this->offset += strlen($bytes);
		return $bytes;
	}

	public function stream_eof(): bool
	{
		return $this->offset >= strlen($this->bytes);
	}

	public function stream_seek(int $offset, int $whence=SEEK_SET): bool
	{
		$next = match ($whence) {
			SEEK_SET => $offset,
			SEEK_CUR => $this->offset + $offset,
			SEEK_END => strlen($this->bytes) + $offset,
			default => -1,
		};
		if ($next < 0 || $next > strlen($this->bytes)) {
			return FALSE;
		}
		$this->offset = $next;
		return TRUE;
	}

	public function stream_tell(): int
	{
		return $this->offset;
	}

	public function stream_stat(): array
	{
		return self::regularStat(strlen($this->bytes));
	}

	public function url_stat(string $path, int $flags): array
	{
		return self::regularStat(strlen("canonical.example\n"));
	}

	private static function regularStat(int $size): array
	{
		return [
			2 => 0100644,
			7 => $size,
			'mode' => 0100644,
			'size' => $size,
		];
	}
}

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
			'dnsbl_top1m'        => PfbToggle::Off,
			'dnsbl_tld_wildcard' => '',
			'dnsblconfig'        => ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''],
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
		$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
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

	public function testCanonicalPublicationUsesTheClassifiedSourceSnapshot(): void
	{
		$scheme = 'pfbtop1mrace';
		$this->assertTrue(stream_wrapper_register($scheme, Top1mChangingSourceStream::class));
		Top1mChangingSourceStream::reset();
		$target = "{$this->tmp}/classified.txt";
		try {
			$result = pfb_unbound_py_top1m_atomic_copy(
				"{$scheme}://source",
				$target,
				$this->successfulOwnershipOps()
			);
		} finally {
			$this->assertTrue(stream_wrapper_unregister($scheme));
		}

		$this->assertTrue($result);
		$this->assertSame(1, Top1mChangingSourceStream::$opens);
		$this->assertSame("canonical.example\n", file_get_contents($target));
	}

	public static function legacyProjectionCases(): array
	{
		return [
			'python-mode' => [
				".Example.COM,,\n,example.com,,\n,www.EXAMPLE.COM,,\n" .
				".Duplicate.Example,,\n,DUPLICATE.example,,\n,www.duplicate.EXAMPLE,,\n" .
				".duplicate.example,,\n,Duplicate.Example,,\n,www.DUPLICATE.EXAMPLE,,\n",
			],
			'native-mode' => [
				".Example.COM 60\n\"example.com 60\n\"www.EXAMPLE.COM 60\n" .
				".Duplicate.Example 60\n\"DUPLICATE.example 60\n\"www.duplicate.EXAMPLE 60\n" .
				".duplicate.example 60\n\"Duplicate.Example 60\n\"www.DUPLICATE.EXAMPLE 60\n",
			],
		];
	}

	#[DataProvider('legacyProjectionCases')]
	public function testEnabledProjectsCompleteLegacyRecordsAndPreservesCachedSource(string $source): void
	{
		$source_path = "{$this->tmp}/db/pfbalexawhitelist.txt";
		file_put_contents($source_path, $source);

		$result = $this->publishTop1m();

		$this->assertIsArray($result);
		$this->assertSame($source, file_get_contents($source_path));
		$this->assertSame(
			"example.com\nduplicate.example\nduplicate.example\n",
			file_get_contents($GLOBALS['pfb']['unbound_py_top1m'])
		);
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_sources']);
	}

	public static function malformedLegacySources(): array
	{
		$comma = static fn(string $domain): string =>
			".{$domain},,\n,{$domain},,\n,www.{$domain},,\n";
		$native = static fn(string $domain): string =>
			".{$domain} 60\n\"{$domain} 60\n\"www.{$domain} 60\n";
		$overlong_domain = 'aa.' . implode('.', array_fill(0, 126, 'a'));

		return [
			'mixed families'       => [$comma('one.example') . $native('two.example')],
			'CRLF'                 => [str_replace("\n", "\r\n", $comma('bad.example'))],
			'blank'                => [$comma('bad.example') . "\n"],
			'header'               => [$comma('bad.example') . "header\n"],
			'extra line'           => [$comma('bad.example') . ".extra.example,,\n"],
			'incomplete triple'    => [".bad.example,,\n,bad.example,,\n"],
			'missing final LF'     => [rtrim($comma('bad.example'), "\n")],
			'mismatched domains'   => [".one.example,,\n,two.example,,\n,www.one.example,,\n"],
			'mixed triple'         => [".bad.example,,\n\"bad.example 60\n\"www.bad.example 60\n"],
			'underscore'           => [$comma('bad_name.example')],
			'Unicode'              => [$comma('tést.example')],
			'dotless'              => [$comma('dotless')],
			'overlong label'       => [$comma(str_repeat('a', 64) . '.example')],
			'overlong domain'      => [$comma($overlong_domain)],
			'leading hyphen'       => [$comma('-bad.example')],
			'trailing hyphen'      => [$comma('bad-.example')],
			'overlong source line' => ['.' . str_repeat('a', 1100) . ",,\n"],
		];
	}

	#[DataProvider('malformedLegacySources')]
	public function testMalformedLegacySourceRollsBackTargetAndManifest(string $source): void
	{
		$this->seedPreviousPublication();
		file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", $source);

		$result = $this->publishTop1m();

		$this->assertFalse($result);
		$this->assertPreviousPublication();
		$this->assertSame([], glob("{$this->tmp}/.pfbtop1m_*") ?: []);
	}

	public static function publicationFailureOperations(): array
	{
		return [
			'write'    => ['write'],
			'flush'    => ['flush'],
			'fsync'    => ['fsync'],
			'metadata' => ['metadata'],
			'rename'   => ['rename'],
		];
	}

	#[DataProvider('publicationFailureOperations')]
	public function testLegacyProjectionFailureRollsBackTargetAndManifest(string $operation): void
	{
		$this->seedPreviousPublication();
		file_put_contents(
			"{$this->tmp}/db/pfbalexawhitelist.txt",
			".legacy.example,,\n,legacy.example,,\n,www.legacy.example,,\n"
		);
		$ops = match ($operation) {
			'write' => ['write' => static fn($stream, string $bytes): int => max(0, strlen($bytes) - 1)],
			'flush' => ['flush' => static fn($stream): bool => FALSE],
			'fsync' => ['fsync' => static fn($stream): bool => FALSE],
			'metadata' => ['metadata' => static fn(string $file): bool => FALSE],
			'rename' => ['rename' => static fn(string $from, string $to): bool => FALSE],
		};

		$result = $this->publishTop1m($ops);

		$this->assertFalse($result);
		$this->assertPreviousPublication();
		$this->assertSame([], glob("{$this->tmp}/.pfbtop1m_*") ?: []);
	}

	public static function nonregularSourceKinds(): array
	{
		return [
			'directory' => ['directory'],
			'FIFO'      => ['FIFO'],
			'symlink'   => ['symlink'],
		];
	}

	#[DataProvider('nonregularSourceKinds')]
	public function testEnabledRejectsNonregularOrSymlinkedSource(string $kind): void
	{
		$this->seedPreviousPublication();
		$source = "{$this->tmp}/db/pfbalexawhitelist.txt";
		$fifo_guard = NULL;
		$fifo_payload = '';
		if ($kind === 'directory') {
			mkdir($source);
		} elseif ($kind === 'FIFO') {
			$this->assertTrue(posix_mkfifo($source, 0600));
			$fifo_guard = fopen($source, 'r+');
			$this->assertIsResource($fifo_guard);
			$this->assertTrue(stream_set_blocking($fifo_guard, FALSE));
			$fifo_payload = ".one.example,,\n,two.example,,\n,www.one.example,,\n";
			$this->assertSame(strlen($fifo_payload), fwrite($fifo_guard, $fifo_payload));
			$this->assertTrue(fflush($fifo_guard));
		} else {
			$linked = "{$this->tmp}/legacy-source.txt";
			file_put_contents($linked, ".legacy.example,,\n,legacy.example,,\n,www.legacy.example,,\n");
			symlink($linked, $source);
		}

		$result = $this->publishTop1m();

		$this->assertFalse($result);
		if (is_resource($fifo_guard)) {
			$this->assertSame($fifo_payload, fread($fifo_guard, strlen($fifo_payload)));
			fclose($fifo_guard);
		}
		$this->assertPreviousPublication();
		$this->assertSame([], glob("{$this->tmp}/.pfbtop1m_*") ?: []);
	}

	public function testEnabledPublicationFailureLeavesPreviousFileAndManifest(): void
	{
		$target = $GLOBALS['pfb']['unbound_py_top1m'];
		file_put_contents($target, "old.example\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"old":true}');
		file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", "new.example\n");
		$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;

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
		$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
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
		$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
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

	private function successfulOwnershipOps(): array
	{
		return [
			'chown' => static fn(string $file, string $owner): bool => TRUE,
			'chgrp' => static fn(string $file, string $group): bool => TRUE,
			'chmod' => static fn(string $file, int $mode): bool => TRUE,
		];
	}

	private function publishTop1m(array $ops=array())
	{
		$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
		return pfb_unbound_python_sources([], [
			'top1m_atomic' => $ops + $this->successfulOwnershipOps(),
		]);
	}

	private function seedPreviousPublication(): void
	{
		file_put_contents($GLOBALS['pfb']['unbound_py_top1m'], "old.example\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"old":true}');
	}

	private function assertPreviousPublication(): void
	{
		$this->assertSame("old.example\n", file_get_contents($GLOBALS['pfb']['unbound_py_top1m']));
		$this->assertSame('{"old":true}', file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
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
