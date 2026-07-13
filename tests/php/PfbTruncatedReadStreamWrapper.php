<?php

declare(strict_types=1);

/**
 * Stream wrapper simulating an aborted read: yields real bytes, then an empty
 * read, while stream_eof() reports FALSE forever -- never a clean end-of-file
 * (issue #1257: the counter must not treat this as a completed count).
 *
 * Shared by CountLinesTest (the primitive) and IpRecomputeSnapshotTest (the
 * caller), so it lives in its own file -- a class defined inside one test file
 * is invisible to a path-scoped run of the other.
 */
final class PfbTruncatedReadStreamWrapper
{
	/** @var resource|null */
	public $context;
	private static string $data = '';
	private int $pos = 0;
	private bool $exhausted = FALSE;

	public static function setData(string $data): void
	{
		self::$data = $data;
	}

	public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
	{
		$this->pos       = 0;
		$this->exhausted = FALSE;
		return TRUE;
	}

	public function stream_read(int $count): string
	{
		if ($this->exhausted) {
			return '';
		}
		$chunk = substr(self::$data, $this->pos, $count);
		$this->pos += strlen($chunk);
		if ($this->pos >= strlen(self::$data)) {
			$this->exhausted = TRUE;
		}
		return $chunk;
	}

	public function stream_eof(): bool
	{
		return FALSE;
	}

	public function stream_close(): void
	{
	}

	/** @return array<string,int> */
	public function stream_stat(): array
	{
		return [];
	}

	/** @return array<string,int> */
	public function url_stat(string $path, int $flags): array
	{
		return array_fill_keys(
			['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'rdev', 'size', 'atime', 'mtime', 'ctime', 'blksize', 'blocks'],
			0
		);
	}
}
