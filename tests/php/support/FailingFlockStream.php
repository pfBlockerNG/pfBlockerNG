<?php

declare(strict_types=1);

/** Test stream that opens successfully but rejects every flock() operation as an I/O error. */
final class PfbFailingFlockStream
{
	public mixed $context;

	public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
	{
		return TRUE;
	}

	public function stream_lock(int $operation): bool
	{
		return FALSE;
	}

	public function stream_stat(): array
	{
		return [];
	}

	public function url_stat(string $path, int $flags): array|false
	{
		return FALSE;
	}
}
