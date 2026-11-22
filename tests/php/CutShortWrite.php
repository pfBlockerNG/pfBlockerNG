<?php

declare(strict_types=1);

/**
 * Runs a call in a forked child whose writes to any file stop after a few bytes (RLIMIT_FSIZE, with SIGXFSZ ignored so a
 * write comes back short instead of killing it), as a full disk cuts them short. The child dies without running shutdown
 * handlers, so it cannot touch the parent's sandbox.
 */
final class CutShortWrite
{
	public static function available(): bool
	{
		return function_exists('pcntl_fork') && function_exists('posix_setrlimit') && function_exists('posix_kill');
	}

	/** @return string what $call returned (var_export), or "ERR:" and the message of what it threw */
	public static function run(int $bytes, callable $call): string
	{
		$pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
		$pid = pcntl_fork();
		if ($pid === 0) {
			fclose($pair[0]);
			pcntl_signal(SIGXFSZ, SIG_IGN);
			posix_setrlimit(POSIX_RLIMIT_FSIZE, $bytes, $bytes);
			try {
				$out = var_export($call(), TRUE);
			} catch (Throwable $e) {
				$out = 'ERR:' . $e->getMessage();
			}
			fwrite($pair[1], $out);
			posix_kill(posix_getpid(), SIGKILL);
		}
		fclose($pair[1]);
		$out = (string) stream_get_contents($pair[0]);
		pcntl_waitpid($pid, $status);
		return $out;
	}
}
