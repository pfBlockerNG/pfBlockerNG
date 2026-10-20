<?php

declare(strict_types=1);

/**
 * Start a command with its stdin on /dev/null and its stdout and stderr on non-blocking pipes. A test that holds several
 * processes at once starts each one here, and collects it with pfb_test_finish_process().
 *
 * @return array{0: resource, 1: array<int, resource>, 2: string} the process, its pipes, and the command as the messages name it
 */
function pfb_test_start_process(array $command, ?array $environment = null): array
{
	$process = proc_open(
		$command,
		[0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
		$pipes,
		null,
		$environment
	);
	if (!is_resource($process)) {
		throw new RuntimeException('test bootstrap: failed to start `' . implode(' ', $command) . '`');
	}

	stream_set_blocking($pipes[1], FALSE);
	stream_set_blocking($pipes[2], FALSE);

	return [$process, $pipes, implode(' ', $command)];
}

/**
 * Collect a started process under a hard deadline. A process still running when the deadline passes is terminated, then
 * killed, and reported as STUCK/ENVIRONMENT: its exit status is never read as a verdict. `termsig` is the signal that ended
 * the command (0 when it exited on its own), for a caller that must tell a signal from a status.
 *
 * @param array{0: resource, 1: array<int, resource>, 2: string} $started
 * @return array{stdout: string, stderr: string, exit: int, termsig: int}
 */
function pfb_test_finish_process(array $started, float $timeoutSeconds = 10.0): array
{
	[$process, $pipes, $command] = $started;
	$deadline = hrtime(TRUE) + (int) ($timeoutSeconds * 1_000_000_000);
	$attemptLimit = max(1, (int) ceil($timeoutSeconds * 100) + 1);
	$attempts = 0;
	$stdout = '';
	$stderr = '';

	do {
		$stdout .= (string) stream_get_contents($pipes[1]);
		$stderr .= (string) stream_get_contents($pipes[2]);
		$status = proc_get_status($process);
		if (!$status['running']) {
			break;
		}
		usleep(10_000);
	} while (++$attempts < $attemptLimit && hrtime(TRUE) < $deadline);

	if ($status['running']) {
		proc_terminate($process);
		usleep(100_000);
		$status = proc_get_status($process);
		if ($status['running']) {
			proc_terminate($process, 9);
		}
	}

	$stdout .= (string) stream_get_contents($pipes[1]);
	$stderr .= (string) stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	$closeExit = proc_close($process);

	if ($attempts >= $attemptLimit || hrtime(TRUE) >= $deadline) {
		throw new RuntimeException('STUCK/ENVIRONMENT: process exceeded hard deadline: `' . $command . '`');
	}

	return ['stdout' => $stdout, 'stderr' => $stderr, 'exit' => $status['exitcode'] >= 0 ? $status['exitcode'] : $closeExit, 'termsig' => !empty($status['signaled']) ? (int) $status['termsig'] : 0];
}

/** @return array{stdout: string, stderr: string, exit: int} */
function pfb_test_run_process(array $command, float $timeoutSeconds = 10.0, ?array $environment = null): array
{
	$run = pfb_test_finish_process(pfb_test_start_process($command, $environment), $timeoutSeconds);
	unset($run['termsig']);

	return $run;
}

/** @return array<string, string> */
function pfb_test_scrubbed_git_env(): array
{
	$environment = getenv();
	if (!is_array($environment)) {
		$environment = [];
	}
	foreach (array_keys($environment) as $name) {
		if (str_starts_with($name, 'GIT_')) {
			unset($environment[$name]);
		}
	}
	$environment['GIT_CONFIG_GLOBAL'] = '/dev/null';
	$environment['GIT_CONFIG_SYSTEM'] = '/dev/null';

	return $environment;
}
