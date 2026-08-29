<?php

declare(strict_types=1);

/** @return array{stdout: string, stderr: string, exit: int} */
function pfb_test_run_process(array $command, float $timeoutSeconds = 10.0, ?array $environment = null): array
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

	stream_set_blocking($pipes[1], false);
	stream_set_blocking($pipes[2], false);
	$deadline = hrtime(true) + (int) ($timeoutSeconds * 1_000_000_000);
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
	} while (++$attempts < $attemptLimit && hrtime(true) < $deadline);

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

	if ($attempts >= $attemptLimit || hrtime(true) >= $deadline) {
		throw new RuntimeException('STUCK/ENVIRONMENT: process exceeded hard deadline: `' . implode(' ', $command) . '`');
	}

	return ['stdout' => $stdout, 'stderr' => $stderr, 'exit' => $status['exitcode'] >= 0 ? $status['exitcode'] : $closeExit];
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
