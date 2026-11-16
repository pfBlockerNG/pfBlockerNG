<?php
const VIEWER_LIMIT = 1_000_000;
const VIEWER_NOTICE = "\n[ pfBlockerNG ] Script output limit (1,000,000 characters) reached; remaining output is in the main log.\n";
function demand(bool $ok, string $why): void {
	if (!$ok) {
		throw new RuntimeException($why);
	}
}

function until(callable $probe, string $why, float $seconds = 30): mixed {
	$end = microtime(TRUE) + $seconds;
	do {
		$value = $probe();
		if ($value) {
			return $value;
		}
		usleep(20_000);
	} while (microtime(TRUE) < $end);
	throw new RuntimeException('deadline: ' . $why);
}

function api(string $dir, string $method, array $body = [], int $timeout = 3): array {
	$curl = curl_init('http://localhost/v1/' . $method);
	curl_setopt_array($curl, [CURLOPT_UNIX_SOCKET_PATH => "$dir/run/api.sock", CURLOPT_POST => TRUE,
		CURLOPT_POSTFIELDS => json_encode($body ?: (object) [], JSON_THROW_ON_ERROR),
		CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_RETURNTRANSFER => TRUE, CURLOPT_TIMEOUT => $timeout]);
	$text = curl_exec($curl);
	$status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
	$error = curl_error($curl);
	curl_close($curl);
	$decoded = is_string($text) ? json_decode($text, TRUE) : NULL;
	return [$status, is_array($decoded) ? $decoded : NULL, $error];
}

function submit_update_start(string $dir, array $requestBody, bool &$attempted, bool &$accepted,
	?callable $request = NULL): array {
	$request ??= static fn(string $method, array $body, int $timeout): array =>
		api($dir, $method, $body, $timeout);
	$attempted = TRUE;
	[$status, $body, $error] = $request('StartUpdate', $requestBody, 3);
	$accepted = $status === 200;
	return [$status, $body, $error];
}

function get_update(string $dir, ?string $after = NULL): array {
	[$status, $body, $error] = api($dir, 'GetUpdate', $after === NULL ? [] : ['after' => $after]);
	demand($status === 200 && is_array($body), "GetUpdate status={$status} error={$error}");
	return $body;
}

function digest(string $bytes): string {
	return 'bytes=' . strlen($bytes) . ' sha256=' . hash('sha256', $bytes);
}

function diagnostic_tail(string $path, int $limit): string {
	if (!is_file($path)) {
		return "{$path}: missing\n";
	}
	$file = fopen($path, 'rb');
	if ($file === FALSE) {
		return "{$path}: unreadable\n";
	}
	$info = fstat($file);
	$size = is_array($info) ? (int) ($info['size'] ?? 0) : 0;
	if ($size > $limit) {
		fseek($file, -$limit, SEEK_END);
	}
	$tail = $size > 0 ? fread($file, min($size, $limit)) : '';
	fclose($file);
	$encoded = json_encode((string) $tail, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
	return sprintf("%s bytes=%d tail=%s\n", $path, $size, $encoded === FALSE ? '[unavailable]' : $encoded);
}

function diagnostic_digest(string $path): string {
	if (!is_file($path)) {
		return "{$path}: missing\n";
	}
	$size = filesize($path);
	$hash = hash_file('sha256', $path);
	return sprintf("%s bytes=%s sha256=%s\n", $path, $size === FALSE ? '?' : (string) $size,
		$hash === FALSE ? 'unavailable' : $hash);
}

function php_runtime_preflight(): string {
	return sprintf(
		'NATIVE_PHP_PREFLIGHT php=%s mbstring=%s intl=%s mb_str_split=%s mb_check_encoding=%s mb_ord=%s IntlChar=%s',
		PHP_VERSION,
		extension_loaded('mbstring') ? 'yes' : 'no',
		extension_loaded('intl') ? 'yes' : 'no',
		function_exists('mb_str_split') ? 'yes' : 'no',
		function_exists('mb_check_encoding') ? 'yes' : 'no',
		function_exists('mb_ord') ? 'yes' : 'no',
		class_exists('IntlChar', FALSE) ? 'yes' : 'no'
	);
}

function fixture_marker_summary(string $dir): string {
	$markers = [];
	foreach (['hook.entered', 'hook.ready', 'hook.done', 'write.output', 'release', 'update.finished', 'cleanup.safe'] as $marker) {
		$markers[] = $marker . '=' . (is_file("$dir/{$marker}") ? '1' : '0');
	}
	return implode(',', $markers);
}
function report_fixture_failure(string $dir, string $kind, string $detail): void {
	$encoded = json_encode(substr($detail, 0, 2048), JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
	$report = sprintf("NATIVE_FIXTURE_FAILURE timestamp=%s phase=%s detail=%s\n",
		gmdate('Y-m-d\TH:i:s\Z'), $kind, $encoded === FALSE ? '[unavailable]' : $encoded);
	$report .= 'markers=' . fixture_marker_summary($dir) . "\n";
	$report .= diagnostic_tail("$dir/controller.preflight", 1024);
	$report .= diagnostic_tail("$dir/core.log", 4096);
	$report .= diagnostic_tail("$dir/update.error", 4096);
	$report .= diagnostic_tail("$dir/error.log", 4096);
	$report .= diagnostic_digest("$dir/state/update.log");
	$report .= diagnostic_digest("$dir/main.log");
	if (file_put_contents("$dir/control.error", $report, FILE_APPEND) === FALSE) {
		fwrite(STDERR, "NATIVE_FIXTURE_DIAGNOSTICS_WRITE_FAILED\n");
	}
	fwrite(STDERR, $report);
}

function hex_window(string $bytes, int $start, int $length): string {
	$size = strlen($bytes);
	$start = max(0, min($start, $size));
	$length = max(0, min($length, $size - $start));
	return bin2hex(substr($bytes, $start, $length));
}

function hook_terminal_diagnostic(string $bytes): string {
	$position = strrpos($bytes, '[ pfB Hook ] pre native output cap');
	if ($position === FALSE) {
		return 'absent';
	}
	$end = strpos($bytes, "\n", $position);
	$line = substr($bytes, $position, $end === FALSE ? 256 : min(256, $end - $position));
	$state = match (TRUE) {
		str_contains($line, ' TIMED OUT after ') => 'timeout',
		str_contains($line, ' exited non-zero [ ') => 'nonzero',
		str_contains($line, ' completed') => 'success',
		default => 'other',
	};
	$encoded = json_encode($line, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
	return $state . ':' . ($encoded === FALSE ? '[unavailable]' : $encoded);
}

function viewer_boundary_diagnostics(string $dir, string $bytes, array $view, int $boundary, string $notice): string {
	$noticeAt = strpos($bytes, $notice);
	$update = json_encode($view['update'] ?? NULL, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
	return sprintf(
		'phase=live-collect time=%s bytes=%d running=%s update=%s next=%s notice_count=%d notice_at=%s hook_terminal=%s markers=%s first_hex=%s cap_before_hex=%s cap_after_hex=%s notice_before_hex=%s notice_after_hex=%s last_hex=%s',
		gmdate('Y-m-d\TH:i:s\Z'), strlen($bytes), ($view['running'] ?? FALSE) ? '1' : '0',
		$update === FALSE ? '[unavailable]' : $update, (string) ($view['next'] ?? ''),
		substr_count($bytes, $notice), $noticeAt === FALSE ? 'missing' : (string) $noticeAt,
		hook_terminal_diagnostic($bytes), fixture_marker_summary($dir), hex_window($bytes, 0, 32),
		hex_window($bytes, $boundary - 32, 32), hex_window($bytes, $boundary, 32),
		$noticeAt === FALSE ? 'missing' : hex_window($bytes, $noticeAt - 32, 32),
		$noticeAt === FALSE ? 'missing' : hex_window($bytes, $noticeAt + strlen($notice), 256),
		hex_window($bytes, strlen($bytes) - 32, 32)
	);
}

/** @return array{string, string} collected bytes and the next independent cursor */
function collect_exact(string $dir, string $after, int $length, string $label, ?callable $fetch = NULL): array {
	$bytes = '';
	$start = $after;
	$next = $after;
	$pages = 0;
	$notice = VIEWER_NOTICE;
	$end = microtime(TRUE) + 45;
	do {
		$view = $fetch === NULL ? get_update($dir, $next) : $fetch($dir, $next);
		$pages++;
		$bytes .= (string) ($view['log'] ?? '');
		$next = (string) ($view['next'] ?? '');
		if (strlen($bytes) > $length) {
			$mask = (1 << 40) - 1;
			$startOffset = ctype_digit($start) ? ((int) $start & $mask) : -1;
			$nextOffset = ctype_digit($next) ? ((int) $next & $mask) : -1;
			$advance = $startOffset >= 0 && $nextOffset >= $startOffset
				? (string) ($nextOffset - $startOffset) : 'invalid';
			$cursorDetail = sprintf('pages=%d cursor_start=%s cursor_end=%s cursor_advance=%s',
				$pages, $start, $next, $advance);
			throw new RuntimeException(sprintf('%s exceeded expected viewer bytes: %s %s %s', $label, digest($bytes),
				$cursorDetail, viewer_boundary_diagnostics($dir, $bytes, $view, $length - strlen($notice), $notice)));
		}
		if (strlen($bytes) === $length) {
			demand(($view['running'] ?? FALSE) === TRUE, "{$label} was not live at the output barrier");
			return [$bytes, $next];
		}
		usleep(20_000);
	} while (microtime(TRUE) < $end);
	throw new RuntimeException("{$label} output deadline: " . digest($bytes) . ' ' .
		viewer_boundary_diagnostics($dir, $bytes, $view, $length - strlen($notice), $notice));
}

/** @return array{string, array} complete transcript and final view */
function collect_complete(string $dir, string $after): array {
	$bytes = '';
	$next = $after;
	$end = microtime(TRUE) + 45;
	do {
		$previous = $next;
		$view = get_update($dir, $next);
		$chunk = (string) ($view['log'] ?? '');
		$bytes .= $chunk;
		$next = (string) ($view['next'] ?? '');
		if (($view['running'] ?? TRUE) === FALSE && $chunk === '' && $next === $previous) {
			return [$bytes, $view];
		}
		usleep(20_000);
	} while (microtime(TRUE) < $end);
	throw new RuntimeException('completed transcript deadline: ' . digest($bytes));
}


function diagnostic_probe_mode(): void {
	$dir = sys_get_temp_dir() . '/pfb-boundary-probe-' . bin2hex(random_bytes(4));
	$log = str_repeat('A', VIEWER_LIMIT) . VIEWER_NOTICE . 'TAIL';
	$after = '123';
	$view = ['running' => TRUE, 'update' => ['trigger' => 'apply', 'startedAt' => 1],
		'next' => (string) ((int) $after + strlen($log)), 'log' => $log];
	$fetch = static function (string $path, string $cursor) use ($after, $view): array {
		demand($cursor === $after, 'diagnostic probe cursor changed unexpectedly');
		return $view;
	};
	$length = VIEWER_LIMIT + strlen(VIEWER_NOTICE);
	try {
		collect_exact($dir, $after, $length, 'diagnostic probe', $fetch);
	} catch (RuntimeException $error) {
		$detail = $error->getMessage();
		demand(str_contains($detail, 'pages=1'), 'diagnostic probe did not report page count');
		demand(str_contains($detail, 'cursor_advance=' . strlen($log)), 'diagnostic probe cursor span is missing');
		demand(str_contains($detail, 'phase=live-collect'), 'diagnostic probe phase is missing');
		demand(str_contains($detail, 'running=1'), 'diagnostic probe running state is missing');
		demand(str_contains($detail, 'notice_count=1'), 'diagnostic probe notice count is wrong');
		demand(str_contains($detail, 'notice_at=' . VIEWER_LIMIT), 'diagnostic probe notice offset is wrong');
		demand(str_contains($detail, 'notice_after_hex=5441494c'), 'diagnostic probe trailing window is missing');
		printf("LOCAL_BOUNDARY_DIAGNOSTIC_PASS %s\n", digest($log));
		return;
	}
	throw new RuntimeException('diagnostic probe did not reject its intentional extra page byte');
}
function start_core(string $binary, string $dir): mixed {
	$core = proc_open([$binary, '--socket', "$dir/run/api.sock", '--state-dir', "$dir/state",
		'--update-cmd', "$dir/update.sh", '--allow-uid', '0'],
		[0 => ['file', '/dev/null', 'r'], 1 => ['file', "$dir/core.log", 'a'], 2 => ['file', "$dir/core.log", 'a']], $pipes);
	demand(is_resource($core), 'private Core spawn failed');
	return $core;
}

function stop_core(mixed &$core): void {
	if (!is_resource($core)) {
		return;
	}
	if (proc_get_status($core)['running']) {
		proc_terminate($core, SIGTERM);
		until(static fn() => !proc_get_status($core)['running'], 'owned private Core shutdown', 15);
	}
	proc_close($core);
	$core = NULL;
}

/**
 * Replay an uncertain StartUpdate before stopping Core or marking its private tree safe.
 *
 * @param array<string, mixed> $startRequest
 * @param list<string> $cleanupErrors
 */
function cleanup_private_core(string $dir, bool $attempted, bool $accepted, array $startRequest,
	array &$cleanupErrors, callable $stop, ?callable $request = NULL, float $seconds = 90): void {
	$request ??= static fn(string $method, array $body, int $timeout): array =>
		api($dir, $method, $body, $timeout);
	$updateSettled = !$attempted;
	if ($attempted) {
		try {
			if (!$accepted) {
				[$status, $body, $error] = $request('StartUpdate', $startRequest, 60);
				demand($status === 200 && is_array($body), "StartUpdate replay status={$status} error={$error}");
			}
			until(static function () use ($request): array|false {
				[$status, $body] = $request('GetUpdate', [], 3);
				return $status === 200 && is_array($body) && ($body['running'] ?? TRUE) === FALSE &&
					is_array($body['update'] ?? NULL) && isset($body['update']['finishedAt']) ? $body : FALSE;
			}, 'Update worker completion and lease release', $seconds);
			$updateSettled = TRUE;
		} catch (Throwable $error) {
			$cleanupErrors[] = 'Update worker completion: ' . $error->getMessage();
		}
	}
	if ($updateSettled) {
		try {
			$stop();
		} catch (Throwable $error) {
			$cleanupErrors[] = 'private Core shutdown: ' . $error->getMessage();
		}
	}
	if ($cleanupErrors === [] && file_put_contents("$dir/cleanup.safe", "safe\n") === FALSE) {
		$cleanupErrors[] = 'cannot mark the private directory safe to remove';
	}
}

function cleanup_probe_mode(): void {
	$scenarios = ['accepted-timeout', 'not-accepted-replay', 'api-unavailable', 'conflict'];
	foreach ($scenarios as $scenario) {
		$dir = sys_get_temp_dir() . '/pfb-update-cleanup-probe-' . bin2hex(random_bytes(4));
		demand(mkdir($dir, 0700), 'cannot create local cleanup-probe directory');
		try {
			$startRequest = ['requestId' => 'cleanup-probe-' . bin2hex(random_bytes(4)), 'trigger' => 'apply'];
			$attempted = FALSE;
			$accepted = FALSE;
			$acceptedAtServer = FALSE;
			$startCalls = [];
			$getCalls = 0;
			$terminal = FALSE;
			$stopCalls = 0;
			$request = static function (string $method, array $body, int $timeout) use (
				$scenario, $startRequest, $dir, &$attempted, &$acceptedAtServer, &$startCalls, &$getCalls, &$terminal
			): array {
				if ($method === 'StartUpdate') {
					demand($attempted, 'StartUpdate was called before the attempt flag was set');
					$startCalls[] = ['body' => $body, 'timeout' => $timeout];
					if (count($startCalls) === 1) {
						if (in_array($scenario, ['accepted-timeout', 'api-unavailable'], TRUE)) {
							$acceptedAtServer = TRUE;
						}
						return [0, NULL, 'simulated response timeout'];
					}
					demand(count($startCalls) === 2, 'StartUpdate was replayed more than once');
					demand($body === $startRequest, 'StartUpdate replay changed its request body');
					if ($scenario === 'api-unavailable') {
						return [0, NULL, 'simulated API unavailable'];
					}
					if ($scenario === 'conflict') {
						return [409, ['error' => ['code' => 'conflict']], 'simulated conflict'];
					}
					if ($scenario === 'not-accepted-replay') {
						$acceptedAtServer = TRUE;
					}
					return $acceptedAtServer ? [200, ['accepted' => TRUE], ''] : [409, NULL, 'not accepted'];
				}
				if ($method === 'GetUpdate') {
					$getCalls++;
					if (!$acceptedAtServer) {
						return [503, NULL, 'no accepted update'];
					}
					if ($scenario === 'accepted-timeout' && $getCalls === 1) {
						demand(!is_file("$dir/cleanup.safe"), 'cleanup became safe while the worker was running');
						return [200, ['running' => TRUE,
							'update' => ['trigger' => 'apply', 'startedAt' => 1], 'next' => '0', 'log' => ''], ''];
					}
					$terminal = TRUE;
					return [200, ['running' => FALSE,
						'update' => ['trigger' => 'apply', 'startedAt' => 1, 'finishedAt' => 2, 'result' => 'success'],
						'next' => '0', 'log' => ''], ''];
				}
				return [404, NULL, 'unknown cleanup-probe method'];
			};
			[$status] = submit_update_start($dir, $startRequest, $attempted, $accepted, $request);
			demand($status === 0 && $attempted && !$accepted, "{$scenario}: response was not ambiguous");
			$cleanupErrors = [];
			$stop = static function () use ($scenario, $dir, &$terminal, &$stopCalls): void {
				demand(!is_file("$dir/cleanup.safe"), 'cleanup marker preceded Core shutdown');
				if (in_array($scenario, ['accepted-timeout', 'not-accepted-replay'], TRUE)) {
					demand($terminal, 'Core shutdown preceded terminal Update status');
				}
				$stopCalls++;
			};
			cleanup_private_core($dir, $attempted, $accepted, $startRequest, $cleanupErrors, $stop, $request);
			$shouldBeSafe = in_array($scenario, ['accepted-timeout', 'not-accepted-replay'], TRUE);
			demand(is_file("$dir/cleanup.safe") === $shouldBeSafe, "{$scenario}: cleanup-safe marker state is wrong");
			demand(($cleanupErrors === []) === $shouldBeSafe, "{$scenario}: cleanup error state is wrong");
			demand($stopCalls === ($shouldBeSafe ? 1 : 0), "{$scenario}: Core shutdown state is wrong");
			demand(count($startCalls) === 2, "{$scenario}: StartUpdate replay count is wrong");
			demand($startCalls[0] === ['body' => $startRequest, 'timeout' => 3], "{$scenario}: initial request changed");
			demand($startCalls[1] === ['body' => $startRequest, 'timeout' => 60], "{$scenario}: replay request changed");
			demand($getCalls === ($scenario === 'accepted-timeout' ? 2 : ($scenario === 'not-accepted-replay' ? 1 : 0)),
				"{$scenario}: GetUpdate call count is wrong");
		} finally {
			if (is_file("$dir/cleanup.safe")) {
				unlink("$dir/cleanup.safe");
			}
			rmdir($dir);
		}
	}
	printf("LOCAL_UPDATE_CLEANUP_PROBE_PASS scenarios=%d\n", count($scenarios));
}

function update_mode(string $dir): void {
	$result = 1;
	register_shutdown_function(static function () use ($dir): void {
		$error = error_get_last();
		$fatal = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR];
		if ($error === NULL || !in_array($error['type'], $fatal, TRUE)) {
			return;
		}
		$detail = sprintf('type=%d at %s:%d: %s', $error['type'], $error['file'], $error['line'],
			substr($error['message'], 0, 2048));
		$line = "NATIVE_UPDATE_FATAL: {$detail}\n";
		if (file_put_contents("$dir/update.error", $line, FILE_APPEND) === FALSE) {
			fwrite(STDERR, "NATIVE_UPDATE_ERROR_WRITE_FAILED\n");
		}
		fwrite(STDERR, $line);
	});
	try {
		$request = json_decode(stream_get_contents(STDIN), TRUE, 512, JSON_THROW_ON_ERROR);
		demand(is_array($request), 'Core Update request is not an object');
		require_once('/etc/inc/config.inc');
		require_once('/etc/inc/util.inc');
		if (!defined('PFB_HOOK_SCRIPT_DIR')) {
			define('PFB_HOOK_SCRIPT_DIR', "$dir/hooks");
		}
		require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');

		$GLOBALS['g'] = [];
		$GLOBALS['pfb'] = ['log' => "$dir/main.log", 'errlog' => "$dir/error.log",
			'core_update' => TRUE, 'core_state' => "$dir/state", 'hook_lifecycle' => ''];
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerng' => ['config' => [0 => ['hooks' => ['row' => [[
			'script' => 'hook_pre_native.sh', 'when' => 'pre', 'enabled' => 'on', 'description' => 'native output cap', 'timeout' => '120',
		]]]]]]]];

		pfb_run_hooks('pre', ['TRIGGER' => (string) ($request['trigger'] ?? 'apply')]);
		pfb_logger("NORMAL_PROGRESS_AFTER_HOOK\n", 1);
		$status = pfb_list_script_exec("$dir/scripts/list_post_native.sh", 'list_post_native.sh', 'post',
			'NATIVE', '', NULL);
		demand($status === 0, "list executor status={$status}");

		$fd = fopen('php://fd/3', 'w');
		demand(is_resource($fd), 'Core result descriptor is unavailable');
		fwrite($fd, json_encode(['version' => 1, 'attempted' => [], 'outcomes' => (object) [], 'geoipReady' => TRUE]) . "\n");
		fclose($fd);
		$result = 0;
	} catch (Throwable $error) {
		$detail = sprintf('%s at %s:%d: %s', get_class($error), $error->getFile(), $error->getLine(),
			substr($error->getMessage(), 0, 2048));
		$line = "NATIVE_UPDATE_EXCEPTION: {$detail}\n";
		if (file_put_contents("$dir/update.error", $line, FILE_APPEND) === FALSE) {
			fwrite(STDERR, "NATIVE_UPDATE_ERROR_WRITE_FAILED\n");
		}
		fwrite(STDERR, $line);
	} finally {
		file_put_contents("$dir/update.finished", "finished\n");
	}
	exit($result);
}

function control_mode(string $self, string $binary, string $dir): void {
	$core = NULL;
	$updateAttempted = FALSE;
	$updateAccepted = FALSE;
	$startRequest = [];
	$failure = NULL;
	$successSummary = '';
	register_shutdown_function(static function () use ($dir): void {
		$error = error_get_last();
		$fatal = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR];
		if ($error !== NULL && in_array($error['type'], $fatal, TRUE)) {
			report_fixture_failure($dir, 'control fatal', sprintf('%s at %s:%d: %s', $error['type'],
				$error['file'], $error['line'], substr($error['message'], 0, 2048)));
		}
	});
	$edgeTailRaw = "\u{00E9}\u{20AC}e\u{0301}\n\t\r\n\x00\x1b\x7f\u{0085}\u{200e}\xe2\x28\xa1";
	$edgeExpected = str_repeat('P', 8190) . "\u{1F4A9}\u{00E9}\u{20AC}e\u{0301}\n\t"
		. "\\x0D\n\\x00\\x1B\\x7F\\u{85}\\u{200E}\\xE2(\\xA1";
	$padCharacters = VIEWER_LIMIT - mb_strlen($edgeExpected, 'UTF-8') - strlen('\\x1B');
	$stdoutPayload = str_repeat('P', 8190) . "\xF0\x9F";
	$stderrPayload = "\x92\xA9" . $edgeTailRaw . str_repeat("\u{20AC}", $padCharacters)
		. "\x1B\x00OVERFLOW\r\n\xFF\xE2\x82";
	$expectedPrefix = $edgeExpected . str_repeat("\u{20AC}", $padCharacters) . '\\x1B';
	$expectedMain = $expectedPrefix . "\\x00OVERFLOW\\x0D\n\\xFF\\xE2\\x82";
	$stdoutPath = "$dir/payload.stdout";
	$stderrPath = "$dir/payload.stderr";
	$mainPath = "$dir/main.log";
	try {
		demand($padCharacters > 0, 'fixture UTF-8 boundary payload is too large');
		demand(mb_strlen($expectedPrefix, 'UTF-8') === VIEWER_LIMIT, 'expected sanitized prefix is not one million codepoints');
		demand(mb_strlen($expectedMain, 'UTF-8') > VIEWER_LIMIT &&
			strlen($stdoutPayload) + strlen($stderrPayload) > VIEWER_LIMIT, 'fixture does not overflow both output units');
		demand(file_put_contents($stdoutPath, $stdoutPayload) === strlen($stdoutPayload), 'cannot write private stdout payload');
		demand(file_put_contents($stderrPath, $stderrPayload) === strlen($stderrPayload), 'cannot write private stderr payload');
		foreach (["$dir/run", "$dir/state", "$dir/hooks", "$dir/scripts"] as $path) {
			demand(is_dir($path) || mkdir($path, 0700), "cannot create private path {$path}");
		}
		file_put_contents($mainPath, '');
		file_put_contents("$dir/error.log", '');

		$hook = "#!/bin/sh\nset -eu\n: > " . escapeshellarg("$dir/hook.entered") . "\n";
		$hook .= 'while [ ! -e ' . escapeshellarg("$dir/write.output") . " ]; do sleep 0.05; done\n";
		$hook .= '/bin/cat ' . escapeshellarg($stdoutPath) . "\n/bin/cat " . escapeshellarg($stderrPath) . " >&2\n";
		$hook .= ': > ' . escapeshellarg("$dir/hook.ready") . "\n";
		$hook .= 'while [ ! -e ' . escapeshellarg("$dir/release") . " ]; do sleep 0.05; done\n";
		$hook .= ': > ' . escapeshellarg("$dir/hook.done") . "\n";
		$hookPath = "$dir/hooks/hook_pre_native.sh";
		demand(file_put_contents($hookPath, $hook) === strlen($hook) && chmod($hookPath, 0700), 'cannot create private global hook');

		$listPath = "$dir/scripts/list_post_native.sh";
		$list = "#!/bin/sh\nset -eu\nprintf 'SECOND_SCRIPT_VISIBLE\\n'\n";
		demand(file_put_contents($listPath, $list) === strlen($list) && chmod($listPath, 0700), 'cannot create private list script');
		$command = "#!/bin/sh\nexec /usr/local/bin/php " . escapeshellarg($self) . ' update ' . escapeshellarg($dir) . "\n";
		demand(file_put_contents("$dir/update.sh", $command) === strlen($command) && chmod("$dir/update.sh", 0700),
			'cannot create private Update command');

		$core = start_core($binary, $dir);
		until(static fn() => api($dir, 'GetVersion')[0] === 200, 'private Core API readiness', 30);
		[$status, , $error] = api($dir, 'InitializeSettings', ['requestId' => 'native-init', 'settings' => (object) []]);
		demand($status === 200, "InitializeSettings status={$status} error={$error}");
		$startRequest = ['requestId' => bin2hex(random_bytes(16)), 'trigger' => 'apply'];
		[$status, , $error] = submit_update_start($dir, $startRequest, $updateAttempted, $updateAccepted);
		demand($status === 200, "StartUpdate status={$status} error={$error}");

		$initial = until(static function () use ($dir): array|false {
			if (!is_file("$dir/hook.entered")) {
				return FALSE;
			}
			$view = get_update($dir);
			return ($view['running'] ?? FALSE) === TRUE ? $view : FALSE;
		}, 'global hook entry and live Update', 45);
		$startCursor = (string) ($initial['next'] ?? '');
		demand(ctype_digit($startCursor), 'GetUpdate did not return the starting cursor');
		demand(str_contains((string) ($initial['log'] ?? ''),
			'[ pfB Hook ] pre native output cap (hook_pre_native.sh, timeout 120s)'),
			'GetUpdate did not expose the real global-hook header: ' . digest((string) ($initial['log'] ?? '')));

		demand(file_put_contents("$dir/write.output", "go\n") !== FALSE, 'cannot release output writer');
		until(static fn() => is_file("$dir/hook.ready"), 'global hook wrote both output streams', 45);
		$expectedViewer = $expectedPrefix . VIEWER_NOTICE;
		$liveLength = strlen($expectedViewer);
		[$viewerA, $cursorA] = collect_exact($dir, $startCursor, $liveLength, 'viewer A');
		[$viewerB] = collect_exact($dir, $startCursor, $liveLength, 'viewer B');
		demand($viewerA === $expectedViewer, 'viewer A sanitized character-cap mismatch: ' . digest($viewerA));
		demand($viewerB === $expectedViewer, 'viewer B sanitized character-cap mismatch: ' . digest($viewerB));
		demand($viewerA === $viewerB, 'independent live viewer positions differ');
		demand(substr_count($viewerA, VIEWER_NOTICE) === 1, 'live viewer does not contain exactly one limit notice');
		demand(is_file("$dir/hook.ready") && !is_file("$dir/hook.done") && !is_file("$dir/update.finished"),
			'global hook did not remain alive at its cooperative barrier');
		$live = get_update($dir);
		demand(($live['running'] ?? FALSE) === TRUE, 'GetUpdate did not remain live at the hook barrier');

		demand(file_put_contents("$dir/release", "release\n") !== FALSE, 'cannot release global hook');
		until(static fn() => is_file("$dir/hook.done"), 'global hook cooperative release', 45);
		until(static fn() => is_file("$dir/update.finished"), 'custom Update command completion', 45);
		$completed = until(static function () use ($dir): array|false {
			$view = get_update($dir);
			return ($view['running'] ?? TRUE) === FALSE && is_array($view['update'] ?? NULL) ? $view : FALSE;
		}, 'Core Update completion', 45);
		demand(($completed['update']['result'] ?? '') === 'success', 'successful PHP child result was not retained');

		[$transcriptA] = collect_complete($dir, $startCursor);
		[$transcriptB] = collect_complete($dir, $startCursor);
		demand($transcriptA === $transcriptB, 'independent completed viewer positions differ');
		demand(str_contains($transcriptA, "NORMAL_PROGRESS_AFTER_HOOK\n"), 'later normal progress is absent from GetUpdate');
		demand(str_contains($transcriptA, "SECOND_SCRIPT_VISIBLE\n"), 'later list-script output is absent from GetUpdate');
		demand(str_starts_with($transcriptA, $expectedViewer), 'completed View did not retain the capped hook transcript');

		$main = file_get_contents($mainPath);
		demand(is_string($main), 'private main log cannot be read');
		$mainMatches = substr_count($main, $expectedMain);
		$progressMatches = substr_count($main, "NORMAL_PROGRESS_AFTER_HOOK\n");
		$listMatches = substr_count($main, "SECOND_SCRIPT_VISIBLE\n");
		demand($mainMatches === 1, 'private main log did not contain full sanitized output exactly once: matches=' . $mainMatches);
		demand($progressMatches === 1, 'private main log did not contain ordinary progress exactly once: matches=' . $progressMatches);
		demand($listMatches === 1, 'private main log did not contain second-script output exactly once: matches=' . $listMatches);
		demand(!str_contains($main, VIEWER_NOTICE), 'viewer-only notice appeared in the main log');

		$rotated = "$dir/main.log.rotated";
		demand(rename($mainPath, $rotated) && file_put_contents($mainPath, '') !== FALSE, 'cannot rotate private main sink');
		[$afterRotation] = collect_complete($dir, $startCursor);
		demand($afterRotation === $transcriptA, 'GetUpdate transcript changed after private main-log rotation');

		$successSummary = sprintf("NATIVE_SCRIPT_OUTPUT_CAP_PASS live=%s transcript=%s main=%s result=%s\n",
			digest($viewerA), digest($transcriptA), digest($expectedMain), $completed['update']['result']);
	} catch (Throwable $error) {
		$failure = $error;
		report_fixture_failure($dir, 'control', sprintf('%s at %s:%d: %s', get_class($error), $error->getFile(),
			$error->getLine(), $error->getMessage()));
	} finally {
		$cleanupErrors = [];
		if (file_put_contents("$dir/write.output", "cleanup\n") === FALSE) {
			$cleanupErrors[] = 'cannot release output writer';
		}
		if (file_put_contents("$dir/release", "cleanup\n") === FALSE) {
			$cleanupErrors[] = 'cannot release global hook';
		}
		cleanup_private_core(
			$dir,
			$updateAttempted,
			$updateAccepted,
			$startRequest,
			$cleanupErrors,
			static function () use (&$core): void {
				if (is_resource($core)) {
					stop_core($core);
				}
			}
		);
		if ($cleanupErrors !== []) {
			$failure = $failure ?? new RuntimeException(implode('; ', $cleanupErrors));
			report_fixture_failure($dir, 'cleanup', implode('; ', $cleanupErrors));
		}
		if ($failure !== NULL) {
			report_fixture_failure($dir, 'post-cleanup', $failure->getMessage());
		}
	}
	if ($failure !== NULL) {
		exit(1);
	}
	fwrite(STDOUT, $successSummary);
}

$mode = (string) ($argv[1] ?? '');
if ($mode === 'cleanup-probe') {
	cleanup_probe_mode();
	exit(0);
}
if ($mode === 'update') {
	update_mode((string) ($argv[2] ?? ''));
}
if ($mode === 'diagnostic-probe') {
	diagnostic_probe_mode();
	exit(0);
}
demand($mode === 'control', 'unknown fixture mode');
	$fixtureDir = (string) ($argv[3] ?? '');
	$preflight = php_runtime_preflight();
	fwrite(STDOUT, $preflight . "\n");
	fflush(STDOUT);
	if (file_put_contents("$fixtureDir/controller.preflight", $preflight . "\n") === FALSE) {
		fwrite(STDERR, "NATIVE_PHP_PREFLIGHT_PERSIST_FAILED\n");
	}
control_mode((string) ($argv[0] ?? ''), (string) ($argv[2] ?? ''), (string) ($argv[3] ?? ''));
