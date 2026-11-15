<?php
const VIEWER_LIMIT = 1_048_576;
const VIEWER_NOTICE = "\n[ pfBlockerNG ] Script output limit (1 MiB) reached; remaining output is in the main log.\n";
const PAYLOAD_BLOCK = '0123456789abcdef';
const PAYLOAD_REPEATS = 49_152;

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

function api(string $dir, string $method, array $body = []): array {
	$curl = curl_init('http://localhost/v1/' . $method);
	curl_setopt_array($curl, [CURLOPT_UNIX_SOCKET_PATH => "$dir/run/api.sock", CURLOPT_POST => TRUE,
		CURLOPT_POSTFIELDS => json_encode($body ?: (object) [], JSON_THROW_ON_ERROR),
		CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_RETURNTRANSFER => TRUE, CURLOPT_TIMEOUT => 3]);
	$text = curl_exec($curl);
	$status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
	$error = curl_error($curl);
	curl_close($curl);
	$decoded = is_string($text) ? json_decode($text, TRUE) : NULL;
	return [$status, is_array($decoded) ? $decoded : NULL, $error];
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

function report_fixture_failure(string $dir, string $kind, string $detail): void {
	$encoded = json_encode(substr($detail, 0, 2048), JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
	$report = sprintf("NATIVE_FIXTURE_FAILURE %s: %s\n", $kind, $encoded === FALSE ? '[unavailable]' : $encoded);
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

/** @return array{string, string} collected bytes and the next independent cursor */
function collect_exact(string $dir, string $after, int $length, string $label): array {
	$bytes = '';
	$next = $after;
	$end = microtime(TRUE) + 45;
	do {
		$view = get_update($dir, $next);
		$bytes .= (string) ($view['log'] ?? '');
		$next = (string) ($view['next'] ?? '');
		if (strlen($bytes) > $length) {
			throw new RuntimeException("{$label} exceeded expected viewer bytes: " . digest($bytes));
		}
		if (strlen($bytes) === $length) {
			demand(($view['running'] ?? FALSE) === TRUE, "{$label} was not live at the output barrier");
			return [$bytes, $next];
		}
		usleep(20_000);
	} while (microtime(TRUE) < $end);
	throw new RuntimeException("{$label} output deadline: " . digest($bytes));
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
	$started = FALSE;
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
	$payload = str_repeat(PAYLOAD_BLOCK, PAYLOAD_REPEATS);
	$combined = $payload . $payload;
	$payloadPath = "$dir/payload.bin";
	$mainPath = "$dir/main.log";

	try {
		demand(strlen($payload) === 786_432 && strlen($combined) > VIEWER_LIMIT, 'fixture payload size is invalid');
		demand(file_put_contents($payloadPath, $payload) === strlen($payload), 'cannot write private payload');
		foreach (["$dir/run", "$dir/state", "$dir/hooks", "$dir/scripts"] as $path) {
			demand(is_dir($path) || mkdir($path, 0700), "cannot create private path {$path}");
		}
		file_put_contents($mainPath, '');
		file_put_contents("$dir/error.log", '');

		$hook = "#!/bin/sh\nset -eu\n: > " . escapeshellarg("$dir/hook.entered") . "\n";
		$hook .= 'while [ ! -e ' . escapeshellarg("$dir/write.output") . "; do sleep 0.05; done\n";
		$hook .= '/bin/cat ' . escapeshellarg($payloadPath) . "\n/bin/cat " . escapeshellarg($payloadPath) . " >&2\n";
		$hook .= ': > ' . escapeshellarg("$dir/hook.ready") . "\n";
		$hook .= 'while [ ! -e ' . escapeshellarg("$dir/release") . "; do sleep 0.05; done\n";
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
		[$status, , $error] = api($dir, 'StartUpdate', ['requestId' => bin2hex(random_bytes(16)), 'trigger' => 'apply']);
		demand($status === 200, "StartUpdate status={$status} error={$error}");
		$started = TRUE;

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
		$liveLength = VIEWER_LIMIT + strlen(VIEWER_NOTICE);
		[$viewerA, $cursorA] = collect_exact($dir, $startCursor, $liveLength, 'viewer A');
		[$viewerB] = collect_exact($dir, $startCursor, $liveLength, 'viewer B');
		$expectedViewer = substr($combined, 0, VIEWER_LIMIT) . VIEWER_NOTICE;
		demand($viewerA === $expectedViewer, 'viewer A cap mismatch: ' . digest($viewerA));
		demand($viewerB === $expectedViewer, 'viewer B cap mismatch: ' . digest($viewerB));
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
		$mainMatches = substr_count($main, $combined);
		$progressMatches = substr_count($main, "NORMAL_PROGRESS_AFTER_HOOK\n");
		$listMatches = substr_count($main, "SECOND_SCRIPT_VISIBLE\n");
		demand($mainMatches === 1, 'private main log did not contain full hook output exactly once: matches=' . $mainMatches);
		demand($progressMatches === 1, 'private main log did not contain ordinary progress exactly once: matches=' . $progressMatches);
		demand($listMatches === 1, 'private main log did not contain second-script output exactly once: matches=' . $listMatches);
		demand(strlen($combined) > VIEWER_LIMIT, 'main-log check did not cross the viewer boundary');

		$rotated = "$dir/main.log.rotated";
		demand(rename($mainPath, $rotated) && file_put_contents($mainPath, '') !== FALSE, 'cannot rotate private main sink');
		[$afterRotation] = collect_complete($dir, $startCursor);
		demand($afterRotation === $transcriptA, 'GetUpdate transcript changed after private main-log rotation');

		$successSummary = sprintf("NATIVE_SCRIPT_OUTPUT_CAP_PASS live=%s transcript=%s main=%s result=%s\n",
			digest($viewerA), digest($transcriptA), digest($combined), $completed['update']['result']);
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
		if ($started) {
			try {
				until(static function () use ($dir): array|false {
					[$status, $body] = api($dir, 'GetUpdate');
					return $status === 200 && is_array($body) && ($body['running'] ?? TRUE) === FALSE &&
						is_array($body['update'] ?? NULL) && isset($body['update']['finishedAt']) ? $body : FALSE;
				}, 'Update worker completion and lease release', 90);
			} catch (Throwable $error) {
				$cleanupErrors[] = 'Update worker completion: ' . $error->getMessage();
			}
		}
		if (is_resource($core)) {
			try {
				stop_core($core);
			} catch (Throwable $error) {
				$cleanupErrors[] = 'private Core shutdown: ' . $error->getMessage();
			}
		}
		if ($cleanupErrors === [] && file_put_contents("$dir/cleanup.safe", "safe\n") === FALSE) {
			$cleanupErrors[] = 'cannot mark the private directory safe to remove';
		}
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
if ($mode === 'update') {
	update_mode((string) ($argv[2] ?? ''));
}
demand($mode === 'control', 'unknown fixture mode');
control_mode((string) ($argv[0] ?? ''), (string) ($argv[2] ?? ''), (string) ($argv[3] ?? ''));
