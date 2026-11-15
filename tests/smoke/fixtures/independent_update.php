<?php
// Private native transaction fixture: never opens a DHCP interface or alters appliance configuration.
function demand(bool $ok, string $why): void {
	if (!$ok) {
		throw new RuntimeException($why);
	}
}
function until(callable $probe, string $why, float $seconds = 20): mixed {
	$end = microtime(TRUE) + $seconds;
	do {
		$value = $probe();
		if ($value) {
			return $value;
		}
		usleep(20000);
	} while (microtime(TRUE) < $end);
	throw new RuntimeException('deadline: ' . $why);
}
function command(string $socket, string $name): array {
	$stream = @stream_socket_client('unix://' . $socket, $errno, $error, 1);
	demand(is_resource($stream), "Kea control $name: $error");
	stream_set_timeout($stream, 2);
	fwrite($stream, json_encode(['command' => $name]) . "\n");
	$reply = stream_get_contents($stream);
	fclose($stream);
	$decoded = json_decode($reply, TRUE);
	// Kea's direct Unix control socket returns an object, not the control-agent's array.
	demand(is_array($decoded) && ($decoded['result'] ?? NULL) === 0, "Kea $name: $reply");
	return $decoded;
}
function api(string $dir, string $method, array $body = []): array {
	$curl = curl_init('http://localhost/v1/' . $method);
	curl_setopt_array($curl, [CURLOPT_UNIX_SOCKET_PATH => "$dir/run/api.sock", CURLOPT_POST => TRUE,
		CURLOPT_POSTFIELDS => json_encode($body ?: (object) []), CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
		CURLOPT_RETURNTRANSFER => TRUE, CURLOPT_TIMEOUT => 3]);
	$text = curl_exec($curl);
	$status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
	return [$status, is_string($text) ? json_decode($text, TRUE) : NULL];
}
function start_core(string $binary, string $dir): mixed {
	$core = proc_open([$binary, '--socket', "$dir/run/api.sock", '--state-dir', "$dir/state",
		'--update-cmd', "$dir/update.sh", '--allow-uid', '0'],
		[0 => ['file', '/dev/null', 'r'], 1 => ['file', "$dir/core.log", 'a'], 2 => ['file', "$dir/core.log", 'a']], $pipes);
	demand(is_resource($core), 'Core spawn failed');
	until(static fn() => api($dir, 'GetVersion')[0] === 200, 'Core API readiness');
	return $core;
}
function evidence(string $label, array $pids): void {
	foreach ($pids as $role => $pid) {
		printf("%s %s PID=%d PGID=%s\n", $label, $role, $pid, var_export(posix_getpgid($pid), TRUE));
	}
}

[$self, $mode, $dir] = $argv;
if ($mode === 'lock') {
	$lock = fopen("$dir/transaction.lock", 'c');
	demand(flock($lock, LOCK_EX | LOCK_NB), 'normal unlock did not release the transaction lock');
	flock($lock, LOCK_UN);
	fclose($lock);
	echo "LOCK_REACQUIRED\n";
	exit(0);
}
if ($mode === 'update') {
	try {
		require_once('/etc/inc/config.inc');
		require_once('/etc/inc/util.inc');
		$request = json_decode(stream_get_contents(STDIN), TRUE, 512, JSON_THROW_ON_ERROR);
		$lock = fopen("$dir/transaction.lock", 'c');
		demand(flock($lock, LOCK_EX | LOCK_NB), 'transaction lock already held');
		file_put_contents("$dir/runs", "run\n", FILE_APPEND);
		file_put_contents("$dir/update.pid", (string) getmypid());
		echo "TRANSACTION_STARTED\n";
		$family = trim(file_get_contents("$dir/family"));
		$binary = '/usr/local/sbin/kea-dhcp' . $family;
		putenv('KEA_PIDFILE_DIR=' . $dir);
		putenv('KEA_LOCKFILE_DIR=' . $dir);
		passthru(escapeshellarg($binary) . ' -t ' . escapeshellarg("$dir/kea.json") . ' 2>&1', $lintStatus);
		printf("KEA_LINT_EXIT=%d\n", $lintStatus);
		demand($lintStatus === 0, 'private Kea configuration lint failed before launch');
		// Exactly the native services.inc leaf and mwexec_bg launch; no setsid, daemon wrapper or descriptor surgery.
		echo "BEFORE_MWEXEC_BG\n";
		$launchedPid = mwexec_bg(escapeshellarg($binary) . ' -c ' . escapeshellarg("$dir/kea.json"));
		printf("AFTER_MWEXEC_BG_PID=%s\n", $launchedPid);
		file_put_contents("$dir/launched.pid", (string) $launchedPid);
		until(static function () use ($dir): bool {
			try {
				command("$dir/kea.sock", 'list-commands');
				return TRUE;
			} catch (Throwable $error) {
				file_put_contents("$dir/readiness-error", $error->getMessage());
				return FALSE;
			}
		}, 'private Kea readiness');
		file_put_contents("$dir/ready", "ready\n");
		until(static fn() => is_file("$dir/release"), 'transaction release', 90);
		file_put_contents("$dir/applied", "settings transaction completed\n");
		unlock($lock);
		file_put_contents("$dir/unlocked", "normal explicit LOCK_UN completed\n");
		$result = fopen('php://fd/3', 'w');
		fwrite($result, json_encode(['version' => 1, 'attempted' => $request['feeds'] ?? [], 'outcomes' => (object) [], 'geoipReady' => TRUE]) . "\n");
		fclose($result);
		echo "TRANSACTION_FINISHED\n";
		exit(0);
	} catch (Throwable $error) {
		fwrite(STDERR, 'UPDATE_EXCEPTION: ' . $error->getMessage() . "\n" . $error->getTraceAsString() . "\n");
		exit(1);
	}
}
if ($mode === 'diagnose') {
	$family = $argv[3] ?? '4';
	$binary = '/usr/local/sbin/kea-dhcp' . $family;
	$config = ['interfaces-config' => ['interfaces' => []], 'subnet' . $family => [],
		'lease-database' => ['type' => 'memfile', 'persist' => FALSE, 'lfc-interval' => 0],
		'dhcp-ddns' => ['enable-updates' => FALSE],
		'control-socket' => ['socket-type' => 'unix', 'socket-name' => "$dir/kea.sock"],
		'loggers' => [['name' => 'kea-dhcp' . $family, 'output_options' => [['output' => "$dir/kea.log"]]]]];
	if ($family === '6') {
		$config['server-id'] = ['type' => 'EN', 'enterprise-id' => 2495, 'identifier' => '01020304', 'persist' => FALSE];
		$config['data-directory'] = $dir;
	}
	file_put_contents("$dir/kea.json", json_encode(['Dhcp' . $family => $config], JSON_PRETTY_PRINT));
	putenv('KEA_PIDFILE_DIR=' . $dir);
	putenv('KEA_LOCKFILE_DIR=' . $dir);
	$proc = proc_open([$binary, '-c', "$dir/kea.json"], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
	demand(is_resource($proc), 'foreground Kea spawn failed');
	stream_set_blocking($pipes[1], FALSE);
	stream_set_blocking($pipes[2], FALSE);
	$stdout = $stderr = '';
	$ready = FALSE;
	$end = microtime(TRUE) + 12;
	do {
		$stdout .= (string) stream_get_contents($pipes[1]);
		$stderr .= (string) stream_get_contents($pipes[2]);
		$status = proc_get_status($proc);
		if (!$status['running']) {
			break;
		}
		if (file_exists("$dir/kea.sock")) {
			$ready = TRUE;
			break;
		}
		usleep(50000);
	} while (microtime(TRUE) < $end);
	if ($ready) {
		try {
			command("$dir/kea.sock", 'list-commands');
			command("$dir/kea.sock", 'shutdown');
			echo "FOREGROUND_CONTROL_READY\n";
		} catch (Throwable $error) {
			echo 'FOREGROUND_CONTROL_ERROR=' . $error->getMessage() . "\n";
		}
	}
	$deadline = microtime(TRUE) + 5;
	do {
		$status = proc_get_status($proc);
		if (!$status['running']) {
			break;
		}
		usleep(50000);
	} while (microtime(TRUE) < $deadline);
	if ($status['running']) {
		proc_terminate($proc, SIGKILL);
		$status = proc_get_status($proc);
	}
	$stdout .= (string) stream_get_contents($pipes[1]);
	$stderr .= (string) stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	proc_close($proc);
	printf("FOREGROUND_READY=%s\nFOREGROUND_EXIT=%s\nFOREGROUND_SIGNALED=%s\n", $ready ? 'yes' : 'no', var_export($status['exitcode'], TRUE), var_export($status['termsig'], TRUE));
	echo "FOREGROUND_STDOUT\n{$stdout}\nFOREGROUND_STDERR\n{$stderr}\n";
	exit(0);
}


demand($mode === 'control', 'unknown fixture mode');
[$binary, $family, $signal, $restart] = array_slice($argv, 3);
$core = NULL;
$services = [];
$failure = NULL;
try {
	file_put_contents("$dir/family", $family);
	file_put_contents("$dir/update.sh", "#!/bin/sh\nexec /usr/local/bin/php " . escapeshellarg($self) . ' update ' . escapeshellarg($dir) . "\n");
	chmod("$dir/update.sh", 0700);
	$config = ['interfaces-config' => ['interfaces' => []], 'subnet' . $family => [],
		'lease-database' => ['type' => 'memfile', 'persist' => FALSE, 'lfc-interval' => 0],
		'dhcp-ddns' => ['enable-updates' => FALSE],
		'control-socket' => ['socket-type' => 'unix', 'socket-name' => "$dir/kea.sock"],
		'loggers' => [['name' => 'kea-dhcp' . $family, 'output_options' => [['output' => "$dir/kea.log"]]]]];
	if ($family === '6') {
		$config['server-id'] = ['type' => 'EN', 'enterprise-id' => 2495, 'identifier' => '01020304', 'persist' => FALSE];
		$config['data-directory'] = $dir;
	}
	file_put_contents("$dir/kea.json", json_encode(['Dhcp' . $family => $config], JSON_PRETTY_PRINT));
	$core = start_core($binary, $dir);
	$initial = api($dir, 'InitializeSettings', ['requestId' => 'native-init', 'settings' => (object) []]);
	demand($initial[0] === 200, 'InitializeSettings: ' . json_encode($initial));
	$started = api($dir, 'StartUpdate', ['requestId' => 'native-start', 'trigger' => 'apply']);
	demand($started[0] === 200, 'StartUpdate: ' . json_encode($started));
	until(static fn() => is_file("$dir/ready"), 'Update locked and real Kea ready');
	$keaPid = (int) trim(file_get_contents("$dir/kea.kea-dhcp$family.pid"));
	demand($keaPid > 1, 'missing private Kea PID');
	$services = ['kea' => $keaPid];
	$updatePid = (int) trim(file_get_contents("$dir/update.pid"));
	$corePid = proc_get_status($core)['pid'];
	evidence('BEFORE_CORE_STOP', ['core' => $corePid, 'update' => $updatePid] + $services);
	command("$dir/kea.sock", 'list-commands');
	$beforeLog = file_get_contents("$dir/state/update.log");
	demand(str_contains($beforeLog, 'TRANSACTION_STARTED'), 'missing transaction log before stop');
	demand(proc_terminate($core, (int) $signal), 'cannot terminate owned Core');
	until(static fn() => !proc_get_status($core)['running'], 'Core stop');
	proc_close($core);
	$core = NULL;
	// The controlled transaction cannot finish until this parent releases it.
	command("$dir/kea.sock", 'list-commands');
	demand(!is_file("$dir/applied"), 'transaction escaped barrier');
	$probe = fopen("$dir/transaction.lock", 'c');
	demand(!flock($probe, LOCK_EX | LOCK_NB), 'Core death interrupted the settings transaction');
	fclose($probe);
	evidence('AFTER_CORE_STOP', ['update' => $updatePid] + $services);
	if ($restart === 'running') {
		$core = start_core($binary, $dir);
		$view = api($dir, 'GetUpdate');
		demand(($view[0] === 200 && ($view[1]['running'] ?? FALSE)) || $view[0] === 503,
			'restarted Core reported a false idle/success: ' . json_encode($view));
		$duplicate = api($dir, 'StartUpdate', ['requestId' => 'native-duplicate', 'trigger' => 'apply']);
		demand(in_array($duplicate[0], [409, 503], TRUE), 'restarted Core admitted conflicting Update: ' . json_encode($duplicate));
		demand(file_get_contents("$dir/state/update.log") === $beforeLog, 'restart/duplicate admission truncated surviving log');
		demand(file_get_contents("$dir/runs") === "run\n", 'duplicate Update process');
	}
	file_put_contents("$dir/release", "release\n");
	until(static fn() => is_file("$dir/unlocked"), 'successful transaction and explicit unlock');
	$lockProbe = proc_open(['/usr/local/bin/php', $self, 'lock', $dir], [0 => ['file', '/dev/null', 'r'], 1 => STDOUT, 2 => STDERR], $pipes);
	demand(proc_close($lockProbe) === 0, 'independent lock reacquisition failed');
	command("$dir/kea.sock", 'list-commands');
	if ($core === NULL) {
		$core = start_core($binary, $dir);
	}
	$view = until(static function () use ($dir): array|false {
		[$status, $body] = api($dir, 'GetUpdate');
		return $status === 200 && !($body['running'] ?? TRUE) && isset($body['update']['finishedAt']) ? $body : FALSE;
	}, 'durable completion reconciliation');
	demand(($view['update']['result'] ?? NULL) === 'success', 'Update completion: ' . json_encode($view));
	demand(str_contains($view['log'], 'TRANSACTION_FINISHED'), 'reconciled log lost completion');
	demand(file_get_contents("$dir/runs") === "run\n", 'completion recovery reran transaction');
	evidence('COMPLETED', $services);
	echo "INDEPENDENT_TRANSACTION_PASS family=$family signal=$signal restart=$restart\n";
} catch (Throwable $error) {
	$failure = $error;
	fwrite(STDERR, 'REGRESSION: ' . $error->getMessage() . "\n");
	if (is_resource($core)) {
		echo 'PRE_CLEANUP_CORE_STATUS=' . json_encode(proc_get_status($core)) . "\n";
	}
	foreach (['update.pid', 'launched.pid'] as $pidfile) {
		$raw = trim((string) @file_get_contents("$dir/$pidfile"));
		if (ctype_digit($raw) && (int) $raw > 1) {
			echo "PRE_CLEANUP_PROCESS $pidfile=$raw alive=" . (posix_kill((int) $raw, 0) ? 'yes' : 'no') . "\n";
			passthru('/bin/ps -p ' . $raw . ' -o pid,ppid,pgid,stat,wchan,args', $psStatus);
			printf("PRE_CLEANUP_PS_EXIT=%d\n", $psStatus);
		}
	}
	if (is_file("$dir/readiness-error")) {
		echo 'PRE_CLEANUP_READINESS_ERROR=' . file_get_contents("$dir/readiness-error") . "\n";
	}
} finally {
	file_put_contents("$dir/release", "cleanup\n");
	if (is_resource($core)) {
		proc_terminate($core, SIGTERM);
		until(static fn() => !proc_get_status($core)['running'], 'cleanup Core stop');
		proc_close($core);
	}
	if (file_exists("$dir/kea.sock")) {
		try {
			command("$dir/kea.sock", 'shutdown');
		} catch (Throwable $error) {
			fwrite(STDERR, 'cleanup shutdown: ' . $error->getMessage() . "\n");
		}
	}
	foreach ($services as $pid) {
		until(static fn() => !posix_kill($pid, 0), 'owned Kea exits after control shutdown');
	}
	echo "OWNED_SERVICE_CLEANUP_COMPLETE\n";
}
exit($failure === NULL ? 0 : 1);
