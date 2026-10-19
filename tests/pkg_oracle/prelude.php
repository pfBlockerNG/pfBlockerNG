<?php
// Real cross-process primitives under the repo's PHPUnit doubles (those are function_exists()-guarded, so these win):
// pfSense util.inc try_lock()/unlock() (a flock polled once a second, the same algorithm) and a file-backed config.xml whose
// write_config() writes the WHOLE in-memory copy, as pfSense does, and whose fresh config_read_file() replaces it from the file.
// A try_lock() that gives up leaves $lock.refused behind: the event the scenario's lock holder lets go on (scenario.sh).
function race_path(string $name): string { return getenv('RACE_DIR') . '/' . $name; }
function try_lock($lock, $timeout = 5) {
	$path = race_path("{$lock}.lock");
	if (!file_exists($path)) { @touch($path); @chmod($path, 0666); }
	if ($fp = fopen($path, 'w')) {
		$n = 0;
		while (!flock($fp, LOCK_EX | LOCK_NB)) {
			if ($n >= $timeout) { fclose($fp); @touch(race_path("{$lock}.refused")); return NULL; }
			sleep(1); $n++;
		}
		return $fp;
	}
	return NULL;
}
function unlock($k = 0) {
	if (!is_resource($k)) { return; }
	flock($k, LOCK_UN); fclose($k);
}
function config_read_file(bool $use_backup = FALSE, bool $use_cache = TRUE): bool {
	if ($use_cache) { return TRUE; }
	$j = @file_get_contents(race_path('config.json'));
	$c = ($j === FALSE) ? NULL : json_decode($j, TRUE);
	if (!is_array($c)) { return FALSE; }
	$GLOBALS['config'] = $c;
	return TRUE;
}
function write_config($desc = 'Unknown', $backup = TRUE, $write_config_only = FALSE) {
	$tmp = race_path('config.json.tmp' . getmypid());
	file_put_contents($tmp, json_encode($GLOBALS['config']));
	rename($tmp, race_path('config.json'));
	return TRUE;
}
