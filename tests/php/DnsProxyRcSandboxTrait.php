<?php

declare(strict_types=1);

/**
 * The sandbox the DNS proxy's generated rc script runs in (issue #3515): the real script executed under dash, every
 * absolute executable path redirected to a command double, `sleep 1` one tick of a controlled clock. A test class
 * calls sandboxUp() from setUp() and sandboxDown() from tearDown(), generates the script itself and runs it with
 * arrange() and rc().
 *
 * The bare `uname` of pfb_dns.sh (the one command the script does not name by an absolute path) is found first on the
 * PATH rc() hands the shell, and answers the machine arrange() was given.
 */
trait DnsProxyRcSandboxTrait
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const RC = 'pfb_dns_proxy.sh';

	private const DOUBLES = ['read_xml_tag.sh', 'daemon', 'kill', 'sleep', 'ps', 'logger', 'lockf', 'uname'];

	/** One script installed under every command name the rc body uses; $0 picks the role. */
	private const DOUBLE = <<<'SH'
		#!/bin/sh
		S=@STATE@
		. "$S/scenario"
		ev() { printf '%s\n' "$1" >> "$S/events"; }
		tick() { read -r t < "$S/ticks"; echo "$t"; }
		# procs: pid|pidfile|death tick|how|args. Reap what is due; a TERM death is a clean daemon exit (the
		# daemon removes its pidfile), a KILL death leaves the pidfile stale.
		reap() {
			now="$(tick)"
			true > "$S/procs.new"
			while IFS='|' read -r pid pidfile due how args; do
				[ -n "$pid" ] || continue
				if [ -n "$due" ] && [ "$now" -ge "$due" ]; then
					[ "$how" != term ] || rm -f "$pidfile"
					continue
				fi
				printf '%s|%s|%s|%s|%s\n' "$pid" "$pidfile" "$due" "$how" "$args" >> "$S/procs.new"
			done < "$S/procs"
			mv "$S/procs.new" "$S/procs"
		}
		signal() {
			how="$1"; after="$2"; shift 2
			now="$(tick)"
			true > "$S/procs.new"
			found=
			while IFS='|' read -r pid pidfile due oldhow args; do
				[ -n "$pid" ] || continue
				for target in "$@"; do
					if [ "$target" = "$pid" ]; then
						found=1
						if [ "$after" != never ] && { [ -z "$due" ] || [ "$((now + after))" -lt "$due" ]; }; then
							due=$((now + after)); oldhow="$how"
						fi
					fi
				done
				printf '%s|%s|%s|%s|%s\n' "$pid" "$pidfile" "$due" "$oldhow" "$args" >> "$S/procs.new"
			done < "$S/procs"
			mv "$S/procs.new" "$S/procs"
			[ -n "$found" ] || return 1
			reap
		}
		case "${0##*/}" in
		read_xml_tag.sh)
			[ "$1" = string ] || { ev bad-xml; exit 2; }
			case "$2" in
			*/pfb_dns_saved) echo "$GATE_SAVED" ;;
			*/pfb_dns) echo "$GATE_PROXY" ;;
			*/pfb_dnsbl) echo "$GATE_DNSBL" ;;
			*) ev bad-xml; exit 2 ;;
			esac
			;;
		kill)
			case "$1" in
			-TERM) how=term; after="$TERM_AFTER" ;;
			-KILL) how=kill; after="$KILL_AFTER" ;;
			*) ev bad-kill; exit 2 ;;
			esac
			shift
			ev "$how"
			signal "$how" "$after" "$@"
			;;
		sleep)
			[ "$#" -eq 1 ] && [ "$1" = 1 ] || { ev bad-sleep; exit 2; }
			ev sleep
			echo "$(( $(tick) + 1 ))" > "$S/ticks"
			reap
			;;
		ps)
			[ "$1" = -ww ] && [ "$2" = -o ] && [ "$3" = 'args=' ] && [ "$4" = -p ] && [ "$#" -eq 5 ] || { ev bad-ps; exit 2; }
			while IFS='|' read -r pid pidfile due how args; do
				if [ "$pid" = "$5" ]; then printf '%s\n' "$args"; exit 0; fi
			done < "$S/procs"
			exit 1
			;;
		logger)
			ev log
			printf '%s\n' "$*" >> "$S/logger"
			;;
		daemon)
			true > "$S/daemon.argv"
			for arg in "$@"; do printf '%s\n' "$arg" >> "$S/daemon.argv"; done
			attached=
			for fd in 0 1 2; do
				if [ "/dev/fd/$fd" -ef /dev/null ]; then attached="$attached$fd "; fi
			done
			echo "${attached:-none}" >> "$S/fds"
			ev launch
			# What the new proxy finds at its launch: the previous marker must be gone (rc removes it before a fresh start)
			if [ -e "$READY_FILE" ]; then echo present >> "$S/launch.marker"; else echo absent >> "$S/launch.marker"; fi
			# Descriptors above stdio that the new proxy inherited. FreeBSD lockf closes its lock descriptor before the command runs,
			# so the native result is an empty list; this double's flock(1) keeps one, so an empty list here is the closes at work.
			for fd in 3 4 5 6 7 8 9; do [ ! -e "/dev/fd/$fd" ] || echo "$fd" >> "$S/launch.fds"; done
			# A test holds the launch open here to let a second start race it (the host's own sleep, not the tick double)
			while [ -e "$S/barrier" ]; do /bin/sleep 0.05; done
			supervisor=; child=; title=
			while [ "$#" -gt 0 ]; do
				case "$1" in
				-P) supervisor="$2"; shift 2 ;;
				-p) child="$2"; shift 2 ;;
				-t) title="$2"; shift 2 ;;
				-o|-R) shift 2 ;;
				-r) shift ;;
				*) break ;;
				esac
			done
			echo 3001 > "$supervisor"
			echo 3002 > "$child"
			printf '%s\n' "3001|$supervisor|||daemon: $title[3002] (daemon)" >> "$S/procs"
			printf '%s\n' "3002|$child|||$*" >> "$S/procs"
			;;
		uname)
			# pfb_dns.sh asks which machine it runs on; the scenario answers
			[ "$1" = -p ] || { ev bad-uname; exit 2; }
			printf '%s\n' "$MACHINE"
			;;
		lockf)
			# FreeBSD lockf(1): lockf [-k] [-t seconds] file command ... -- the lock is held until the command exits; -t gives up
			# with status 75 (EX_TEMPFAIL). The rc script must keep the lock file (-k) and wait at most 10 s. This double takes the
			# lock with Linux flock(1), which hands its descriptor on to the command; the daemon double's probe covers the closes.
			keep=; wait=
			while [ "$#" -gt 0 ]; do
				case "$1" in
				-k) keep=1; shift ;;
				-t) wait="$2"; shift 2 ;;
				-*) ev bad-lockf; exit 2 ;;
				*) break ;;
				esac
			done
			{ [ -n "$keep" ] && [ "$wait" = 10 ] && [ "$#" -ge 2 ]; } || { ev bad-lockf; exit 2; }
			printf '%s\n' "$1" >> "$S/lockf.calls"
			[ -z "$LOCKF_BUSY" ] || exit 75
			lockfile="$1"; shift
			exec /usr/bin/flock -w "$wait" -E 75 "$lockfile" "$@"
			;;
		*)
			exit 2
			;;
		esac
		SH;

	private string $dir = '';
	private string $shell = '';
	private array $savedGlobals = [];

	private function sandboxUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_rcfile_dir', 'pfb_test_rcfile_writes', 'pfb_test_rcfiles', 'pfb_test_interface_ip',
			'pfb_test_configured_ipv6', 'pfb_test_interface_info', 'pfb_test_configured_ip_addresses'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dns_proxy_rc_' . bin2hex(random_bytes(6));
		foreach (['bin', 'state', 'run', 'log', 'rc'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0777, TRUE), "sandbox mkdir failed: {$this->dir}/{$sub}");
		}
		$double = "{$this->dir}/double.sh";
		file_put_contents($double, str_replace('@STATE@', escapeshellarg("{$this->dir}/state"), self::DOUBLE) . "\n");
		chmod($double, 0755);
		foreach (self::DOUBLES as $name) {
			$this->assertTrue(symlink($double, "{$this->dir}/bin/{$name}"), "double link failed: {$name}");
		}
		$rm = trim((string) shell_exec('command -v rm'));
		$this->assertNotSame('', $rm, 'no rm on this host');
		$this->assertTrue(symlink($rm, "{$this->dir}/bin/rm"));
		$dash = trim((string) shell_exec('command -v dash 2>/dev/null'));
		$this->shell = $dash !== '' ? $dash : '/bin/sh';

		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->dir,
			'log'    => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_rcfile_dir'] = "{$this->dir}/rc";
	}

	private function sandboxDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->dir);
	}

	/** config.xml of a box in proxy mode: the saved Resolver listened on `lan`, with or without DoT. */
	private function moveResolver(bool $dot = FALSE, string $interfaces = 'lan', array $v4 = ['lan' => '192.0.2.1'], array $v6 = []): void
	{
		$keys = [
			'active_interface' => ['present' => TRUE, 'value' => $interfaces],
			'enablessl'        => ['present' => $dot, 'value' => $dot ? '' : NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$up = ['status' => 'up', 'enable' => TRUE];
		$GLOBALS['pfb_test_interface_ip'] = $v4;
		$GLOBALS['pfb_test_configured_ipv6'] = $v6;
		$GLOBALS['pfb_test_interface_info'] = array_fill_keys(array_keys($v4 + $v6), $up);
	}


	private function rcText(): string
	{
		$text = @file_get_contents("{$this->dir}/rc/" . self::RC);
		$this->assertIsString($text, 'pfb_dns_proxy_service() wrote no rc script');
		return $text;
	}

	/**
	 * Seed the sandbox process table and clock, then install the sandboxed generated script.
	 *
	 * @param array<string,string> $gates GATE_DNSBL / GATE_PROXY / GATE_SAVED values read_xml_tag.sh answers
	 * @param string $termAfter ticks a live proxy takes to exit after TERM ('never' = ignores it)
	 * @param string $killAfter ticks it takes after KILL
	 * @param bool $running whether a proxy (supervisor 1001 + child 1002) is alive and named by the pidfiles
	 * @param string $machine what `uname -p` answers for pfb_dns.sh (amd64, aarch64, ...)
	 */
	private function arrange(array $gates = [], string $termAfter = '2', string $killAfter = '1', bool $running = FALSE, string $machine = 'amd64'): void
	{
		$gates += ['GATE_DNSBL' => 'on', 'GATE_PROXY' => 'on', 'GATE_SAVED' => (string) config_get_path(self::SAVED, '')];
		$state = "{$this->dir}/state";
		$vars = $gates + ['TERM_AFTER' => $termAfter, 'KILL_AFTER' => $killAfter, 'READY_FILE' => $this->readyFile(), 'LOCKF_BUSY' => '', 'MACHINE' => $machine];
		file_put_contents("{$state}/scenario", implode('', array_map(
			static fn (string $k, string $v): string => "{$k}=" . escapeshellarg($v) . "\n",
			array_keys($vars),
			array_values($vars)
		)));
		file_put_contents("{$state}/ticks", "0\n");
		foreach (['events', 'fds', 'procs', 'logger', 'daemon.argv', 'launch.marker', 'launch.fds', 'lockf.calls'] as $file) {
			file_put_contents("{$state}/{$file}", '');
		}
		if ($running) {
			file_put_contents("{$this->dir}/run/pfb_dns_proxy_daemon.pid", "1001\n");
			file_put_contents("{$this->dir}/run/pfb_dns_proxy.pid", "1002\n");
			file_put_contents("{$state}/procs",
				"1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
				. "1002|{$this->dir}/run/pfb_dns_proxy.pid|||python3.11 -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py\n");
		}
		file_put_contents("{$this->dir}/run.sh", $this->sandboxPaths($this->rcText()));
	}

	/** Where the sandboxed script keeps the proxy's ready marker (the production path is $pfb['dns_proxy_ready']). */
	private function readyFile(): string
	{
		return "{$this->dir}/run/pfb_dns_ready";
	}

	/** Point every absolute path in the generated script at the sandbox; fail closed on any other. A slash after a glob `*` is part of a case pattern, not a path. */
	private function sandboxPaths(string $script): string
	{
		return (string) preg_replace_callback(
			'~(?<![\w$.\-/*])/(?:[\w.\-]+/)*[\w.\-]+~',
			function (array $m): string {
				$path = $m[0];
				if ($path === $GLOBALS['pfb']['dns_proxy_ready']) {
					return $this->readyFile();
				}
				if (in_array($path, ['/dev/null', '/bin/sh', '/var/unbound', '/var/unbound/unbound.conf'], TRUE) ||
				    str_starts_with($path, "{$this->dir}/dns_proxy/") ||
				    preg_match('~^/(?:\d{1,3}$|usr/local/pkg/pfblockerng/|cf/conf/)~', $path) === 1) {
					return $path;
				}
				if (preg_match('~^/(?:usr/local/sbin|usr/local/bin|usr/sbin|usr/bin|sbin|bin)/([\w.\-]+)$~', $path, $cmd) === 1) {
					$this->assertFileExists("{$this->dir}/bin/{$cmd[1]}", "no command double for {$path}; refusing to run a host binary");
					return "{$this->dir}/bin/{$cmd[1]}";
				}
				if (preg_match('~^/var/run/([\w.\-]+)$~', $path, $file) === 1) {
					return "{$this->dir}/run/{$file[1]}";
				}
				if (preg_match('~^/var/log/pfblockerng/([\w.\-]+)$~', $path, $file) === 1) {
					return "{$this->dir}/log/{$file[1]}";
				}
				$this->fail("generated rc script references {$path} with no sandbox replacement; refusing to run it");
			},
			$script
		);
	}

	/**
	 * Run the generated script's verb with pipes (never /dev/null) on fds 0/1/2 under a hard watchdog.
	 *
	 * @return array{0: int, 1: string} exit status and combined stdout/stderr
	 */
	private function rc(string $verb): array
	{
		$proc = proc_open(
			[$GLOBALS['pfb']['timeout'], '-k', '2', '20', $this->shell, "{$this->dir}/run.sh", $verb],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
			$pipes,
			NULL,
			['PATH' => "{$this->dir}/bin:" . (string) getenv('PATH')]
		);
		$this->assertIsResource($proc, 'proc_open failed');
		fclose($pipes[0]);
		$output = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		return [proc_close($proc), $output];
	}

	/**
	 * Recorded command events in order: term, kill, sleep, launch, log.
	 *
	 * @return list<string>
	 */
	private function events(bool $withLogs = FALSE): array
	{
		$lines = file("{$this->dir}/state/events", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		return $withLogs ? $lines : array_values(array_filter($lines, static fn (string $e): bool => $e !== 'log'));
	}

	/** @return list<string> pids of the processes still alive in the sandbox table */
	private function livePids(): array
	{
		$pids = [];
		foreach (file("{$this->dir}/state/procs", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
			$pids[] = explode('|', $line, 2)[0];
		}
		return $pids;
	}

	/** @return list<string> the argv the daemon double was launched with, one entry per argument */
	private function daemonArgv(): array
	{
		return file("{$this->dir}/state/daemon.argv", FILE_IGNORE_NEW_LINES) ?: [];
	}


	private function pidfile(string $name): string
	{
		return "{$this->dir}/run/{$name}";
	}
}
