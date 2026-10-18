<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNS proxy runs as the supervised rc service pfb_dns_proxy.
 *
 * Function under test: pfb_dns_proxy_service() -- writes /usr/local/etc/rc.d/pfb_dns_proxy.sh from the SAVED
 * Resolver (listen addresses, DoT). Intent pinned here:
 *   - the rc script launches the shipped proxy only through pfb_python.sh, on exactly the saved addresses,
 *     as the unprivileged `unbound` user, with every value shell-quoted and stdio detached;
 *   - it starts while the moved-Resolver snapshot is set, whatever the proxy toggle and DNSBL say (a restore that
 *     was abandoned leaves the Resolver moved, and the proxy must keep serving it until a retry succeeds), and never
 *     launches over a survivor; the proxy listens on the saved Resolver's non-loopback addresses plus loopback, so a
 *     Resolver saved on Localhost only, or on an interface with no address, still gets a proxy;
 *   - a start over a proxy whose supervisor and child both serve keeps it: nothing is signalled or launched, so the
 *     package start after the boot hook does not bounce it; a restart always stops first, and starts only when that stop succeeded;
 *   - it stops by TERM, KILL at 5 s, giving up (status 1) at 7 s, signalling only live processes that its
 *     own pidfiles name AND whose command line is the proxy's, so a stale pidfile whose pid was reused can
 *     never get an unrelated process killed;
 *   - it is written on every call, like the other pfBlockerNG rc services.
 *
 * The real generator's output is written through the write_rcfile() double (wrapped as pfSense wraps it) and
 * executed under dash. Every absolute executable path is redirected to a sandbox command double (a path with
 * no double fails the test instead of running a host binary); `sleep 1` is one tick of a controlled clock, so
 * the 5 s / 7 s deadlines are counted in ticks, never measured.
 */
#[CoversFunction('pfb_dns_proxy_service')]
final class DnsProxyServiceTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const RC = 'pfb_dns_proxy.sh';

	private const DOUBLES = ['read_xml_tag.sh', 'daemon', 'kill', 'sleep', 'ps', 'logger', 'lockf'];

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

	protected function setUp(): void
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

	protected function tearDown(): void
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

	private function generate(): void
	{
		pfb_dns_proxy_service();
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
	 */
	private function arrange(array $gates = [], string $termAfter = '2', string $killAfter = '1', bool $running = FALSE): void
	{
		$gates += ['GATE_DNSBL' => 'on', 'GATE_PROXY' => 'on', 'GATE_SAVED' => (string) config_get_path(self::SAVED, '')];
		$state = "{$this->dir}/state";
		$vars = $gates + ['TERM_AFTER' => $termAfter, 'KILL_AFTER' => $killAfter, 'READY_FILE' => $this->readyFile(), 'LOCKF_BUSY' => ''];
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

	/** Point every absolute path in the generated script at the sandbox; fail closed on any other. */
	private function sandboxPaths(string $script): string
	{
		return (string) preg_replace_callback(
			'~(?<![\w$.\-/])/(?:[\w.\-]+/)*[\w.\-]+~',
			function (array $m): string {
				$path = $m[0];
				if ($path === $GLOBALS['pfb']['dns_proxy_ready']) {
					return $this->readyFile();
				}
				if (in_array($path, ['/dev/null', '/bin/sh', '/var/unbound', '/var/unbound/unbound.conf'], TRUE) ||
				    str_starts_with($path, "{$this->dir}/bin/pfb_dns_gateway") ||
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
			$pipes
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

	/** @return list<string> the addresses the daemon double was told to --listen on, in order */
	private function daemonListen(): array
	{
		$argv = $this->daemonArgv();
		$listen = [];
		foreach ($argv as $i => $arg) {
			if ($arg === '--listen') {
				$listen[] = $argv[$i + 1];
			}
		}
		return $listen;
	}

	private function pidfile(string $name): string
	{
		return "{$this->dir}/run/{$name}";
	}

	// -----------------------------------------------------------------------
	// S2 -- what the generated script says
	// -----------------------------------------------------------------------

	public function testScriptLaunchesTheShippedProxyThroughPfbPythonOnTheSavedAddressesAndLoopbackAsUnbound(): void
	{
		// Given a Resolver that was saved listening on lan (IPv4 and IPv6), without DoT
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);

		// When the rc service is generated and started under dash
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the daemon is launched with exactly this argument vector
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(
			[
				'-r', '-R', '5', '-t', 'pfb_dns_proxy',
				'-P', $this->pidfile('pfb_dns_proxy_daemon.pid'), '-p', $this->pidfile('pfb_dns_proxy.pid'),
				'-o', "{$this->dir}/log/dns_proxy.log",
				'/usr/local/pkg/pfblockerng/pfb_python.sh', '-u', '/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py',
				'--listen', '192.0.2.1', '--listen', '2001:db8::1', '--listen', '127.0.0.1', '--listen', '::1',
				'--port', '53', '--upstream', '127.0.0.1:5353', '--module-dir', '/var/unbound', '--user', 'unbound',
				'--ready-file', "{$this->dir}/run/pfb_dns_ready", '--no-module',
			],
			$this->daemonArgv()
		);
		$this->assertSame(['launch'], $this->events());
	}

	public function testTheProxyAlsoServesLoopbackSoTheFirewallsOwnLookupsAreFilteredWhateverTheSavedInterfaces(): void
	{
		// Given a Resolver saved on one IPv4-only interface: loopback is not among its addresses, and Unbound has
		// moved to its own loopback ports, so loopback on the Listen Port is free for the proxy
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$GLOBALS['config']['unbound']['port'] = '5300';

		// When the rc service is generated and started
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the proxy listens on the interface address first, then on both loopback addresses, all on that port:
		// the firewall's resolv.conf (127.0.0.1, ::1) reaches the proxy, not Unbound
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$listen = [];
		foreach ($argv as $i => $arg) {
			if ($arg === '--listen') {
				$listen[] = $argv[$i + 1];
			}
		}
		$this->assertSame(['192.0.2.1', '127.0.0.1', '::1'], $listen);
		$this->assertSame('5300', $argv[(int) array_search('--port', $argv, TRUE) + 1]);
	}

	public function testScriptNamesNoInterpreterPathAndQuotesEveryListenValue(): void
	{
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);
		$this->generate();
		$text = $this->rcText();

		$this->assertDoesNotMatchRegularExpression('~\bpython|/bin/php|\bphp\b~i', $text,
			'the proxy is launched through pfb_python.sh only: no interpreter path may appear in the script');
		$this->assertStringContainsString("--listen '192.0.2.1' --listen '2001:db8::1' --listen '127.0.0.1' --listen '::1'", $text, 'every listen value is shell-quoted');
		$this->assertStringContainsString('</dev/null >/dev/null 2>&1', $text, 'stdio is detached (#662)');
		$this->assertStringContainsString("rc_stop || return 1\n", $text, 'never launch over a survivor');
	}

	public function testGeneratedScriptIsValidPosixShell(): void
	{
		$this->moveResolver(TRUE);
		$this->generate();

		$proc = proc_open([$this->shell, '-n', "{$this->dir}/rc/" . self::RC], [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
		$this->assertIsResource($proc);
		$output = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		$this->assertSame(0, proc_close($proc), "sh -n rejected the generated script: {$output}");
	}

	/** @return array<string,array{bool}> */
	public static function dotRows(): array
	{
		return ['saved Resolver had DoT' => [TRUE], 'saved Resolver had no DoT' => [FALSE]];
	}

	#[DataProvider('dotRows')]
	public function testDotIsPassedExactlyWhenTheSavedResolverHadIt(bool $dot): void
	{
		$this->moveResolver($dot);
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$this->assertSame($dot, in_array('--dot', $argv, TRUE), '--dot iff the saved Resolver had enablessl');
		$this->assertSame($dot, in_array('--pfsense-config', $argv, TRUE));
		if ($dot) {
			$at = array_search('--dot', $argv, TRUE);
			$this->assertSame(['--dot', '--pfsense-config', '/cf/conf/config.xml'], array_slice($argv, (int) $at, 3));
		}
	}

	public function testANonNumericTlsPortInConfigNeverReachesTheScript(): void
	{
		$this->moveResolver(TRUE);
		$GLOBALS['config']['unbound']['tlsport'] = '853; reboot';
		$this->generate();

		$this->assertStringNotContainsString('tlsport', $this->rcText());
		$this->assertStringNotContainsString('reboot', $this->rcText(),
			'the proxy reads the DoT port from config.xml itself; the rc script passes no port');
	}

	/** @return array<string,array{?string,string}> the Resolver's `port` as config.xml holds it => the port the proxy is told to bind */
	public static function listenPortRows(): array
	{
		return [
			'Listen Port absent (the default)' => [NULL, '53'],
			'Listen Port 53'                   => ['53', '53'],
			'Listen Port 5300'                 => ['5300', '5300'],
			'Listen Port 65535'                => ['65535', '65535'],
			'Listen Port empty'                => ['', '53'],
			'Listen Port a service name'       => ['domain', '53'],
			'Listen Port 0'                    => ['0', '53'],
			'Listen Port above 65535'          => ['65536', '53'],
			'Listen Port with a shell payload' => ['5300; reboot', '53'],
		];
	}

	#[DataProvider('listenPortRows')]
	public function testTheProxyBindsTheResolversListenPortAndFallsBackToTheDefaultWhenItIsNotAPort(?string $configured, string $expected): void
	{
		// Given a moved Resolver whose Listen Port is $configured (Unbound keeps it on loopback; the proxy takes it on the LAN)
		$this->moveResolver();
		if ($configured !== NULL) {
			$GLOBALS['config']['unbound']['port'] = $configured;
		}

		// When the rc service is generated and started under dash
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the proxy is launched with exactly one --port, the Resolver's port or 53, and nothing else of the value reaches the script
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$this->assertSame(1, count(array_keys($argv, '--port', TRUE)), 'exactly one --port');
		$this->assertSame($expected, $argv[(int) array_search('--port', $argv, TRUE) + 1]);
		$this->assertStringNotContainsString('reboot', $this->rcText());
	}

	// -----------------------------------------------------------------------
	// S2/S4 -- the start gate
	// -----------------------------------------------------------------------

	public function testStartDoesNothingAndLeavesARunningProxyAloneWithoutAMovedResolver(): void
	{
		// Given a proxy that is running and a generated script whose gate finds no moved-Resolver snapshot
		$this->moveResolver();
		$this->generate();
		$this->arrange(['GATE_SAVED' => ''], '2', '1', TRUE);

		// When it is started (boot)
		[$status, $output] = $this->rc('start');

		// Then it neither stops nor launches anything
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE), 'a closed gate means no daemon, no signal, no log');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	/** @return array<string,array{array<string,string>}> */
	public static function toggleAndDnsblRows(): array
	{
		return [
			'DNS proxy toggle off' => [['GATE_PROXY' => '']],
			'DNSBL off'            => [['GATE_DNSBL' => '']],
			'both off'             => [['GATE_PROXY' => '', 'GATE_DNSBL' => '']],
		];
	}

	/** @param array<string,string> $gates */
	#[DataProvider('toggleAndDnsblRows')]
	public function testStartLaunchesWhileTheSnapshotRemainsWhateverTheToggleAndDnsblSay(array $gates): void
	{
		// Given a restore that was abandoned (config locked, or the proxy outlived its stop): the toggle or DNSBL is
		// already off, but the Resolver is still moved and its snapshot kept
		$this->moveResolver();
		$this->generate();
		$this->arrange($gates);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the proxy is launched: nothing else serves the moved Resolver's port until a retry restores it
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
	}

	/** @return array<string,array{string,array<string,string>,array<string,string>,list<string>}> */
	public static function loopbackRows(): array
	{
		return [
			'Resolver saved on Localhost only'   => ['lo0', ['lo0' => '127.0.0.1'], ['lo0' => '::1'], ['127.0.0.1', '::1']],
			'Resolver saved on Localhost and LAN' => ['lo0,lan', ['lo0' => '127.0.0.1', 'lan' => '192.0.2.1'], ['lo0' => '::1'], ['192.0.2.1', '127.0.0.1', '::1']],
			'Resolver saved on an interface with no address' => ['opt9', [], [], ['127.0.0.1', '::1']],
		];
	}

	/**
	 * @param array<string,string> $v4
	 * @param array<string,string> $v6
	 * @param list<string> $expected
	 */
	#[DataProvider('loopbackRows')]
	public function testTheProxyStartsOnLoopbackPlusWhateverAddressesTheSavedInterfacesHave(string $interfaces, array $v4, array $v6, array $expected): void
	{
		// Given a Resolver saved on these interfaces: the firewall's own lookups reach the proxy on loopback however
		// few client-facing addresses there are
		$this->moveResolver(FALSE, $interfaces, $v4, $v6);
		$this->generate();
		$this->arrange();

		// When the service is started
		[$status, $output] = $this->rc('start');

		// Then the proxy is launched on the saved interfaces' addresses and on loopback, each once
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertSame($expected, $this->daemonListen());
	}

	/** @return array<string,array{bool,bool,string}> DNSBL on, Resolver forwarding, the one module flag expected ('' = none) */
	public static function moduleFlagRows(): array
	{
		return [
			'DNSBL off: there is no module to host'          => [FALSE, FALSE, '--no-module'],
			'DNSBL off, Resolver forwarding'                 => [FALSE, TRUE, '--no-module'],
			'DNSBL on, Resolver recursing: no upstream to observe' => [TRUE, FALSE, ''],
			'DNSBL on, Resolver forwarding: upstream blocks are reported' => [TRUE, TRUE, '--observer'],
		];
	}

	#[DataProvider('moduleFlagRows')]
	public function testTheProxyBootsTheModuleOnlyWithDnsblAndListensForTheObserverOnlyWhileForwarding(bool $dnsbl, bool $forwarding, string $flag): void
	{
		// Given pfBlockerNG enabled, DNSBL on or off, and the Resolver forwarding or not
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = $dnsbl ? PfbToggle::On : PfbToggle::Off;
		if ($forwarding) {
			config_set_path('unbound/forwarding', '');
		}
		$this->moveResolver();

		// When the service is generated and started
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the daemon is launched with exactly the module flag that mode needs
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$argv = $this->daemonArgv();
		$this->assertSame($flag === '--no-module', in_array('--no-module', $argv, TRUE), '--no-module iff DNSBL is off');
		$this->assertSame($flag === '--observer', in_array('--observer', $argv, TRUE), '--observer iff DNSBL is on and the Resolver forwards');
	}

	/** @return array<string,array{bool,?PfbToggle,list<string>}> DNSBL on, the DNS Reply Logging preference ($pfb['dnsbl_py_reply'], NULL = unread), the module flags expected in order */
	public static function replyLogFlagRows(): array
	{
		return [
			'DNSBL off, DNS Reply Logging on: the proxy logs the replies it forwards' => [FALSE, PfbToggle::On, ['--no-module', '--reply-log']],
			'DNSBL off, DNS Reply Logging off: nothing is logged'                    => [FALSE, PfbToggle::Off, ['--no-module']],
			'DNSBL off, preference never read: nothing is logged'                    => [FALSE, NULL, ['--no-module']],
			'DNSBL on, DNS Reply Logging on: the module has its own log'             => [TRUE, PfbToggle::On, []],
			'DNSBL on, DNS Reply Logging off'                                        => [TRUE, PfbToggle::Off, []],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('replyLogFlagRows')]
	public function testTheProxyLogsRepliesOnlyWithoutTheModuleAndOnlyWhileTheSharedPreferenceIsOn(bool $dnsbl, ?PfbToggle $preference, array $expected): void
	{
		// Given pfBlockerNG enabled, DNSBL on or off, and the DNS Reply Logging preference (the DNSBL module's own switch) set or not
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = $dnsbl ? PfbToggle::On : PfbToggle::Off;
		if ($preference !== NULL) {
			$GLOBALS['pfb']['dnsbl_py_reply'] = $preference;
		}
		$this->moveResolver();

		// When the service is generated and started
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');

		// Then the daemon is launched with --reply-log iff it hosts no module and the preference is on
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame($expected, array_values(array_intersect($this->daemonArgv(), ['--no-module', '--reply-log', '--observer'])));
	}

	public function testAMarkerThatIsNotAValidSnapshotLaunchesNothingAndFailsLoudly(): void
	{
		// Given a stored marker that is non-empty but no valid Resolver snapshot (hand-edited, truncated): the PHP side
		// sees no snapshot while a gate that only asks "non-empty?" would start a proxy on loopback alone
		config_set_path(self::SAVED, 'not-a-snapshot');
		$this->generate();
		$this->arrange();

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then it logs one error and exits 1, without launching or stopping anything
		$this->assertSame(1, $status, "rc start must fail: {$output}");
		$this->assertSame(['log'], $this->events(TRUE), 'one error line, no daemon, no signal');
		$this->assertStringContainsString('not a valid', (string) file_get_contents("{$this->dir}/state/logger"));
	}

	public function testAMarkerThatChangedSinceTheScriptWasWrittenLaunchesNothing(): void
	{
		// Given a script written for one snapshot, and a different one stored now (restored and moved again since)
		$this->moveResolver();
		$this->generate();
		$this->arrange(['GATE_SAVED' => base64_encode('{"another":"snapshot"}')]);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the stale script does nothing: the next apply regenerates it for the stored snapshot
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
	}

	public function testLauncherStdFdsAreDetachedToDevNull(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->arrange();

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['0 1 2'], array_map('trim', file("{$this->dir}/state/fds", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []),
			'the daemon sees stdin, stdout and stderr on /dev/null (#662)');
	}

	// -----------------------------------------------------------------------
	// S4 -- stop and restart
	// -----------------------------------------------------------------------

	public function testStopWaitsForBothProcessesToExitAfterTerm(): void
	{
		// Given a proxy that exits two ticks after TERM
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->assertSame(['1001', '1002'], $this->livePids(), 'precondition: proxy alive');

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then stop returns only after both exited, with no KILL, and nothing stale is left behind
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep'], $this->events());
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy_daemon.pid'));
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'));
	}

	public function testAProcessIgnoringTermIsKilledAfterFiveTicksAndItsStalePidfilesAreRemoved(): void
	{
		// Given a proxy that ignores TERM and dies one tick after KILL
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', '1', TRUE);

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then TERM is waited on for exactly 5 ticks, the escalation is logged and sent, the exit is
		// observed, and the pidfile a KILLed supervisor could not remove is cleaned up
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep'], $this->events());
		$all = $this->events(TRUE);
		$kill = array_search('kill', $all, TRUE);
		$this->assertSame('log', $all[$kill - 1] ?? NULL, 'the KILL escalation is logged before it is sent');
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy_daemon.pid'));
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'));
	}

	public static function survivorVerbs(): array
	{
		$cycle = ['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep', 'sleep'];
		return [
			'stop'    => ['stop', $cycle],
			// rc_restart stops, then starts only when that stop succeeded: a survivor fails the restart after one stop
			'restart' => ['restart', $cycle],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('survivorVerbs')]
	public function testAProcessSurvivingKillGivesUpAtSevenTicksAndNeverLaunchesAReplacement(string $verb, array $expected): void
	{
		// Given a proxy that survives both TERM and KILL
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', 'never', TRUE);

		// When the service is stopped / started / restarted
		[$status, $output] = $this->rc($verb);

		// Then 7 ticks are spent, the command fails on its own (not by harness timeout), no replacement is
		// launched over the survivor, and its pidfiles are left in place
		$this->assertNotContains($status, [0, 124, 137], "rc {$verb} must fail on its own: {$output}");
		$this->assertSame($expected, $this->events(), "rc {$verb} command events");
		$this->assertSame(['1001', '1002'], $this->livePids());
		$this->assertFileExists($this->pidfile('pfb_dns_proxy.pid'));
	}

	public function testAStartThatCannotStopASupervisorWhoseChildDiedFailsAndNeverLaunches(): void
	{
		// Given a supervisor that survives TERM and KILL, and a child that is already gone
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', 'never', TRUE);
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "4242\n");
		file_put_contents("{$this->dir}/state/procs", "1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[4242] (daemon)\n");

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the pair is not healthy, so the stop runs to its bound (7 ticks) and the start fails on its own, with no launch
		$this->assertNotContains($status, [0, 124, 137], "rc start must fail on its own: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep', 'sleep'], $this->events());
		$this->assertSame(['1001'], $this->livePids());
	}

	public function testRestartReplacesARunningProxyOnlyAfterItExited(): void
	{
		// Given a serving proxy
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);

		// When it is restarted explicitly: the proxy must take a new process
		[$status, $output] = $this->rc('restart');

		// Then it is stopped once and launched once, and the launch comes only after the old pair exited
		$this->assertSame(0, $status, "rc restart failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events(), 'one stop, then one launch after the old pair exited');
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	/** @return array<string,array{?string,string}> pidfile content (NULL = absent), process table lines */
	public static function nothingToStop(): array
	{
		return [
			'pidfile absent'                 => [NULL, ''],
			'pidfile names a dead pid'       => ["4242\n", ''],
			'pidfile is garbage'             => ["1001; touch @DIR@/pwned\n", "1001|X|||pfb_dns_proxy.py\n"],
			'pidfile is empty'               => ['', ''],
			'pid reused by an unrelated process' => ["1001\n", "1001|X|||/usr/sbin/sshd -D\n"],
		];
	}

	#[DataProvider('nothingToStop')]
	public function testStopSignalsNothingWhenNoLiveProxyProcessIsNamedByItsPidfiles(?string $pidfile, string $procs): void
	{
		// Given a stale or hostile pidfile
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		if ($pidfile !== NULL) {
			file_put_contents($this->pidfile('pfb_dns_proxy.pid'), str_replace('@DIR@', $this->dir, $pidfile));
		}
		file_put_contents("{$this->dir}/state/procs", $procs);

		// When the service is stopped
		[$status, $output] = $this->rc('stop');

		// Then it returns at once and signals nothing: a recycled pid is never killed
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->events(), 'no signal, no wait');
		$this->assertSame($procs === '' ? [] : ['1001'], $this->livePids());
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'), 'the stale pidfile is removed');
		$this->assertFileDoesNotExist("{$this->dir}/pwned", 'a hostile pidfile value is never interpreted');
	}

	public function testStartLaunchesEvenWhenAStalePidfileNamesAnUnrelatedLiveProcess(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "1001\n");
		file_put_contents("{$this->dir}/state/procs", "1001|X|||/usr/sbin/sshd -D\n");

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'the unrelated process is neither waited on nor signalled');
	}

	/** @return array<string,array{string,string,string,string}> supervisor pid, child pid, process table ('@DIR@' = the sandbox), the reused pid */
	public static function reusedPidRows(): array
	{
		return [
			'the supervisor pidfile names a pid reused by sshd' => ['1003', '1002',
				"1003|@DIR@/run/pfb_dns_proxy_daemon.pid|||/usr/sbin/sshd -D\n"
				. "1002|@DIR@/run/pfb_dns_proxy.pid|||python3.11 -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py\n", '1003'],
			'the child pidfile names a pid reused by sshd' => ['1001', '1002',
				"1001|@DIR@/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
				. "1002|@DIR@/run/pfb_dns_proxy.pid|||/usr/sbin/sshd -D\n", '1002'],
		];
	}

	public function testSecondStartWhileBothProcessesServeKeepsThemAndLaunchesNothing(): void
	{
		// Given a proxy the first start launched: its supervisor and child are both live and named by their pidfiles
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		[$status, $output] = $this->rc('start');
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'precondition: the first start launched the proxy');

		// When the package start runs again after the boot hook already started the proxy
		[$status, $output] = $this->rc('start');

		// Then the serving pair is kept: no stop, no signal, and no second daemon launch
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'a second start neither stops nor relaunches a serving proxy');
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testStartWithAChildThatDiedStopsTheSurvivingSupervisorAndLaunchesOnce(): void
	{
		// Given a supervisor still alive whose child is gone: the child pidfile names a pid that is no longer running
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "4242\n");
		file_put_contents("{$this->dir}/state/procs", "1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[4242] (daemon)\n");

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the bounded recovery runs: the supervisor gets TERM, both pidfiles are cleared, and the proxy launches once
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events());
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testAStaleMarkerLeavesEvenAServingProxyAlone(): void
	{
		// Given a serving proxy, and a script written for a snapshot that has since changed
		$this->moveResolver();
		$this->generate();
		$this->arrange(['GATE_SAVED' => base64_encode('{"another":"snapshot"}')], '2', '1', TRUE);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the stale script does nothing at all, the health check included: the next apply regenerates it
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	#[DataProvider('reusedPidRows')]
	public function testAStartNeverCountsAReusedPidAsHealthyAndNeverSignalsIt(string $supervisor, string $child, string $procs, string $reused): void
	{
		// Given a pidfile that names a pid now reused by an unrelated process (sshd), beside a live proxy process
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '1', '1');
		file_put_contents($this->pidfile('pfb_dns_proxy_daemon.pid'), "{$supervisor}\n");
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "{$child}\n");
		file_put_contents("{$this->dir}/state/procs", str_replace('@DIR@', $this->dir, $procs));

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the pair is not taken for healthy: the proxy's own process is stopped and relaunched, and the unrelated
		// process is neither signalled nor waited on
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['term', 'sleep', 'launch'], $this->events());
		$this->assertContains($reused, $this->livePids(), 'the reused pid was never signalled');
	}

	// -----------------------------------------------------------------------
	// S3 -- written on every call, like the sibling services
	// -----------------------------------------------------------------------

	public function testTheScriptIsWrittenOnEveryCallEvenWhenTheFileOnDiskIsAlreadyCurrent(): void
	{
		// Given the double writes where production looks (the appliance's rc.d), so a rewrite-only-on-change
		// check would find an identical file there on the second call
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
		$this->moveResolver();

		// When the script is generated twice with the same inputs
		pfb_dns_proxy_service();
		$first = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);
		pfb_dns_proxy_service();

		// Then write_rcfile() ran both times, as for pfb_filter.sh and pfb_dnsbl.sh, with the same content
		$this->assertSame(2, $GLOBALS['pfb_test_rcfile_writes'][self::RC]);
		$this->assertSame($first, (string) file_get_contents(PFB_DNS_PROXY_RCFILE));
		@unlink(PFB_DNS_PROXY_RCFILE);
	}

	public function testAnInterfaceAddressThatChangedIsInTheNextScript(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->assertStringContainsString("'192.0.2.1'", $this->rcText());

		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.77']);
		$this->generate();

		$this->assertStringContainsString("'192.0.2.77'", $this->rcText());
		$this->assertStringNotContainsString("'192.0.2.1'", $this->rcText());
	}

	public function testWithNoMovedResolverTheScriptStillExistsAndNeverLaunchesAnything(): void
	{
		// Given no snapshot (not in proxy mode): stop_service() can only reach a script that exists
		$this->generate();
		$this->arrange(['GATE_SAVED' => '']);

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
	}

	// -----------------------------------------------------------------------
	// S6 -- the listener-ready marker: written by the proxy itself, cleared by the rc script only around a fresh start
	// -----------------------------------------------------------------------

	private function seedMarker(string $pid): void
	{
		file_put_contents($this->readyFile(), "{$pid}\n");
	}

	/** @return list<string> what each launched proxy found at the marker's path when it started */
	private function markerAtLaunch(): array
	{
		return file("{$this->dir}/state/launch.marker", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	/** @return list<string> the descriptors above stdio each launched proxy inherited */
	private function inheritedFds(): array
	{
		return file("{$this->dir}/state/launch.fds", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	public function testTheLaunchedProxyInheritsNoDescriptorFromTheStartLock(): void
	{
		// Given a start under lockf: FreeBSD's lockf closes its lock descriptor before the command runs, but this double's flock(1)
		// passes it on, so the rc script's closes of descriptors 3-9 at launch are what keep the proxy from holding the lock
		$this->moveResolver();
		$this->generate();
		$this->arrange();

		// When it launches the proxy
		[$status, $output] = $this->rc('start');

		// Then the proxy has no descriptor above stdio: one that held the lock would keep it for as long as the proxy runs,
		// and every later start would wait its 10 s and fail
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertSame([], $this->inheritedFds());
	}

	public function testAFreshStartRemovesThePreviousMarkerBeforeTheNewProxyIsLaunched(): void
	{
		// Given the marker an earlier proxy left behind (a killed proxy cannot remove its own)
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		$this->seedMarker('999');

		// When a fresh start launches the proxy
		[$status, $output] = $this->rc('start');

		// Then the old marker was gone before the daemon was launched: nothing can mistake it for the new proxy's
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertSame(['absent'], $this->markerAtLaunch());
		$this->assertFileDoesNotExist($this->readyFile());
	}

	public function testAHealthyRepeatedStartKeepsTheMarkerOfTheServingProxy(): void
	{
		// Given a serving proxy (supervisor 1001, child 1002) whose marker names its child
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->seedMarker('1002');

		// When the package start runs again after the boot hook (or an earlier apply) started it
		[$status, $output] = $this->rc('start');

		// Then nothing is stopped, launched or removed: the marker still names the serving child
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE));
		$this->assertSame("1002\n", (string) file_get_contents($this->readyFile()));
		$this->assertSame(['1001', '1002'], $this->livePids());
		$this->assertSame([], $this->markerAtLaunch(), 'no new proxy was launched');
	}

	public function testAStopRemovesTheMarkerOfTheProxyItStopped(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->seedMarker('1002');

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->readyFile(), 'the marker names a process that was stopped here');
	}

	public function testAStopLeavesAMarkerThatNamesAProcessItDidNotStop(): void
	{
		// Given a marker published by another proxy process (a start that finished while this stop ran), not the one stopped
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		$this->seedMarker('7777');

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->livePids());
		$this->assertSame("7777\n", (string) file_get_contents($this->readyFile()), 'another process\'s marker is never removed');
	}

	public function testAProxyKilledAfterIgnoringTermHasItsMarkerRemovedByTheStop(): void
	{
		// Given a proxy that ignores TERM and is KILLed: it could not remove its own marker
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', '1', TRUE);
		$this->seedMarker('1002');

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertFileDoesNotExist($this->readyFile());
	}

	public function testAProxyThatSurvivesItsStopKeepsItsMarker(): void
	{
		// Given a proxy that survives TERM and KILL: it still serves, so its marker is still true
		$this->moveResolver();
		$this->generate();
		$this->arrange([], 'never', 'never', TRUE);
		$this->seedMarker('1002');

		[$status] = $this->rc('stop');

		$this->assertNotSame(0, $status);
		$this->assertSame("1002\n", (string) file_get_contents($this->readyFile()));
	}

	// -----------------------------------------------------------------------
	// S7 -- starts are serialized: the boot hook's background start and an apply's start_service() must not both launch
	// -----------------------------------------------------------------------

	/** @return array{0: resource, 1: resource} the running verb and its output pipe */
	private function startVerb(string $verb): array
	{
		$proc = proc_open(
			[$GLOBALS['pfb']['timeout'], '-k', '2', '30', $this->shell, "{$this->dir}/run.sh", $verb],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
			$pipes
		);
		$this->assertIsResource($proc, 'proc_open failed');
		fclose($pipes[0]);
		return [$proc, $pipes[1]];
	}

	/** @param array{0: resource, 1: resource} $started @return array{0: int, 1: string} */
	private function finishVerb(array $started): array
	{
		$output = (string) stream_get_contents($started[1]);
		fclose($started[1]);
		return [proc_close($started[0]), $output];
	}

	private function launchCount(): int
	{
		return count(array_keys($this->events(), 'launch', TRUE));
	}

	/** @return list<string> */
	private function lockfCalls(): array
	{
		return file("{$this->dir}/state/lockf.calls", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	/** The watchdog only salvages a stuck run: it fails the test, and the caller's finally block reaps what it started. */
	private function waitUntil(callable $condition, string $what): void
	{
		$deadline = hrtime(TRUE) + 15 * 1000000000;
		while (!$condition()) {
			if (hrtime(TRUE) >= $deadline) {
				$this->fail("STUCK/ENVIRONMENT: {$what}");
			}
			usleep(20000);
		}
	}

	public function testEveryStartRunsUnderTheKeptLockWithATenSecondWaitAndTheStopDoesNot(): void
	{
		// Given a generated script
		$this->moveResolver();
		$this->generate();
		$this->arrange();

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then the start ran under one lockf (kept lock file, 10 s wait: the double rejects any other form), however many
		// times the script runs itself inside the lock
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(["{$this->dir}/run/pfb_dns_proxy.lock"], $this->lockfCalls());
		$this->assertSame(['launch'], $this->events());

		// And a stop takes no lock: it must be able to run while a start waits
		[$status, $output] = $this->rc('stop');
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertCount(1, $this->lockfCalls(), 'stop is not serialized with start');
	}

	public function testTwoStartsRacingAtTheDaemonLaunchLaunchExactlyOneProxy(): void
	{
		// Given the daemon launch held open (the proxy's pidfiles are written when it returns), and a first start inside it
		$this->moveResolver();
		$this->generate();
		$this->arrange();
		touch("{$this->dir}/state/barrier");
		$first = $second = NULL;

		try {
			$first = $this->startVerb('start');
			$this->waitUntil(fn (): bool => $this->launchCount() >= 1, 'the first start never reached the daemon launch');

			// When a second start (the boot hook's background start, or an apply's start_service()) arrives while it is held:
			// without a lock it passes the same "already serving?" check and launches too; with one it waits behind the first
			$second = $this->startVerb('start');
			$this->waitUntil(
				fn (): bool => $this->launchCount() >= 2 || count($this->lockfCalls()) >= 2,
				'the second start neither reached the daemon launch nor the lock'
			);
		} catch (Throwable $e) {
			foreach ([$first, $second] as $started) {
				if ($started !== NULL) {
					proc_terminate($started[0]);
				}
			}
			throw $e;
		} finally {
			@unlink("{$this->dir}/state/barrier");
		}

		[$firstStatus, $firstOutput] = $this->finishVerb($first);
		[$secondStatus, $secondOutput] = $this->finishVerb($second);

		// Then both succeed and exactly one proxy was launched: the second found the first's serving pair and kept it
		$this->assertSame(0, $firstStatus, "first start failed: {$firstOutput}");
		$this->assertSame(0, $secondStatus, "second start failed: {$secondOutput}");
		$this->assertSame(['launch'], $this->events(), 'one daemon launch for two concurrent starts');
		$this->assertSame(['3001', '3002'], $this->livePids(), 'one supervisor and one child');
	}

	public function testAStartThatCannotTakeTheLockWithinItsWaitFailsLoudlyAndLaunchesNothing(): void
	{
		// Given another start that holds the lock for longer than the wait
		$this->moveResolver();
		$this->generate();
		$this->arrange(['LOCKF_BUSY' => '1']);

		// When it is started
		[$status, $output] = $this->rc('start');

		// Then it gives up with lockf's own "try again" status (75), one error line, and no launch or signal
		$this->assertSame(75, $status, "rc start must fail with EX_TEMPFAIL: {$output}");
		$this->assertSame(['log'], $this->events(TRUE), 'one error line, no daemon, no signal');
		$this->assertStringContainsString('lock', (string) file_get_contents("{$this->dir}/state/logger"));
	}

	// -----------------------------------------------------------------------
	// issue #3513 -- the Go gateway replaces the Python listener while its binary is installed
	// -----------------------------------------------------------------------

	private const SETTINGS = 'installedpackages/pfblockerngdnsblsettings/config/0/';
	private const DECIDER = [
		'--', '/usr/local/pkg/pfblockerng/pfb_python.sh', '-u', '/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py',
		'--decision-fd', '3', '--module-dir', '/var/unbound', '--user', 'unbound',
	];

	/** An executable stand-in for the gateway binary; the script runs whatever path it is given. */
	private function gateway(int $mode = 0755): string
	{
		$path = "{$this->dir}/bin/pfb_dns_gateway";
		file_put_contents($path, "#!/bin/sh\n");
		chmod($path, $mode);
		return $path;
	}

	private function generateWith(string $gateway): void
	{
		pfb_dns_proxy_service($gateway);
	}

	private function setting(string $key, string $value): void
	{
		config_set_path(self::SETTINGS . $key, $value);
	}

	/** The Resolver of a box with two interfaces: lan (192.0.2.1, 2001:db8::1) and opt1 (198.51.100.1, 2001:db8:1::1). */
	private function moveTwoInterfaceResolver(bool $dot = FALSE): void
	{
		$this->moveResolver(
			$dot,
			'lan,opt1',
			['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'],
			['lan' => '2001:db8::1', 'opt1' => '2001:db8:1::1']
		);
	}

	/**
	 * The daemon argv the gateway rc script must launch.
	 *
	 * @param list<string> $listen plain DNS addresses the Resolver's interfaces give; the loopback pair is appended
	 * @param list<string> $tls the --doh-* / --doq-* arguments, in order
	 * @param string $port the Resolver's Listen Port the gateway binds for plain DNS
	 * @return list<string>
	 */
	private function gatewayArgv(string $gateway, array $listen, bool $dot = FALSE, array $tls = [], string $port = '53'): array
	{
		$addresses = [];
		foreach ([...$listen, '127.0.0.1', '::1'] as $address) {
			array_push($addresses, '--listen', $address);
		}
		return [
			'-r', '-R', '5', '-t', 'pfb_dns_proxy',
			'-P', $this->pidfile('pfb_dns_proxy_daemon.pid'), '-p', $this->pidfile('pfb_dns_proxy.pid'),
			'-o', "{$this->dir}/log/dns_proxy.log",
			$gateway, ...$addresses,
			'--port', $port, '--upstream', '127.0.0.1:5353', ...($dot ? ['--dot'] : []),
			'--pfsense-config', '/cf/conf/config.xml', ...$tls,
			'--unbound-conf', '/var/unbound/unbound.conf', '--user', 'unbound', ...self::DECIDER,
		];
	}

	/** @return list<string> the daemon argv after the rc script started under dash */
	private function startAndReadArgv(string $gateway): array
	{
		$this->generateWith($gateway);
		$this->arrange();
		[$status, $output] = $this->rc('start');
		$this->assertSame(0, $status, "rc start failed: {$output}");
		return $this->daemonArgv();
	}

	/** @return list<string> pfBlockerNG error-log lines that name the gateway binary */
	private function gatewayWarnings(): array
	{
		$lines = explode("\n", (string) @file_get_contents("{$this->dir}/pfb.err"));
		return array_values(array_filter($lines, static fn (string $line): bool => str_contains($line, 'pfb_dns_gateway')));
	}

	/** @return array<string,array{bool}> */
	public static function gatewayDotRows(): array
	{
		return ['DoT off' => [FALSE], 'DoT on' => [TRUE]];
	}

	#[DataProvider('gatewayDotRows')]
	public function testWithTheGatewayInstalledTheScriptRunsItWithTheDeciderAfterTheSeparatorAndDotOnlyWhenSaved(bool $dot): void
	{
		// Given the gateway binary and a saved Resolver that listened on lan (both families), DoH/DoQ off
		$gateway = $this->gateway();
		$this->moveResolver($dot, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);

		// When the rc service is generated and started under dash
		$argv = $this->startAndReadArgv($gateway);

		// Then the daemon runs the gateway with the plain addresses, Unbound's PROXY port, Unbound's config (where it
		// reads the ACL) and the unprivileged user, and hands the Python decider's argv over after `--`
		$this->assertSame($this->gatewayArgv($gateway, ['192.0.2.1', '2001:db8::1'], $dot), $argv);
		$this->assertSame(['launch'], $this->events());
	}

	public function testTheGatewayScriptQuotesEveryValueAndStaysPosixShell(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(TRUE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);
		$this->generateWith($gateway);
		$text = $this->rcText();

		$this->assertStringContainsString("--listen '192.0.2.1' --listen '2001:db8::1'", $text);
		$this->assertStringContainsString(escapeshellarg($gateway), $text, 'the binary path is quoted too');
		$this->assertStringContainsString('</dev/null >/dev/null 2>&1', $text, 'stdio is detached (#662)');
		$this->assertStringContainsString("rc_stop || return 1\n", $text, 'never launch over a survivor');
		$proc = proc_open([$this->shell, '-n', "{$this->dir}/rc/" . self::RC], [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
		$this->assertIsResource($proc);
		$output = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		$this->assertSame(0, proc_close($proc), "sh -n rejected the generated script: {$output}");
	}

	/** @return list<string> the loopback pair DoH and DoQ always listen on, next to the interfaces they are given */
	private static function loopbackListen(string $kind): array
	{
		return ["--{$kind}-listen", '127.0.0.1', "--{$kind}-listen", '::1'];
	}

	/** @return array<string,array{string,string,list<string>}> DoH interface setting, trusted setting, the --doh-* arguments */
	public static function dohRows(): array
	{
		$loopback = self::loopbackListen('doh');
		return [
			'no interface and no trusted entry: the plain addresses and loopback' => [
				'', '',
				['--doh-listen', '192.0.2.1', '--doh-listen', '2001:db8::1', '--doh-listen', '198.51.100.1',
					'--doh-listen', '2001:db8:1::1', ...$loopback, '--doh-port', '8443'],
			],
			'opt1 only, two trusted entries' => [
				'opt1', '192.0.2.10 2001:db8::/32',
				['--doh-listen', '198.51.100.1', '--doh-listen', '2001:db8:1::1', ...$loopback, '--doh-port', '8443',
					'--doh-trusted', '192.0.2.10/32', '--doh-trusted', '2001:db8::/32'],
			],
			'repeated interface, comma and space separators' => [
				'opt1,opt1,', "10.0.0.0/8,\t 192.0.2.10",
				['--doh-listen', '198.51.100.1', '--doh-listen', '2001:db8:1::1', ...$loopback, '--doh-port', '8443',
					'--doh-trusted', '10.0.0.0/8', '--doh-trusted', '192.0.2.10/32'],
			],
		];
	}

	/**
	 * @param list<string> $expected
	 */
	#[DataProvider('dohRows')]
	public function testDohOnAddsItsListenersPortAndTrustedFrontEndsToTheGatewayLine(string $interfaces, string $trusted, array $expected): void
	{
		// Given DoH on at port 8443 with this interface and trusted setting
		$gateway = $this->gateway();
		$this->moveTwoInterfaceResolver();
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_port', '8443');
		$this->setting('pfb_dns_proxy_doh_interface', $interfaces);
		$this->setting('pfb_dns_proxy_doh_trusted', $trusted);

		// When the script starts
		$argv = $this->startAndReadArgv($gateway);

		// Then the DoH group sits between --pfsense-config and --unbound-conf, loopback after its interfaces' addresses;
		// the plain DNS addresses are untouched
		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1', '2001:db8::1', '198.51.100.1', '2001:db8:1::1'], FALSE, $expected),
			$argv
		);
	}

	/** @return array<string,array{string,list<string>}> DoQ interface setting, the --doq-* arguments */
	public static function doqRows(): array
	{
		$loopback = self::loopbackListen('doq');
		return [
			'no interface: the plain addresses and loopback' => [
				'', ['--doq-listen', '192.0.2.1', '--doq-listen', '2001:db8::1', '--doq-listen', '198.51.100.1',
					'--doq-listen', '2001:db8:1::1', ...$loopback, '--doq-port', '8853'],
			],
			'lan only' => ['lan', ['--doq-listen', '192.0.2.1', '--doq-listen', '2001:db8::1', ...$loopback, '--doq-port', '8853']],
		];
	}

	/**
	 * @param list<string> $expected
	 */
	#[DataProvider('doqRows')]
	public function testDoqOnAddsItsListenersAndPortAndNoTrustedFrontEnds(string $interfaces, array $expected): void
	{
		$gateway = $this->gateway();
		$this->moveTwoInterfaceResolver();
		$this->setting('pfb_dns_proxy_doq', 'on');
		$this->setting('pfb_dns_proxy_doq_port', '8853');
		$this->setting('pfb_dns_proxy_doq_interface', $interfaces);
		$this->setting('pfb_dns_proxy_doh_trusted', '192.0.2.10');

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1', '2001:db8::1', '198.51.100.1', '2001:db8:1::1'], FALSE, $expected),
			$argv,
			'DoQ has no trusted front ends, and DoH (off) leaves nothing behind'
		);
	}

	public function testDohAndDoqTogetherListDohFirst(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doq', 'on');

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doh-listen', '192.0.2.1', ...self::loopbackListen('doh'), '--doh-port', '4443',
				'--doq-listen', '192.0.2.1', ...self::loopbackListen('doq'), '--doq-port', '853',
			]),
			$this->startAndReadArgv($gateway)
		);
	}

	#[DataProvider('listenPortRows')]
	public function testTheGatewayBindsTheResolversListenPortAndFallsBackToTheDefaultWhenItIsNotAPort(?string $configured, string $expected): void
	{
		// Given the gateway binary and a moved Resolver whose Listen Port is $configured
		$gateway = $this->gateway();
		$this->moveResolver();
		if ($configured !== NULL) {
			$GLOBALS['config']['unbound']['port'] = $configured;
		}

		// When the rc service is generated and started under dash
		$argv = $this->startAndReadArgv($gateway);

		// Then the gateway gets exactly one --port (--doh-port and --doq-port are other flags), the Resolver's or 53
		$this->assertSame(1, count(array_keys($argv, '--port', TRUE)), 'exactly one --port');
		$this->assertSame($expected, $argv[(int) array_search('--port', $argv, TRUE) + 1]);
		$this->assertStringNotContainsString('reboot', $this->rcText());
	}

	public function testTheGatewayServesLoopbackOnTheListenPortWhileDohAndDoqKeepTheirOwnListeners(): void
	{
		// Given a Resolver saved on one IPv4-only interface, Listen Port 5300, DoH and DoQ on their own ports
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$GLOBALS['config']['unbound']['port'] = '5300';
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doq', 'on');

		// When the rc service is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then plain DNS is served on the interface address and on both loopback addresses at 5300, so the firewall's
		// resolv.conf (127.0.0.1, ::1) reaches the gateway; DoH and DoQ keep their own ports and also listen on loopback
		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doh-listen', '192.0.2.1', ...self::loopbackListen('doh'), '--doh-port', '4443',
				'--doq-listen', '192.0.2.1', ...self::loopbackListen('doq'), '--doq-port', '853',
			], '5300'),
			$argv
		);
	}

	public function testTlsSettingsWhileTheirToggleIsOffAddNothing(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', '');
		$this->setting('pfb_dns_proxy_doh_port', '8443');
		$this->setting('pfb_dns_proxy_doh_trusted', '192.0.2.10');
		$this->setting('pfb_dns_proxy_doq_port', '8853');

		$this->assertSame($this->gatewayArgv($gateway, ['192.0.2.1']), $this->startAndReadArgv($gateway));
	}

	public function testATlsListenerWhoseInterfacesHaveNoAddressStillListensOnLoopbackAlone(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_interface', 'opt9');
		$this->setting('pfb_dns_proxy_doh_trusted', '192.0.2.10');

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				...self::loopbackListen('doh'), '--doh-port', '4443', '--doh-trusted', '192.0.2.10/32',
			]),
			$this->startAndReadArgv($gateway),
			'the loopback backend for a local HAProxy is there whatever the interfaces came to'
		);
	}

	public function testAHandEditedTrustedEntryThatIsNotAnAddressNeverReachesTheScript(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_trusted', "192.0.2.10 evil;touch {$this->dir}/pwned fe80::1%em0 \$(id) 10.0.0.0/33");

		$this->generateWith($gateway);
		$text = $this->rcText();

		$this->assertSame(1, substr_count($text, '--doh-trusted'), 'only the real address survives');
		$this->assertStringContainsString("--doh-trusted '192.0.2.10/32'", $text);
		foreach (['evil', 'pwned', 'fe80', '$(id)', '/33'] as $junk) {
			$this->assertStringNotContainsString($junk, $text, "{$junk} must not reach the script");
		}
	}

	public function testThreeHundredTrustedEntriesAreEachQuotedAndLaunched(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$entries = [];
		for ($i = 0; $i < 300; $i++) {
			$entries[] = '10.' . intdiv($i, 250) . '.' . ($i % 250) . '.0/24';
		}
		$this->setting('pfb_dns_proxy_doh_trusted', implode(' ', $entries));

		$argv = $this->startAndReadArgv($gateway);

		$trusted = [];
		foreach ($argv as $i => $arg) {
			if ($arg === '--doh-trusted') {
				$trusted[] = $argv[$i + 1];
			}
		}
		$this->assertSame($entries, $trusted);
		$this->assertSame(300, substr_count($this->rcText(), " --doh-trusted '"), 'each entry is its own quoted word');
	}

	public function testAGatewayThatIsNotExecutableIsNotUsed(): void
	{
		// Given the unchanged Python line a box without the binary gets
		$this->moveResolver(TRUE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->generateWith("{$this->dir}/bin/absent");
		$python = $this->rcText();

		// When the binary exists but lacks the execute bit
		$this->generateWith($this->gateway(0644));

		// Then the Python listener is still the one launched
		$this->assertSame($python, $this->rcText());
		$this->assertStringNotContainsString('--decision-fd', $python, 'the Python line carries no gateway arguments');
	}

	#[DataProvider('gatewayDotRows')]
	public function testWithoutTheGatewayTheScriptIsTheUnchangedPythonLineWhateverTheDohAndDoqSettings(bool $dot): void
	{
		// Given a box in proxy mode and the script it gets with DoH and DoQ off
		$this->moveResolver($dot, 'lan', ['lan' => '192.0.2.1']);
		$this->generateWith("{$this->dir}/bin/absent");
		$before = $this->rcText();
		$this->assertStringContainsString(
			"/usr/local/pkg/pfblockerng/pfb_python.sh -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py --listen '192.0.2.1' --listen '127.0.0.1' --listen '::1' --port 53 "
			. "--upstream 127.0.0.1:5353 --module-dir /var/unbound --user unbound --ready-file " . escapeshellarg($GLOBALS['pfb']['dns_proxy_ready']) .
			($dot ? ' --dot --pfsense-config /cf/conf/config.xml' : '') . ' --no-module </dev/null',
			$before
		);

		// When DoH and DoQ are turned on and configured
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_port', '8443');
		$this->setting('pfb_dns_proxy_doh_trusted', '192.0.2.10');
		$this->setting('pfb_dns_proxy_doq', 'on');

		// Then the generated script does not change by a byte
		$this->generateWith("{$this->dir}/bin/absent");
		$this->assertSame($before, $this->rcText());
	}

	/** @return array<string,array{array<string,string>,int}> settings, expected number of warnings */
	public static function warnRows(): array
	{
		return [
			'DoH on'       => [['pfb_dns_proxy_doh' => 'on'], 1],
			'DoQ on'       => [['pfb_dns_proxy_doq' => 'on'], 1],
			'both on'      => [['pfb_dns_proxy_doh' => 'on', 'pfb_dns_proxy_doq' => 'on'], 1],
			'both off'     => [[], 0],
		];
	}

	/** @param array<string,string> $settings */
	#[DataProvider('warnRows')]
	public function testDohOrDoqOnWithoutTheGatewayLogsOneWarning(array $settings, int $warnings): void
	{
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		foreach ($settings as $key => $value) {
			$this->setting($key, $value);
		}

		$this->generateWith("{$this->dir}/bin/absent");

		$this->assertCount($warnings, $this->gatewayWarnings(), 'warnings naming the gateway: ' . json_encode($this->gatewayWarnings()));
	}

	public function testWithTheGatewayInstalledDohAndDoqLogNoWarning(): void
	{
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doq', 'on');

		$this->generateWith($this->gateway());

		$this->assertSame([], $this->gatewayWarnings());
	}

	public function testStopSignalsTheGatewayItStartedAndWaitsForItAndItsSupervisor(): void
	{
		// Given the gateway script was started: the supervisor and the gateway child are live in the sandbox
		$gateway = $this->gateway();
		$this->moveResolver();
		$this->startAndReadArgv($gateway);
		$this->assertStringContainsString($gateway, (string) file_get_contents("{$this->dir}/state/procs"), 'precondition: the child is the gateway');
		$this->assertSame(['3001', '3002'], $this->livePids(), 'precondition: supervisor and gateway alive');

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then both get TERM and are waited for, with no KILL
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['launch', 'term', 'sleep', 'sleep'], $this->events());
		$this->assertSame([], $this->livePids());
	}

	/** @return array<string,array{string}> the gateway child's command line as ps shows it */
	public static function gatewayChildLines(): array
	{
		return [
			'with the decider argv after the separator' => [
				'/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_gateway --listen 192.0.2.1 --port 53 -- '
				. '/usr/local/pkg/pfblockerng/pfb_python.sh -u /usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py --decision-fd 3',
			],
			'by its own name alone' => ['/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_gateway --listen 192.0.2.1'],
		];
	}

	#[DataProvider('gatewayChildLines')]
	public function testStopRecognisesAGatewayChildByItsCommandLine(string $childArgs): void
	{
		// Given a live supervisor and a child whose command line is the gateway's
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);
		file_put_contents("{$this->dir}/state/procs",
			"1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
			. "1002|{$this->dir}/run/pfb_dns_proxy.pid|||{$childArgs}\n");

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->livePids(), 'the gateway child was signalled and exited with its supervisor');
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'));
	}

	public function testAGatewayThatIgnoresTermIsKilledAtFiveTicksAndGivenUpOnAtSeven(): void
	{
		// Given a gateway that survives both signals
		$gateway = $this->gateway();
		$this->moveResolver();
		$this->generateWith($gateway);
		$this->arrange([], 'never', 'never', TRUE);
		file_put_contents("{$this->dir}/state/procs",
			"1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[1002] (daemon)\n"
			. "1002|{$this->dir}/run/pfb_dns_proxy.pid|||{$gateway} --listen 192.0.2.1\n");

		// When it is stopped
		[$status, $output] = $this->rc('stop');

		// Then the wait is still bounded exactly as for the Python proxy: TERM, KILL after 5 ticks, give up after 7
		$this->assertNotContains($status, [0, 124, 137], "rc stop must fail on its own: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill', 'sleep', 'sleep'], $this->events());
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	// -----------------------------------------------------------------------
	// issue #3513 gate fixes -- what the gateway is handed must be what it can parse and nothing wider
	// -----------------------------------------------------------------------

	/** @return list<string> the values of every `$flag` argument the daemon double was launched with */
	private function flagValues(array $argv, string $flag): array
	{
		$values = [];
		foreach ($argv as $i => $arg) {
			if ($arg === $flag) {
				$values[] = $argv[$i + 1];
			}
		}
		return $values;
	}

	/** @return list<string> error-log lines about a stored DoH/DoQ port the gateway could not parse */
	private function portWarnings(): array
	{
		$lines = explode("\n", (string) @file_get_contents("{$this->dir}/pfb.err"));
		return array_values(array_filter($lines, static fn (string $line): bool => str_contains($line, 'is not a whole number')));
	}

	/** @return array<string,array{string,list<string>}> trusted setting, the --doh-trusted values the gateway gets */
	public static function trustedHostPrefixes(): array
	{
		return [
			'bare v4 is a /32'            => ['192.0.2.10', ['192.0.2.10/32']],
			'bare v6 is a /128'           => ['2001:db8::1', ['2001:db8::1/128']],
			'bare v4-mapped v6 is a /128' => ['::ffff:192.0.2.10', ['::ffff:192.0.2.10/128']],
			'prefixes pass through'       => ['10.0.0.0/8 2001:db8::/32', ['10.0.0.0/8', '2001:db8::/32']],
			'mixed, in order'             => ['192.0.2.10, 2001:db8::1 10.0.0.0/8', ['192.0.2.10/32', '2001:db8::1/128', '10.0.0.0/8']],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('trustedHostPrefixes')]
	public function testABareTrustedAddressBecomesAHostPrefixOfItsOwnFamilyNeverAWiderOne(string $trusted, array $expected): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_trusted', $trusted);

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame($expected, $this->flagValues($argv, '--doh-trusted'));
		$this->assertStringContainsString(
			implode(' ', array_map(static fn (string $c): string => '--doh-trusted ' . escapeshellarg($c), $expected)),
			$this->rcText(),
			'each prefix is its own quoted word, in order'
		);
	}

	public function testEveryListenAddressPortAndTrustedValueOfTheTlsGroupsIsShellQuoted(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1'], ['lan' => '2001:db8::1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_port', '8443');
		$this->setting('pfb_dns_proxy_doh_trusted', '192.0.2.10');
		$this->setting('pfb_dns_proxy_doq', 'on');
		$this->setting('pfb_dns_proxy_doq_port', '8853');
		$this->generateWith($gateway);
		$text = $this->rcText();

		foreach ([
			"--doh-listen '192.0.2.1'", "--doh-listen '2001:db8::1'", "--doh-port '8443'", "--doh-trusted '192.0.2.10/32'",
			"--doq-listen '192.0.2.1'", "--doq-listen '2001:db8::1'", "--doq-port '8853'",
		] as $quoted) {
			$this->assertStringContainsString($quoted, $text, "{$quoted} must be a quoted word of the daemon line");
		}
	}

	/** @return array<string,array{string}> */
	public static function unparsablePorts(): array
	{
		return [
			'shell text'         => ["4443'; touch PWNED #"],
			'command substitution' => ['$(touch PWNED)'],
			'a word'             => ['abc'],
			'zero'               => ['0'],
			'one past the top'   => ['65536'],
			'overflowing int'    => ['99999999999999999999'],
			'negative'           => ['-1'],
			'padded'             => [' 443'],
		];
	}

	#[DataProvider('unparsablePorts')]
	public function testAStoredPortTheGatewayCouldNotParseOmitsItsGroupAndWarnsOnce(string $port): void
	{
		// Given DoH and DoQ on, each with a hand-edited port, and a trusted front end
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		foreach (['doh', 'doq'] as $kind) {
			$this->setting("pfb_dns_proxy_{$kind}", 'on');
		}
		$this->setting('pfb_dns_proxy_doh_trusted', '192.0.2.10');
		$this->setting('pfb_dns_proxy_doh_port', $port);
		$this->setting('pfb_dns_proxy_doq_port', '8853');

		// When the script is generated and started
		$argv = $this->startAndReadArgv($gateway);

		// Then the DoH group is left out whole, the DoQ group is intact, the bad value is nowhere in the script,
		// and one warning says so
		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, ['--doq-listen', '192.0.2.1', '--doq-port', '8853']),
			$argv
		);
		$this->assertStringNotContainsString('PWNED', $this->rcText());
		$this->assertCount(1, $this->portWarnings(), 'one warning: ' . json_encode($this->portWarnings()));
		$this->assertStringContainsString('DoH', $this->portWarnings()[0]);
		$this->assertFileDoesNotExist("{$this->dir}/PWNED");
	}

	public function testABadDoqPortOmitsOnlyTheDoqGroup(): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doq', 'on');
		$this->setting('pfb_dns_proxy_doq_port', 'abc');

		$this->assertSame(
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, ['--doh-listen', '192.0.2.1', '--doh-port', '4443']),
			$this->startAndReadArgv($gateway)
		);
		$this->assertCount(1, $this->portWarnings());
		$this->assertStringContainsString('DoQ', $this->portWarnings()[0]);
	}

	/** @return array<string,array{string,string}> stored port, the one the gateway gets */
	public static function paddedPorts(): array
	{
		return [
			'one leading zero' => ['0443', '443'], 'octal-looking' => ['010', '10'], 'zero padded to five' => ['00080', '80'],
			'plain' => ['8443', '8443'], 'cleared: the registered default' => ['', '4443'],
		];
	}

	#[DataProvider('paddedPorts')]
	public function testAStoredPortWithLeadingZerosIsHandedOverWithoutThemSoNoParserReadsItAsOctal(string $stored, string $expected): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_port', $stored);

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame([$expected], $this->flagValues($argv, '--doh-port'));
		$this->assertSame([], $this->portWarnings(), 'a port that parses is not a warning');
	}

	/** @return array<string,array{string}> */
	public static function untrustworthyPrefixes(): array
	{
		return [
			'leading zero'        => ['10.0.0.0/08'],
			'two leading zeros'   => ['10.0.0.0/008'],
			'host prefix padded'  => ['192.0.2.10/032'],
			'v6 leading zero'     => ['2001:db8::/064'],
			'v4 with a v6 prefix' => ['192.0.2.1/64'],
			'zone'                => ['fe80::1%em0'],
		];
	}

	#[DataProvider('untrustworthyPrefixes')]
	public function testAHandEditedTrustedPrefixTheGatewayWouldRejectNeverReachesTheScript(string $bad): void
	{
		$gateway = $this->gateway();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_trusted', "{$bad} 198.51.100.7");

		$argv = $this->startAndReadArgv($gateway);

		$this->assertSame(['198.51.100.7/32'], $this->flagValues($argv, '--doh-trusted'),
			"{$bad} is dropped, the valid neighbour stays");
	}

	/** The double writes where pfb_dns_proxy_service() reads the previous script from, so an unchanged one can be told. */
	private function writeRcWhereProductionReadsIt(): void
	{
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
	}

	public function testTheMissingGatewayWarningIsLoggedWhenTheScriptChangesNotOnEveryApply(): void
	{
		// Given DoH on, no gateway binary installed, and a box whose script was just generated (one warning)
		$absent = "{$this->dir}/bin/absent";
		$this->writeRcWhereProductionReadsIt();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->generateWith($absent);
		$this->assertCount(1, $this->gatewayWarnings(), 'before: the generation that wrote the script warned once');

		// When the next apply regenerates an identical script
		$this->generateWith($absent);

		// Then it does not warn again
		$this->assertCount(1, $this->gatewayWarnings(), 'warnings: ' . json_encode($this->gatewayWarnings()));

		// When an address change makes the script differ, it warns once more
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.77']);
		$this->generateWith($absent);
		$this->assertCount(2, $this->gatewayWarnings());
	}

	public function testTheBadPortWarningIsLoggedWhenTheScriptChangesNotOnEveryApply(): void
	{
		$gateway = $this->gateway();
		$this->writeRcWhereProductionReadsIt();
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		$this->setting('pfb_dns_proxy_doh', 'on');
		$this->setting('pfb_dns_proxy_doh_port', 'abc');
		$this->generateWith($gateway);
		$this->assertCount(1, $this->portWarnings(), 'before: the generation that wrote the script warned once');

		$this->generateWith($gateway);

		$this->assertCount(1, $this->portWarnings(), 'warnings: ' . json_encode($this->portWarnings()));
	}
}
