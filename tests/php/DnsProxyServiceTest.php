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
 *   - it starts only while DNSBL, the proxy toggle and the moved-Resolver snapshot are all set, and never
 *     launches over a survivor;
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
	private const SAVED = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dns_proxy_saved';
	private const RC = 'pfb_dns_proxy.sh';

	private const DOUBLES = ['read_xml_tag.sh', 'daemon', 'kill', 'sleep', 'ps', 'logger'];

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
			*/pfb_dns_proxy_saved) echo "$GATE_SAVED" ;;
			*/pfb_dns_proxy) echo "$GATE_PROXY" ;;
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
		$gates += ['GATE_DNSBL' => 'on', 'GATE_PROXY' => 'on', 'GATE_SAVED' => 'eyJwb3J0IjoxfQ=='];
		$state = "{$this->dir}/state";
		$vars = $gates + ['TERM_AFTER' => $termAfter, 'KILL_AFTER' => $killAfter];
		file_put_contents("{$state}/scenario", implode('', array_map(
			static fn (string $k, string $v): string => "{$k}=" . escapeshellarg($v) . "\n",
			array_keys($vars),
			array_values($vars)
		)));
		file_put_contents("{$state}/ticks", "0\n");
		foreach (['events', 'fds', 'procs', 'logger', 'daemon.argv'] as $file) {
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

	/** Point every absolute path in the generated script at the sandbox; fail closed on any other. */
	private function sandboxPaths(string $script): string
	{
		return (string) preg_replace_callback(
			'~(?<![\w$.\-/])/(?:[\w.\-]+/)*[\w.\-]+~',
			function (array $m): string {
				$path = $m[0];
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

	/** @return array<string,array{array<string,string>}> */
	public static function closedGates(): array
	{
		return [
			'DNSBL off'                      => [['GATE_DNSBL' => '']],
			'DNS proxy toggle off'           => [['GATE_PROXY' => '']],
			'Resolver not moved (no snapshot)' => [['GATE_SAVED' => '']],
		];
	}

	/** @param array<string,string> $gates */
	#[DataProvider('closedGates')]
	public function testStartDoesNothingUnlessDnsblProxyAndMovedResolverAreAllSet(array $gates): void
	{
		// Given a proxy that is running and a generated script whose gate has one condition closed
		$this->moveResolver();
		$this->generate();
		$this->arrange($gates, '2', '1', TRUE);

		// When it is started (boot)
		[$status, $output] = $this->rc('start');

		// Then it neither stops nor launches anything
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(TRUE), 'a closed gate means no daemon, no signal, no log');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	public function testStartWithNoListenAddressLogsAnErrorAndFailsWithoutLaunching(): void
	{
		// Given a saved Resolver whose only interface has no address at the last apply
		$this->moveResolver(FALSE, 'opt9', [], []);
		$this->generate();
		$this->arrange();

		// When the service is started
		[$status, $output] = $this->rc('start');

		// Then the failure is logged and the proxy is never launched listening nowhere
		$this->assertNotSame(0, $status, "a proxy with no address must fail its start: {$output}");
		$this->assertNotContains('launch', $this->events());
		$this->assertContains('log', $this->events(TRUE));
		$this->assertStringContainsString('listen', (string) file_get_contents("{$this->dir}/state/logger"));
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
			'start'   => ['start', $cycle],
			// pfSense's default rc_restart is rc_stop then rc_start, and rc_start stops again.
			'restart' => ['restart', [...$cycle, ...$cycle]],
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

	public function testStartReplacesARunningProxyOnlyAfterItExited(): void
	{
		$this->moveResolver();
		$this->generate();
		$this->arrange([], '2', '1', TRUE);

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events(), 'launch only after the old pair exited');
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
			. "--upstream 127.0.0.1:5353 --module-dir /var/unbound --user unbound" . ($dot ? ' --dot --pfsense-config /cf/conf/config.xml' : '') . ' </dev/null',
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
			"--doh-listen '192.0.2.1'", "--doh-listen '2001:db8::1'", "--doh-listen '127.0.0.1'", "--doh-listen '::1'",
			"--doh-port '8443'", "--doh-trusted '192.0.2.10/32'",
			"--doq-listen '192.0.2.1'", "--doq-listen '2001:db8::1'", "--doq-listen '127.0.0.1'", "--doq-listen '::1'",
			"--doq-port '8853'",
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
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doq-listen', '192.0.2.1', ...self::loopbackListen('doq'), '--doq-port', '8853',
			]),
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
			$this->gatewayArgv($gateway, ['192.0.2.1'], FALSE, [
				'--doh-listen', '192.0.2.1', ...self::loopbackListen('doh'), '--doh-port', '4443',
			]),
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
