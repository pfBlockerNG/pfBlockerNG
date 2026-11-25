<?php

declare(strict_types=1);

require_once __DIR__ . '/CoreRcSandboxTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3841 -- pfb-core, the Core API daemon (go/pfb_core), runs as the supervised rc service pfb_core.
 *
 * Function under test: pfb_core_service() -- writes /usr/local/etc/rc.d/pfb_core.sh. Intent pinned here:
 *   - start runs this machine's pfb-core (bin/freebsd-amd64 or bin/freebsd-arm64 under the package's core directory) under
 *     daemon(8): restarted when it exits, its output in the package log, its socket the one PHP calls, stdio detached;
 *   - a package that ships no pfb-core for this machine starts nothing and is not a failure; an unknown machine is;
 *   - a start over a Core that serves keeps it, also a supervisor that has not set its process title yet; a restart stops first;
 *   - starts are serialized by a lock (a start that cannot get it in 20 s launches nothing) and return once the supervisor is confirmed;
 *     a daemon(8) that fails is a failed start;
 *   - stop signals only the processes its own pidfiles name while their command line is pfb-core's, TERM first, KILL at 5 s; a Core
 *     still running 7 s after TERM fails the stop (pidfiles kept), and a start or restart over it launches nothing;
 *   - issue #3924: Core reads and writes its settings through the adapter script the daemon line names (--settings-backend-cmd),
 *     the start pushes nothing, and generating the service retires the settings store and push records of the earlier model.
 *
 * The script runs in Core's rc sandbox (CoreRcSandboxTrait), which also holds the lock, stop, survivor and start-confirmation rows
 * this service shares with the CrowdSec bouncer's.
 */
#[CoversFunction('pfb_core_service')]
final class PfbCoreServiceTest extends TestCase
{
	use CoreRcSandboxTrait;

	/** Issue #3975: the folders a file:// feed may sit directly in (pfb_filter()'s local-path rule), as Core's --feed-local-dir flags, without the trailing slash. */
	private const LOCAL_DIRS = ['/var/db/pfblockerng', '/var/db/pfblockerng/deny', '/var/db/pfblockerng/permit', '/var/db/pfblockerng/match',
		'/var/db/pfblockerng/native', '/var/db/pfblockerng/original', '/var/db/pfblockerng/dnsbl', '/var/db/pfblockerng/dnsblorig', '/var/db/pfblockerng/ET',
		'/var/db/pfblockerng/ut1', '/var/db/pfblockerng/shallalist', '/usr/local/www', '/usr/local/share/GeoIP', '/usr/local/share/GeoIP/cc'];
	/** The list scripts' folders in search order (pfb_resolve_list_script()), Core's --script-dir flags. */
	private const SCRIPT_DIRS = ['/usr/local/pkg/pfblockerng/list_scripts', '/usr/local/pkg/pfblockerng'];
	private const RSYNC = '/usr/local/bin/rsync';
	/** The cURL user agent the package sends, with the unique id of the doubled pfSense. */
	private const USER_AGENT = 'pfSense/pfBlockerNG cURL download agent-phpunit-0000000000000000';

	protected function setUp(): void
	{
		$this->sandboxUp(['daemon', 'logger', 'lockf', 'uname', 'pgrep', 'pkill', 'sleep', 'id'],
			['log', 'core/bin/freebsd-amd64', 'core/bin/freebsd-arm64'], [
				'core_socket'         => 'run/pfb_core/api.sock',
				'core_state'          => 'db/pfb_core',
				'dbdir'               => 'dbdir',
				'logdir'              => 'log',
				'schedule_state_dir'  => 'etc',
				'core_log'            => 'log/core.log',
				'core_pidfile'        => 'run/pfb_core.pid',
				'core_daemon_pidfile' => 'run/pfb_core_daemon.pid',
				'core_lockfile'       => 'run/pfb_core.lock',
			]);
	}

	protected function tearDown(): void
	{
		$this->sandboxDown();
	}

	private static function rcService(): array
	{
		return ['tag' => 'pfb_core', 'pidfile' => 'core_pidfile', 'daemon_pidfile' => 'core_daemon_pidfile', 'lockfile' => 'core_lockfile',
			'lock_var' => 'PFB_CORE_START_LOCKED', 'started' => 'Core API started', 'lock_held' => 'held the start lock'];
	}

	private function childArgs(string $binary): string
	{
		return "{$binary} --socket {$GLOBALS['pfb']['core_socket']}";
	}

	private function binary(): string
	{
		return "{$this->dir}/core/bin/freebsd-amd64/pfb-core";
	}

	private function preLaunchEvents(): array
	{
		return [];
	}

	private function arrangeInstalled(bool $running = FALSE, array $scenario = [], ?string $child = NULL): void
	{
		$this->install('freebsd-amd64');
		$this->arrange(running: $running, scenario: $scenario, child: $child);
	}

	/** The installed pfb-core of one architecture: an executable file is all the start looks at. */
	private function install(string $target, int $mode = 0755): string
	{
		$binary = "{$this->dir}/core/bin/{$target}/pfb-core";
		file_put_contents($binary, "not run by the test\n");
		chmod($binary, $mode);
		return $binary;
	}

	/**
	 * Generate the script, point its commands at the doubles, and seed the scenario.
	 *
	 * @param array<string, string> $scenario overrides of the double's variables (sandboxArrange())
	 */
	private function arrange(string $machine = 'amd64', bool $running = FALSE, array $scenario = [], ?string $child = NULL): void
	{
		pfb_core_service("{$this->dir}/core");
		$text = @file_get_contents("{$this->dir}/rc/pfb_core.sh");
		$this->assertIsString($text, 'pfb_core_service() wrote no rc script');
		// The settings adapter and update scripts, which Core runs, the host's zone file, which it reads, and the feed phase's folders,
		// scripts and rsync (issue #3975), which it is told, are the host paths an argument may name
		$named = ['/usr/local/pkg/pfblockerng/pfb_core_settings.sh', '/usr/local/pkg/pfblockerng/pfb_core_update.sh', '/usr/local/pkg/pfblockerng/pfb_core_maintenance.sh', '/usr/local/pkg/pfblockerng/pfb_core_metrics.sh', '/usr/local/pkg/pfblockerng/pfb_core_counters.sh', '--zoneinfo /etc/localtime', self::RSYNC,
			...self::LOCAL_DIRS, ...self::SCRIPT_DIRS];
		$this->sandboxArrange($text, $named, $scenario + ['MACHINE' => $machine, 'TERM_AFTER' => '2'], $running, $child);
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function machines(): array
	{
		return ['amd64' => ['amd64', 'freebsd-amd64'], 'aarch64' => ['aarch64', 'freebsd-arm64'], 'arm64' => ['arm64', 'freebsd-arm64']];
	}

	#[DataProvider('machines')]
	public function testStartRunsThisMachinesBinaryUnderDaemonWithTheSocketStateLogAndSettingsAdapter(string $machine, string $target): void
	{
		// Given both architectures' pfb-core are installed
		$this->install('freebsd-amd64');
		$this->install('freebsd-arm64');
		$this->arrange($machine);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then daemon(8) supervises this machine's binary, restarting it, with the package log, the API socket, Core's state directory, the settings adapter, the update program and the host's zone (issue #3941: the scheduler reads local time)
		$this->assertSame(0, $status, $out);
		$this->assertSame([
			'-r', '-R', '5', '-t', 'pfb_core',
			'-P', $GLOBALS['pfb']['core_daemon_pidfile'], '-p', $GLOBALS['pfb']['core_pidfile'], '-o', $GLOBALS['pfb']['core_log'],
			"{$this->dir}/core/bin/{$target}/pfb-core", '--socket', $GLOBALS['pfb']['core_socket'],
			'--state-dir', $GLOBALS['pfb']['core_state'],
			'--settings-backend-cmd', '/usr/local/pkg/pfblockerng/pfb_core_settings.sh',
			'--update-cmd', '/usr/local/pkg/pfblockerng/pfb_core_update.sh',
			'--maintenance-cmd', '/usr/local/pkg/pfblockerng/pfb_core_maintenance.sh',
			'--metrics-cmd', '/usr/local/pkg/pfblockerng/pfb_core_metrics.sh',
			'--counters-cmd', '/usr/local/pkg/pfblockerng/pfb_core_counters.sh',
			'--zoneinfo', '/etc/localtime',
			'--client-uid', '59', '--socket-group', '60',
			...$this->loopFlags(),
			...$this->feedFlags(),
		], $this->lines('daemon.argv'));
		$this->assertSame(['0 1 2 '], $this->lines('fds'), 'the daemon inherited a descriptor of the caller (stdio must be /dev/null)');
	}

	/** Issue #4250: an id that is no number is not passed on: Core would refuse its flags and daemon(8) restart it every 5 s. */
	public function testAnUnboundIdThatIsNoNumberStartsCoreWithNoClient(): void
	{
		// Given an id(1) that succeeds but prints no number
		$this->arrangeInstalled(scenario: ['UNBOUND_UID' => 'unbound', 'UNBOUND_GID' => '']);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then Core starts with no client and no socket group
		$this->assertSame(0, $status, $out);
		$argv = $this->lines('daemon.argv');
		$this->assertContains('--socket', $argv, 'Core was not started');
		$this->assertNotContains('--client-uid', $argv);
		$this->assertNotContains('--socket-group', $argv);
	}

	/** Issue #4250: a system without the unbound user still starts Core, with no client. */
	public function testWithoutAnUnboundUserCoreStartsAndAdmitsNoClient(): void
	{
		// Given a system with no unbound user
		$this->arrangeInstalled(scenario: ['UNBOUND_UID' => '']);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then Core starts, and is given no client and no socket group
		$this->assertSame(0, $status, $out);
		$argv = $this->lines('daemon.argv');
		$this->assertContains('--socket', $argv, 'Core was not started');
		$this->assertNotContains('--client-uid', $argv);
		$this->assertNotContains('--socket-group', $argv);
	}

	public function testMaintenanceProducerPreservesQuotedRuntimePathsAndSupervisorIdentity(): void
	{
		$GLOBALS['pfb']['core_socket'] = "{$this->dir}/run/api space's.sock";
		$GLOBALS['pfb']['core_state'] = "{$this->dir}/state space's";
		$GLOBALS['pfb']['core_log'] = "{$this->dir}/log/core space's.log";
		$this->arrangeInstalled();
		[$status, $out] = $this->rc('start');
		$this->assertSame(0, $status, $out);
		$args = $this->lines('daemon.argv');
		$this->assertSame(['-r', '-R', '5', '-t', 'pfb_core'], array_slice($args, 0, 5));
		foreach (['--socket' => 'core_socket', '--state-dir' => 'core_state', '-o' => 'core_log'] as $flag => $key) {
			$idx = array_search($flag, $args, TRUE);
			$this->assertNotFalse($idx, $flag);
			$this->assertSame($GLOBALS['pfb'][$key], $args[$idx + 1], $flag . ' must remain one argument');
		}
		$idx = array_search('--maintenance-cmd', $args, TRUE);
		$this->assertNotFalse($idx, 'the real producer must name the maintenance program');
		$this->assertSame('/usr/local/pkg/pfblockerng/pfb_core_maintenance.sh', $args[$idx + 1]);
		foreach (['--metrics-cmd' => 'pfb_core_metrics.sh', '--counters-cmd' => 'pfb_core_counters.sh'] as $flag => $script) {
			$idx = array_search($flag, $args, TRUE);
			$this->assertNotFalse($idx, "the real producer must name {$flag}");
			$this->assertSame("/usr/local/pkg/pfblockerng/{$script}", $args[$idx + 1]);
		}
	}

	public function testTheServiceFileNamesTheMetricsAndCountersPrograms(): void
	{
		$this->install('freebsd-amd64');

		pfb_core_service("{$this->dir}/core");

		$text = (string) file_get_contents("{$this->dir}/rc/pfb_core.sh");
		$this->assertStringContainsString("--maintenance-cmd '/usr/local/pkg/pfblockerng/pfb_core_maintenance.sh' --metrics-cmd '/usr/local/pkg/pfblockerng/pfb_core_metrics.sh' --counters-cmd '/usr/local/pkg/pfblockerng/pfb_core_counters.sh' --zoneinfo", $text);
	}

	/**
	 * Issue #4038 (9k): the Core Updater loop's path flags, passed with the switch off: no --update-loop, so a real Update still runs
	 * the update program, and no --main-log, which Core refuses without the switch.
	 *
	 * @return list<string>
	 */
	private function loopFlags(): array
	{
		$pfb = $GLOBALS['pfb'];
		return ['--resource-dir', "{$pfb['dbdir']}/store", '--hook-dir', '/usr/local/pkg/pfblockerng/hooks', '--python-wrapper', PFB_PYTHON_WRAPPER,
			'--db-dir', $pfb['dbdir'], '--geoip-dir', '/usr/local/share/GeoIP', '--cc-dir', '/usr/local/share/GeoIP/cc', '--log-dir', $pfb['logdir'],
			'--pkg-dir', '/usr/local/pkg/pfblockerng', '--asn-table', '/usr/local/www/pfblockerng/pfblockerng_asn.txt'];
	}

	/** @param list<string> $dirs @return list<string> the flags of the feed phase (issue #3975) Core is started with */
	private function feedFlags(array $dirs = self::LOCAL_DIRS, string $userAgent = self::USER_AGENT): array
	{
		$flags = [];
		foreach ($dirs as $dir) {
			array_push($flags, '--feed-local-dir', $dir);
		}
		foreach (self::SCRIPT_DIRS as $dir) {
			array_push($flags, '--script-dir', $dir);
		}
		return [...$flags, '--rsync-bin', self::RSYNC, '--user-agent', $userAgent];
	}

	public function testStartTellsCoreTheFolderOfAFileFeedTheScriptFoldersRsyncAndTheUserAgentAndNamesTheDbdirByItsRealPath(): void
	{
		// Given the package's database folder is a link to the real folder (the rc script must name what realpath() resolves, as pfb_filter() compares)
		$this->assertTrue(mkdir("{$this->dir}/real_db", 0700));
		$this->assertTrue(symlink("{$this->dir}/real_db", "{$this->dir}/dbdir"));
		$this->arrangeInstalled();

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then Core is told the fixed folders, then the real database folder, the two script folders, rsync and the user agent
		$this->assertSame(0, $status, $out);
		$argv = $this->lines('daemon.argv');
		$first = array_search('--feed-local-dir', $argv, TRUE);
		$this->assertIsInt($first, 'the daemon was given no --feed-local-dir: ' . implode(' ', $argv));
		$this->assertSame($this->feedFlags([...self::LOCAL_DIRS, (string) realpath("{$this->dir}/real_db")]), array_slice($argv, $first),
			'the feed flags: every value its own argument');
	}

	public function testTheUserAgentCoreIsToldHasNoLineBreak(): void
	{
		// Given a unique id the platform wrote with a trailing newline (Core refuses a user agent with a line break, so Core would not start)
		$GLOBALS['pfb']['curl_defaults'][CURLOPT_USERAGENT] = self::USER_AGENT . "\n";
		$this->arrangeInstalled();

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the user agent is the package's, whole, on one line: the daemon double writes each argument and a newline, so one that held a
		// line break would leave a blank line that lines() skips; the raw file must end with the flag and the agent alone
		$this->assertSame(0, $status, $out);
		$raw = (string) file_get_contents("{$this->dir}/state/daemon.argv");
		$this->assertStringEndsWith("\n--user-agent\n" . self::USER_AGENT . "\n", $raw, 'the user agent argument holds a line break');
	}

	public function testStartWithNoBinaryForThisMachineStartsNothingAndSaysSo(): void
	{
		// Given only the other architecture's pfb-core, or one that is not executable
		$this->install('freebsd-arm64');
		$this->install('freebsd-amd64', 0644);
		$this->arrange('amd64');

		[$status, $out] = $this->rc('start');

		$this->assertSame(0, $status, "a package without a usable pfb-core is not a failed start: {$out}");
		$this->assertSame([], $this->lines('events'), 'something was launched or signalled');
		$this->assertStringContainsString('not installed', implode("\n", $this->lines('logger')));
	}

	public function testStartOnAnUnknownMachineFails(): void
	{
		$this->install('freebsd-amd64');
		$this->install('freebsd-arm64');
		$this->arrange('riscv64');

		[$status, $out] = $this->rc('start');

		$this->assertSame(1, $status, $out);
		$this->assertSame([], $this->lines('events'));
		$this->assertStringContainsString('riscv64', implode("\n", $this->lines('logger')));
	}

	public function testStopNeverSignalsAnIndependentUpdateWorkerNamedByAStaleChildPidfile(): void
	{
		$this->arrangeInstalled(running: TRUE);
		$worker = "{$this->dir}/core/bin/freebsd-amd64/pfb-core --update-worker {$this->dir}/db/pfb_core/update.log";
		file_put_contents("{$this->dir}/state/procs", "1001|/usr/sbin/cron|\n1002|{$worker}|\n");

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'a stale controller pidfile signalled the independent worker');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	public function testStartPushesNothingToCoreAndNamesNoPhpVerb(): void
	{
		// Given a Core whose socket exists, as soon as the service starts
		$this->arrangeInstalled();
		$this->assertTrue(mkdir(dirname($GLOBALS['pfb']['core_socket']), 0700, TRUE));
		$server = stream_socket_server('unix://' . $GLOBALS['pfb']['core_socket'], $errno, $errstr);
		$this->assertNotFalse($server, "socket: {$errstr}");
		$text = (string) file_get_contents("{$this->dir}/rc/pfb_core.sh");

		try {
			// When the service starts
			[$status, $out] = $this->rc('start');
		} finally {
			fclose($server);
		}

		// Then it launched the daemon and nothing else: Core reads the settings itself, through the adapter
		$this->assertSame(0, $status, $out);
		$this->assertSame(['launch'], $this->lines('events'));
		$this->assertStringNotContainsString('core_push', $text);
		$this->assertStringNotContainsString('pfblockerng.inc', $text, 'the rc script runs no PHP verb');
	}

	public function testGeneratingTheServiceRetiresTheSettingsStoreAndPushRecordsOfTheEarlierModel(): void
	{
		// Given Core's state directory with the old store, and the old push records
		$state = $GLOBALS['pfb']['core_state'];
		$this->assertTrue(mkdir($state, 0700, TRUE));
		$this->assertTrue(mkdir($GLOBALS['pfb']['dbdir'], 0700, TRUE));
		$old = [
			"{$state}/settings.json", "{$state}/settings.json.tmp", "{$state}/settings.lock",
			"{$GLOBALS['pfb']['dbdir']}/core_pushed", "{$GLOBALS['pfb']['dbdir']}/core_push_failed",
		];
		$keep = ["{$state}/core.lock", "{$state}/other.dat", "{$GLOBALS['pfb']['dbdir']}/core_settings_failed"];
		foreach ([...$old, ...$keep] as $file) {
			$this->assertNotFalse(file_put_contents($file, 'x'), "fixture {$file}");
		}

		// When the service is generated (every install and upgrade does)
		pfb_core_service("{$this->dir}/core");

		// Then the old files are gone and nothing else is
		foreach ($old as $file) {
			$this->assertFileDoesNotExist($file);
		}
		foreach ($keep as $file) {
			$this->assertFileExists($file);
		}
	}

	public function testGeneratingTheServiceRetiresThePhpSchedulerStateAndKeepsTheOutpostsLedgerEntries(): void
	{
		// Given the PHP scheduler's state file (and its lock), and a due ledger holding its schedule entries beside the Outpost's own
		$stateDir = $GLOBALS['pfb']['schedule_state_dir'];
		$this->assertTrue(mkdir($stateDir, 0700, TRUE));
		$this->assertTrue(is_dir($GLOBALS['pfb']['dbdir']) || mkdir($GLOBALS['pfb']['dbdir'], 0700, TRUE));
		file_put_contents("{$stateDir}/pfb_schedule_state.json", '{"schema":1,"items":{}}');
		file_put_contents("{$stateDir}/pfb_schedule_state.json.lock", '');
		file_put_contents("{$stateDir}/pfb_schedule_dispatch.lock", '');
		$entry = static fn (array $more = []): array => ['last_run' => 5, 'next_due' => 9, 'jitter' => 0] + $more;
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/pfb_due_ledger.json", json_encode(
			['_meta' => ['schema' => 1, 'config_hash' => str_repeat('a', 64)]] + [
				'cron' => $entry(['pending_apply' => TRUE]), 'extra:dcc' => $entry(), 'extra:bl' => $entry(),
				'ss_refresh' => $entry(), 'apply_reconcile' => $entry(),
			]
		));

		// When the service is generated (every install and upgrade does)
		pfb_core_service("{$this->dir}/core");

		// Then the state file is gone, the lock of the Outpost's own entry points stays, and the ledger keeps only the Outpost's
		$this->assertFileDoesNotExist("{$stateDir}/pfb_schedule_state.json");
		$this->assertFileDoesNotExist("{$stateDir}/pfb_schedule_state.json.lock");
		$this->assertFileExists("{$stateDir}/pfb_schedule_dispatch.lock");
		$ledger = json_decode((string) file_get_contents("{$GLOBALS['pfb']['dbdir']}/pfb_due_ledger.json"), TRUE);
		$this->assertSame(['cron', 'ss_refresh', 'apply_reconcile'], array_keys($ledger));
		$this->assertSame(['last_run' => 0, 'next_due' => 0, 'jitter' => 0, 'pending_apply' => TRUE], $ledger['cron'], 'the pending apply flag is the Outpost\'s');
		$this->assertSame($entry(), $ledger['ss_refresh']);
		$this->assertSame($entry(), $ledger['apply_reconcile']);
	}

	public function testRetiringAnUnflaggedCronEntryRemovesItAndRetiringTwiceChangesNothing(): void
	{
		$this->assertTrue(is_dir($GLOBALS['pfb']['dbdir']) || mkdir($GLOBALS['pfb']['dbdir'], 0700, TRUE));
		$this->assertTrue(is_dir($GLOBALS['pfb']['schedule_state_dir']) || mkdir($GLOBALS['pfb']['schedule_state_dir'], 0700, TRUE));
		$entry = ['last_run' => 5, 'next_due' => 9, 'jitter' => 0];
		$this->assertTrue(pfb_due_ledger_write_entry('cron', $entry, $GLOBALS['pfb']['dbdir']));
		$this->assertTrue(pfb_due_ledger_write_entry('ss_refresh', $entry, $GLOBALS['pfb']['dbdir']));

		pfb_core_service("{$this->dir}/core");
		$once = (string) file_get_contents("{$GLOBALS['pfb']['dbdir']}/pfb_due_ledger.json");
		pfb_core_service("{$this->dir}/core");

		$this->assertSame(['ss_refresh'], array_keys(json_decode($once, TRUE)));
		$this->assertSame($once, (string) file_get_contents("{$GLOBALS['pfb']['dbdir']}/pfb_due_ledger.json"), 'a ledger with nothing left to retire is not rewritten');
	}

	public function testTheServiceIsRegisteredWithPfSense(): void
	{
		$xml = (string) file_get_contents(__DIR__ . '/../../src/usr/local/pkg/pfblockerng.xml');
		$this->assertMatchesRegularExpression(
			'~<service>\s*<name>pfb_core</name>\s*<rcfile>pfb_core\.sh</rcfile>\s*'
			. '<custom_php_service_status_command>isvalidpid\(\'/var/run/pfb_core\.pid\'\)</custom_php_service_status_command>\s*'
			. '<description>[^<]+</description>\s*</service>~',
			$xml
		);
	}
}
