<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3713 — on a RAM-disk /var the boot restores IP aliastables and the DNSBL cache from two archives. A missing
 * archive must be written by every pass ('conf') and by the rc stop that runs before a clean reboot, and never
 * rewritten when present. A disk /var is untouched.
 */
#[CoversFunction('pfb_aliastables')]
#[CoversFunction('pfb_dnsbl_cache')]
#[CoversFunction('pfb_filter_service')]
#[CoversFunction('pfb_dnsbl_service')]
final class RamDiskArchiveTest extends TestCase
{
	/** Every command the rc stop bodies run, as one script that picks its role from $0. */
	private const DOUBLE = <<<'SH'
		#!/bin/sh
		# One script under every command name the rc stop bodies use; $0 picks the role.
		S=@STATE@
		. "$S/scenario"
		case "${0##*/}" in
		read_xml_tag.sh) [ "$1 $2" = 'boolean system/use_mfs_tmpvar' ] || exit 2; echo "$MFS" ;;
		timeout) echo "$*" >> "$S/timeout.args"; shift 5; exec "$@" ;;
		php|pfblockerng.sh) echo "${0##*/} $*" >> "$S/calls"; exit "$SAVE_RC" ;;
		pgrep) exit 1 ;;
		ps|grep|awk|logger|kill|killall|sleep) : ;;
		*) exit 2 ;;
		esac
		SH;

	/** The `$pfb['script']` stand-in: the SHIPPED helpers, sourced with PFB_SOURCED=1 and given temp paths only. */
	private const SCRIPT = <<<'SH'
		#!/bin/sh
		PFB_SOURCED=1
		. @SH@
		pathtar=@TAR@
		case "$1" in
		pfb_compress) shift; pfb_archive_compress "$@" ;;
		dnsbl_cache)
			pfbchroot=@UNBOUND@
			pfbpkgdir=@PKG@
			pfbdb=@DB@
			dnsblarchive=@DNSBL@
			dnsbl_cache "$2" 2>/dev/null
			;;
		*) exit 2 ;;
		esac
		SH;

	/** Host executables the generated stop bodies name; each one is redirected to its command double. */
	private const HOST_BINARIES = [
		'/usr/local/sbin/read_xml_tag.sh',
		'/usr/bin/timeout',
		'/usr/bin/logger',
		'/bin/ps',
		'/usr/bin/grep',
		'/usr/bin/awk',
		'/bin/kill',
		'/bin/pgrep',
		'/usr/bin/killall',
		'/bin/sleep',
	];

	private string $repo;

	private string $dir = '';

	private string $shell = '';

	private string $aliasBase = '';

	private string $dnsblBase = '';

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_rcfiles', 'pfb_test_write_config_calls'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->repo = dirname(__DIR__, 2);
		$this->dir = sys_get_temp_dir() . '/pfb_ramdisk_archive_' . bin2hex(random_bytes(6));
		foreach (['aliastables', 'unbound', 'db', 'etc', 'pkg', 'bin', 'state'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0777, TRUE), "sandbox mkdir failed: {$sub}");
		}
		$this->aliasBase = "{$this->dir}/etc/aliastables.tar";
		$this->dnsblBase = "{$this->dir}/etc/pfb_dnsbl_cache.tar";

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'aliasdir'           => "{$this->dir}/aliastables",
			'dnsbl_file'         => "{$this->dir}/unbound/pfb_dnsbl",
			'dbdir'              => "{$this->dir}/db",
			'aliasarchive'       => $this->aliasBase,
			'dnsblarchive'       => $this->dnsblBase,
			'unbound_py_sources' => "{$this->dir}/unbound/pfb_py_sources.json",
			'script'             => "{$this->dir}/script.sh",
			'logdir'             => $this->dir,
			'log'                => "{$this->dir}/pfb.log",
			'errlog'             => "{$this->dir}/pfb.err",
			'enable'             => PfbToggle::On,
			'dnsbl'              => PfbToggle::On,
			'pfb_dns'            => PfbToggle::Off,
			'unbound_state'      => PfbToggle::On,
		]);

		$this->writeScript();
		$this->writeExecutable("{$this->dir}/double.sh", str_replace('@STATE@', escapeshellarg("{$this->dir}/state"), self::DOUBLE) . "\n");
		foreach (['read_xml_tag.sh', 'timeout', 'php', 'pfblockerng.sh', 'pgrep', 'ps', 'grep', 'awk', 'logger', 'kill', 'killall', 'sleep'] as $name) {
			$this->assertTrue(symlink("{$this->dir}/double.sh", "{$this->dir}/bin/{$name}"), "double link failed: {$name}");
		}

		$dash = trim((string) shell_exec('command -v dash 2>/dev/null'));
		$this->shell = $dash !== '' ? $dash : '/bin/sh';
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
		rmdir_recursive($this->dir);
	}

	private function writeScript(): void
	{
		$body = strtr(self::SCRIPT, [
			'@SH@'      => escapeshellarg("{$this->repo}/src/usr/local/pkg/pfblockerng/pfblockerng.sh"),
			'@TAR@'     => escapeshellarg(pfb_test_tar()),
			'@UNBOUND@' => escapeshellarg("{$this->dir}/unbound"),
			'@PKG@'     => escapeshellarg("{$this->dir}/pkg"),
			'@DB@'      => escapeshellarg("{$this->dir}/db"),
			'@DNSBL@'   => escapeshellarg($this->dnsblBase),
		]);
		$this->writeExecutable("{$this->dir}/script.sh", $body);
	}

	private function writeExecutable(string $path, string $body): void
	{
		$this->assertNotFalse(file_put_contents($path, $body), "failed to write {$path}");
		$this->assertTrue(chmod($path, 0755), "failed to make {$path} executable");
	}

	private function ramDisk(): void
	{
		config_set_path('system/use_mfs_tmpvar', '');
	}

	private function aliasFile(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->dir}/aliastables/pfB_Test_v4.txt", "192.0.2.1\n"), 'failed to write the IP aliastable');
	}

	private function manifest(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->dir}/unbound/pfb_py_sources.json", '{"feeds":[]}'), 'failed to write the DNSBL manifest');
	}

	/** Write `{$base}.{$ext}` with known bytes and an old mtime, so a rewrite is visible. */
	private function existing(string $base, string $ext): string
	{
		$file = "{$base}.{$ext}";
		$this->assertNotFalse(file_put_contents($file, 'EXISTING'), "failed to write {$file}");
		$this->assertTrue(touch($file, 1000000000), "failed to date {$file}");
		return $file;
	}

	/** The archive a pass left for this base: `.zst` first, then `.bz2`, or NULL when neither exists. */
	private function archive(string $base): ?string
	{
		if (is_file("{$base}.zst")) {
			return "{$base}.zst";
		}
		if (is_file("{$base}.bz2")) {
			return "{$base}.bz2";
		}
		return NULL;
	}

	/** @return list<string> member basenames of an archive, listed by the host bsdtar */
	private function members(string $archive): array
	{
		$listing = (string) shell_exec(escapeshellarg(pfb_test_tar()) . ' -tf ' . escapeshellarg($archive) . ' 2>/dev/null');
		return array_map('basename', array_values(array_filter(
			array_map('trim', explode("\n", $listing)),
			static fn (string $line): bool => $line !== ''
		)));
	}

	/** Build the rc script the real generator writes; its stop body is pointed at the command doubles. */
	private function arrangeRc(string $file, callable $writer, bool $mfs, int $saveRc = 0): void
	{
		$state = "{$this->dir}/state";
		file_put_contents("{$state}/scenario", 'MFS=' . ($mfs ? 'true' : 'false') . "\nSAVE_RC={$saveRc}\n");
		file_put_contents("{$state}/calls", '');
		file_put_contents("{$state}/timeout.args", '');
		$GLOBALS['pfb']['php'] = "{$this->dir}/bin/php";
		$GLOBALS['pfb']['script'] = "{$this->dir}/bin/pfblockerng.sh";

		$GLOBALS['pfb_test_rcfiles'] = [];
		$writer();
		$rc = $GLOBALS['pfb_test_rcfiles'][$file] ?? NULL;
		$this->assertIsArray($rc, "write_rcfile() never produced {$file}");

		$map = ['/usr/local/sbin/clog_pfb' => "{$this->dir}/absent/clog_pfb"];
		foreach (self::HOST_BINARIES as $path) {
			$map[$path] = "{$this->dir}/bin/" . basename($path);
		}
		$stop = strtr((string) $rc['stop'], $map);
		$this->assertDoesNotMatchRegularExpression(
			'~(?<![\w.\-/])/(?:usr/(?:local/)?)?s?bin/~',
			$stop,
			'stop body still names a host binary'
		);

		$restart = (string) ($rc['restart'] ?? "\trc_stop\n\trc_start\n");
		// Same wrapper as pfSense service-utils.inc write_rcfile(); the start body is never run here.
		$script = "#!/bin/sh\n\nrc_start() {\n\t{$rc['start']}\n}\n\nrc_stop() {\n\t{$stop}\n}\n\n"
			. "rc_restart() {\n{$restart}\n}\n\n"
			. "case \$1 in\n\tstart)\n\t\trc_start\n\t\t;;\n\tstop)\n\t\trc_stop\n\t\t;;\n\trestart)\n\t\trc_restart\n\t\t;;\nesac\n\n";
		$this->assertNotFalse(file_put_contents("{$this->dir}/rc.sh", $script), 'failed to write rc.sh');
	}

	/** Run `rc.sh stop` under dash and the host timeout(1) watchdog. @return array{0: int, 1: string} */
	private function rcStop(): array
	{
		return $this->runWatched($GLOBALS['pfb_test_timeout'], '-k', '2', '20', $this->shell, "{$this->dir}/rc.sh", 'stop');
	}

	/**
	 * Run a command with pipes (never /dev/null) on fds 0/1/2.
	 *
	 * @return array{0: int, 1: string} exit status and combined stdout/stderr
	 */
	private function runWatched(string ...$command): array
	{
		$proc = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
		$this->assertIsResource($proc, 'proc_open failed');
		fclose($pipes[0]);
		$output = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		return [proc_close($proc), $output];
	}

	/** @return list<string> lines of a state file the doubles appended to */
	private function stateLines(string $file): array
	{
		return file("{$this->dir}/state/{$file}", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	public static function extProvider(): array
	{
		return ['zst' => ['zst'], 'bz2' => ['bz2']];
	}

	public static function noManifestProvider(): array
	{
		return [
			'DNSBL on, never built' => [TRUE, FALSE],
			'pfB-DNS only' => [FALSE, TRUE],
		];
	}

	public function testAnUnchangedPassWritesTheMissingAliastablesArchive(): void
	{
		// Given a RAM-disk /var with an IP aliastable file and no archive yet
		$this->ramDisk();
		$this->aliasFile();
		$this->assertNull($this->archive($this->aliasBase), 'precondition: no aliastables archive');

		// When the every-pass 'conf' step runs with no list changed
		pfb_aliastables('conf');

		// Then the archive is written and holds the IP aliastable
		$archive = $this->archive($this->aliasBase);
		$this->assertNotNull($archive, 'the missing aliastables archive is written on an unchanged pass');
		$this->assertContains('pfB_Test_v4.txt', $this->members($archive), 'the aliastables archive lists the IP table');
	}

	#[DataProvider('extProvider')]
	public function testAPresentAliastablesArchiveIsNotRewritten(string $ext): void
	{
		// Given a RAM-disk /var, an IP aliastable file, and an archive already present as .{$ext}
		$this->ramDisk();
		$this->aliasFile();
		$file = $this->existing($this->aliasBase, $ext);

		// When the every-pass 'conf' step runs
		pfb_aliastables('conf');

		// Then the present archive keeps its bytes and mtime, and no archive in the other codec appears
		clearstatcache();
		$this->assertSame('EXISTING', file_get_contents($file), "the present .{$ext} archive keeps its bytes");
		$this->assertSame(1000000000, filemtime($file), "the present .{$ext} archive keeps its mtime");
		$other = $ext === 'zst' ? "{$this->aliasBase}.bz2" : "{$this->aliasBase}.zst";
		$this->assertFileDoesNotExist($other, 'no archive in the other codec is written');
	}

	public function testADiskVarNeverWritesTheAliastablesArchive(): void
	{
		// Given a disk /var (no RAM-disk flag) with an IP aliastable file
		$this->aliasFile();

		// When the 'conf' step runs
		pfb_aliastables('conf');

		// Then no aliastables archive is written
		$this->assertNull($this->archive($this->aliasBase), 'a disk /var writes no aliastables archive');
	}

	public function testAnUnchangedPassWritesTheMissingDnsblArchive(): void
	{
		// Given a RAM-disk /var with a DNSBL manifest and no archive yet
		$this->ramDisk();
		$this->manifest();
		$this->assertNull($this->archive($this->dnsblBase), 'precondition: no DNSBL archive');

		// When the every-pass 'conf' step runs with no list changed
		pfb_dnsbl_cache('conf');

		// Then the archive is written and holds the manifest
		$archive = $this->archive($this->dnsblBase);
		$this->assertNotNull($archive, 'the missing DNSBL archive is written on an unchanged pass');
		$this->assertContains('pfb_py_sources.json', $this->members($archive), 'the DNSBL archive lists the manifest');
	}

	#[DataProvider('extProvider')]
	public function testAPresentDnsblArchiveIsNotRewritten(string $ext): void
	{
		// Given a RAM-disk /var, a DNSBL manifest, and an archive already present as .{$ext}
		$this->ramDisk();
		$this->manifest();
		$file = $this->existing($this->dnsblBase, $ext);

		// When the every-pass 'conf' step runs
		pfb_dnsbl_cache('conf');

		// Then the present archive keeps its bytes and mtime, and no archive in the other codec appears
		clearstatcache();
		$this->assertSame('EXISTING', file_get_contents($file), "the present .{$ext} archive keeps its bytes");
		$this->assertSame(1000000000, filemtime($file), "the present .{$ext} archive keeps its mtime");
		$other = $ext === 'zst' ? "{$this->dnsblBase}.bz2" : "{$this->dnsblBase}.zst";
		$this->assertFileDoesNotExist($other, 'no archive in the other codec is written');
	}

	#[DataProvider('noManifestProvider')]
	public function testNoDnsblArchiveWithoutAManifest(bool $dnsbl, bool $pfbDns): void
	{
		// Given a RAM-disk /var, DNSBL or pfB-DNS wanted, a generated status file that a save would archive, and no manifest
		$this->ramDisk();
		$GLOBALS['pfb']['dnsbl'] = $dnsbl ? PfbToggle::On : PfbToggle::Off;
		$GLOBALS['pfb']['pfb_dns'] = $pfbDns ? PfbToggle::On : PfbToggle::Off;
		$this->assertNotFalse(file_put_contents("{$this->dir}/unbound/pfb_py_status.json", '{}'), 'failed to write pfb_py_status.json');
		$this->assertFileDoesNotExist("{$this->dir}/unbound/pfb_py_sources.json", 'precondition: no manifest');

		// When the every-pass 'conf' step runs
		pfb_dnsbl_cache('conf');

		// Then no DNSBL archive is written
		$this->assertNull($this->archive($this->dnsblBase), 'a cache without a manifest restores no DNSBL');
	}

	public function testADiskVarNeverWritesTheDnsblArchive(): void
	{
		// Given a disk /var (no RAM-disk flag) with a DNSBL manifest
		$this->manifest();

		// When the 'conf' step runs
		pfb_dnsbl_cache('conf');

		// Then no DNSBL archive is written
		$this->assertNull($this->archive($this->dnsblBase), 'a disk /var writes no DNSBL archive');
	}

	public function testTheRcStopEntryPointWritesTheAliastablesArchive(): void
	{
		// Given the aliastables arm of the CLI dispatcher, read from the shipped source
		$source = (string) file_get_contents("{$this->repo}/src/usr/local/pkg/pfblockerng/pfblockerng.inc");
		$this->assertSame(1, preg_match("~\\belseif \\(\\\$argv\\[1\\] == 'aliastables'\\) \\{(.*?)\\bexit\\(0\\);\\s*\\}~s", $source, $arm), 'the aliastables arm of the CLI dispatcher');
		$this->ramDisk();
		$this->aliasFile();

		// When the rc stop runs the arm as `php -f pfblockerng.inc aliastables`
		(static function (array $argv) use ($arm): void {
			eval($arm[1]);
		})(['pfblockerng.inc', 'aliastables']);

		// Then the aliastables archive is written and lists the IP table
		$archive = $this->archive($this->aliasBase);
		$this->assertNotNull($archive, 'the aliastables arm writes the missing archive');
		$this->assertContains('pfB_Test_v4.txt', $this->members($archive), 'the aliastables archive lists the IP table');
	}

	public function testFilterStopWritesTheMissingAliastablesArchiveOnARamDisk(): void
	{
		// Given a RAM-disk /var (the rc reads use_mfs_tmpvar on) and no aliastables archive
		$this->arrangeRc('pfb_filter.sh', static fn () => pfb_filter_service(), TRUE);
		$this->assertNull($this->archive($this->aliasBase), 'precondition: no aliastables archive');

		// When the rc stop runs before a clean reboot
		[$status, $output] = $this->rcStop();

		// Then exactly one bounded php call writes the archive, and the stop still succeeds
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(
			['php -f /usr/local/pkg/pfblockerng/pfblockerng.inc aliastables'],
			$this->stateLines('calls'),
			'the stop runs one aliastables archive write'
		);
		$this->assertSame(
			["-s TERM -k 5 60 {$this->dir}/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc aliastables"],
			$this->stateLines('timeout.args'),
			'the archive write is bounded by timeout(1)'
		);
	}

	#[DataProvider('extProvider')]
	public function testFilterStopLeavesAPresentArchiveAlone(string $ext): void
	{
		// Given a RAM-disk /var and an aliastables archive already present as .{$ext}
		$this->existing($this->aliasBase, $ext);
		$this->arrangeRc('pfb_filter.sh', static fn () => pfb_filter_service(), TRUE);

		// When the rc stop runs
		[$status, $output] = $this->rcStop();

		// Then no php call is made and the stop succeeds
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->stateLines('calls'), 'a present aliastables archive is never rewritten at stop');
	}

	public function testFilterStopOnADiskVarArchivesNothing(): void
	{
		// Given a disk /var (the rc reads use_mfs_tmpvar off) and no aliastables archive
		$this->arrangeRc('pfb_filter.sh', static fn () => pfb_filter_service(), FALSE);

		// When the rc stop runs
		[$status, $output] = $this->rcStop();

		// Then no php call is made and the stop succeeds
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->stateLines('calls'), 'a disk /var writes no aliastables archive at stop');
	}

	public function testDnsblStopWritesTheMissingDnsblArchiveOnARamDisk(): void
	{
		// Given a RAM-disk /var, a DNSBL manifest, and no DNSBL archive
		$this->manifest();
		$this->arrangeRc('pfb_dnsbl.sh', static fn () => pfb_dnsbl_service(), TRUE);
		$this->assertNull($this->archive($this->dnsblBase), 'precondition: no DNSBL archive');

		// When the rc stop runs before a clean reboot
		[$status, $output] = $this->rcStop();

		// Then exactly one bounded `dnsbl_cache save` runs, and the stop still succeeds
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['pfblockerng.sh dnsbl_cache save'], $this->stateLines('calls'), 'the stop runs one DNSBL archive save');
		$this->assertSame(
			["-s TERM -k 5 60 {$this->dir}/bin/pfblockerng.sh dnsbl_cache save"],
			$this->stateLines('timeout.args'),
			'the DNSBL archive save is bounded by timeout(1)'
		);
	}

	#[DataProvider('extProvider')]
	public function testDnsblStopLeavesAPresentArchiveAlone(string $ext): void
	{
		// Given a RAM-disk /var, a DNSBL manifest, and a DNSBL archive already present as .{$ext}
		$this->manifest();
		$this->existing($this->dnsblBase, $ext);
		$this->arrangeRc('pfb_dnsbl.sh', static fn () => pfb_dnsbl_service(), TRUE);

		// When the rc stop runs
		[$status, $output] = $this->rcStop();

		// Then no save is run and the stop succeeds
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->stateLines('calls'), 'a present DNSBL archive is never rewritten at stop');
	}

	public function testDnsblStopWithoutAManifestArchivesNothing(): void
	{
		// Given a RAM-disk /var and no DNSBL manifest
		$this->arrangeRc('pfb_dnsbl.sh', static fn () => pfb_dnsbl_service(), TRUE);

		// When the rc stop runs
		[$status, $output] = $this->rcStop();

		// Then no save is run and the stop succeeds
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->stateLines('calls'), 'a cache without a manifest is not saved at stop');
	}

	public function testDnsblStopOnADiskVarArchivesNothing(): void
	{
		// Given a disk /var (the rc reads use_mfs_tmpvar off) and a DNSBL manifest
		$this->manifest();
		$this->arrangeRc('pfb_dnsbl.sh', static fn () => pfb_dnsbl_service(), FALSE);

		// When the rc stop runs
		[$status, $output] = $this->rcStop();

		// Then no save is run and the stop succeeds
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame([], $this->stateLines('calls'), 'a disk /var writes no DNSBL archive at stop');
	}

	public function testAFailedDnsblSaveNeverFailsTheStop(): void
	{
		// Given a RAM-disk /var, a DNSBL manifest, no DNSBL archive, and a save that exits 1
		$this->manifest();
		$this->arrangeRc('pfb_dnsbl.sh', static fn () => pfb_dnsbl_service(), TRUE, 1);

		// When the rc stop runs
		[$status, $output] = $this->rcStop();

		// Then the save is attempted once and the stop still exits 0
		$this->assertSame(['pfblockerng.sh dnsbl_cache save'], $this->stateLines('calls'), 'the failing save is attempted once');
		$this->assertSame(0, $status, "rc_start runs rc_stop || return 1: a failed save must not keep the web server down: {$output}");
	}
}
