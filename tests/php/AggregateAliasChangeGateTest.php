<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3156 — an aggregate ("Uber") alias is reported changed only when its content changed.
 *
 * `pfb_aggregate()`'s rebuild gate is an mtime gate: a member file rewritten with byte-identical
 * content still bumps its mtime, so the union is rebuilt. That is a cheap heuristic and it is
 * allowed to over-trigger. What may NOT over-trigger is what the rebuild is taken to MEAN — the
 * aggregate's name entering `$pfb['changed_ip_aliases']` and `$pfb_alias_lists`, and its pf table
 * being re-pushed. Every member alias already decides that on content (ADR-40); the aggregate
 * decided it on the output file's mtime, so a content-identical rebuild read as a change and the
 * kernel table was replaced on every pass.
 *
 * The shell side is the SHIPPED `pfb_aggregate()`, sourced through a wrapper — the mtime gate under
 * test is the real one, not a stand-in. CIDR Aggregation is on, so the union takes the sort -u path
 * and needs no `iprange`.
 */
#[CoversFunction('pfb_build_aggregate_aliases')]
final class AggregateAliasChangeGateTest extends TestCase
{
	/** @var array<string,array{bool,mixed}> */
	private array $saved = [];

	private string $tmp;
	private string $denydir;
	private string $aliasdir;
	private string $dbdir;
	private string $pfctl_call_log;
	private string $tables_fixture;

	private const ALIAS = 'pfB_Deny_Aggregated_v4';

	protected function setUp(): void
	{
		foreach (['pfb', 'g', 'config'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}

		$this->tmp      = sys_get_temp_dir() . '/pfb_agg_gate_' . getmypid() . '_' . uniqid();
		$this->denydir  = "{$this->tmp}/deny";
		$this->aliasdir = "{$this->tmp}/alias";
		$this->dbdir    = "{$this->tmp}/db";
		foreach ([$this->tmp, $this->denydir, $this->aliasdir, $this->dbdir] as $dir) {
			$this->assertTrue(mkdir($dir, 0777, TRUE), "failed to create {$dir}");
		}

		$this->pfctl_call_log = "{$this->tmp}/pfctl_calls.txt";
		// What the mock pfctl reports for `-vvsTables`; the tests rewrite it to say whether the
		// aggregate's kernel table currently holds addresses.
		$this->tables_fixture = "{$this->tmp}/pfctl_tables.txt";
		$this->setKernelTable(0);

		global $pfb;
		$pfb['denydir']       = $this->denydir;
		$pfb['permitdir']     = "{$this->tmp}/permit";
		$pfb['matchdir']      = "{$this->tmp}/match";
		$pfb['nativedir']     = "{$this->tmp}/native";
		$pfb['aliasdir']      = $this->aliasdir;
		$pfb['dbdir']         = $this->dbdir;
		$pfb['weblocal']      = 'http://127.0.0.1/pfblockerng/www/index.php';
		$pfb['ip_ph']         = '127.1.7.7';
		$pfb['enable']        = PfbToggle::On;
		$pfb['agg']           = PfbToggle::On;
		$pfb['agg_types']     = ['Deny'];
		$pfb['pfctl']         = $this->writePfctlMock();
		$pfb['script']        = $this->writeAggregateWrapper();
		$pfb['changed_ip_aliases'] = [];
		$pfb['log']           = "{$this->tmp}/pfblockerng.log";
		$pfb['errlog']        = "{$this->tmp}/error.log";
		$pfb['runlog']        = '';
		$pfb['runlog_active'] = FALSE;
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmp);
		foreach ($this->saved as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	/**
	 * A mock pfctl: records `-T <op>` calls, and answers `-vvsTables` from the fixture file.
	 *
	 * Its paths are baked into the script rather than passed as arguments, because
	 * pfb_pfctl_tables_raw() escapeshellarg()s $pfb['pfctl'] as a single binary path — a
	 * "binary plus args" value would be quoted whole and fail to execute.
	 */
	private function writePfctlMock(): string
	{
		$path = "{$this->tmp}/pfctl_mock.sh";
		$mock = "#!/bin/sh\n"
			. 'LOG=' . escapeshellarg($this->pfctl_call_log) . "\n"
			. 'TABLES=' . escapeshellarg($this->tables_fixture) . "\n"
			. <<<'SH'
			if [ "$1" = '-vvsTables' ]; then
			    cat "$TABLES"
			    exit 0
			fi
			table=''
			action=''
			while [ "$#" -gt 0 ]; do
			    case "$1" in
			        -t) table="$2"; shift 2 ;;
			        -T) action="$2"; shift 2 ;;
			        *)  shift ;;
			    esac
			done
			printf '%s\t%s\n' "$action" "$table" >> "$LOG"
			SH;
		$this->assertNotFalse(file_put_contents($path, $mock), 'failed to write the pfctl mock');
		$this->assertTrue(chmod($path, 0755), 'failed to make the pfctl mock executable');
		return $path;
	}

	/**
	 * A `$pfb['script']` stand-in that runs the SHIPPED pfb_aggregate() — sourced with
	 * PFB_SOURCED=1, given the temp paths the executable path would have set, and no appliance
	 * path anywhere.
	 */
	private function writeAggregateWrapper(): string
	{
		$sh   = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.sh';
		$path = "{$this->tmp}/script_wrapper.sh";
		$body = "#!/bin/sh\n"
			. "PFB_SOURCED=1\n"
			. ". " . escapeshellarg($sh) . "\n"
			. "tmpdir=" . escapeshellarg("{$this->tmp}/shell") . "\n"
			. "mkdir -p \"\${tmpdir}\"\n"
			. "tempfile=\"\${tmpdir}/t1\"\n"
			. "dedupfile=\"\${tmpdir}/dedup\"\n"
			. "errorlog=\"\${tmpdir}/error.log\"\n"
			. "pathaggregate=/nonexistent/iprange\n"
			. "case \"\$1\" in\n"
			. "  aggregate) pfb_aggregate \"\$@\" ;;\n"
			. "  *) exit 0 ;;\n"
			. "esac\n";
		$this->assertNotFalse(file_put_contents($path, $body), 'failed to write the script wrapper');
		$this->assertTrue(chmod($path, 0755), 'failed to make the script wrapper executable');
		return $path;
	}

	/** Make the mock pfctl report $addresses entries for the aggregate's kernel table. */
	private function setKernelTable(int $addresses): void
	{
		$alias = self::ALIAS;
		$this->assertNotFalse(
			file_put_contents($this->tables_fixture, "--a-r-\t{$alias}\n\tAddresses:   {$addresses}\n"),
			'failed to write the pfctl tables fixture'
		);
	}

	/**
	 * The pfctl operations aimed at the alias under test. Scoped by table because selecting a
	 * type builds BOTH families, and the memberless v6 sibling has its own (empty) verdict.
	 *
	 * @return list<string>
	 */
	private function pfctlOps(): array
	{
		if (!file_exists($this->pfctl_call_log)) {
			return [];
		}
		$ops = [];
		foreach (array_filter(explode("\n", file_get_contents($this->pfctl_call_log) ?: '')) as $line) {
			[$action, $table] = explode("\t", $line, 2);
			if ($table === self::ALIAS) {
				$ops[] = $action;
			}
		}
		return $ops;
	}

	/**
	 * One builder pass. Returns what it reported: the reload set, the ADR-12 changed set, the
	 * previous-set stash, and the pfctl calls it made.
	 *
	 * @return array{lists:list<string>,changed:list<string>,prev:array<string,array<int,string>>,ops:list<string>}
	 */
	private function runBuilder(): array
	{
		global $pfb;
		@unlink($this->pfctl_call_log);
		$pfb['changed_ip_aliases'] = [];
		$new_aliases      = [];
		$new_aliases_list = [];
		$alias_lists      = [];
		$prev_sets        = [];

		pfb_build_aggregate_aliases($new_aliases, $new_aliases_list, $alias_lists, $prev_sets);

		return [
			'lists'   => $alias_lists,
			'changed' => $pfb['changed_ip_aliases'],
			'prev'    => $prev_sets,
			'ops'     => $this->pfctlOps(),
		];
	}

	private function writeMember(string $header, array $entries): string
	{
		$path = "{$this->denydir}/{$header}_v4.txt";
		$this->assertNotFalse(file_put_contents($path, implode("\n", $entries) . "\n"), "failed to write {$path}");
		return $path;
	}

	/**
	 * Scenario: the reported defect.
	 *
	 * Given an aggregate already built from its members, and its kernel table loaded
	 * When a member is rewritten with byte-identical content, moving only its mtime
	 * Then the aggregate is not reported changed and its kernel table is not touched,
	 *      even though the union was rebuilt.
	 */
	public function testMemberRewrittenWithIdenticalContentReportsNoChange(): void
	{
		$member = $this->writeMember('Feed', ['198.51.100.7', '203.0.113.0/24']);

		$first = $this->runBuilder();
		$this->assertContains(self::ALIAS, $first['lists'], 'the initial build must report a change');
		$aggregate = "{$this->aliasdir}/" . self::ALIAS . '.txt';
		$this->assertFileExists($aggregate, 'the initial build must write the aggregate');
		$before = (string) file_get_contents($aggregate);

		// The table now holds what the first pass loaded, and the member's mtime moves without
		// its content changing — the recompute swap and the suppression republish both do this
		// (issue #3158).
		$this->setKernelTable(2);
		$this->assertTrue(touch($member, time() + 5), 'failed to bump the member mtime');

		$second = $this->runBuilder();

		$this->assertSame($before, (string) file_get_contents($aggregate),
			'the rebuilt aggregate must be byte-identical — otherwise this test proves nothing');
		$this->assertNotContains(self::ALIAS, $second['lists'],
			'an unchanged aggregate must not enter the alias reload set');
		$this->assertNotContains(self::ALIAS, $second['changed'],
			'an unchanged aggregate must not enter PFB_CHANGED_IP_ALIASES');
		$this->assertSame([], $second['ops'],
			'an unchanged aggregate must not be re-pushed to the kernel: ' . implode(',', $second['ops']));
	}

	/**
	 * Given an aggregate whose kernel table is loaded
	 * When a member's content actually changes
	 * Then the aggregate is reported changed, its table is replaced, and its PREVIOUS canonical
	 *      set is stashed so the apply site can take the ADR-40 delta path instead of a full
	 *      replace.
	 */
	public function testMemberContentChangeReportsChangeAndStashesThePreviousSet(): void
	{
		$this->writeMember('Feed', ['198.51.100.7']);
		$this->runBuilder();
		$this->setKernelTable(1);

		$this->writeMember('Feed', ['198.51.100.7', '192.0.2.9']);
		$second = $this->runBuilder();

		$this->assertContains(self::ALIAS, $second['lists'], 'a changed aggregate must enter the reload set');
		$this->assertContains(self::ALIAS, $second['changed'], 'a changed aggregate must enter PFB_CHANGED_IP_ALIASES');
		$this->assertSame(['replace'], $second['ops'], 'a changed aggregate is loaded into the kernel');
		$this->assertSame(['198.51.100.7'], $second['prev'][self::ALIAS] ?? NULL,
			'the previous canonical set must be stashed so the apply site deltas instead of replacing');
	}

	/**
	 * The empty-kernel-table repopulation path: an aggregate whose file did not change but whose
	 * table holds nothing must still be loaded. This is the same signal the member-alias write
	 * loop uses, and without it a boot or a stray `pfctl -T kill` would leave the table empty
	 * until a member's content happened to change.
	 */
	public function testUnchangedAggregateWithAnEmptyKernelTableIsStillLoaded(): void
	{
		$this->writeMember('Feed', ['198.51.100.7']);
		$this->runBuilder();

		// Table emptied out from under us; the aggregate file is untouched.
		$this->setKernelTable(0);
		$third = $this->runBuilder();

		$this->assertContains(self::ALIAS, $third['lists'], 'an empty kernel table must force a reload');
		$this->assertSame(['replace'], $third['ops'], 'an empty kernel table must be repopulated');
		$this->assertSame([], $third['prev'][self::ALIAS] ?? NULL,
			'an empty kernel table stashes an empty previous set, so the apply site full-replaces');
	}

	/** A box that selects no aggregate type pays nothing: no build, no pfctl call, no report. */
	public function testNoSelectedTypeTouchesNothing(): void
	{
		global $pfb;
		$pfb['agg_types'] = [];
		$this->writeMember('Feed', ['198.51.100.7']);

		$result = $this->runBuilder();

		$this->assertSame([], $result['lists'], 'nothing selected must report no change');
		$this->assertSame([], $result['changed'], 'nothing selected must report no change');
		$this->assertSame([], $result['ops'], 'nothing selected must not call pfctl');
		$this->assertFileDoesNotExist("{$this->aliasdir}/" . self::ALIAS . '.txt');
	}
}
