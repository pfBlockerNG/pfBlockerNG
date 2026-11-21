<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The ADR-40 alias-table apply fed by files (issue #4037): the Outpost apply hands pfb_apply_alias_delta_files() the members
 * to add and to remove as files of one member per line, with their counts, and gets back whether the delta path was taken
 * and whether every pfctl call succeeded.
 *
 * Every assertion is on the pfctl calls a recording double saw: the verb, the table, each argument, and the lines of the
 * file it was handed with -f.
 */
#[CoversFunction('pfb_apply_alias_delta_files')]
final class AliasDeltaApplyFilesTest extends TestCase
{
	private const TABLE = 'pfB_Files_v4';

	private string $dir = '';

	/** Where the function under test may write its batch file. */
	private string $batchdir = '';

	protected function setUp(): void
	{
		global $pfb;
		@mkdir($pfb['logdir'], 0777, TRUE);
		$this->dir = sys_get_temp_dir() . '/pfbdeltafiles' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
		$this->batchdir = "{$this->dir}/batch";
		$this->assertTrue(mkdir($this->batchdir, 0700));
		// A pfctl double: records each call's arguments (one per line), the file it got with -f and that file's mode, and fails the calls
		// whose numbers the file "fail" lists, as pfctl does: a message on its output and a non-zero status.
		file_put_contents("{$this->dir}/pfctl", <<<'SH'
#!/bin/sh
dir=$1
shift
n=1
[ -f "$dir/log" ] && n=$(( $(wc -l < "$dir/log") + 1 ))
printf '%s\n' "$@" > "$dir/argv$n"
table='' action='' infile=''
while [ "$#" -gt 0 ]; do
	case "$1" in
		-t) table=$2; shift 2 ;;
		-T) action=$2; shift 2 ;;
		-f) infile=$2; shift 2 ;;
		*) shift ;;
	esac
done
[ -n "$infile" ] && cp "$infile" "$dir/call$n" && stat -c %a "$infile" > "$dir/mode$n"
printf '%s\t%s\t%s\n' "$action" "$table" "$infile" >> "$dir/log"
if [ -f "$dir/fail" ] && grep -qx "$n" "$dir/fail"; then
	echo "pfctl: Cannot $action table: Operation not permitted"
	exit 1
fi
exit 0
SH
		);
		chmod("{$this->dir}/pfctl", 0755);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	private function pfctl(): string
	{
		return escapeshellarg("{$this->dir}/pfctl") . ' ' . escapeshellarg($this->dir);
	}

	/** Write $members to a file of one member per line, as the Outpost resource client leaves a delta part. */
	private function members(string $name, array $members): string
	{
		$path = "{$this->dir}/{$name}";
		file_put_contents($path, $members === [] ? '' : implode("\n", $members) . "\n");
		return $path;
	}

	/** @return list<string> $n distinct IPv4 addresses under 10.<$net>. */
	private static function addresses(int $n, int $net = 0): array
	{
		$out = [];
		for ($i = 0; $i < $n; $i++) {
			$out[] = sprintf('10.%d.%d.%d', $net, $i >> 8, $i & 255);
		}
		return $out;
	}

	/** @return list<array{verb: string, table: string, file: string, lines: list<string>}> every pfctl call, in order */
	private function calls(): array
	{
		$log = "{$this->dir}/log";
		if (!is_file($log)) {
			return [];
		}
		$calls = [];
		foreach (file($log, FILE_IGNORE_NEW_LINES) as $i => $row) {
			[$verb, $table, $file] = explode("\t", $row);
			$copy = "{$this->dir}/call" . ($i + 1);
			$calls[] = ['verb' => $verb, 'table' => $table, 'file' => $file,
				'lines' => is_file($copy) ? file($copy, FILE_IGNORE_NEW_LINES) : []];
		}
		return $calls;
	}

	/** @return list<array{0: string, 1: int}> each call's verb and the number of lines it was handed */
	private function shape(): array
	{
		return array_map(static fn (array $c): array => [$c['verb'], count($c['lines'])], $this->calls());
	}

	/**
	 * @param list<string> $add
	 * @param list<string> $remove
	 * @return array{delta: bool, ok: bool}
	 */
	private function apply(array $add, array $remove, int $entries, int $previous, string $mode, int $batch = 64, bool $force = FALSE): array
	{
		return pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', $add), count($add), $this->members('remove', $remove), count($remove),
			$entries, $previous, $mode, $batch, $force, $this->batchdir);
	}

	/** The length of the pfBlockerNG log now, for loggedSince(). */
	private static function logOffset(): int
	{
		global $pfb;
		clearstatcache();
		return is_file($pfb['log']) ? (int) filesize($pfb['log']) : 0;
	}

	/** @return list<string> the lines logged about the table since $offset */
	private static function loggedSince(int $offset): array
	{
		global $pfb;
		$tail = (string) @file_get_contents($pfb['log'], FALSE, NULL, $offset);
		return array_values(array_filter(explode("\n", $tail), static fn (string $l): bool => str_contains($l, self::TABLE)));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// The mode and churn decision, from counts
	// ---------------------------------------------------------------------------------------------------------------

	public function testModeReplaceReplacesTheTableFromItsFileWhateverTheChurn(): void
	{
		$result = $this->apply(['10.1.0.1'], [], 1000, 1000, 'replace');

		$this->assertSame(['delta' => FALSE, 'ok' => TRUE], $result);
		$calls = $this->calls();
		$this->assertSame([['replace', self::TABLE, "{$this->dir}/mirror", ['10.255.0.1']]],
			array_map(static fn (array $c): array => array_values($c), $calls), 'one replace from the table file, nothing else');
	}

	public function testForceReplaceReplacesEvenInDeltaMode(): void
	{
		$result = $this->apply(['10.1.0.1'], [], 1000, 1000, 'delta', 64, TRUE);

		$this->assertSame(['delta' => FALSE, 'ok' => TRUE], $result);
		$this->assertSame([['replace', 1]], $this->shape());
	}

	public function testModeDeltaAppliesAddsThenDeletesWhateverTheChurn(): void
	{
		$add = self::addresses(3, 1);
		$remove = self::addresses(2, 2);

		$result = $this->apply($add, $remove, 3, 2, 'delta');

		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result, 'a churn of 5 in 3 entries is 167 %: delta mode ignores it');
		$calls = $this->calls();
		$this->assertSame([['add', $add], ['delete', $remove]],
			array_map(static fn (array $c): array => [$c['verb'], $c['lines']], $calls));
		$this->assertSame([self::TABLE, self::TABLE], array_column($calls, 'table'));
	}

	/** @return array<string, array{0: int, 1: int, 2: int, 3: string}> add, remove, entries, previous entries, and the path auto mode takes */
	public static function churnEdges(): array
	{
		return [
			'4 of 100 (4 %) is under the threshold'                 => [3, 1, 100, 100, 'delta'],
			'5 of 100 (5 %) is at it'                               => [3, 2, 100, 100, 'replace'],
			'6 of 100 (6 %) is over it'                             => [3, 3, 100, 100, 'replace'],
			'4 of max(50, 100): the larger count is the table size' => [3, 1, 50, 100, 'delta'],
			'4 of max(100, 50): either side can be the larger'      => [3, 1, 100, 50, 'delta'],
			'4 of max(50, 79) is over it'                           => [3, 1, 50, 79, 'replace'],
		];
	}

	#[DataProvider('churnEdges')]
	public function testAutoModeReplacesAtOrOverTheChurnThresholdAndAppliesADeltaUnderIt(int $add, int $remove, int $entries, int $previous, string $path): void
	{
		$this->assertSame(0.05, PFB_DELTA_CHURN_THRESHOLD, 'the edges below are cut for a 5 % threshold');

		$result = $this->apply(self::addresses($add, 1), self::addresses($remove, 2), $entries, $previous, 'auto');

		$this->assertTrue($result['ok']);
		if ($path === 'replace') {
			$this->assertSame(['delta' => FALSE, 'ok' => TRUE], $result);
			$this->assertSame([['replace', 1]], $this->shape());
		} else {
			$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
			$this->assertSame([['add', $add], ['delete', $remove]], $this->shape());
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Batches cut from the files
	// ---------------------------------------------------------------------------------------------------------------

	/** @return array<string, array{0: int, 1: int, 2: list<array{0: string, 1: int}>}> */
	public static function batchBoundaries(): array
	{
		return [
			'exactly one batch makes one call'           => [64, 0, [['add', 64]]],
			'one line more makes a second call'          => [65, 0, [['add', 64], ['add', 1]]],
			'two batches exactly make two calls'         => [128, 0, [['add', 64], ['add', 64]]],
			'an empty add makes delete calls only'       => [0, 65, [['delete', 64], ['delete', 1]]],
			'an empty remove makes add calls only'       => [1, 0, [['add', 1]]],
			'both sides are cut on their own boundaries' => [65, 64, [['add', 64], ['add', 1], ['delete', 64]]],
		];
	}

	/** @param list<array{0: string, 1: int}> $shape */
	#[DataProvider('batchBoundaries')]
	public function testBatchesAreCutAtTheBatchSize(int $add, int $remove, array $shape): void
	{
		$addMembers = self::addresses($add, 1);
		$removeMembers = self::addresses($remove, 2);

		$result = $this->apply($addMembers, $removeMembers, 10000, 10000, 'delta');

		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
		$this->assertSame($shape, $this->shape());
		$calls = $this->calls();
		$sent = static fn (string $verb): array => array_merge([], ...array_column(
			array_filter($calls, static fn (array $c): bool => $c['verb'] === $verb), 'lines'));
		$this->assertSame($addMembers, $sent('add'), 'every add line is sent once, in file order');
		$this->assertSame($removeMembers, $sent('delete'), 'every remove line is sent once, in file order');
	}

	public function testABatchSizeBelowTheFloorIsClampedTo64(): void
	{
		$this->apply(self::addresses(65, 1), [], 10000, 10000, 'delta', 1);

		$this->assertSame([['add', 64], ['add', 1]], $this->shape());
	}

	public function testBothFilesEmptyMakeNoCallAndNeedNoFile(): void
	{
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			"{$this->dir}/no-add", 0, "{$this->dir}/no-remove", 0, 100, 100, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
		$this->assertSame([], $this->calls());
	}

	public function testZeroAndZeroReadNoFileEvenWhenTheFilesHoldLines(): void
	{
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), 0, $this->members('remove', ['10.2.0.1']), 0, 100, 100, 'delta', 64, FALSE,
			$this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result, 'counts of zero are nothing to do: the files are not read');
		$this->assertSame([], $this->calls());
	}

	/** @return array<string, array{0: int, 1: int, 2: string}> the add and remove counts, and the mode */
	public static function negativeCounts(): array
	{
		return [
			'-1 and +1 do not cancel out'  => [-1, 1, 'delta'],
			'+1 and -1 do not cancel out'  => [1, -1, 'delta'],
			'a negative add alone'         => [-5, 0, 'delta'],
			'a negative count in replace'  => [0, -1, 'replace'],
		];
	}

	#[DataProvider('negativeCounts')]
	public function testANegativeCountFailsTheResultWithNoCall(int $addCount, int $removeCount, string $mode): void
	{
		$offset = self::logOffset();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), $addCount, $this->members('remove', ['10.2.0.1']), $removeCount, 100, 100, $mode,
			64, FALSE, $this->batchdir);

		$this->assertFalse($result['ok'], 'a negative count is refused, never applied as nothing to do');
		$this->assertSame([], $this->calls());
		$this->assertCount(1, self::loggedSince($offset), 'one line says why: ' . implode(' | ', self::loggedSince($offset)));
	}

	public function testALastLineWithoutANewlineIsSentAsAMember(): void
	{
		$add = "{$this->dir}/add";
		file_put_contents($add, "10.1.0.1\n10.1.0.2");

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$add, 2, $this->members('remove', []), 0, 100, 100, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
		$this->assertSame(['10.1.0.1', '10.1.0.2'], $this->calls()[0]['lines']);
		$this->assertSame("10.1.0.1\n10.1.0.2\n", file_get_contents("{$this->dir}/call1"), 'each member pfctl reads ends its line');
	}

	public function testTheBatchFileIsGoneAfterTheApply(): void
	{
		$this->apply(self::addresses(65, 1), self::addresses(1, 2), 10000, 10000, 'delta');

		$this->assertCount(3, $this->calls());
		$this->assertSame([], array_values(array_diff(scandir($this->batchdir), ['.', '..'])));
		$this->assertStringStartsWith("{$this->batchdir}/", $this->calls()[0]['file'], 'the batch file is written where the caller said');
	}

	/** @return array<string, array{int}> */
	public static function umasks(): array
	{
		return ['umask 022' => [0022], 'umask 000' => [0000]];
	}

	#[DataProvider('umasks')]
	public function testABatchFileIsReadableByItsOwnerOnlyWhateverTheUmask(int $umask): void
	{
		$old = umask($umask);
		try {
			$this->apply(['10.1.0.1'], ['10.2.0.1'], 10000, 10000, 'delta');
		} finally {
			umask($old);
		}

		$this->assertSame([['add', 1], ['delete', 1]], $this->shape());
		$this->assertSame(['600', '600'], [trim((string) file_get_contents("{$this->dir}/mode1")),
			trim((string) file_get_contents("{$this->dir}/mode2"))], 'pfctl was handed a batch file others could read');
	}

	public function testABatchFileIsRemovedWhenThePfctlStepThrows(): void
	{
		global $pfb;
		$dbdir = $pfb['dbdir'];
		// the ledger write after the pfctl call takes a string: a NULL makes the pfctl step throw once pfctl has run
		$pfb['dbdir'] = NULL;
		try {
			$this->apply(['10.1.0.1'], [], 10000, 10000, 'delta');
			$this->fail('the pfctl step did not throw, so this test proves nothing');
		} catch (TypeError) {
		} finally {
			$pfb['dbdir'] = $dbdir;
		}

		$this->assertSame([['add', 1]], $this->shape(), 'pfctl ran before the step threw');
		$this->assertSame([], array_values(array_diff(scandir($this->batchdir), ['.', '..'])), 'the batch file was left behind');
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Failure is reported, never only logged
	// ---------------------------------------------------------------------------------------------------------------

	/** @return array<string, array{0: list<int>}> the calls that fail: three add batches (calls 1 to 3), then one delete (call 4) */
	public static function failingCalls(): array
	{
		return [
			'the first batch'  => [[1]],
			'a middle batch'   => [[2]],
			'the last batch'   => [[4]],
			'every batch'      => [[1, 2, 3, 4]],
		];
	}

	/**
	 * A failed pfctl call fails the result, and every remaining batch is still sent: the table ends as close to the desired
	 * set as pf allows, and the caller, told of the failure, keeps its cursor so the table is later replaced from its mirror.
	 *
	 * @param list<int> $failing
	 */
	#[DataProvider('failingCalls')]
	public function testAFailedPfctlCallFailsTheResultAndTheRemainingBatchesAreStillSent(array $failing): void
	{
		$add = self::addresses(129, 1);
		$remove = self::addresses(1, 2);
		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $this->apply($add, $remove, 10000, 10000, 'delta'), 'before: no call fails');
		unlink("{$this->dir}/log");

		file_put_contents("{$this->dir}/fail", implode("\n", $failing) . "\n");
		$result = $this->apply($add, $remove, 10000, 10000, 'delta');

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$this->assertSame([['add', 64], ['add', 64], ['add', 1], ['delete', 1]], $this->shape(), 'every batch is sent after a failure');
	}

	public function testAFailedReplaceFailsTheResult(): void
	{
		file_put_contents("{$this->dir}/fail", "1\n");

		$result = $this->apply(['10.1.0.1'], [], 10, 10, 'replace');

		$this->assertSame(['delta' => FALSE, 'ok' => FALSE], $result);
		$this->assertSame([['replace', 1]], $this->shape());
	}

	public function testABatchFileThatCannotBeCreatedIsSentNowhereAndFailsTheResult(): void
	{
		$offset = self::logOffset();
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), 1, $this->members('remove', []), 0, 100, 100, 'delta', 64, FALSE,
			"{$this->dir}/no-such-dir");

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls(), 'no member is sent when the batch file cannot be written');
		$this->assertCount(1, array_filter(self::loggedSince($offset), static fn (string $l): bool => str_contains($l, 'temporary file failed')),
			'one line says the batch was dropped: ' . implode(' | ', self::loggedSince($offset)));
	}

	/** @return array<string, array{0: string, 1: string}> which side is broken, and how */
	public static function unreadableSides(): array
	{
		return [
			'a missing add file'           => ['add', 'missing'],
			'a remove path to a directory' => ['remove', 'directory'],
		];
	}

	#[DataProvider('unreadableSides')]
	public function testAMemberFileThatCannotBeReadFailsTheResultBeforeAnyCall(string $side, string $how): void
	{
		$paths = ['add' => $this->members('add', ['10.1.0.1']), 'remove' => $this->members('remove', ['10.2.0.1'])];
		$paths[$side] = "{$this->dir}/broken-{$side}";
		if ($how === 'directory') {
			$this->assertTrue(mkdir($paths[$side]));
		}

		$offset = self::logOffset();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$paths['add'], 1, $paths['remove'], 1, 100, 100, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls(), 'neither side is sent when one cannot be read: no half-applied delta');
		$this->assertCount(1, array_filter(self::loggedSince($offset), static fn (string $l): bool => str_contains($l, "cannot read {$paths[$side]}")),
			'one line names the file that cannot be read: ' . implode(' | ', self::loggedSince($offset)));
	}

	/** @return array<string, array{0: string, 1: int, 2: int}> the side, the lines its file holds, and the count it is given */
	public static function miscounted(): array
	{
		return [
			'an add file longer than its count'     => ['add', 3, 2],
			'an add file shorter than its count'    => ['add', 2, 3],
			'a remove file longer than its count'   => ['remove', 3, 2],
			'a remove file shorter than its count'  => ['remove', 2, 3],
		];
	}

	/** Both files are counted before anything is sent: a file that is not its count sends nothing, from either side. */
	#[DataProvider('miscounted')]
	public function testAFileThatIsNotItsCountSendsNothing(string $side, int $lines, int $count): void
	{
		$members = ['add' => self::addresses(70, 1), 'remove' => self::addresses(70, 2)];
		$counts = ['add' => 70, 'remove' => 70];
		$members[$side] = self::addresses($lines, 3);
		$counts[$side] = $count;
		$offset = self::logOffset();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', $members['add']), $counts['add'], $this->members('remove', $members['remove']), $counts['remove'],
			10000, 10000, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result, 'a file that is not its count is a failure, not another delta');
		$this->assertSame([], $this->calls(), 'nothing is sent from a file its count contradicts');
		$named = array_values(array_filter(self::loggedSince($offset),
			static fn (string $l): bool => str_contains($l, $side) && str_contains($l, (string) $lines) && str_contains($l, (string) $count)));
		$this->assertCount(1, $named, 'one line names the side and both numbers: ' . implode(' | ', self::loggedSince($offset)));
	}

	/** The counts 1 of 100 choose a delta; the add file holds 50 members, a churn that would have been a replace: nothing is sent. */
	public function testADeltaChosenFromACountTheFileContradictsSendsNothing(): void
	{
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', self::addresses(50, 1)), 1, $this->members('remove', []), 0, 100, 100, 'auto', 64, FALSE,
			$this->batchdir);

		$this->assertFalse($result['ok']);
		$this->assertSame([], $this->calls());
	}

	/** A member is at most 64 bytes: a line of 64 is sent whole, and one of 65 sends nothing, even where its pieces would make up the count. */
	public function testALineOfSixtyFourBytesIsAMemberAndOneOfSixtyFiveIsNot(): void
	{
		$member = str_repeat('1', 64);
		$add = "{$this->dir}/add";
		file_put_contents($add, "{$member}\n");
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$add, 1, $this->members('remove', []), 0, 10000, 10000, 'delta', 64, FALSE, $this->batchdir);
		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
		$this->assertSame([['add', [$member]]], array_map(static fn (array $c): array => [$c['verb'], $c['lines']], $this->calls()));

		unlink("{$this->dir}/log");
		file_put_contents($add, "{$member}1\n");
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$add, 2, $this->members('remove', []), 0, 10000, 10000, 'delta', 64, FALSE, $this->batchdir);
		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result, 'a 65-byte line read in two pieces is two lines: a bound must not split it');
		$this->assertSame([], $this->calls());
	}

	/**
	 * A line longer than an IP set member (64 bytes and its newline) fails its file before anything is sent, and is never
	 * read whole: a 1 MiB line with no newline costs no more memory than a member.
	 */
	public function testALineLongerThanAMemberSendsNothingAndIsNeverReadWhole(): void
	{
		$add = "{$this->dir}/add";
		file_put_contents($add, str_repeat('1', 1 << 20));
		gc_collect_cycles();
		memory_reset_peak_usage();
		$base = memory_get_usage();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
			$add, 1, $this->members('remove', []), 0, 10000, 10000, 'delta', 64, FALSE, $this->batchdir);
		$peak = memory_get_peak_usage() - $base;

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls());
		$this->assertLessThan(256 << 10, $peak, 'the long line was read whole');
	}

	// ---------------------------------------------------------------------------------------------------------------
	// A member is never an argument
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * A line that pfctl would read as an option (a leading "-") reaches pfctl only inside the file it is handed with -f:
	 * the command line of every call is exactly -t <table> -T <verb> -f <batch file>, whatever the members hold.
	 */
	public function testAMemberThatLooksLikeAnOptionNeverReachesTheCommandLine(): void
	{
		$hostile = ['-Fall', '-e', '--', '-f/etc/passwd'];

		$result = $this->apply($hostile, ['-d'], 10000, 10000, 'delta');

		$this->assertTrue($result['delta']);
		$calls = $this->calls();
		$this->assertSame([['add', $hostile], ['delete', ['-d']]],
			array_map(static fn (array $c): array => [$c['verb'], $c['lines']], $calls), 'the members travel in the -f files');
		foreach ($calls as $i => $call) {
			$argv = file("{$this->dir}/argv" . ($i + 1), FILE_IGNORE_NEW_LINES);
			$this->assertSame(['-t', self::TABLE, '-T', $call['verb'], '-f', $call['file']], $argv, 'nothing else is on the command line');
			$this->assertStringStartsWith("{$this->batchdir}/", $call['file']);
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Memory: the files are read a line at a time
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * Run $code in a child PHP that loads the package as the suite does, then caps its memory at what it holds plus
	 * $headroom bytes.
	 *
	 * @return array{stdout: string, stderr: string, exit: int, termsig: int}
	 */
	private function underMemoryCap(string $code, int $headroom): array
	{
		$worker = "{$this->dir}/worker.php";
		file_put_contents($worker, "<?php\nrequire " . var_export(__DIR__ . '/bootstrap.php', TRUE) . ";\n"
			. "global \$pfb;\n@mkdir(\$pfb['logdir'], 0777, TRUE);\n"
			. "ini_set('memory_limit', (string) (memory_get_usage() + {$headroom}));\nmemory_reset_peak_usage();\n\$base = memory_get_usage();\n"
			. $code);
		return pfb_test_finish_process(pfb_test_start_process([PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'display_errors=stderr', $worker]), 300.0);
	}

	public function testTwoHundredThousandAddsApplyUnderAMemoryCapThatTheirListWouldExceed(): void
	{
		$add = "{$this->dir}/add";
		$fh = fopen($add, 'wb');
		for ($i = 0; $i < 200_000; $i++) {
			fwrite($fh, sprintf("10.%d.%d.%d\n", $i >> 16, ($i >> 8) & 255, $i & 255));
		}
		fclose($fh);
		$remove = $this->members('remove', ['10.200.0.1']);
		$headroom = 8 << 20;

		// the cap bites: the same child cannot hold the add file's members as a list
		$control = $this->underMemoryCap('$m = file(' . var_export($add, TRUE) . ", FILE_IGNORE_NEW_LINES);\necho count(\$m);\n", $headroom);
		$this->assertNotSame(0, $control['exit'], "the list of members fit under the cap, so the cap proves nothing: {$control['stdout']}");
		$this->assertStringContainsString('Allowed memory size', $control['stderr']);

		$args = implode(', ', [var_export($this->pfctl(), TRUE), var_export(self::TABLE, TRUE), var_export($remove, TRUE),
			var_export($add, TRUE), '200000', var_export($remove, TRUE), '1', '200000', '1', "'delta'", '4096', 'FALSE',
			var_export($this->batchdir, TRUE)]);
		$run = $this->underMemoryCap('$r = pfb_apply_alias_delta_files(' . $args . ");\n"
			. 'echo json_encode($r);' . "\n", $headroom);
		$this->assertSame(0, $run['exit'], "the apply did not finish under the cap: {$run['stderr']}");
		$this->assertSame('', $run['stderr']);
		$got = json_decode($run['stdout'], TRUE, 4, JSON_THROW_ON_ERROR);
		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], ['delta' => $got['delta'], 'ok' => $got['ok']]);
		$shape = $this->shape();
		$this->assertCount(50, $shape, 'ceil(200000 / 4096) = 49 add calls and one delete');
		$this->assertSame(200_000, array_sum(array_column(array_filter($shape, static fn (array $s): bool => $s[0] === 'add'), 1)));
		$this->assertSame(['delete', 1], end($shape));
	}
}
