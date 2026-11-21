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

	/** @var mixed the ledger directory ($pfb['dbdir']) the test found, put back by tearDown() */
	private mixed $dbdir = NULL;

	protected function setUp(): void
	{
		global $pfb;
		$this->dbdir = $pfb['dbdir'] ?? NULL;
		@mkdir($pfb['logdir'], 0777, TRUE);
		$this->dir = sys_get_temp_dir() . '/pfbdeltafiles' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
		$pfb['dbdir'] = $this->dir;
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
[ -n "$infile" ] && cp "$infile" "$dir/call$n" && { stat -c %a "$infile" 2>/dev/null || stat -f %Lp "$infile"; } > "$dir/mode$n"
printf '%s\t%s\t%s\n' "$action" "$table" "$infile" >> "$dir/log"
# a test's "rewrite" file replaces, in place, the file named in "rewrite.to" when the first call arrives
if [ "$n" = 1 ] && [ -f "$dir/rewrite" ]; then cp "$dir/rewrite" "$(cat "$dir/rewrite.to")"; fi
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
		global $pfb;
		$pfb['dbdir'] = $this->dbdir;
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
		return pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
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
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			"{$this->dir}/no-add", 0, "{$this->dir}/no-remove", 0, 100, 100, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
		$this->assertSame([], $this->calls());
	}

	public function testZeroAndZeroReadNoFileEvenWhenTheFilesHoldLines(): void
	{
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
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
		];
	}

	#[DataProvider('negativeCounts')]
	public function testANegativeCountFailsTheResultWithNoCall(int $addCount, int $removeCount, string $mode): void
	{
		$offset = self::logOffset();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), $addCount, $this->members('remove', ['10.2.0.1']), $removeCount, 100, 100, $mode,
			64, FALSE, $this->batchdir);

		$this->assertFalse($result['ok'], 'a negative count is refused, never applied as nothing to do');
		$this->assertSame([], $this->calls());
		$this->assertCount(1, self::loggedSince($offset), 'one line says why: ' . implode(' | ', self::loggedSince($offset)));
	}

	/** A replace reloads the table from its file and never uses the add and remove counts: a negative one does not stop it. */
	#[DataProvider('replacePaths')]
	public function testANegativeCountDoesNotStopAReplace(string $mode, bool $force): void
	{
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), -1, $this->members('remove', ['10.2.0.1']), -7, 100, 100, $mode,
			64, $force, $this->batchdir);

		$this->assertSame(['delta' => FALSE, 'ok' => TRUE], $result);
		$this->assertSame([['replace', 1]], $this->shape());
	}

	/** @return array<string, array{string, bool}> */
	public static function replacePaths(): array
	{
		return ['mode replace' => ['replace', FALSE], 'a forced replace in delta mode' => ['delta', TRUE],
			'a forced replace in auto mode' => ['auto', TRUE]];
	}

	/** @return array<string, array{int, int, string}> the entries after, the entries before, the mode */
	public static function negativeTableSizes(): array
	{
		return [
			'auto, negative entries'            => [-1, 100, 'auto'],
			'auto, negative previous entries'   => [100, -1, 'auto'],
			'delta, negative entries'           => [-1, 100, 'delta'],
			'delta, negative previous entries'  => [100, -1, 'delta'],
		];
	}

	#[DataProvider('negativeTableSizes')]
	public function testANegativeTableSizeFailsTheDeltaWithNoCall(int $entries, int $previous, string $mode): void
	{
		$offset = self::logOffset();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), 1, $this->members('remove', []), 0, $entries, $previous, $mode, 64, FALSE,
			$this->batchdir);

		$this->assertSame(['delta' => FALSE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls());
		$this->assertCount(1, self::loggedSince($offset), 'one line says why: ' . implode(' | ', self::loggedSince($offset)));
	}

	/** @return array<string, array{string, string, int, int}> the side, the file's bytes, its count, the line a refusal names */
	public static function badLines(): array
	{
		return [
			'an add file with CRLF endings'         => ['add', "10.1.0.1\r\n10.1.0.2\r\n", 2, 1],
			'an add file with an empty line'        => ['add', "10.1.0.1\n\n10.1.0.2\n", 3, 2],
			'a remove file with a leading minus'    => ['remove', "10.2.0.1\n10.2.0.2\n-d\n", 3, 3],
			'a remove file with a space'            => ['remove', "10.2.0.1 10.2.0.2\n", 1, 1],
		];
	}

	/** pf takes no line with a byte outside an address or a prefix: the files are checked before anything is sent. */
	#[DataProvider('badLines')]
	public function testALineThatIsNoMemberSendsNothingAndNamesItsSideAndLine(string $side, string $bytes, int $count, int $line): void
	{
		$paths = ['add' => $this->members('add', ['10.1.0.1']), 'remove' => $this->members('remove', ['10.2.0.1'])];
		$counts = ['add' => 1, 'remove' => 1];
		file_put_contents($paths[$side], $bytes);
		$counts[$side] = $count;
		$offset = self::logOffset();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			$paths['add'], $counts['add'], $paths['remove'], $counts['remove'], 10000, 10000, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls(), 'nothing is sent from a file pf would not read');
		$named = array_values(array_filter(self::loggedSince($offset),
			static fn (string $l): bool => str_contains($l, "the {$side} file") && str_contains($l, "line {$line} ")));
		$this->assertCount(1, $named, 'one line names the side and the line: ' . implode(' | ', self::loggedSince($offset)));
	}

	/** The umask is the process's: a batch file that cannot be opened must not leave it at 0077. */
	public function testAThrowingBatchFileOpenLeavesTheUmaskAsItWas(): void
	{
		$old = umask(0022);
		try {
			try {
				pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
					$this->members('add', ['10.1.0.1']), 1, $this->members('remove', []), 0, 10000, 10000, 'delta', 64, FALSE,
					"{$this->dir}/nul\0dir");
				$this->fail('a temporary directory holding a NUL byte did not throw');
			} catch (ValueError) {
			}
			$this->assertSame(0022, umask(), 'the umask is left changed');
		} finally {
			umask($old);
		}
		$this->assertSame([], $this->calls());
	}

	public function testALastLineWithoutANewlineIsSentAsAMember(): void
	{
		$add = "{$this->dir}/add";
		file_put_contents($add, "10.1.0.1\n10.1.0.2");

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
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
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
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
			'a missing remove file'        => ['remove', 'missing'],
			'an add path to a directory'   => ['add', 'directory'],
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

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
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

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
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
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			$this->members('add', self::addresses(50, 1)), 1, $this->members('remove', []), 0, 100, 100, 'auto', 64, FALSE,
			$this->batchdir);

		$this->assertFalse($result['ok']);
		$this->assertSame([], $this->calls());
	}

	/** The longest spelling the rule admits (49 bytes) is sent whole; a line of 65 bytes is refused, even where its pieces would make up the count. */
	public function testTheLongestMemberIsSentAndALineOfSixtyFiveBytesIsNot(): void
	{
		$member = 'ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128';
		$this->assertSame(49, strlen($member));
		$add = "{$this->dir}/add";
		file_put_contents($add, "{$member}\n");
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv6', $this->members('mirror', ['10.255.0.1']),
			$add, 1, $this->members('remove', []), 0, 10000, 10000, 'delta', 64, FALSE, $this->batchdir);
		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
		$this->assertSame([['add', [$member]]], array_map(static fn (array $c): array => [$c['verb'], $c['lines']], $this->calls()));

		unlink("{$this->dir}/log");
		file_put_contents($add, str_repeat('1', 65) . "\n");
		$offset = self::logOffset();
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv6', $this->members('mirror', ['10.255.0.1']),
			$add, 2, $this->members('remove', []), 0, 10000, 10000, 'delta', 64, FALSE, $this->batchdir);
		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls());
		// the line is no member either, so the refusal is told by the log: it is the length rule that stopped it
		$logged = self::loggedSince($offset);
		$this->assertCount(1, array_filter($logged, static fn (string $l): bool => str_contains($l, 'the add file holds a line over 64 bytes')),
			'one line names the length rule: ' . implode(' | ', $logged));
		$this->assertSame([], array_filter($logged, static fn (string $l): bool => str_contains($l, 'is not a member')),
			'no line blames the line for being no member: ' . implode(' | ', $logged));
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

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
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
	 * The members reach pfctl only inside the file it is handed with -f: the command line of every call is exactly
	 * -t <table> -T <verb> -f <batch file>. (A line pfctl would read as an option, a leading "-", is refused before any call.)
	 */
	public function testNoMemberReachesTheCommandLine(): void
	{
		$add = ['10.1.0.1', '10.3.0.0/24'];

		$result = $this->apply($add, ['10.2.0.0/16'], 10000, 10000, 'delta');

		$this->assertTrue($result['delta']);
		$calls = $this->calls();
		$this->assertSame([['add', $add], ['delete', ['10.2.0.0/16']]],
			array_map(static fn (array $c): array => [$c['verb'], $c['lines']], $calls), 'the members travel in the -f files');
		foreach ($calls as $i => $call) {
			$argv = file("{$this->dir}/argv" . ($i + 1), FILE_IGNORE_NEW_LINES);
			$this->assertSame(['-t', self::TABLE, '-T', $call['verb'], '-f', $call['file']], $argv, 'nothing else is on the command line');
			$this->assertStringStartsWith("{$this->batchdir}/", $call['file']);
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// A line must be a member of the table's family, on both passes
	// ---------------------------------------------------------------------------------------------------------------

	/** @return array<string, array{string, string}> the table's family and a line pf would not read as an address of it */
	public static function nonMembers(): array
	{
		return [
			'an interface name, ae0'                         => ['ipv4', 'ae0'],
			'an interface name made of hex digits, bce0'     => ['ipv6', 'bce0'],
			'a host name made of hex digits, dead.beef'      => ['ipv4', 'dead.beef'],
			'an incomplete address, abc'                     => ['ipv4', 'abc'],
			'a prefix over the width, 1.2.3.4/99'            => ['ipv4', '1.2.3.4/99'],
			'only separators, ////'                          => ['ipv6', '////'],
			'an IPv6 address in an ipv4 table'               => ['ipv4', '2001:db8::1'],
			'an IPv4 address in an ipv6 table'               => ['ipv6', '10.1.0.1'],
			'an IPv6 prefix in an ipv4 table'                => ['ipv4', '2001:db8::/32'],
		];
	}

	#[DataProvider('nonMembers')]
	public function testALineThatIsNotAMemberOfTheTablesFamilySendsNothingAndNamesItsSideAndLine(string $family, string $line): void
	{
		foreach (['add', 'remove'] as $side) {
			$fix = ['ipv4' => '10.1.0.1', 'ipv6' => '2001:db8::1'][$family];
			$paths = ['add' => $this->members('add', [$fix]), 'remove' => $this->members('remove', [$fix])];
			$paths[$side] = $this->members($side, [$fix, $line]);
			$counts = ['add' => 1, 'remove' => 1, $side => 2];
			@unlink("{$this->dir}/log");
			$offset = self::logOffset();

			$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $family, $this->members('mirror', ['10.255.0.1']),
				$paths['add'], $counts['add'], $paths['remove'], $counts['remove'], 10000, 10000, 'delta', 64, FALSE, $this->batchdir);

			$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result, "{$line} in the {$side} file of an {$family} table");
			$this->assertSame([], $this->calls(), 'nothing is sent from a file pf would read differently');
			$named = array_values(array_filter(self::loggedSince($offset),
				static fn (string $l): bool => str_contains($l, "the {$side} file") && str_contains($l, 'line 2 ')));
			$this->assertCount(1, $named, 'one line names the side and the line: ' . implode(' | ', self::loggedSince($offset)));
		}
	}

	/** @return array<string, array{string, string}> the table's family and a member pf reads as an address of it */
	public static function memberSpellings(): array
	{
		return [
			'an IPv4 prefix'                  => ['ipv4', '10.9.0.0/16'],
			'an IPv6 prefix'                  => ['ipv6', '2001:db8::/32'],
			'upper-case hexadecimal'          => ['ipv6', 'FE80::ABCD'],
			'an uncompressed IPv6 address'    => ['ipv6', '2001:0db8:0000:0000:0000:0000:0000:0001'],
		];
	}

	#[DataProvider('memberSpellings')]
	public function testAMemberOfTheTablesFamilyIsSent(string $family, string $line): void
	{
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $family, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', [$line]), 1, $this->members('remove', []), 0, 10000, 10000, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => TRUE], $result);
		$this->assertSame([['add', [$line]]], array_map(static fn (array $c): array => [$c['verb'], $c['lines']], $this->calls()));
	}

	/** @return array<string, array{string, string, bool}> */
	public static function unknownFamilies(): array
	{
		return [
			'ipv5 in delta mode'    => ['ipv5', 'delta', FALSE],
			'upper-case IPV4'       => ['IPV4', 'delta', FALSE],
			'an empty family'       => ['', 'delta', FALSE],
			'a family on a replace' => ['inet', 'replace', FALSE],
			'a family on a forced replace' => ['inet6', 'delta', TRUE],
		];
	}

	#[DataProvider('unknownFamilies')]
	public function testAFamilyThatIsNeitherIpv4NorIpv6RefusesTheCallWithNoPfctlCall(string $family, string $mode, bool $force): void
	{
		$offset = self::logOffset();

		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, $family, $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), 1, $this->members('remove', []), 0, 10000, 10000, $mode, 64, $force, $this->batchdir);

		$this->assertSame(['delta' => FALSE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls());
		$this->assertCount(1, self::loggedSince($offset), 'one line says why: ' . implode(' | ', self::loggedSince($offset)));
	}

	/**
	 * A member file rewritten in place after the first pass is checked again as it is sent: the double rewrites the file named
	 * in "rewrite.to" when pfctl gets its first call, and the function, which reads the file in batches, reaches the new bytes
	 * on its next batch. The lines before the bad one keep their length, so what the stream already buffered is still the old
	 * file's prefix.
	 *
	 * @return array<string, array{string}>
	 */
	public static function rewrittenSides(): array
	{
		return ['the add file' => ['add'], 'the remove file' => ['remove']];
	}

	#[DataProvider('rewrittenSides')]
	public function testALineRewrittenBetweenThePassesStopsTheSendingAfterTheBatchesAlreadySent(string $side): void
	{
		$members = self::addresses(2000, 1);
		$long = $this->members($side, $members);
		$short = $this->members($side === 'add' ? 'remove' : 'add', ['10.2.0.1']);
		$this->assertGreaterThan(16384, filesize($long), 'the file outgrows the stream buffer, so later lines are read after the rewrite');
		$bad = $members;
		$bad[1899] = 'ae0';
		file_put_contents("{$this->dir}/rewrite", implode("\n", $bad) . "\n");
		file_put_contents("{$this->dir}/rewrite.to", $long);
		$offset = self::logOffset();

		$result = $side === 'add'
			? pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
				$long, 2000, $short, 1, 100000, 100000, 'delta', 64, FALSE, $this->batchdir)
			: pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
				$short, 1, $long, 2000, 100000, 100000, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		// the add side is rewritten while its own batches go out; the remove side is rewritten when the one add batch has gone
		$expected = $side === 'add'
			? array_fill(0, 29, ['add', 64])
			: array_merge([['add', 1]], array_fill(0, 29, ['delete', 64]));
		$this->assertSame($expected, $this->shape(), '29 batches of 64 (lines 1 to 1856) went out; the batch holding line 1900 and what follows it did not');
		$named = array_values(array_filter(self::loggedSince($offset),
			static fn (string $l): bool => str_contains($l, "the {$side} file") && str_contains($l, 'line 1900 ')));
		$this->assertCount(1, $named, 'one line names the side and the line: ' . implode(' | ', self::loggedSince($offset)));
		$this->assertCount(1, array_filter(self::loggedSince($offset), static fn (string $l): bool => !str_contains($l, 'delta +')),
			'and no other line besides the delta decision: ' . implode(' | ', self::loggedSince($offset)));
	}

	/**
	 * A batch that is skipped for want of its file leaves the table behind its mirror, as a failed pfctl call does: the ledger
	 * holds the open ip/<table>/apply entry, so the tick's retry has something to reconcile. The batch directory is a regular
	 * file, so no batch file can be created.
	 *
	 * @return array<string, array{string}>
	 */
	public static function applyPaths(): array
	{
		return ['members from files' => ['files'], 'members from arrays' => ['arrays']];
	}

	#[DataProvider('applyPaths')]
	public function testASkippedBatchOpensTheTablesApplyEntryInTheLedger(string $path): void
	{
		$notadir = "{$this->dir}/notadir";
		file_put_contents($notadir, '');
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'), 'no entry is open before the apply');

		$result = $path === 'files'
			? pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
				$this->members('add', ['10.1.0.1']), 1, $this->members('remove', []), 0, 100, 100, 'delta', 64, FALSE, $notadir)
			: pfb_apply_alias_delta_members($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
				static fn (): array => [['10.1.0.1'], []], 1, 0, 100, 100, 'delta', 64, FALSE, $notadir);

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$this->assertSame([], $this->calls(), 'no pfctl call was made');
		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'the skipped batch opens one entry');
		$this->assertSame(['ip', self::TABLE, 'apply'], [$open[0]['facility'], $open[0]['item'], $open[0]['stage']]);
		$this->assertStringContainsString('batch file', $open[0]['message']);
	}

	/**
	 * A file that gained lines after the first pass is sent only up to its count: the line that would exceed it is refused, so no
	 * batch holds a line beyond the count, and the result fails.
	 */
	#[DataProvider('rewrittenSides')]
	public function testALineBeyondTheCountOfAFileThatGrewIsNeverSent(string $side): void
	{
		$members = self::addresses(2000, 1);
		$grown = array_merge($members, self::addresses(100, 2));
		$long = $this->members($side, $members);
		$short = $this->members($side === 'add' ? 'remove' : 'add', ['10.2.0.1']);
		file_put_contents("{$this->dir}/rewrite", implode("\n", $grown) . "\n");
		file_put_contents("{$this->dir}/rewrite.to", $long);
		$offset = self::logOffset();

		$result = $side === 'add'
			? pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
				$long, 2000, $short, 1, 100000, 100000, 'delta', 64, FALSE, $this->batchdir)
			: pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
				$short, 1, $long, 2000, 100000, 100000, 'delta', 64, FALSE, $this->batchdir);

		$this->assertSame(['delta' => TRUE, 'ok' => FALSE], $result);
		$sent = [];
		foreach ($this->calls() as $call) {
			if ($call['verb'] === ($side === 'add' ? 'add' : 'delete')) {
				array_push($sent, ...$call['lines']);
			}
		}
		$this->assertSame([], array_slice(array_diff($sent, $members), 0, 5), 'none of the lines the file gained was sent (first five shown)');
		$this->assertCount(2000, $sent, 'exactly the 2000 lines of the count were sent');
		$over = array_filter(self::loggedSince($offset), static fn (string $l): bool => str_contains($l, "the {$side} file holds more than 2000 members"));
		$this->assertCount(1, $over, 'one line says the file outgrew its count: ' . implode(' | ', self::loggedSince($offset)));
	}

	/**
	 * An exception that is not a refused line is never reported as one, whatever its type: one thrown while the batches are sent
	 * escapes with its own type, and no batch of the interrupted run reaches pfctl.
	 */
	public function testAnExceptionFromAMemberSourceEscapesInsteadOfCountingAsARefusedLine(): void
	{
		$source = static function (): Generator {
			yield '10.1.0.1';
			throw new UnexpectedValueException('a failure of the source, not a refused line');
		};

		try {
			pfb_apply_alias_delta_members($this->pfctl(), self::TABLE, $this->members('mirror', ['10.255.0.1']),
				static fn (): array => [$source(), []], 2, 0, 100000, 100000, 'delta', 64, FALSE, $this->batchdir);
			$this->fail('the exception was swallowed');
		} catch (UnexpectedValueException $e) {
			$this->assertSame('a failure of the source, not a refused line', $e->getMessage());
		}
		$this->assertSame([], $this->calls());
	}

	/** @return array<string, array{int, int, string, bool}> the entries after, the entries before, the mode, the force flag */
	public static function negativeTableSizesOnAReplace(): array
	{
		$rows = [];
		foreach ([[-1, 100], [100, -1], [-1, -1]] as [$entries, $previous]) {
			foreach ([['replace', FALSE], ['delta', TRUE]] as [$mode, $force]) {
				$rows["entries {$entries}, previous {$previous}, " . ($force ? 'a forced replace' : "mode {$mode}")] = [$entries, $previous, $mode, $force];
			}
		}
		return $rows;
	}

	/** A replace reloads the table from its file: a negative table size, like a negative add or remove count, does not stop it. */
	#[DataProvider('negativeTableSizesOnAReplace')]
	public function testANegativeTableSizeDoesNotStopAReplace(int $entries, int $previous, string $mode, bool $force): void
	{
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), 1, $this->members('remove', []), 0, $entries, $previous, $mode, 64, $force, $this->batchdir);

		$this->assertSame(['delta' => FALSE, 'ok' => TRUE], $result);
		$this->assertSame([['replace', 1]], $this->shape());
	}

	/** A replace that goes ahead although a count is negative says so once, with the four counts; one with sound counts says nothing of the kind. */
	public function testAReplaceWithANegativeCountLogsTheFourCountsOnce(): void
	{
		$offset = self::logOffset();
		$result = pfb_apply_alias_delta_files($this->pfctl(), self::TABLE, 'ipv4', $this->members('mirror', ['10.255.0.1']),
			$this->members('add', ['10.1.0.1']), 3, $this->members('remove', []), -2, 40, -1, 'replace', 64, FALSE, $this->batchdir);
		$this->assertSame(['delta' => FALSE, 'ok' => TRUE], $result);
		$negative = array_values(array_filter(self::loggedSince($offset), static fn (string $l): bool => str_contains($l, 'negative count')));
		$this->assertCount(1, $negative, implode(' | ', self::loggedSince($offset)));
		$this->assertStringContainsString('add 3, remove -2, entries 40, previous -1', $negative[0]);

		unlink("{$this->dir}/log");
		$offset = self::logOffset();
		$this->apply(['10.1.0.1'], [], 40, 40, 'replace');
		$this->assertSame([], array_values(array_filter(self::loggedSince($offset), static fn (string $l): bool => str_contains($l, 'negative count'))),
			'sound counts log no such line');
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

		$args = implode(', ', [var_export($this->pfctl(), TRUE), var_export(self::TABLE, TRUE), "'ipv4'", var_export($remove, TRUE),
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
