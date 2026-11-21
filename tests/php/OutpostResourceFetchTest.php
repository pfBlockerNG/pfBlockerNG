<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4037 (slice 8c): the Outpost apply's resource client fetches one resource from the Core API
 * (docs/misc/core-api-protocol.md "Resources"). It sends the cursor it holds, the stored generation with the digest of the
 * mirror as it is on disk now, and turns each answer into a new mirror, verified, or a named failure that leaves the old
 * mirror in place. The socket is served by support/CoreApiStandIn.php, which answers a script and records every request.
 */
#[CoversFunction('pfb_outpost_fetch')]
#[CoversFunction('pfb_core_fetch_body')]
final class OutpostResourceFetchTest extends TestCase
{
	private const ID = 'ip-set/Abuse/ipv4';

	private const OLD = "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n";

	private string $dir = '';

	private string $mirror = '';

	private string $work = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfbfetch' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
		$this->mirror = "{$this->dir}/pfB_Abuse_v4.txt";
		$this->work = "{$this->dir}/work";
		$this->assertTrue(mkdir($this->work, 0700));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/** A GetResources reply naming one item for $id. */
	private static function items(array $item, string $id = self::ID): array
	{
		return ['status' => 200, 'type' => 'application/json', 'body' => json_encode(['resources' => [$id => $item]])];
	}

	private static function full(string $generation, string $body, ?string $digest = NULL, ?int $entries = NULL, string $id = self::ID): array
	{
		return self::items(['kind' => 'full', 'generation' => $generation, 'digest' => $digest ?? hash('xxh128', $body),
			'entries' => $entries ?? substr_count($body, "\n"), 'metadata' => ['action' => 'deny']], $id);
	}

	private static function delta(string $generation, string $from, string $add, string $remove, string $result): array
	{
		return self::items(['kind' => 'delta', 'generation' => $generation, 'from' => $from,
			'addEntries' => substr_count($add, "\n"), 'removeEntries' => substr_count($remove, "\n"),
			'digest' => hash('xxh128', $result), 'entries' => substr_count($result, "\n"), 'metadata' => ['action' => 'deny']]);
	}

	private static function text(string $body, ?int $length = NULL): array
	{
		return ['status' => 200, 'type' => 'text/plain; charset=utf-8', 'body' => $body] + ($length === NULL ? [] : ['length' => $length]);
	}

	private static function error(int $status, string $code): array
	{
		return ['status' => $status, 'type' => 'application/json', 'body' => json_encode(['error' => ['code' => $code, 'message' => 'no']])];
	}

	/** The cursor file's entry the Outpost holds for the mirror's content $body at $generation. */
	private static function cursor(string $generation, string $body): array
	{
		return ['generation' => $generation, 'digest' => hash('xxh128', $body), 'entries' => substr_count($body, "\n")];
	}

	/**
	 * Serve $script on a fresh socket while the fetch runs against it.
	 *
	 * @return array{0: array, 1: list<array{path: string, params: mixed}>} what the fetch returned, then the requests in order
	 */
	private function fetch(array $script, ?array $cursor, int $timeout = 30, string $id = self::ID): array
	{
		$socket = "{$this->dir}/api.sock";
		file_put_contents("{$this->dir}/script.json", json_encode($script));
		@unlink("{$this->dir}/requests");
		$started = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreApiStandIn.php', $socket, "{$this->dir}/requests",
			'script', "{$this->dir}/script.json"]);
		$this->awaitListening($started);
		$result = pfb_outpost_fetch($id, $cursor, $this->mirror, $this->work, $socket, $timeout);
		$run = pfb_test_finish_process($started, 30.0);
		$this->assertSame(0, $run['exit'], "the stand-in did not serve its whole script: {$run['stderr']}");
		$requests = [];
		foreach (file("{$this->dir}/requests", FILE_IGNORE_NEW_LINES) ?: [] as $line) {
			$requests[] = json_decode($line, TRUE);
		}
		return [$result, $requests];
	}

	/**
	 * Block until the stand-in prints "ready". A stand-in that exits first fails at once with what it said; the deadline only
	 * salvages a stuck run.
	 *
	 * @param array{0: resource, 1: array<int, resource>, 2: string} $started
	 */
	private function awaitListening(array $started): void
	{
		$stdout = $started[1][1];
		$said = '';
		$deadline = hrtime(TRUE) + 10_000_000_000;
		while (!str_contains($said, "ready\n")) {
			if (feof($stdout)) {
				$run = pfb_test_finish_process($started, 5.0);
				$this->fail("the stand-in exited ({$run['exit']}) before it listened: {$run['stderr']}");
			}
			if (hrtime(TRUE) > $deadline) {
				pfb_test_finish_process($started, 1.0);
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
			$read = [$stdout];
			$write = $except = NULL;
			stream_select($read, $write, $except, 0, 100_000);
			$said .= (string) fread($stdout, 64);
		}
	}

	/** The mirror holds $body exactly, and no temporary file of the fetch is left beside it. */
	private function assertMirror(string $body): void
	{
		$this->assertFileExists($this->mirror);
		$this->assertSame($body, file_get_contents($this->mirror), 'the mirror does not hold the expected body');
		$this->assertSame([basename($this->mirror)], array_values(array_diff(scandir($this->dir), ['.', '..', 'work', 'script.json', 'requests'])),
			'a temporary file of the fetch was left beside the mirror');
	}

	private function assertFailed(array $result, string $failure): void
	{
		$this->assertFalse($result['ok'], 'the fetch succeeded: ' . json_encode($result));
		$this->assertSame($failure, $result['failure'], 'the failure is not the one expected: ' . json_encode($result));
		$this->assertIsString($result['error']);
		$this->assertNotSame('', $result['error']);
	}

	public function testWithNoCursorTheFullBodyIsFetchedVerifiedAndBecomesTheMirror(): void
	{
		[$result, $requests] = $this->fetch([self::full('7', "1.1.1.1\n198.51.100.0/24\n"), self::text("1.1.1.1\n198.51.100.0/24\n")], NULL);

		$this->assertSame('/v1/GetResources', $requests[0]['path']);
		$this->assertSame(['resources' => [self::ID => []]], $requests[0]['params'], 'with no cursor the request must carry the empty cursor');
		$this->assertSame('/v1/GetResourceBody', $requests[1]['path']);
		$this->assertSame(['id' => self::ID, 'generation' => '7', 'part' => 'members'], $requests[1]['params']);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['full', NULL, '7', hash('xxh128', "1.1.1.1\n198.51.100.0/24\n"), 2, ['action' => 'deny'], FALSE, $this->mirror],
			[$result['kind'], $result['failure'], $result['generation'], $result['digest'], $result['entries'], $result['metadata'],
				$result['fellBack'], $result['mirror']]);
		$this->assertSame([NULL, NULL, 0, 0], [$result['add'], $result['remove'], $result['addEntries'], $result['removeEntries']]);
		$this->assertMirror("1.1.1.1\n198.51.100.0/24\n");
	}

	public function testAnEmptyFullBodyIsAValidStateAndLeavesAnEmptyMirror(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::full('8', ''), self::text('')], self::cursor('7', self::OLD));

		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['full', 0], [$result['kind'], $result['entries']]);
		$this->assertMirror('');
	}

	public function testTheCursorSentIsTheStoredGenerationWithTheMirrorsDigestAndUnchangedFetchesNothing(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result, $requests] = $this->fetch([self::items(['kind' => 'unchanged', 'generation' => '7'])], self::cursor('7', self::OLD));

		$this->assertCount(1, $requests, 'an unchanged resource must fetch no body');
		$this->assertSame(['resources' => [self::ID => ['generation' => '7', 'digest' => hash('xxh128', self::OLD)]]], $requests[0]['params']);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['unchanged', '7', $this->mirror], [$result['kind'], $result['generation'], $result['mirror']]);
		$this->assertMirror(self::OLD);
	}

	public function testADeltaFetchesItsPartsToFilesAndMergesThemIntoAVerifiedMirror(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$add = "172.16.0.0/12\n203.0.113.9\n";
		$remove = "1.1.1.1\n";
		$new = "10.0.0.0/8\n172.16.0.0/12\n192.0.2.7\n203.0.113.9\n";
		[$result, $requests] = $this->fetch([self::delta('9', '7', $add, $remove, $new), self::text($add), self::text($remove)],
			self::cursor('7', self::OLD));

		$this->assertSame(['id' => self::ID, 'generation' => '9', 'part' => 'add', 'from' => '7'], $requests[1]['params']);
		$this->assertSame(['id' => self::ID, 'generation' => '9', 'part' => 'remove', 'from' => '7'], $requests[2]['params']);
		$this->assertCount(3, $requests);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['delta', '9', hash('xxh128', $new), 4, 2, 1, FALSE],
			[$result['kind'], $result['generation'], $result['digest'], $result['entries'], $result['addEntries'], $result['removeEntries'],
				$result['fellBack']]);
		$this->assertSame($add, file_get_contents((string) $result['add']), 'the add part was not handed back as a file');
		$this->assertSame($remove, file_get_contents((string) $result['remove']), 'the remove part was not handed back as a file');
		$this->assertStringStartsWith($this->work . '/', (string) $result['add']);
		$this->assertStringStartsWith($this->work . '/', (string) $result['remove']);
		$this->assertMirror($new);
	}

	public function testAMetadataOnlyDeltaKeepsTheMembersAndAdvancesTheGeneration(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::delta('8', '7', '', '', self::OLD), self::text(''), self::text('')], self::cursor('7', self::OLD));

		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['delta', '8', 0, 0], [$result['kind'], $result['generation'], $result['addEntries'], $result['removeEntries']]);
		$this->assertMirror(self::OLD);
	}

	public function testAResourceTheStoreDoesNotHoldIsReportedRemovedAndTheMirrorIsLeftAlone(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result, $requests] = $this->fetch([self::items(['error' => ['code' => 'not_found', 'message' => 'gone']])], self::cursor('7', self::OLD));

		$this->assertCount(1, $requests);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame('not_found', $result['kind']);
		$this->assertMirror(self::OLD);
	}

	public function testAResourceTheStoreCannotServeFailsThatResource(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::items(['error' => ['code' => 'unavailable', 'message' => 'damaged']])], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'unavailable');
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{array, string, ?string}> */
	public static function callErrors(): array
	{
		return [
			'Core runs no store or is stopping' => [self::error(503, 'unavailable'), 'core_unavailable', 'unavailable'],
			'the caller is not admitted'        => [self::error(401, 'unauthenticated'), 'refused', 'unauthenticated'],
			'the request was refused'           => [self::error(400, 'invalid_argument'), 'refused', 'invalid_argument'],
			'a code holding a line break'       => [self::error(400, "invalid_argument\nINJECTED"), 'refused', NULL],
			'a code of 100 bytes'               => [self::error(400, str_repeat('a', 100)), 'refused', NULL],
		];
	}

	#[DataProvider('callErrors')]
	public function testAnErrorAnsweredToTheWholeCallIsNamedAndChangesNothing(array $reply, string $failure, ?string $code): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([$reply], self::cursor('7', self::OLD));

		$this->assertFailed($result, $failure);
		$this->assertSame($code, $result['code']);
		$this->assertMirror(self::OLD);
	}

	public function testCoreAnsweringNothingUntilTheCallsDeadlineIsUnreachable(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result, $requests] = $this->fetch([['hang' => TRUE]], self::cursor('7', self::OLD), 1);

		$this->assertCount(1, $requests);
		$this->assertFailed($result, 'unreachable');
		$this->assertMirror(self::OLD);
	}

	public function testCoreNotListeningIsUnreachable(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$result = pfb_outpost_fetch(self::ID, self::cursor('7', self::OLD), $this->mirror, $this->work, "{$this->dir}/none.sock", 5);

		$this->assertFailed($result, 'unreachable');
		$this->assertMirror(self::OLD);
	}

	public function testABodyThatGoesSilentUntilItsDeadlineIsUnreachable(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n"), ['hang' => TRUE]], self::cursor('7', self::OLD), 1);

		$this->assertFailed($result, 'unreachable');
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{array}> */
	public static function wrongShapes(): array
	{
		$full = ['kind' => 'full', 'generation' => '8', 'digest' => str_repeat('a', 32), 'entries' => 1, 'metadata' => []];
		$delta = ['kind' => 'delta', 'generation' => '8', 'from' => '7', 'addEntries' => 0, 'removeEntries' => 0,
			'digest' => str_repeat('a', 32), 'entries' => 1, 'metadata' => []];
		$json = static fn (string $body): array => ['status' => 200, 'type' => 'application/json', 'body' => $body];
		return [
			'not JSON'                              => [$json('oops')],
			'a list'                                => [$json('[1]')],
			'no resources'                          => [$json('{"other":{}}')],
			'resources is a list'                   => [$json('{"resources":[1]}')],
			'an item for another id only'           => [self::items($full, 'ip-set/Other/ipv4')],
			'two items'                             => [$json(json_encode(['resources' => [self::ID => $full, 'ip-set/Other/ipv4' => $full]]))],
			'the item is not an object'             => [$json(json_encode(['resources' => [self::ID => 'full']]))],
			'an unknown kind'                       => [self::items(['kind' => 'patch'] + $full)],
			'an unknown error code'                 => [self::items(['error' => ['code' => 'internal', 'message' => 'x']])],
			'full without a digest'                 => [self::items(array_diff_key($full, ['digest' => 1]))],
			'full with an upper-case digest'        => [self::items(['digest' => str_repeat('A', 32)] + $full)],
			'full with a short digest'              => [self::items(['digest' => str_repeat('a', 31)] + $full)],
			'full with a numeric generation'        => [self::items(['generation' => 8] + $full)],
			'full with a signed generation'         => [self::items(['generation' => '-8'] + $full)],
			'full with a generation over 64 bits'   => [self::items(['generation' => '18446744073709551616'] + $full)],
			'full with negative entries'            => [self::items(['entries' => -1] + $full)],
			'full with entries as a string'         => [self::items(['entries' => '1'] + $full)],
			'full with metadata that is no object'  => [self::items(['metadata' => 'deny'] + $full)],
			'delta without removeEntries'           => [self::items(array_diff_key($delta, ['removeEntries' => 1]))],
			'delta with negative addEntries'        => [self::items(['addEntries' => -1] + $delta)],
			'delta with negative removeEntries'     => [self::items(['removeEntries' => -1] + $delta)],
			'delta from another generation'         => [self::items(['from' => '6'] + $delta)],
			'delta whose generation goes backwards' => [self::items(['generation' => '5'] + $delta)],
			'delta whose generation is its from'    => [self::items(['generation' => '7'] + $delta)],
			'delta from a generation that is none'  => [self::items(['from' => '07x'] + $delta)],
			'unchanged at another generation'       => [self::items(['kind' => 'unchanged', 'generation' => '6'])],
		];
	}

	#[DataProvider('wrongShapes')]
	public function testAnAnswerOfTheWrongShapeIsRefusedWholeAndNoBodyIsFetched(array $reply): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result, $requests] = $this->fetch([$reply], self::cursor('7', self::OLD));

		$this->assertCount(1, $requests, 'a body was fetched for an answer of the wrong shape');
		$this->assertFailed($result, 'reply');
		$this->assertMirror(self::OLD);
	}

	public function testUnchangedOrADeltaAnsweredToNoCursorIsTheWrongShape(): void
	{
		[$result] = $this->fetch([self::items(['kind' => 'unchanged', 'generation' => '7'])], NULL);
		$this->assertFailed($result, 'reply');

		[$result] = $this->fetch([self::delta('8', '7', '', '', '')], NULL);
		$this->assertFailed($result, 'reply');
		$this->assertFileDoesNotExist($this->mirror);
	}

	/** A connection that ends short of the body's Content-Length is a transport failure, not a body of the wrong shape. */
	public function testABodyCutShortOfItsContentLengthIsUnreachableAndKeepsTheMirror(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "1.1.1.1\n8.8.8.8\n";
		[$result] = $this->fetch([self::full('8', $body), self::text("1.1.1.1\n8.8", strlen($body))], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'unreachable');
		$this->assertMirror(self::OLD);
	}

	public function testABodyWhoseDigestDiffersFromTheReplysFailsTheResourceAndKeepsTheMirror(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n"), self::text("8.8.8.8\n")], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'verify');
		$this->assertMirror(self::OLD);
	}

	public function testABodyWhoseLineCountDiffersFromTheReplysFailsTheResource(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "1.1.1.1\n8.8.8.8\n";
		[$result] = $this->fetch([self::full('8', $body, NULL, 3), self::text($body)], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'verify');
		$this->assertMirror(self::OLD);
	}

	public function testABodyThatIsNotPlainTextFailsTheResource(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "1.1.1.1\n";
		[$result] = $this->fetch([self::full('8', $body), ['status' => 200, 'type' => 'application/json', 'body' => $body]],
			self::cursor('7', self::OLD));

		$this->assertFailed($result, 'body');
		$this->assertMirror(self::OLD);
	}

	public function testABodyAnsweredUnavailableFailsThatResource(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n"), self::error(503, 'unavailable')], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'unavailable');
		$this->assertMirror(self::OLD);
	}

	public function testABodyPrunedByARacingPublishIsAskedForAgainOnce(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "8.8.8.8\n";
		[$result, $requests] = $this->fetch([self::full('8', "1.1.1.1\n"), self::error(404, 'not_found'), self::full('9', $body), self::text($body)],
			self::cursor('7', self::OLD));

		$this->assertCount(4, $requests);
		$this->assertSame($requests[0]['params'], $requests[2]['params'], 'the second ask must send the same cursor');
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['full', '9'], [$result['kind'], $result['generation']]);
		$this->assertMirror($body);
	}

	public function testABodyPrunedTwiceFailsTheResource(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result, $requests] = $this->fetch([self::full('8', "1.1.1.1\n"), self::error(404, 'not_found'), self::full('9', "2.2.2.2\n"),
			self::error(404, 'not_found')], self::cursor('7', self::OLD));

		$this->assertCount(4, $requests);
		$this->assertFailed($result, 'body');
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{string, string}> */
	public static function failedMerges(): array
	{
		return [
			'the merge gives another digest'            => ["2.2.2.2\n", "1.1.1.1\n"],
			'remove names a member the mirror lacks'    => ['', "3.3.3.3\n"],
			'add names a member the mirror already has' => ["10.0.0.0/8\n", ''],
		];
	}

	#[DataProvider('failedMerges')]
	public function testADeltaWhoseMergeFailsIsDiscardedAndTheFullBodyIsFetchedInstead(string $add, string $remove): void
	{
		file_put_contents($this->mirror, self::OLD);
		$full = "4.4.4.4\n";
		// the delta names a digest its parts cannot produce from this mirror
		$reply = self::delta('9', '7', $add, $remove, "9.9.9.9\n");
		[$result, $requests] = $this->fetch([$reply, self::text($add), self::text($remove), self::full('9', $full), self::text($full)],
			self::cursor('7', self::OLD));

		$this->assertCount(5, $requests);
		$this->assertSame(['resources' => [self::ID => []]], $requests[3]['params'], 'the fallback must ask with the empty cursor');
		$this->assertSame(['id' => self::ID, 'generation' => '9', 'part' => 'members'], $requests[4]['params']);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['full', TRUE, NULL, NULL], [$result['kind'], $result['fellBack'], $result['add'], $result['remove']]);
		$this->assertMirror($full);
	}

	/**
	 * The merge must give exactly the body the reply describes. A merge of the right line count whose digest is that of another
	 * body of the same length, or of the right digest beside another count, is discarded (review of slice 8c, L2).
	 *
	 * @return array<string, array{string, int}>
	 */
	public static function mergesThatAreNotTheReply(): array
	{
		$merged = "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n";
		return [
			'the digest of another body of the same length' => ["1.1.1.1\n10.0.0.0/8\n192.0.2.7\n3.3.3.3\n", 4],
			'the right digest beside another count'         => [$merged, 5],
		];
	}

	#[DataProvider('mergesThatAreNotTheReply')]
	public function testAMergeThatIsNotTheBodyTheReplyDescribesFallsBack(string $described, int $entries): void
	{
		file_put_contents($this->mirror, self::OLD);
		$add = "2.2.2.2\n";
		$reply = self::items(['kind' => 'delta', 'generation' => '9', 'from' => '7', 'addEntries' => 1, 'removeEntries' => 0,
			'digest' => hash('xxh128', $described), 'entries' => $entries, 'metadata' => []]);
		$full = "4.4.4.4\n";
		[$result, $requests] = $this->fetch([$reply, self::text($add), self::text(''), self::full('9', $full), self::text($full)],
			self::cursor('7', self::OLD));

		$this->assertCount(5, $requests);
		$this->assertSame(['resources' => [self::ID => []]], $requests[3]['params'], 'the fallback must ask with the empty cursor');
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['full', TRUE], [$result['kind'], $result['fellBack']]);
		$this->assertMirror($full);
	}

	/** @return array<string, array{string}> */
	public static function scratchPaths(): array
	{
		return ['the add part' => ['work/add'], 'the remove part' => ['work/remove'], 'the staged mirror' => ['pfB_Abuse_v4.txt.new']];
	}

	/** A symbolic link where the fetch writes is replaced, never written through (review of slice 8c, L9). */
	#[DataProvider('scratchPaths')]
	public function testALinkWhereTheFetchWritesIsNotFollowed(string $path): void
	{
		file_put_contents($this->mirror, self::OLD);
		$target = "{$this->dir}/target";
		file_put_contents($target, 'keep');
		$this->assertTrue(symlink($target, "{$this->dir}/{$path}"));
		$add = "2.2.2.2\n";
		$new = "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n";
		[$result] = $this->fetch([self::delta('9', '7', $add, '', $new), self::text($add), self::text('')], self::cursor('7', self::OLD));

		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame('keep', file_get_contents($target), 'the link target was written through');
		unlink($target);
		$this->assertMirror($new);
	}

	public function testWhenTheFallbackFullBodyFailsTooTheMirrorIsUnchangedAndTheFailureNamed(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$reply = self::delta('9', '7', "2.2.2.2\n", '', "9.9.9.9\n");
		[$result] = $this->fetch([$reply, self::text("2.2.2.2\n"), self::text(''), self::full('9', "4.4.4.4\n"), self::text("5.5.5.5\n")],
			self::cursor('7', self::OLD));

		$this->assertFailed($result, 'verify');
		$this->assertTrue($result['fellBack']);
		$this->assertMirror(self::OLD);
	}

	public function testAFullBodyWithALineThatIsNotAMemberIsRefusedWhole(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "1.1.1.1\n1.2.3.4-1.2.3.9\n";
		[$result] = $this->fetch([self::full('8', $body), self::text($body)], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'members');
		$this->assertMirror(self::OLD);
	}

	public function testAFullBodyThatIsNotSortedIsRefusedWhole(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "8.8.8.8\n1.1.1.1\n";
		[$result] = $this->fetch([self::full('8', $body), self::text($body)], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'members');
		$this->assertMirror(self::OLD);
	}

	public function testADeltaPartWithALineThatIsNotAMemberIsRefusedWithoutAFallback(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$add = "evil.example.com\n";
		[$result, $requests] = $this->fetch([self::delta('9', '7', $add, '', self::OLD . $add), self::text($add), self::text('')],
			self::cursor('7', self::OLD));

		$this->assertCount(3, $requests, 'a part that fails the member check must not be retried as a full body');
		$this->assertFailed($result, 'members');
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{array, array}> */
	public static function failedDeltaParts(): array
	{
		$add = "2.2.2.2\n";
		return [
			'an add part of more lines than the reply named' => [self::text("2.2.2.2\n3.3.3.3\n"), self::text('')],
			'a remove part of more lines than it named'      => [self::text($add), self::text("1.1.1.1\n")],
		];
	}

	/**
	 * A delta part that does not arrive as the reply described it fails the same way on every run, so it is discarded like a
	 * failed merge and the full body asked for (review of slice 8c, L4).
	 */
	#[DataProvider('failedDeltaParts')]
	public function testADeltaPartThatIsNotWhatTheReplyNamedFallsBackToTheFullBody(array $addReply, array $removeReply): void
	{
		file_put_contents($this->mirror, self::OLD);
		$reply = self::delta('9', '7', "2.2.2.2\n", '', "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n");
		$full = "4.4.4.4\n";
		[$result, $requests] = $this->fetch([$reply, $addReply, $removeReply, self::full('9', $full), self::text($full)],
			self::cursor('7', self::OLD));

		$this->assertSame(['resources' => [self::ID => []]], $requests[count($requests) - 2]['params'], 'the fallback must ask with the empty cursor');
		$this->assertSame(['id' => self::ID, 'generation' => '9', 'part' => 'members'], $requests[count($requests) - 1]['params']);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['full', TRUE, NULL, NULL, 0, 0], [$result['kind'], $result['fellBack'], $result['add'], $result['remove'],
			$result['addEntries'], $result['removeEntries']]);
		$this->assertMirror($full);
	}

	/** @return array<string, array{array, int}> */
	public static function partsCutOffByTheTransport(): array
	{
		return [
			'closed short of its Content-Length' => [self::text('2.2.', 8), 30],
			'silent after a few bytes'           => [['stall' => TRUE] + self::text('2.2.', 8), 1],
		];
	}

	/**
	 * Scenario: a delta part starts to arrive and the transport ends it (the connection closes short of its Content-Length, or
	 * the call's deadline passes while it is silent). Core is not answering: the fetch is unreachable and asks for no full body
	 * under the same deadline.
	 */
	#[DataProvider('partsCutOffByTheTransport')]
	public function testADeltaPartTheTransportCutsOffIsUnreachableWithoutAFallback(array $addReply, int $timeout): void
	{
		file_put_contents($this->mirror, self::OLD);
		$reply = self::delta('9', '7', "2.2.2.2\n", '', "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n");
		[$result, $requests] = $this->fetch([$reply, $addReply], self::cursor('7', self::OLD), $timeout);

		$this->assertSame(['/v1/GetResources', '/v1/GetResourceBody'], array_column($requests, 'path'));
		$this->assertFailed($result, 'unreachable');
		$this->assertFalse($result['fellBack']);
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{?array, string}> */
	public static function partFailuresThatAreNotTheDeltas(): array
	{
		return [
			'an error envelope with a code'       => [self::error(500, 'internal'), 'body'],
			'the store cannot serve the part'     => [self::error(503, 'unavailable'), 'unavailable'],
			'Core stops listening before the part' => [NULL, 'unreachable'],
		];
	}

	/**
	 * A delta part that fails for a reason a full body would meet too (Core named the error, cannot serve, or does not answer)
	 * fails the resource: no full body is asked for.
	 */
	#[DataProvider('partFailuresThatAreNotTheDeltas')]
	public function testADeltaPartFailureThatIsNotTheDeltasOwnDoesNotFallBack(?array $addReply, string $failure): void
	{
		file_put_contents($this->mirror, self::OLD);
		$reply = self::delta('9', '7', "2.2.2.2\n", '', "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n");
		[$result, $requests] = $this->fetch($addReply === NULL ? [$reply] : [$reply, $addReply], self::cursor('7', self::OLD));

		$this->assertSame(1, count(array_keys(array_column($requests, 'path'), '/v1/GetResources')), 'a full body was asked for');
		$this->assertFailed($result, $failure);
		$this->assertFalse($result['fellBack']);
		$this->assertMirror(self::OLD);
	}

	public function testAFallbackFullBodyThatIsNotWhatTheReplyNamedFailsWithoutAnotherFallback(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$reply = self::delta('9', '7', "2.2.2.2\n", '', "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n");
		[$result, $requests] = $this->fetch([$reply, self::text("2.2.2.2\n3.3.3.3\n"), self::text(''), self::full('9', "4.4.4.4\n"),
			self::text("4.4.4.4\n5.5.5.5\n")], self::cursor('7', self::OLD));

		$this->assertCount(5, $requests);
		$this->assertFailed($result, 'verify');
		$this->assertTrue($result['fellBack']);
		$this->assertMirror(self::OLD);
	}

	/**
	 * Scenario: the cursor file holds a generation as "007" and Core answers "7". A generation is a number written as decimal
	 * digits (protocol "Request": "007" is valid), so the answer is to that cursor (review of slice 8c, L3).
	 */
	public function testAGenerationIsComparedByItsValueNotItsSpelling(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::items(['kind' => 'unchanged', 'generation' => '7'])], self::cursor('007', self::OLD));
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['unchanged', '7'], [$result['kind'], $result['generation']]);

		$add = "2.2.2.2\n";
		$new = "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n";
		[$result, $requests] = $this->fetch([self::delta('9', '7', $add, '', $new), self::text($add), self::text('')], self::cursor('007', self::OLD));
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['delta', '9'], [$result['kind'], $result['generation']]);
		$this->assertSame(['id' => self::ID, 'generation' => '9', 'part' => 'add', 'from' => '7'], $requests[1]['params'],
			'a part must name the generations as GetResources gave them');
		$this->assertMirror($new);
	}

	/** Scenario: the cursor file holds "7" and Core spells the same generation "007": the answer is to that cursor. */
	public function testAGenerationCoreSpellsWithLeadingZerosIsTheCursorsGeneration(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::items(['kind' => 'unchanged', 'generation' => '007'])], self::cursor('7', self::OLD));
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['unchanged', '007'], [$result['kind'], $result['generation']]);

		$add = "2.2.2.2\n";
		$new = "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n2.2.2.2\n";
		[$result] = $this->fetch([self::delta('9', '007', $add, '', $new), self::text($add), self::text('')], self::cursor('7', self::OLD));
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['delta', '9'], [$result['kind'], $result['generation']]);
		$this->assertMirror($new);
	}

	public function testADeltaAcrossADigitBoundaryMovesForward(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$new = "1.1.1.1\n10.0.0.0/8\n";
		[$result] = $this->fetch([self::delta('10', '9', '', "192.0.2.7\n", $new), self::text(''), self::text("192.0.2.7\n")],
			self::cursor('9', self::OLD));

		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['delta', '10'], [$result['kind'], $result['generation']]);
		$this->assertMirror($new);
	}

	/**
	 * Scenario: a delta is answered, its body was pruned by a racing publish, and the second GetResources says the resource is
	 * gone. The result describes only what the second answer said: nothing of the vanished generation (review of slice 8c, L8).
	 */
	public function testASecondPassReturnsNoFieldOfTheFirst(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$add = "2.2.2.2\n";
		[$result, $requests] = $this->fetch([self::delta('9', '7', $add, '', self::OLD . $add), self::error(404, 'not_found'),
			self::items(['error' => ['code' => 'not_found', 'message' => 'gone']])], self::cursor('7', self::OLD));

		$this->assertCount(3, $requests);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['not_found', NULL, NULL, NULL, NULL, NULL, NULL, 0, 0],
			[$result['kind'], $result['generation'], $result['digest'], $result['entries'], $result['metadata'], $result['add'],
				$result['remove'], $result['addEntries'], $result['removeEntries']]);
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{mixed}> */
	public static function malformedCodes(): array
	{
		return [
			'upper case'           => ['NotFound'],
			'a line feed'          => ["not_found\nINJECTED"],
			'a space'              => ['not found'],
			'empty'                => [''],
			'longer than 64 bytes' => [str_repeat('a', 65)],
			'a number'             => [404],
		];
	}

	/** Only a code of the protocol's shape reaches the result, which the apply logs (review of slice 8c, L5). */
	#[DataProvider('malformedCodes')]
	public function testABodyErrorWhoseCodeIsNotACodeIsAMalformedReply(mixed $code): void
	{
		file_put_contents($this->mirror, self::OLD);
		$reply = ['status' => 500, 'type' => 'application/json', 'body' => json_encode(['error' => ['code' => $code, 'message' => 'no']])];
		[$result, $requests] = $this->fetch([self::full('8', "1.1.1.1\n"), $reply], self::cursor('7', self::OLD));

		$this->assertCount(2, $requests);
		$this->assertFailed($result, 'body');
		$this->assertNull($result['code']);
		$this->assertStringContainsString('malformed', (string) $result['error']);
		if (is_string($code) && $code !== '') {
			$this->assertStringNotContainsString($code, (string) $result['error'], 'the code that is not a code reached the error text');
		}
		$this->assertMirror(self::OLD);
	}

	public function testABodyErrorWithTheLongestCodeKeepsItsCode(): void
	{
		file_put_contents($this->mirror, self::OLD);
		$code = str_repeat('a', 63) . '_';
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n"), self::error(500, $code)], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'body');
		$this->assertSame($code, $result['code']);
	}

	/** @return array<string, array{array}> */
	public static function bodiesOverTheirBound(): array
	{
		// one member of an IP set is at most 64 bytes and its line feed: the bound of a one-entry body is 65 bytes
		$long = "1.1.1.1\n2.2.2.2\n3.3.3.3\n4.4.4.4\n5.5.5.5\n6.6.6.6\n7.7.7.7\n8.8.8.8\n9.9.9.9\n";
		return [
			'a Content-Length over the bound'            => [self::text($long)],
			'a body with no Content-Length that runs on' => [['close' => TRUE] + self::text($long)],
		];
	}

	/** A body longer than the reply's entries can make is refused, not written to disk whole (review of slice 8c, L6). */
	#[DataProvider('bodiesOverTheirBound')]
	public function testABodyLongerThanItsEntriesAllowIsRefused(array $body): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n"), $body], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'body');
		$this->assertStringContainsString('65 bytes', (string) $result['error'], 'the refusal must name the bound');
		$this->assertMirror(self::OLD);
	}

	/** A Content-Length over the bound refuses the body before any of it is written, even when fewer bytes would follow. */
	public function testAContentLengthOverTheBoundIsRefusedBeforeTheBodyIsRead(): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n"), self::text("1.1.1.1\n", 1000)], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'body');
		$this->assertStringContainsString('65 bytes', (string) $result['error'], 'the refusal must name the bound');
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{int}> */
	public static function lineCountsAtTheLimitOfTheBound(): array
	{
		// 65 bytes a line: the largest count whose bound a PHP integer holds, and the next, whose bound is every size
		return [
			'the largest count'   => [intdiv(PHP_INT_MAX, 65)],
			'one line more'       => [intdiv(PHP_INT_MAX, 65) + 1],
		];
	}

	/**
	 * A line count so large that its bound passes what a PHP integer holds bounds nothing, rather than wrapping to a negative
	 * bound that refuses every body: the body arrives and is refused for its line count.
	 */
	#[DataProvider('lineCountsAtTheLimitOfTheBound')]
	public function testALineCountWhoseBoundPassesTheIntegerRangeLeavesTheBodyUnbounded(int $entries): void
	{
		file_put_contents($this->mirror, self::OLD);
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n", NULL, $entries), self::text("1.1.1.1\n")], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'verify');
		$this->assertMirror(self::OLD);
	}

	/** An error envelope of exactly $length bytes with the code unavailable. */
	private static function envelope(int $length): string
	{
		$empty = json_encode(['error' => ['code' => 'unavailable', 'message' => '']]);
		return json_encode(['error' => ['code' => 'unavailable', 'message' => str_repeat('x', $length - strlen($empty))]]);
	}

	/** @return array<string, array{int, int}> */
	public static function envelopesOverTheirCap(): array
	{
		return [
			'HTTP 200, one byte over 64 KiB'  => [200, 65537],
			'HTTP 503, one byte over 64 KiB'  => [503, 65537],
			'HTTP 200, well over 64 KiB'      => [200, 300000],
		];
	}

	/**
	 * An answer that is not a plain-text body is an error envelope, and an envelope is read at most 64 KiB whatever the status
	 * and the part's bound: a longer one is malformed, its code untaken.
	 */
	#[DataProvider('envelopesOverTheirCap')]
	public function testAnEnvelopeOverSixtyFourKiBIsMalformedWhateverTheStatus(int $status, int $length): void
	{
		file_put_contents($this->mirror, self::OLD);
		$envelope = ['status' => $status, 'type' => 'application/json', 'body' => self::envelope($length)];
		$this->assertSame($length, strlen($envelope['body']));
		// 10000 lines of an IP set: a bound of 650000 bytes, far over the envelope's cap
		[$result] = $this->fetch([self::full('8', "1.1.1.1\n", NULL, 10000), $envelope], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'body');
		$this->assertNull($result['code']);
		$this->assertStringContainsString('65536 bytes', (string) $result['error'], 'the refusal must name the envelope cap');
		$this->assertMirror(self::OLD);
	}

	/** @return array<string, array{int}> */
	public static function errorStatuses(): array
	{
		return ['404' => [404], '500' => [500]];
	}

	/** Only an HTTP 200 answer is a body: plain text of well-formed members under an error status is not taken. */
	#[DataProvider('errorStatuses')]
	public function testAPlainTextAnswerUnderAnErrorStatusIsNotABody(int $status): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "1.1.1.1\n";
		[$result] = $this->fetch([self::full('8', $body), ['status' => $status] + self::text($body)], self::cursor('7', self::OLD));

		$this->assertFailed($result, 'body');
		$this->assertMirror(self::OLD);
	}

	public function testABodyOfAnotherResourceMayHoldMembersOfOneMebibyte(): void
	{
		$rows = str_repeat('a', 1 << 20) . "\n";
		[$result] = $this->fetch([self::full('3', $rows, NULL, NULL, 'geo-catalog'), ['close' => TRUE] + self::text($rows)], NULL, 30, 'geo-catalog');
		$this->assertTrue($result['ok'], json_encode(['error' => $result['error']]));
		$this->assertMirror($rows);

		unlink($this->mirror);
		$over = $rows . 'b';
		[$result] = $this->fetch([self::full('4', $rows, NULL, NULL, 'geo-catalog'), ['close' => TRUE] + self::text($over)], NULL, 30, 'geo-catalog');
		$this->assertFailed($result, 'body');
		$this->assertFileDoesNotExist($this->mirror);
	}

	/** @return array<string, array{string, bool}> */
	public static function contentTypes(): array
	{
		return [
			'text/plain'                 => ['text/plain', TRUE],
			'text/plain with parameters' => ['text/plain; charset=utf-8', TRUE],
			'Text/Plain'                 => ['Text/Plain;charset=utf-8', TRUE],
			'a longer type name'         => ['text/plainish', FALSE],
			'text/html'                  => ['text/html', FALSE],
		];
	}

	#[DataProvider('contentTypes')]
	public function testOnlyAPlainTextBodyIsTaken(string $type, bool $taken): void
	{
		file_put_contents($this->mirror, self::OLD);
		$body = "1.1.1.1\n";
		[$result] = $this->fetch([self::full('8', $body), ['type' => $type] + self::text($body)], self::cursor('7', self::OLD));

		if ($taken) {
			$this->assertTrue($result['ok'], json_encode($result));
			$this->assertMirror($body);
		} else {
			$this->assertFailed($result, 'body');
			$this->assertMirror(self::OLD);
		}
	}

	public function testAnIPv6SetRefusesAnIPv4Member(): void
	{
		$body = "1.1.1.1\n";
		[$result] = $this->fetch([self::full('3', $body, NULL, NULL, 'ip-set/Abuse/ipv6'), self::text($body)], NULL, 30, 'ip-set/Abuse/ipv6');

		$this->assertFailed($result, 'members');
		$this->assertFileDoesNotExist($this->mirror);
	}

	public function testABodyOfAResourceThatIsNotAnIPSetIsCheckedAgainstCoresMemberRule(): void
	{
		$rows = "{\"cc\":\"AD\"}\n{\"cc\":\"AE\"}\n";
		[$result] = $this->fetch([self::full('3', $rows, NULL, NULL, 'geo-catalog'), self::text($rows)], NULL, 30, 'geo-catalog');
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertMirror($rows);

		unlink($this->mirror);
		$bad = "#comment\n{\"cc\":\"AD\"}\n";
		[$result] = $this->fetch([self::full('4', $bad, NULL, NULL, 'geo-catalog'), self::text($bad)], NULL, 30, 'geo-catalog');
		$this->assertFailed($result, 'members');
		$this->assertFileDoesNotExist($this->mirror);
	}

	public function testALowerGenerationIsTakenOnlyAsAFullBodyThatVerifies(): void
	{
		// a rebuilt store answers full from generation 1 (decision on issue #4036)
		file_put_contents($this->mirror, self::OLD);
		$body = "8.8.8.8\n";
		[$result] = $this->fetch([self::full('3', $body), self::text($body)], self::cursor('42', self::OLD));
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertSame(['full', '3'], [$result['kind'], $result['generation']]);
		$this->assertMirror($body);

		[$result] = $this->fetch([self::full('2', "9.9.9.9\n"), self::text("1.2.3.4\n")], self::cursor('42', $body));
		$this->assertFailed($result, 'verify');
		$this->assertMirror($body);
	}

	public function testAMirrorEditedOnDiskIsSentWithItsOwnDigestSoCoreAnswersFull(): void
	{
		file_put_contents($this->mirror, "1.1.1.1\n6.6.6.6\n");
		$body = "8.8.8.8\n";
		[$result, $requests] = $this->fetch([self::full('7', $body), self::text($body)], self::cursor('7', self::OLD));

		$sent = $requests[0]['params']['resources'][self::ID];
		$this->assertSame(['generation' => '7', 'digest' => hash('xxh128', "1.1.1.1\n6.6.6.6\n")], $sent,
			'the cursor must carry the digest of the mirror as it is on disk, not the stored one');
		$this->assertNotSame(self::cursor('7', self::OLD)['digest'], $sent['digest']);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertMirror($body);
	}

	public function testAMissingMirrorSendsNoCursor(): void
	{
		$body = "8.8.8.8\n";
		[$result, $requests] = $this->fetch([self::full('8', $body), self::text($body)], self::cursor('7', self::OLD));

		$this->assertSame(['resources' => [self::ID => []]], $requests[0]['params']);
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertMirror($body);
	}

	public function testAMirrorThatIsASymbolicLinkIsNeitherTrustedNorFollowed(): void
	{
		$target = "{$this->work}/elsewhere";
		file_put_contents($target, self::OLD);
		$this->assertTrue(symlink($target, $this->mirror));
		$body = "8.8.8.8\n";
		[$result, $requests] = $this->fetch([self::full('8', $body), self::text($body)], self::cursor('7', self::OLD));

		$this->assertSame(['resources' => [self::ID => []]], $requests[0]['params'], 'a linked mirror must not be sent as a cursor');
		$this->assertTrue($result['ok'], json_encode($result));
		$this->assertFalse(is_link($this->mirror), 'the link was not replaced by the new mirror');
		$this->assertMirror($body);
		$this->assertSame(self::OLD, file_get_contents($target), 'the link target was written through');
	}

	public function testAMirrorThatIsADirectoryFailsTheResourceAndStaysAsItWas(): void
	{
		$this->assertTrue(mkdir($this->mirror));
		$body = "8.8.8.8\n";
		[$result, $requests] = $this->fetch([self::full('8', $body), self::text($body)], self::cursor('7', self::OLD));

		$this->assertSame(['resources' => [self::ID => []]], $requests[0]['params']);
		$this->assertFailed($result, 'mirror');
		$this->assertDirectoryExists($this->mirror);
		$this->assertSame([basename($this->mirror)], array_values(array_diff(scandir($this->dir), ['.', '..', 'work', 'script.json', 'requests'])),
			'a temporary file of the fetch was left beside the mirror');
	}
}
