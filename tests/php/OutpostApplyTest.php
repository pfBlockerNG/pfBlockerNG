<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #4037 (slice 8e): the version 2 apply. Core's request on stdin names the resources to apply; the Outpost fetches each
 * from the Core API, brings its mirror and its pf table to the generation served, keeps its cursor, and reports per resource
 * on fd 3 (docs/misc/core-api-protocol.md, "Update command, version 2").
 *
 * Each scenario runs in the child process of corpus A (support/OutpostApplyCorpusWorker.php) over the PHPUnit doubles, with
 * everything it writes under its own directory: a first step runs today's update pass to build the alias, its rules and its
 * table, and a later step runs the version 2 apply against a Core API served by support/CoreApiStandIn.php from a script.
 */
#[CoversFunction('pfb_outpost_apply')]
#[CoversFunction('pfb_core_update_serve')]
final class OutpostApplyTest extends TestCase
{
	private const ABUSE = 'ip-set/Abuse/ipv4';

	private const BETA = 'ip-set/Beta/ipv4';

	private const OLD = ['192.0.2.1', '192.0.2.2', '198.51.100.0/24'];

	private const NEW = ['192.0.2.1', '198.51.100.0/24', '203.0.113.9'];

	/** @var list<string> */
	private array $dirs = [];

	protected function tearDown(): void
	{
		foreach ($this->dirs as $dir) {
			rmdir_recursive($dir);
		}
	}

	// ---- scenario builders --------------------------------------------------------------------

	/** $lines as a body: one member per line in byte order, each ending in a newline. */
	private static function body(array $lines): string
	{
		sort($lines, SORT_STRING);
		return implode('', array_map(static fn (string $l): string => "{$l}\n", $lines));
	}

	private static function digest(array $lines): string
	{
		return hash('xxh128', self::body($lines));
	}

	/** An IP group of config.xml with a custom list, so it is an alias the configuration expects. */
	private static function group(string $name, string $action = 'Deny_Both'): array
	{
		return ['aliasname' => $name, 'action' => $action, 'cron' => 'EveryDay', 'aliaslog' => 'enabled', 'autoproto_in' => '',
			'autoproto_out' => '', 'agateway_in' => 'default', 'agateway_out' => 'default', 'srcint' => '', 'whois_convert' => '',
			'custom' => ['192.0.2.1'], 'row' => []];
	}

	/** The first step: today's update pass builds the groups' aliases, rules and tables. */
	private static function prime(array $groups): array
	{
		return ['config' => ['installedpackages/pfblockernglistsv4/config' => $groups,
			'installedpackages/pfblockerng/config/0/pfb_alias_delta_mode' => 'delta']];
	}

	/** The files and kernel table of an alias at a generation the cursor file records. */
	private static function at(array $cursors): array
	{
		$files = [];
		$kernel = [];
		$entries = [];
		foreach ($cursors as $id => [$generation, $lines]) {
			$alias = pfb_core_update_v2_alias($id);
			$files["{aliasdir}/{$alias}.txt"] = explode("\n", rtrim(self::body($lines), "\n"));
			$kernel[$alias] = 'mirror';
			$entries[$id] = ['generation' => $generation, 'digest' => self::digest($lines), 'entries' => count($lines)];
		}
		$files['{dbdir}/pfb_apply_cursors.json'] = [json_encode(['schema' => 1, 'resources' => $entries], JSON_UNESCAPED_SLASHES)];
		return ['files' => $files, 'kernel' => $kernel];
	}

	private static function request(array $resources, array $more = []): array
	{
		return array_replace(['version' => 2, 'trigger' => 'manual', 'scope' => 'ip', 'resources' => $resources], $more);
	}

	private static function resource(string $id, string $generation, int $entries, string $action = 'deny'): array
	{
		return ['id' => $id, 'generation' => $generation, 'action' => $action, 'direction' => ['ingress', 'egress'], 'entries' => $entries];
	}

	private static function items(string $id, array $item): array
	{
		return ['status' => 200, 'type' => 'application/json', 'body' => json_encode(['resources' => [$id => $item]])];
	}

	private static function full(string $id, string $generation, array $lines): array
	{
		return self::items($id, ['kind' => 'full', 'generation' => $generation, 'digest' => self::digest($lines), 'entries' => count($lines),
			'metadata' => ['action' => 'deny']]);
	}

	private static function delta(string $id, string $generation, string $from, array $add, array $remove, array $result): array
	{
		return self::items($id, ['kind' => 'delta', 'generation' => $generation, 'from' => $from, 'addEntries' => count($add),
			'removeEntries' => count($remove), 'digest' => self::digest($result), 'entries' => count($result), 'metadata' => ['action' => 'deny']]);
	}

	private static function unchanged(string $id, string $generation): array
	{
		return self::items($id, ['kind' => 'unchanged', 'generation' => $generation]);
	}

	private static function text(array $lines): array
	{
		return ['status' => 200, 'type' => 'text/plain; charset=utf-8', 'body' => $lines === [] ? '' : self::body($lines)];
	}

	/** The scenario's steps, run by the corpus worker; one record per step. */
	private function runSteps(array $steps): array
	{
		$work = sys_get_temp_dir() . '/pfb_outpost_v2_' . bin2hex(random_bytes(6));
		mkdir($work, 0700, TRUE);
		$this->dirs[] = $work;
		file_put_contents("{$work}/scenario.json", json_encode(['description' => 'OutpostApplyTest', 'steps' => $steps], JSON_THROW_ON_ERROR));
		$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/OutpostApplyCorpusWorker.php', "{$work}/scenario.json", $work,
			"{$work}/result.json"], 300.0);
		$this->assertSame(0, $process['exit'], "the worker failed: {$process['stderr']}");
		$records = json_decode((string) file_get_contents("{$work}/result.json"), TRUE, 64, JSON_THROW_ON_ERROR);
		$this->assertCount(count($steps), $records);
		return $records;
	}

	/** One step of today's update pass that builds the groups, then the apply step: the apply's record. */
	private function applyOnce(array $apply, array $groups = ['Abuse']): array
	{
		return $this->runSteps([self::prime(array_map(static fn (string $name): array => self::group($name), $groups)), $apply])[1];
	}

	/** @return list<array{0: string, 1: string}> the id and stage of each failed resource on the record's result line */
	private static function failedPairs(array $record): array
	{
		return array_map(static fn (array $f): array => [$f['id'], $f['stage']], $record['resultLines'][0]['failed'] ?? []);
	}

	/** The table-changing pfctl calls of a record, each with the lines of its -f file. */
	private static function pushes(array $record): array
	{
		return array_values(array_filter($record['pfctl'], static fn (array $call): bool =>
			preg_match('/ -T (add|delete|replace|kill)\b/', $call['call']) === 1));
	}

	/** @return array<string, string> id => generation of the cursor file */
	private static function generations(array $record): array
	{
		return array_map(static fn (array $c): string => $c['generation'], $record['cursors']['resources'] ?? []);
	}

	// ---- the coverage matrix and the cursors ---------------------------------------------------

	/** WHEN a delta is applied THEN the mirror's digest equals the reply's and the table equals the canonical set. */
	public function testADeltaIsAppliedFromItsPartsAndAdvancesTheCursor(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['pendingToken' => 'tok-1', 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['pendingToken' => 'tok-1']),
			'core'    => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']),
				self::text(['192.0.2.2'])],
		]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame(0, $r['coreServed'], 'Core served the GetResources item and both parts');
		$this->assertSame(['resources' => [self::ABUSE => ['generation' => '1', 'digest' => self::digest(self::OLD)]]], $r['coreRequests'][0]['params'],
			'the cursor sent is the stored generation with the digest of the mirror on disk');
		$this->assertSame([['call' => '-t pfB_Abuse_v4 -T add -f <tmp>/pfb_add_*', 'lines' => ['203.0.113.9']],
			['call' => '-t pfB_Abuse_v4 -T delete -f <tmp>/pfb_del_*', 'lines' => ['192.0.2.2']]],
			array_map(static fn (array $c): array => ['call' => (string) preg_replace('#-f \S+/(pfb_(?:add|del)_)\S*#', '-f <tmp>/$1*', $c['call']), 'lines' => $c['lines']], self::pushes($r)),
			'mode delta: the add part, then the remove part');
		$this->assertSame(self::NEW, $r['mirrors']['pfB_Abuse_v4.txt']);
		$this->assertSame(self::digest(self::NEW), hash('xxh128', self::body($r['mirrors']['pfB_Abuse_v4.txt'])));
		$this->assertSame(self::NEW, $r['kernel']['pfB_Abuse_v4'], 'pfctl -T show equals the canonical set');
		$this->assertSame(['schema' => 1, 'resources' => [self::ABUSE => ['generation' => '2', 'digest' => self::digest(self::NEW), 'entries' => 3]]],
			$r['cursors']);
		$this->assertSame([['version' => 2, 'applied' => [self::ABUSE => '2'], 'changedAliases' => ['pfB_Abuse_v4'], 'ipChanged' => FALSE]],
			$r['resultLines']);
		$this->assertFalse($r['pending'], "the request's pending token is settled");
	}

	/** A full reply, or no cursor for the table, replaces the table from the new mirror whatever the mode. */
	public function testAFullReplyReplacesTheTable(): void
	{
		$apply = ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '5', 3)]),
			'core'    => [self::full(self::ABUSE, '5', self::NEW), self::text(self::NEW)],
		]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame(['resources' => [self::ABUSE => []]], $r['coreRequests'][0]['params'], 'no cursor: the empty cursor');
		$this->assertCount(1, self::pushes($r));
		$this->assertStringContainsString('-t pfB_Abuse_v4 -T replace -f ', self::pushes($r)[0]['call']);
		$this->assertSame(self::NEW, self::pushes($r)[0]['lines']);
		$this->assertSame(self::NEW, $r['kernel']['pfB_Abuse_v4']);
		$this->assertSame([self::ABUSE => '5'], self::generations($r));
		$this->assertSame([self::ABUSE => '5'], $r['resultLines'][0]['applied']);
	}

	/** An unchanged reply fetches nothing and calls no pfctl; the resource is applied at its generation. */
	public function testAnUnchangedResourceIsNeitherFetchedNorPushed(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)]),
			'core'    => [self::unchanged(self::ABUSE, '2')],
		]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertCount(1, $r['coreRequests'], 'no GetResourceBody');
		$this->assertSame([], self::pushes($r));
		$this->assertSame([['version' => 2, 'applied' => [self::ABUSE => '2'], 'ipChanged' => FALSE]], $r['resultLines']);
	}

	/** WHEN pfctl fails for one table THEN its cursor stays, the others advance, the exit status is 1, and the pending marker is kept. */
	public function testOneFailedTableKeepsItsCursorWhileTheOthersAdvance(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD], self::BETA => ['1', self::OLD]]) + ['pendingToken' => 'tok-2',
			'pfctlFail' => ['pfB_Beta_v4.add'], 'apply' => [
				'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '2', 3)], ['pendingToken' => 'tok-2']),
				'core'    => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']),
					self::text(['192.0.2.2']), self::delta(self::BETA, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW),
					self::text(['203.0.113.9']), self::text(['192.0.2.2'])],
			]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([self::ABUSE => '2', self::BETA => '1'], self::generations($r));
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied']);
		$this->assertSame([[self::BETA, 'apply']], self::failedPairs($r));
		$this->assertTrue($r['pending'], 'a failed apply settles no pending change');
	}

	// ---- deferral ------------------------------------------------------------------------------

	/** @return array<string, array{array<string, mixed>}> an apply step that cannot reach every resource */
	public static function deferrals(): array
	{
		return [
			'the apply lock is held'       => [['lockHeld' => TRUE]],
			'the Core API does not answer' => [[]],
		];
	}

	/** WHEN the apply lock is held or the Core API does not answer THEN the apply exits 75, writes no result line and moves nothing. */
	#[DataProvider('deferrals')]
	public function testADeferredApplyWritesNoResultLineAndMovesNothing(array $apply): void
	{
		$r = $this->applyOnce(self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)])] + $apply]);

		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertSame([], $r['resultLines']);
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
		$this->assertSame([], self::pushes($r));
		$this->assertSame(self::OLD, $r['mirrors']['pfB_Abuse_v4.txt']);
	}

	/** @return array<string, array{0: array<string, mixed>, 1: int}> a step of the apply trigger that does not complete, and its exit status */
	public static function applyTriggersThatDoNotComplete(): array
	{
		$request = self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => 'apply']);
		return [
			'deferred: Core does not answer' => [['apply' => ['request' => $request]], PFB_EXIT_LOCKED],
			'failed: pfctl fails for the table' => [['pfctlFail' => ['pfB_Abuse_v4.add'], 'apply' => ['request' => $request,
				'core' => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']),
					self::text(['192.0.2.2'])]]], 1],
		];
	}

	/** The apply trigger clears the due-ledger flag first and puts it back when the apply does not complete. */
	#[DataProvider('applyTriggersThatDoNotComplete')]
	public function testTheApplyTriggerClearsTheDueFlagAndRestoresItWhenTheApplyDoesNotComplete(array $step, int $exit): void
	{
		$incomplete = self::at([self::ABUSE => ['1', self::OLD]]) + ['pending' => TRUE] + $step;
		$applied = ['pending' => TRUE, 'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => 'apply']),
			'core' => [self::unchanged(self::ABUSE, '2')]]];
		[, $i, $a] = $this->runSteps([self::prime([self::group('Abuse')]), $incomplete, self::at([self::ABUSE => ['2', self::OLD]]) + $applied]);

		$this->assertSame($exit, $i['exit'], $i['log']);
		$this->assertFalse($i['fetches']['ledgerPending'], 'the flag is clear before the apply fetches anything');
		$this->assertTrue($i['ledgerPending'], 'an apply that does not complete keeps the pending apply flag');
		$this->assertSame(0, $a['exit'], $a['log']);
		$this->assertFalse($a['fetches']['ledgerPending'], 'the flag is clear before the apply fetches anything');
		$this->assertFalse($a['ledgerPending'], 'a completed apply clears it');
	}

	// ---- the pending marker --------------------------------------------------------------------

	/** WHEN a change is marked pending while the apply runs THEN the marker survives; only the request's pendingToken is settled. */
	public function testAChangeMarkedAfterTheSnapshotSurvivesTheApply(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD]]) + ['pendingToken' => 'tok-newer', 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['pendingToken' => 'tok-older']),
			'core'    => [self::unchanged(self::ABUSE, '2')],
		]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertTrue($r['pending'], 'the later mark is still pending');
	}

	/** With pendingOutsideWindow the apply marks the changes pending, applies nothing and writes one line without applied. */
	public function testOutsideTheWindowTheChangesAreMarkedPendingAndNothingIsApplied(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['pendingOutsideWindow' => TRUE])]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame([['version' => 2]], $r['resultLines']);
		$this->assertSame(0, $r['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([], self::pushes($r));
		$this->assertTrue($r['pending']);
		$this->assertTrue($r['ledgerPending']);
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
	}

	// ---- issues --------------------------------------------------------------------------------

	/**
	 * WHEN the request carries issues THEN each appears once as a notice and as an ADR-61 ledger entry of its stage, and a later
	 * clean request closes them. A message of 900 KiB with markup reaches both as text of at most 1,024 bytes.
	 */
	public function testIssuesAreFiledOnceAndAClearRequestClosesThem(): void
	{
		$issue = ['resource' => 'feed/ipv4:Foo_v4', 'stage' => 'download', 'code' => 'curl_incomplete',
			'message' => str_repeat('<b>broken</b> ', intdiv(900 * 1024, 14))];
		$with = ['apply' => ['request' => self::request([], ['issues' => [$issue]])]];
		$clear = ['apply' => ['request' => self::request([])]];
		[, $first, $again, $closed] = $this->runSteps([self::prime([self::group('Abuse')]), $with, $with, $clear]);

		// the notices of the issue: over the doubles the copied-object detector also files one on a node's second apply (a reread
		// config.xml gives a rule's tracker as a string, the double keeps the integer), as today's update pass does
		$mine = static fn (array $record): array => array_values(array_filter($record['notices'],
			static fn (array $n): bool => str_contains($n['notice'], 'feed/ipv4:Foo_v4')));
		$this->assertSame(0, $first['exit'], $first['log']);
		$this->assertCount(1, $mine($first), 'the issue is filed as a notice');
		$notice = $mine($first)[0]['notice'];
		$this->assertStringContainsString('feed/ipv4:Foo_v4', $notice);
		$this->assertStringContainsString('<b>broken</b>', $notice, 'markup reaches the notice as text');
		// each carries the message after a prefix of its own: the message itself is what the limit bounds
		$shown = 'pfBlockerNG Update [ feed/ipv4:Foo_v4 ] download curl_incomplete: ';
		$this->assertStringStartsWith($shown, $notice);
		$this->assertGreaterThan(1000, strlen($notice) - strlen($shown), 'before: the message was cut, not dropped');
		$this->assertLessThanOrEqual(PFB_CORE_UPDATE_V2_MESSAGE_BYTES, strlen($notice) - strlen($shown), 'the notice\'s message is bounded');
		$ledger = json_decode($first['syncStatus']['pfb_sync_status.json'], TRUE);
		$entry = $ledger['ip']['feed/ipv4:Foo_v4']['download'] ?? NULL;
		$this->assertIsArray($entry, 'the issue is an ADR-61 entry of its stage: ' . $first['syncStatus']['pfb_sync_status.json']);
		$this->assertStringStartsWith('curl_incomplete: ', $entry['message']);
		$this->assertLessThanOrEqual(PFB_CORE_UPDATE_V2_MESSAGE_BYTES, strlen($entry['message']) - strlen('curl_incomplete: '), 'the entry\'s message is bounded');

		$this->assertSame([], $mine($again), 'an issue already filed is not filed again');
		$this->assertArrayHasKey('feed/ipv4:Foo_v4', json_decode($again['syncStatus']['pfb_sync_status.json'], TRUE)['ip'] ?? []);

		$this->assertArrayNotHasKey('feed/ipv4:Foo_v4', json_decode($closed['syncStatus']['pfb_sync_status.json'] ?? '{}', TRUE)['ip'] ?? [],
			'a clean request closes the entry it opened');
	}

	// ---- resources the apply refuses -----------------------------------------------------------

	/** An id that maps to no alias the configuration expects is not applied: it fails with stage apply and is never fetched. */
	public function testAResourceOfNoConfiguredAliasFails(): void
	{
		$apply = ['apply' => ['request' => self::request([self::resource('ip-set/Ghost/ipv4', '1', 3)])]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame(0, $r['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([['ip-set/Ghost/ipv4', 'apply']], self::failedPairs($r));
	}

	/** A full body that would exceed the firewall's table entries limit is not fetched and fails with stage apply. */
	public function testAResourceOverTheTableEntriesLimitIsNotFetched(): void
	{
		$apply = ['apply' => ['request' => self::request([self::resource(self::ABUSE, '9', 3000000)])]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame(0, $r['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([[self::ABUSE, 'apply']], self::failedPairs($r));
		$this->assertStringContainsString('table entries limit', $r['resultLines'][0]['failed'][0]['message']);
	}

	/** Decision 2 on #4037: a resource whose action disagrees with config.xml is not applied and keeps its cursor. */
	public function testAResourceWhoseActionChangedSinceTheSnapshotFails(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3, 'permit')])]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame(0, $r['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([[self::ABUSE, 'apply']], self::failedPairs($r));
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
	}

	// ---- removal -------------------------------------------------------------------------------

	/** A removed resource's table is killed, its mirror unlinked and its cursor dropped; the removal is reported. */
	public function testARemovedResourceIsTornDown(): void
	{
		$apply = self::at([self::BETA => ['3', self::OLD]]) + ['config' => ['installedpackages/pfblockernglistsv4/config' => [self::group('Abuse')]],
			'apply' => ['request' => self::request([], ['removed' => [self::BETA]])]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertArrayNotHasKey('pfB_Beta_v4', $r['kernel']);
		$this->assertArrayNotHasKey('pfB_Beta_v4.txt', $r['mirrors']);
		$this->assertSame([], self::generations($r));
		$this->assertSame([self::BETA], $r['resultLines'][0]['removed']);
		$this->assertNotContains('pfB_Beta_v4', array_column($r['aliases'], 'name'));
	}

	// ---- what the apply reaches, against today's update pass ----------------------------------

	/** The alias objects the apply registers for the aliases it holds are the ones today's update pass registers. */
	public function testTheApplyRegistersTheAliasObjectsThePassRegisters(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD], self::BETA => ['4', self::NEW]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '4', 3)]),
			'core'    => [self::unchanged(self::ABUSE, '2'), self::unchanged(self::BETA, '4')],
		]];
		[$pass, $r] = $this->runSteps([self::prime([self::group('Abuse'), self::group('Beta')]), $apply]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame(['pfB_Abuse_v4', 'pfB_Beta_v4'], array_column($pass['aliases'], 'name'), 'before: the pass registered both');
		$this->assertSame($pass['aliases'], $r['aliases']);
	}

	/** Both today's update pass and the apply end their DNS steps with the DNS proxy's start check, which reports a proxy that cannot start. */
	public function testThePassAndTheApplyBothRunTheDnsProxyStartCheck(): void
	{
		// our block in the Resolver's custom options and no snapshot: pfB-DNS owns the Resolver and its proxy cannot start. Each
		// step's write of the observer's settings is refused, so nothing tries to mount the host's /usr/local folders for it.
		$owned = ['config' => ['unbound/custom_options' => base64_encode(PFB_DNS_PROXY_MARKER . "\n"), 'unbound/python_script' => ''],
			'writeConfigFail' => ['pfBlockerNG: Added DNSBL Unbound upstream observer settings']];
		$apply = $owned + ['apply' => ['request' => self::request([], ['scope' => 'dnsbl'])]];
		[$pass, $r] = $this->runSteps([array_merge_recursive(self::prime([self::group('Abuse')]), $owned), $apply]);

		$said = 'pfB-DNS: the DNS proxy did not become ready; see the notices';
		$this->assertStringContainsString($said, $pass['log'], 'the update pass');
		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertStringContainsString($said, $r['log'], 'the version 2 apply');
		$this->assertStringNotContainsString('python mounts', $pass['log'] . $r['log'], 'nothing tried to mount a host folder');
	}

	/** The DNS step hands the DNS-redirect and DoT/DoQ writers its mode, in that order: with DNSBL off each removes its rows. */
	public function testTheDnsStepHandsBothWritersItsModeInTodaysOrder(): void
	{
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$apply = ['config' => ["{$dnsbl}/dnsbl_redir" => 'on', "{$dnsbl}/dnsbl_redir_int" => 'lan', "{$dnsbl}/dnsbl_dot_block" => 'on',
			"{$dnsbl}/dnsbl_dot_block_int" => 'lan',
			'nat/rule' => [['descr' => 'pfB_DNS_Redirect_lan_v4', 'interface' => 'lan'], ['descr' => 'pfB_DNS_Redirect_lan_v6', 'interface' => 'lan']],
			'filter/rule' => [['descr' => 'pfB_DoT_Block_lan', 'interface' => 'lan']]],
			'apply' => ['request' => self::request([], ['scope' => 'dnsbl'])]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame([], $r['nat'], 'the redirect rows are removed');
		$this->assertNotContains('pfB_DoT_Block_lan', array_column($r['rules'], 'descr'), 'the DoT/DoQ row is removed');
		$this->assertSame(['pfBlockerNG: saving DNS-redirect rule changes', 'pfBlockerNG: saving DoT/DoQ block rule changes'],
			array_values(array_filter(array_map(static fn (mixed $call): string => is_array($call) ? (string) ($call[0] ?? $call['desc'] ?? '') : (string) $call,
				$r['writeConfig']), static fn (string $desc): bool => str_contains($desc, 'DNS-redirect') || str_contains($desc, 'DoT/DoQ'))));
	}

	// ---- the coverage matrix, continued ----------------------------------------------------------

	/** Decision 2 on #4037: a resource whose direction disagrees with config.xml is not applied and keeps its cursor. */
	public function testAResourceWhoseDirectionChangedSinceTheSnapshotFails(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)])]];
		$r = $this->runSteps([self::prime([self::group('Abuse', 'Deny_Inbound')]), $apply])[1];

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame(0, $r['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([[self::ABUSE, 'apply']], self::failedPairs($r));
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
	}

	/** #3813: with a reload needed that could not be launched, nothing is reported applied and reloadLaunched is FALSE. */
	public function testNothingIsAppliedWhenTheNeededReloadIsNotLaunched(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD]]) + ['reload' => 'missing',
			'config' => ['installedpackages/pfblockernglistsv4/config' => [self::group('Abuse'), self::group('Beta')]],
			'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '1', 3)]),
				'core' => [self::unchanged(self::ABUSE, '2'), self::full(self::BETA, '1', self::NEW), self::text(self::NEW)]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertContains('pfB_Beta_v4', array_column($r['aliases'], 'name'), 'before: the new alias and its rule need a reload');
		$this->assertSame(['version' => 2, 'changedAliases' => ['pfB_Beta_v4'], 'ipChanged' => TRUE, 'reloadLaunched' => FALSE],
			$r['resultLines'][0], 'no applied: both resources stay pending');
		$this->assertTrue($r['pending']);
	}

	/** changedAliases names only aliases of the request: an IP unlock re-blocks every table, and only the request's are reported. */
	public function testChangedAliasesNamesOnlyTheRequestsAliases(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD], self::BETA => ['1', self::OLD]]);
		$apply['files']['ip_unlock'] = [''];	// the Alerts page's IP unlock: every table is re-blocked
		$apply['apply'] = ['request' => self::request([self::resource(self::ABUSE, '2', 3)]), 'core' => [self::unchanged(self::ABUSE, '2')]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame(['pfB_Abuse_v4', 'pfB_Beta_v4'], array_values(array_unique(array_map(static fn (array $c): string =>
			(string) preg_replace('/^-t (\S+) .*$/', '$1', $c['call']), self::pushes($r)))), 'before: the unlock re-blocks both tables');
		$this->assertSame(['pfB_Abuse_v4'], $r['resultLines'][0]['changedAliases']);
		$this->assertTrue($r['resultLines'][0]['ipChanged']);
	}

	/** An empty kernel table is replaced from the mirror, though the cursor would allow a delta. */
	public function testAnEmptyKernelTableIsReplacedWhateverTheMode(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]);
		$apply['kernel']['pfB_Abuse_v4'] = [];
		$apply['apply'] = ['request' => self::request([self::resource(self::ABUSE, '2', 3)]),
			'core' => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']), self::text(['192.0.2.2'])]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertCount(1, self::pushes($r));
		$this->assertStringContainsString('-t pfB_Abuse_v4 -T replace -f ', self::pushes($r)[0]['call']);
		$this->assertSame(self::NEW, $r['kernel']['pfB_Abuse_v4']);
	}

	/** @return list<string> $count addresses of 10.0.0.0/24 */
	private static function hosts(int $count, int $from = 1): array
	{
		return array_map(static fn (int $i): string => "10.0.0.{$i}", range($from, $from + $count - 1));
	}

	/** @return array<string, array{0: string, 1: list<string>, 2: list<string>, 3: string}> mode, adds, removes, the pfctl verbs */
	public static function deltaModes(): array
	{
		return [
			'auto, churn under 5%: a delta' => ['auto', ['10.0.1.1'], [], 'add'],
			'auto, churn at 5%: a replace'  => ['auto', ['10.0.1.1'], ['10.0.0.1'], 'replace'],
			'replace: a replace'            => ['replace', ['10.0.1.1'], [], 'replace'],
			'delta: a delta'                => ['delta', ['10.0.1.1'], ['10.0.0.1'], 'add delete'],
		];
	}

	/** The operator's delta mode and the churn decide between a delta and a replace of a table of 40 members. */
	#[DataProvider('deltaModes')]
	public function testTheDeltaModeAndTheChurnDecideHowTheTableIsPushed(string $mode, array $add, array $remove, string $verbs): void
	{
		$old = self::hosts(40);
		$new = array_values(array_diff([...$old, ...$add], $remove));
		$apply = self::at([self::ABUSE => ['1', $old]]) + ['config' => ['installedpackages/pfblockerng/config/0/pfb_alias_delta_mode' => $mode],
			'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', count($new))]),
				'core' => [self::delta(self::ABUSE, '2', '1', $add, $remove, $new), self::text($add), self::text($remove)]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame($verbs, implode(' ', array_map(static fn (array $c): string => (string) preg_replace('/^.* -T (\w+) .*$/', '$1', $c['call']),
			self::pushes($r))));
		$sorted = $new;
		sort($sorted, SORT_STRING);
		$this->assertSame($sorted, $r['kernel']['pfB_Abuse_v4']);
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied']);
	}

	/** @return array<string, array{0: string, 1: bool, 2: bool}> scope, whether the IP resources are fetched, whether DNSBL is applied */
	public static function scopes(): array
	{
		return ['ip' => ['ip', TRUE, FALSE], 'dnsbl' => ['dnsbl', FALSE, TRUE], 'both' => ['both', TRUE, TRUE]];
	}

	/** The scope decides what the apply acts on: the IP resources, the DNSBL statistics and dnsblChanged, or both. */
	#[DataProvider('scopes')]
	public function testTheScopeDecidesWhatIsApplied(string $scope, bool $ip, bool $dnsbl): void
	{
		$groups = [['name' => 'Ads', 'entries' => 120, 'changed' => TRUE], ['name' => 'Malware', 'entries' => 7, 'changed' => FALSE]];
		$apply = self::at([self::ABUSE => ['2', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['scope' => $scope, 'dnsbl' => ['generation' => '9', 'groups' => $groups]]),
			'core'    => $ip ? [self::unchanged(self::ABUSE, '2')] : []]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame($ip ? 1 : 0, $r['fetches']['calls'], 'the IP resources are fetched only in scope ip and both');
		$this->assertCount($ip ? 1 : 0, $r['coreRequests']);
		$this->assertSame($ip ? [self::ABUSE => '2'] : NULL, $r['resultLines'][0]['applied'] ?? NULL);
		$this->assertSame($dnsbl ? ['DNSBL_Ads' => '120', 'DNSBL_Malware' => '7'] : NULL, $r['dnsblStats'], 'the statistics rows of the groups Core published');
		$this->assertSame($dnsbl ? TRUE : NULL, $r['resultLines'][0]['dnsblChanged'] ?? NULL, 'a group Core changed changes DNSBL');
	}

	/** dnsblChanged is FALSE when no group changed and the Resolver's configuration did not. */
	public function testDnsblIsUnchangedWhenNoGroupChanged(): void
	{
		$r = $this->applyOnce(['apply' => ['request' => self::request([], ['scope' => 'dnsbl', 'dnsbl' => ['generation' => '9',
			'groups' => [['name' => 'Ads', 'entries' => 120, 'changed' => FALSE]]]])]]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame(['version' => 2, 'ipChanged' => FALSE, 'dnsblChanged' => FALSE], $r['resultLines'][0]);
	}

	/** The geo-catalog's body renders the GeoIP pages. */
	public function testTheGeoCatalogRendersTheGeoipPages(): void
	{
		$rows = array_map(static fn (array $row): string => json_encode($row, JSON_THROW_ON_ERROR), [
			['kind' => 'country', 'page' => 'Africa', 'family' => 4, 'position' => 1, 'iso' => 'AA', 'country' => 'Alpha', 'networks' => 2],
			['kind' => 'page', 'page' => 'Africa', 'continent' => 'Africa']]);
		$apply = ['apply' => ['request' => self::request([['id' => 'geo-catalog', 'generation' => '3']]),
			'core' => [self::full('geo-catalog', '3', $rows), self::text($rows)]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertContains('pfblockerng_Africa.php', $r['geoPages']);
		$this->assertSame(['geo-catalog' => '3'], $r['resultLines'][0]['applied']);
	}

	/** An aggregate and a continent are aliases the configuration expects: each is applied and registered. */
	public function testAnAggregateAndAContinentAreApplied(): void
	{
		$agg = 'ip-aggregate/deny/ipv4';
		$africa = 'ip-set/Africa/ipv4';
		$apply = ['config' => ['installedpackages/pfblockerng/config/0/pfb_agg_types' => 'Deny',
			'installedpackages/pfblockerngafrica/config/0' => ['action' => 'Deny_Both', 'countries4' => 'AA', 'aliaslog' => 'enabled']],
			'apply' => ['request' => self::request([['id' => $agg, 'generation' => '1', 'action' => 'alias_only', 'entries' => 3],
				self::resource($africa, '1', 3)]),
				'core' => [self::full($agg, '1', self::NEW), self::text(self::NEW), self::full($africa, '1', self::OLD), self::text(self::OLD)]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame([$agg => '1', $africa => '1'], $r['resultLines'][0]['applied']);
		$this->assertContains('pfB_Deny_Aggregated_v4', array_column($r['aliases'], 'name'));
		$this->assertContains('pfB_Africa_v4', array_column($r['aliases'], 'name'));
		$this->assertSame(self::NEW, $r['kernel']['pfB_Deny_Aggregated_v4'] ?? $r['mirrors']['pfB_Deny_Aggregated_v4.txt']);
	}

	// ---- the first review round's findings -------------------------------------------------------

	/** A table whose push fails, though no ledger entry records it (the ledger cannot be written), fails and keeps its cursor. */
	public function testATableWhosePushFailsKeepsItsCursorWithoutALedgerEntry(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD], self::BETA => ['1', self::OLD]]);
		$apply['files']['{dbdir}/pfb_sync_status.json/unwritable'] = [];	// a folder at the ledger's path: no entry is written
		$apply += ['pfctlFail' => ['pfB_Beta_v4.add'], 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '2', 3)]),
			'core'    => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']),
				self::text(['192.0.2.2']), self::delta(self::BETA, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW),
				self::text(['203.0.113.9']), self::text(['192.0.2.2'])]]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertArrayNotHasKey('pfb_sync_status.json', $r['syncStatus'], 'before: no ledger entry was written');
		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([self::ABUSE => '2', self::BETA => '1'], self::generations($r));
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied']);
		$this->assertSame([[self::BETA, 'apply']], self::failedPairs($r));
	}

	/**
	 * WHEN the Core API stops serving part way through the fetch THEN the apply exits 75 having changed nothing: no mirror, no
	 * table, no cursor, no NAT rule, no DNSBL statistics row and no issue filed.
	 */
	public function testADeferralPartWayThroughTheFetchChangesNothing(): void
	{
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$nat = [['descr' => 'pfB_DNS_Redirect_lan_v4', 'interface' => 'lan']];
		$apply = self::at([self::ABUSE => ['1', self::OLD], self::BETA => ['1', self::OLD]]) + ['config' => ['nat/rule' => $nat,
			"{$dnsbl}/dnsbl_redir" => 'on', "{$dnsbl}/dnsbl_redir_int" => 'lan'], 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '2', 3)], ['scope' => 'both',
				'dnsbl' => ['generation' => '9', 'groups' => [['name' => 'Ads', 'entries' => 120, 'changed' => TRUE]]],
				'issues' => [['resource' => 'feed/ipv4:Foo_v4', 'stage' => 'download', 'code' => 'curl_incomplete', 'message' => 'cut']]]),
			'core'    => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']),
				self::text(['192.0.2.2']), ['status' => 503, 'type' => 'application/json',
				'body' => json_encode(['error' => ['code' => 'unavailable', 'message' => 'the store is not open']])]]]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertCount(4, $r['coreRequests'], 'before: Abuse was fetched whole and Beta asked for');
		$this->assertSame([], $r['resultLines']);
		$this->assertSame(['pfB_Abuse_v4.txt' => self::OLD, 'pfB_Beta_v4.txt' => self::OLD], $r['mirrors'], 'no mirror moved and none is left staged');
		$this->assertSame([], self::pushes($r));
		$this->assertSame([self::ABUSE => '1', self::BETA => '1'], self::generations($r));
		$this->assertSame($nat, $r['nat'], 'the DNS step did not run');
		$this->assertNull($r['dnsblStats'], 'no DNSBL statistics row was written');
		$this->assertSame([], array_filter($r['notices'], static fn (array $n): bool => str_contains($n['notice'], 'feed/ipv4:Foo_v4')));
		$this->assertStringNotContainsString('feed/ipv4:Foo_v4', $r['syncStatus']['pfb_sync_status.json'] ?? '');
	}

	/** Core's issue of stage apply is filed where the tick's reconciler, which re-applies every open ip and dnsbl apply entry, does not act. */
	public function testCoresApplyIssueIsNoEntryTheTickReconcilerActsOn(): void
	{
		$issue = ['resource' => self::ABUSE, 'stage' => 'apply', 'code' => 'publish_failed', 'message' => 'the store refused the body'];
		$r = $this->applyOnce(['apply' => ['request' => self::request([], ['issues' => [$issue]])]]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertCount(1, array_filter($r['notices'], static fn (array $n): bool => str_contains($n['notice'], self::ABUSE . ' ] apply publish_failed')),
			'the notice names Core\'s stage');
		$ledger = json_decode($r['syncStatus']['pfb_sync_status.json'] ?? '{}', TRUE);
		$this->assertSame(['core'], array_keys($ledger['ip'][self::ABUSE] ?? []), 'the entry is of stage core');
		$open = [];
		foreach ($ledger as $facility => $items) {
			foreach ($items as $item => $stages) {
				if (isset($stages['apply'])) {
					$open[] = "{$facility}/{$item}";
				}
			}
		}
		$this->assertSame([], $open, 'no apply entry is open');
	}

	/**
	 * Issue #4038: the Core Updater names a Blacklist category's feed feed/blacklist:<provider>:<category>. WHEN a request carries
	 * issues of a category, a DNSBL feed and an IP feed THEN the category's and the DNSBL feed's are dnsbl entries, the IP feed's
	 * an ip entry.
	 */
	public function testACategorysIssueIsADnsblEntry(): void
	{
		$issues = [];
		foreach (['feed/blacklist:UT1:ads', 'feed/dnsbl:Foo', 'feed/ipv4:Foo_v4'] as $resource) {
			$issues[] = ['resource' => $resource, 'stage' => 'download', 'code' => 'curl_incomplete', 'message' => 'cut'];
		}
		$r = $this->applyOnce(['apply' => ['request' => self::request([], ['issues' => $issues])]]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$ledger = json_decode($r['syncStatus']['pfb_sync_status.json'] ?? '{}', TRUE);
		$this->assertSame(['feed/blacklist:UT1:ads', 'feed/dnsbl:Foo'], array_keys($ledger['dnsbl'] ?? []),
			'the dnsbl entries: ' . json_encode($ledger));
		$this->assertSame(['feed/ipv4:Foo_v4'], array_keys($ledger['ip'] ?? []), 'the ip entries: ' . json_encode($ledger));
	}

	/** @return array<string, array{0: string, 1: int}> a trigger, and the exit status of its apply while GeoIP is not ready */
	public static function triggersWhileGeoipIsNotReady(): array
	{
		return ['scheduled' => ['scheduled', 0], 'retry' => ['retry', 0], 'apply' => ['apply', 0], 'manual' => ['manual', 1]];
	}

	/** WHILE a GeoIP generation swap is in progress the apply applies nothing and keeps the changes pending, exiting as version 1 does. */
	#[DataProvider('triggersWhileGeoipIsNotReady')]
	public function testWhileGeoipIsNotReadyNothingIsAppliedAndTheChangesStayPending(string $trigger, int $exit): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]);
		$apply['files']['{ccdir}/.pfb_generation_swapping'] = [];
		$apply['apply'] = ['request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => $trigger])];
		$r = $this->applyOnce($apply);

		$this->assertSame($exit, $r['exit'], $r['log']);
		$this->assertSame(0, $r['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([['version' => 2]], $r['resultLines']);
		$this->assertSame([], self::pushes($r));
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
		$this->assertTrue($r['pending']);
		$this->assertTrue($r['ledgerPending']);
	}

	/** @return array<string, array{array<string, mixed>}> a lock another process holds */
	public static function locksHeldElsewhere(): array
	{
		return [
			'the scheduler dispatcher lock' => [['apply' => ['dispatchLockHeld' => TRUE]]],
			'the DNS configuration lock'    => [['dnsConfigLockHeld' => TRUE, 'config' => ['installedpackages/pfblockerng/config/0/pfb_dns_listen_vip' => 'on']]],
		];
	}

	/** WHEN a lock the update pass takes is held elsewhere THEN the apply defers with no result line and leaves no lock of its own held. */
	#[DataProvider('locksHeldElsewhere')]
	public function testALockThePassTakesDefersTheApply(array $step): void
	{
		// nothing listens for Core: the fetch count, not a Core that waits for a request, shows that nothing was asked
		$apply = array_replace_recursive(self::at([self::ABUSE => ['2', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)])]], $step);
		$r = $this->applyOnce($apply);

		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertSame([], $r['resultLines']);
		$this->assertSame(0, $r['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([FALSE, FALSE], [$r['locks']['feedPass'], $r['locks']['dispatch']], 'the apply released what it took');
	}

	/** The cron-disable sentinel stops a scheduled apply (exit 75, nothing fetched) and leaves a manual one alone. */
	public function testTheCronDisableSentinelStopsOnlyAScheduledApply(): void
	{
		$sentinel = self::at([self::ABUSE => ['2', self::OLD]]);
		$sentinel['files']['{dbdir}/.pfb_cron_disable'] = [];
		$manual = $sentinel + ['apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)]), 'core' => [self::unchanged(self::ABUSE, '2')]]];
		$scheduled = $sentinel + ['apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => 'scheduled'])]];
		[, $m, $s] = $this->runSteps([self::prime([self::group('Abuse')]), $manual, $scheduled]);

		$this->assertSame(0, $m['exit'], $m['log']);
		$this->assertSame([self::ABUSE => '2'], $m['resultLines'][0]['applied'], 'before: a manual apply runs');
		$this->assertSame(PFB_EXIT_LOCKED, $s['exit'], $s['log']);
		$this->assertStringContainsString('/.pfb_cron_disable disables scheduled work', $s['log'], 'the sentinel, not the absent Core, defers it');
		$this->assertSame(0, $s['fetches']['calls'], 'nothing was fetched');
		$this->assertSame([], $s['resultLines'] ?? []);
	}

	/** A removal whose kill fails keeps the resource's cursor and its ledger entry, with no mirror: the tick's retry kills the table. */
	public function testARemovalWhoseKillFailsIsRetriedAsAKill(): void
	{
		$apply = self::at([self::BETA => ['3', self::OLD]]) + ['pfctlFail' => ['pfB_Beta_v4.kill'],
			'config' => ['installedpackages/pfblockernglistsv4/config' => [self::group('Abuse')]],
			'apply' => ['request' => self::request([], ['removed' => [self::BETA]])]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([[self::BETA, 'apply']], self::failedPairs($r));
		$this->assertSame([self::BETA => '3'], self::generations($r));
		$this->assertArrayHasKey('pfB_Beta_v4', $r['kernel'], 'the table is still loaded');
		$this->assertArrayNotHasKey('pfB_Beta_v4.txt', $r['mirrors'], 'no mirror: pfb_ip_apply_retry() kills a table that has none');
		$this->assertArrayHasKey('apply', json_decode($r['syncStatus']['pfb_sync_status.json'], TRUE)['ip']['pfB_Beta_v4'] ?? []);
	}

	/** A failed resource is recorded on the received policy's apply record as a resource failure, not as an unconfirmed reload. */
	public function testAFailedResourceIsRecordedAsSuch(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['openRecord' => TRUE, 'pfctlFail' => ['pfB_Abuse_v4.add'], 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)]),
			'core'    => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']), self::text(['192.0.2.2'])]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame(['outcome' => 'failed', 'reason' => 'a resource was not applied; pending changes kept'], $r['applyRecord']);
	}

	/** A body over the table entries limit fails its resource and never reaches the mirror, which keeps the generation it holds. */
	public function testABodyOverTheTableEntriesLimitNeverReachesTheMirror(): void
	{
		$four = [...self::NEW, '203.0.113.10'];
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['config' => ['system/maximumtableentries' => '3'], 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)]),
			'core'    => [self::full(self::ABUSE, '2', $four), self::text($four)]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertCount(2, $r['coreRequests'], 'before: the body was fetched');
		$this->assertSame([[self::ABUSE, 'apply']], self::failedPairs($r));
		$this->assertStringContainsString('table entries limit', $r['resultLines'][0]['failed'][0]['message']);
		$this->assertSame(['pfB_Abuse_v4.txt' => self::OLD], $r['mirrors'], 'the mirror is untouched and nothing is left staged');
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
		$this->assertSame([], self::pushes($r));
	}

	/** @return array<string, array{array<string, mixed>}> what tells the apply a resource left, for a group config.xml still holds */
	public static function removalsOfAGroupTheConfigurationHolds(): array
	{
		return [
			'the request removes it' => [['request' => self::request([], ['removed' => [self::BETA]])]],
			'Core answers not_found' => [['request' => self::request([self::resource(self::BETA, '4', 3)]),
				'core' => [self::items(self::BETA, ['error' => ['code' => 'not_found', 'message' => 'no such resource']])]]],
		];
	}

	/**
	 * The first review round's decision on #4037: a resource that left Core's configuration while config.xml still holds its
	 * group is not applied. It fails with stage apply and keeps its table, mirror, cursor and alias.
	 */
	#[DataProvider('removalsOfAGroupTheConfigurationHolds')]
	public function testARemovalOfAGroupTheConfigurationHoldsIsNotApplied(array $request): void
	{
		$r = $this->applyOnce(self::at([self::ABUSE => ['2', self::OLD], self::BETA => ['3', self::OLD]]) + ['apply' => $request], ['Abuse', 'Beta']);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([[self::BETA, 'apply']], self::failedPairs($r));
		$this->assertStringContainsString("settings changed since the Update's snapshot", $r['resultLines'][0]['failed'][0]['message']);
		$this->assertArrayNotHasKey('removed', $r['resultLines'][0]);
		$this->assertSame(self::OLD, $r['kernel']['pfB_Beta_v4'] ?? NULL);
		$this->assertSame(self::OLD, $r['mirrors']['pfB_Beta_v4.txt'] ?? NULL);
		$this->assertSame([self::ABUSE => '2', self::BETA => '3'], self::generations($r));
		$this->assertContains('pfB_Beta_v4', array_column($r['aliases'], 'name'));
	}

	/** WHEN the apply throws THEN the apply trigger still puts the due-ledger flag back. */
	public function testTheApplyTriggerRestoresTheDueFlagWhenTheApplyThrows(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD]]) + ['pending' => TRUE, 'config' => ['system/maximumtableentries' => ''],
			'writeConfigThrow' => ['pfBlockerNG: save max Firewall table entries limit'],
			'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => 'apply'])]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertStringContainsString('throws, as the scenario asks', $r['log'], 'before: the apply threw');
		$this->assertTrue($r['ledgerPending']);
		$this->assertTrue($r['pending']);
		$this->assertFalse($r['locks']['feedPass']);
	}

	// ---- the Resolver reload, its archive and its accounting ---------------------------------------

	/** @return array<string, array{0: array<string, mixed>, 1: int}> what pfb_apply_dns() reports => the Resolver reloads */
	public static function dnsStepReports(): array
	{
		return [
			'the Unbound configuration changed' => [['mode' => 'enabled', 'update' => TRUE], 1],
			'the python integration changed'    => [['mode' => 'enabled', 'python' => TRUE], 1],
			'nothing changed'                   => [['mode' => 'enabled'], 0],
		];
	}

	/** WHEN the DNS step reports a change THEN the Resolver is reloaded with its mode; WHEN nothing changed THEN it is not. */
	#[DataProvider('dnsStepReports')]
	public function testTheResolverIsReloadedOnlyWhenTheDnsStepReportsAChange(array $dns, int $reloads): void
	{
		$r = $this->applyOnce(['apply' => ['request' => self::request([], ['scope' => 'dnsbl']),
			'seams' => ['dns' => $dns, 'unbound' => []]]]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertCount($reloads, $r['seamCalls']['unbound']);
		if ($reloads === 1) {
			$this->assertSame(['enabled', !empty($dns['update']), !empty($dns['python'])], $r['seamCalls']['unbound'][0]);
		}
	}

	/** @return array<string, array{0: array<string, mixed>, 1: array<string, mixed>, 2: int}> */
	public static function archiveCases(): array
	{
		$changed = ['mode' => 'enabled', 'update' => TRUE, 'active' => TRUE];
		// the boot registrations are in place, so the apply's own registration steps change nothing
		$aliastables = '/usr/local/pkg/pfblockerng/pfblockerng.sh aliastables restore';
		$ram = ['system/use_mfs_tmpvar' => '', 'system/earlyshellcmd' => [$aliastables],
			'installedpackages/shellcmdsettings/config' => [['cmd' => $aliastables, 'cmdtype' => 'earlyshellcmd', 'description' => 'pfBlockerNG']]];
		return [
			'DNSBL changed on a RAM-disk /var'    => [$changed, $ram, 1],
			'/var is not a RAM disk'              => [$changed, [], 0],
			'the Resolver was not reloaded'       => [array_replace($changed, ['update' => FALSE]), $ram, 0],
			'DNSBL is not active'                 => [['active' => FALSE] + $changed, $ram, 0],
		];
	}

	/** #468, as the update pass: the generated DNSBL state is archived after a reload on a RAM-disk /var, and only then. */
	#[DataProvider('archiveCases')]
	public function testTheReloadArchivesTheDnsblStateAsThePassDoes(array $dns, array $config, int $saves): void
	{
		$r = $this->applyOnce(['config' => $config, 'apply' => ['request' => self::request([], ['scope' => 'dnsbl']),
			'seams' => ['dns' => $dns, 'unbound' => [], 'cache' => TRUE]]]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame($saves, $r['seamCalls']['cache']);
		if ($saves === 1) {
			$this->assertSame('save', $r['seamCalls']['cacheMode']);
		}
	}

	/** @return array<string, array{0: string}> */
	public static function failedAccountings(): array
	{
		return ['the accounting-failed flag is set' => ['flag'], 'the accounting retry marker is set' => ['marker']];
	}

	/** WHEN the Resolver step's accounting failed THEN the apply exits 1, keeps the changes pending and records a failure. */
	#[DataProvider('failedAccountings')]
	public function testAFailedAccountingIsNotSettledAsApplied(string $effect): void
	{
		$apply = ['pendingToken' => 'tok-5', 'openRecord' => TRUE, 'apply' => ['request' => self::request([], ['scope' => 'dnsbl', 'pendingToken' => 'tok-5'] + self::dnsblGroups()),
			'seams' => ['dns' => ['mode' => 'enabled', 'update' => TRUE], 'unbound' => ['effect' => $effect]]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertTrue($r['pending'], 'the changes stay pending');
		$this->assertSame('failed', $r['applyRecord']['outcome'] ?? NULL);
	}

	/** @return array{dnsbl: array<string, mixed>} the groups of a DNSBL request, so its statistics are written */
	private static function dnsblGroups(): array
	{
		return ['dnsbl' => ['generation' => '9', 'groups' => [['name' => 'Ads', 'entries' => 120, 'changed' => FALSE]]]];
	}

	/** @return array<string, array{0: array<string, mixed>, 1: array<string, mixed>}> what is stored before the apply and the DNS step reports => the Resolver reloads */
	public static function reloadsTheDnsStepDoesNotReport(): array
	{
		return [
			'an accounting retry is recorded' => [['retryMarker' => TRUE], ['mode' => 'enabled']],
		];
	}

	/** WHEN an accounting retry is recorded THEN the Resolver reloads although the DNS step reports no change. */
	#[DataProvider('reloadsTheDnsStepDoesNotReport')]
	public function testTheResolverReloadsForARetryTheDnsStepDoesNotReport(array $before, array $dns): void
	{
		$r = $this->applyOnce(['apply' => $before + ['request' => self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups()),
			'seams' => ['dns' => $dns, 'unbound' => []]]]);

		$this->assertSame([['enabled', FALSE, FALSE]], $r['seamCalls']['unbound'], $r['log']);
	}

	/** WHEN the accounting retry marker is stale and the apply's own accounting succeeded and DNSBL is disabled THEN the marker is cleared and the apply exits 0, as does the next one. */
	public function testTheAccountingRetryMarkerIsClearedOnceDnsblIsDisabled(): void
	{
		$apply = ['apply' => ['request' => self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups()),
			'seams' => ['dns' => ['mode' => 'disabled'], 'unbound' => []]]];
		[, $first, $second] = $this->runSteps([self::prime([self::group('Abuse')]),
			['apply' => ['retryMarker' => TRUE] + $apply['apply']], $apply]);

		$this->assertSame(0, $first['exit'], $first['log']);
		$this->assertNull($first['retryMarker'], 'the stale marker is cleared');
		$this->assertSame(0, $second['exit'], $second['log']);
	}

	/** WHEN the reload did not converge THEN the marker stays and the changes stay pending. */
	public function testTheAccountingRetryMarkerStaysWhileTheReloadHasNotConverged(): void
	{
		$r = $this->applyOnce(['apply' => ['retryMarker' => TRUE, 'request' => self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups()),
			'seams' => ['dns' => ['mode' => 'enabled'], 'unbound' => []]]]);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame('accounting', $r['retryMarker']);
	}

	/** WHEN the DNSBL statistics cannot be written THEN the Resolver is not reloaded, as in the pass, and the apply exits 1; a stale publish flag does not suppress a reload. */
	public function testAFailedStatisticsStepSuppressesTheReloadAndAStalePublishFlagDoesNot(): void
	{
		$request = self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups());
		$seams = ['dns' => ['mode' => 'enabled', 'update' => TRUE], 'unbound' => []];
		$failed = $this->applyOnce(['apply' => ['statsFail' => TRUE, 'request' => $request, 'seams' => $seams]]);
		$stale = $this->applyOnce(['apply' => ['publishFailed' => TRUE, 'request' => $request, 'seams' => $seams]]);

		$this->assertSame(1, $failed['exit'], $failed['log']);
		$this->assertSame([], $failed['seamCalls']['unbound'], 'no reload after the failed statistics');
		$this->assertCount(1, $stale['seamCalls']['unbound'], 'the flag of an earlier run is reset: ' . $stale['log']);
	}

	/**
	 * WHEN a step's DNSBL statistics cannot be written THEN the next step of the same worker writes its rows: the failure ends with
	 * its step. The next step runs with DNSBL disabled, so the accounting retry its predecessor recorded is reconciled.
	 */
	public function testAFailedStatisticsStepDoesNotCarryOverToTheNextApply(): void
	{
		$request = self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups());
		[, $failed, $next] = $this->runSteps([self::prime([self::group('Abuse')]),
			['apply' => ['statsFail' => TRUE, 'request' => $request, 'seams' => ['dns' => ['mode' => 'enabled'], 'unbound' => []]]],
			['apply' => ['request' => $request, 'seams' => ['dns' => ['mode' => 'disabled'], 'unbound' => []]]]]);

		$this->assertSame(1, $failed['exit'], 'before: the first step could not write its statistics: ' . $failed['log']);
		$this->assertNull($failed['dnsblStats']);
		$this->assertSame(['DNSBL_Ads' => '120'], $next['dnsblStats'], 'the next step writes its rows');
		$this->assertSame(0, $next['exit'], $next['log']);
	}

	/** @return array<string, array{0: string}> the DNS step's mode */
	public static function dnsModes(): array
	{
		return ['DNSBL is enabled' => ['enabled'], 'DNSBL is disabled' => ['disabled']];
	}

	/** WHEN the request has no dnsbl body THEN the apply cannot reconcile a stale accounting marker: it neither fails on it nor clears it. */
	#[DataProvider('dnsModes')]
	public function testARequestWithNoDnsblBodyNeitherFailsOnNorClearsTheRetryMarker(string $mode): void
	{
		$r = $this->applyOnce(['apply' => ['retryMarker' => TRUE, 'request' => self::request([], ['scope' => 'dnsbl']),
			'seams' => ['dns' => ['mode' => $mode], 'unbound' => []]]]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame('accounting', $r['retryMarker'], 'the pass reconciles the marker');
	}

	/** @return array<string, array{0: bool, 1: int}> the DNS step's report => the Resolver reloads, with a temporary unlock stored */
	public static function reloadsWithAStoredUnlock(): array
	{
		return ['the DNS step reports no change' => [FALSE, 0], 'the DNS step reports a change' => [TRUE, 1]];
	}

	/** WHEN only a temporary unlock is stored THEN the Resolver is not reloaded; WHEN it reloads for another reason THEN it does, as the pass does. */
	#[DataProvider('reloadsWithAStoredUnlock')]
	public function testAStoredTemporaryUnlockAloneDoesNotReloadTheResolver(bool $update, int $reloads): void
	{
		$r = $this->applyOnce(['apply' => ['unlock' => TRUE, 'request' => self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups()),
			'seams' => ['dns' => ['mode' => 'enabled', 'update' => $update], 'unbound' => []]]]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertCount($reloads, $r['seamCalls']['unbound'], $r['log']);
	}

	/** @return array<string, array{0: bool, 1: int, 2: ?string}> */
	public static function proxyStates(): array
	{
		return ['the proxy runs: converged' => [TRUE, 0, NULL], 'the proxy is down: not converged' => [FALSE, 1, 'accounting']];
	}

	/** WHEN the marker is stale and the host hosts DNSBL THEN it is cleared only once the reload converged (the proxy runs); without that it stays. */
	#[DataProvider('proxyStates')]
	public function testTheAccountingRetryMarkerIsClearedOnlyWhenTheHostRunsTheConvergedReload(bool $running, int $exit, ?string $marker): void
	{
		$r = $this->applyOnce(['config' => ['unbound/custom_options' => base64_encode(PFB_DNS_PROXY_MARKER . "\n"), 'unbound/python_script' => ''],
			'writeConfigFail' => ['pfBlockerNG: Added DNSBL Unbound upstream observer settings'],
			'apply' => ['retryMarker' => TRUE, 'proxyRunning' => $running, 'request' => self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups()),
				'seams' => ['dns' => ['mode' => 'enabled', 'active' => TRUE], 'unbound' => []]]]);

		$this->assertCount(1, $r['seamCalls']['unbound'], 'before: the retry reloads the Resolver: ' . $r['log']);
		$this->assertSame($exit, $r['exit'], $r['log']);
		$this->assertSame($marker, $r['retryMarker']);
	}

	/** WHEN the Resolver reloaded because a retry was recorded THEN the result line says DNSBL changed. */
	public function testDnsblChangedIsReportedWhenTheResolverReloadedForARetry(): void
	{
		$r = $this->applyOnce(['apply' => ['retryMarker' => TRUE, 'request' => self::request([], ['scope' => 'dnsbl'] + self::dnsblGroups()),
			'seams' => ['dns' => ['mode' => 'enabled'], 'unbound' => []]]]);

		$this->assertCount(1, $r['seamCalls']['unbound'], 'before: the Resolver reloaded: ' . $r['log']);
		$this->assertTrue($r['resultLines'][0]['dnsblChanged']);
	}

	/** @return array<string, array{0: string, 1: bool, 2: bool}> trigger, due flag before, due flag after a deferral that marks nothing pending */
	public static function deferralsAndTheDueFlag(): array
	{
		return [
			'manual: Core does not retry it'               => ['manual', FALSE, TRUE],
			'apply that cleared the flag: puts it back'    => ['apply', TRUE, TRUE],
			'apply that found no flag: sets none'          => ['apply', FALSE, FALSE],
			'scheduled: Core retries it on its next tick'  => ['scheduled', FALSE, FALSE],
			'retry: Core retries it on its next tick'      => ['retry', FALSE, FALSE],
		];
	}

	/** WHEN the Core API does not answer THEN the due flag is set for the triggers Core does not retry, only if the apply cleared it for the apply trigger, and nothing is marked pending. */
	#[DataProvider('deferralsAndTheDueFlag')]
	public function testADeferralSetsTheDueFlagOnlyForTheTriggersCoreDoesNotRetry(string $trigger, bool $before, bool $after): void
	{
		$r = $this->applyOnce(self::at([self::ABUSE => ['1', self::OLD]]) + ['pending' => $before, 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => $trigger])]]);

		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertSame($after, $r['ledgerPending']);
		$this->assertSame($before, $r['pending'], 'the deferral marks no change pending');
	}

	/** WHEN a scheduled apply defers (a lock is held, Core does not answer) THEN it marks nothing pending: Core's next tick retries it. */
	#[DataProvider('deferrals')]
	public function testADeferredApplyLeavesThePendingStateAlone(array $apply): void
	{
		$r = $this->applyOnce(self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => 'scheduled'])] + $apply]);

		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertFalse($r['pending'], 'the deferral does not mark changes pending');
		$this->assertFalse($r['ledgerPending'], 'nor the due flag');
	}

	/** WHEN the result line cannot be written THEN the apply record says failed, not applied, and the changes stay pending. */
	public function testAnUnwrittenResultLineIsNotRecordedAsApplied(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD]]) + ['pendingToken' => 'tok-6', 'openRecord' => TRUE, 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['pendingToken' => 'tok-6']),
			'core' => [self::unchanged(self::ABUSE, '2')], 'seams' => ['reportFails' => TRUE]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertTrue($r['pending']);
		$this->assertSame('failed', $r['applyRecord']['outcome'] ?? NULL);
	}

	/** WHEN the apply does not complete THEN the due flag is set again, whatever the trigger. */
	#[DataProvider('triggersOfAnApply')]
	public function testAnApplyThatFailsKeepsTheDueFlagForEveryTrigger(string $trigger): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['pending' => TRUE, 'pfctlFail' => ['pfB_Abuse_v4.add'], 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => $trigger]),
			'core'    => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']),
				self::text(['192.0.2.2'])]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertTrue($r['ledgerPending'], "a failed {$trigger} apply keeps the pending apply flag");
	}

	/** @return array<string, array{0: string}> */
	public static function triggersOfAnApply(): array
	{
		return ['manual' => ['manual'], 'scheduled' => ['scheduled'], 'apply' => ['apply']];
	}

	/** WHEN the apply throws part way through the fetch THEN no staged mirror is left beside the old ones and nothing moved. */
	public function testAnExceptionAfterTheFirstStagedMirrorLeavesNoStagedFile(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD], self::BETA => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '2', 3)]),
			'core'    => [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']),
				self::text(['192.0.2.2'])],
			'seams'   => ['fetchThrowAt' => 2]]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertStringContainsString('the fetch throws, as the scenario asks', $r['log']);
		$this->assertSame(['pfB_Abuse_v4.txt' => self::OLD, 'pfB_Beta_v4.txt' => self::OLD], $r['mirrors'], 'no mirror moved and none is left staged');
		$this->assertSame([], self::pushes($r));
	}

	// ---- what a push, a fetch, a removal and the settlement report -------------------------------

	/** @return array{status: int, type: string, body: string} Core's answer that the store cannot serve what was asked */
	private static function unavailable(): array
	{
		return ['status' => 503, 'type' => 'application/json', 'body' => json_encode(['error' => ['code' => 'unavailable', 'message' => 'the body fails verification']])];
	}

	/** @return list<array<string, mixed>> Core's delta of Abuse from generation 1 to 2, with both parts */
	private static function abuseDelta(): array
	{
		return [self::delta(self::ABUSE, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW), self::text(['203.0.113.9']), self::text(['192.0.2.2'])];
	}

	/** @return list<string> the pfctl verb of each table-changing call of a record, with its table */
	private static function verbs(array $record): array
	{
		return array_map(static fn (array $c): string => (string) preg_replace('/^-t (\S+) -T (\w+).*$/', '$1 $2', $c['call']), self::pushes($record));
	}

	/** WHEN an IP unlock coincides with a delta THEN the table is replaced from its mirror: the delta alone would leave the unlocked member out. */
	public function testAnIpUnlockThatCoincidesWithADeltaReplacesTheTable(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]);
		$apply['files']['ip_unlock'] = [''];	// the Alerts page's IP unlock
		$apply['apply'] = ['request' => self::request([self::resource(self::ABUSE, '2', 3)]), 'core' => self::abuseDelta()];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertTrue($r['resultLines'][0]['ipChanged'], 'before: the unlock forced a re-block');
		$this->assertSame(['pfB_Abuse_v4 replace'], self::verbs($r), 'mode delta, yet a replace from the mirror');
		$this->assertSame(self::NEW, $r['kernel']['pfB_Abuse_v4']);
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied']);
	}

	/** WHEN Core answers a resource but cannot serve its body THEN the apply defers (exit 75): no result line, and no mirror, table or cursor moves. */
	public function testABodyCoreCannotServeDefersTheApply(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD], self::BETA => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '2', 3)]),
			'core'    => [self::full(self::ABUSE, '2', self::NEW), self::text(self::NEW), self::full(self::BETA, '2', self::NEW), self::unavailable()]]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertCount(4, $r['coreRequests'], "before: Abuse was fetched whole and Beta's body asked for");
		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertSame([], $r['resultLines']);
		$this->assertSame(['pfB_Abuse_v4.txt' => self::OLD, 'pfB_Beta_v4.txt' => self::OLD], $r['mirrors'], 'no mirror moved and none is left staged');
		$this->assertSame([], self::pushes($r));
		$this->assertSame([self::ABUSE => '1', self::BETA => '1'], self::generations($r));
	}

	/** WHEN Core's answer names one resource it cannot serve THEN that resource fails and the others are applied: one unreadable resource does not hide the others. */
	public function testAResourceCoreAnswersUnavailableFailsAlone(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD], self::BETA => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '2', 3)]),
			'core'    => [self::unchanged(self::ABUSE, '2'), self::items(self::BETA, ['error' => ['code' => 'unavailable', 'message' => 'damaged']])]]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([[self::BETA, 'fetch']], self::failedPairs($r));
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied']);
	}

	/** @return array<string, array{0: ?list<string>}> a kernel table its resource's mirror is not empty for */
	public static function lostTables(): array
	{
		return ['the table is empty' => [[]], 'the table is gone' => [NULL]];
	}

	/** WHEN Core answers unchanged but pf lost the table THEN the table is replaced from the verified mirror and the resource is applied. */
	#[DataProvider('lostTables')]
	public function testAnUnchangedResourceWhoseTableWasLostIsReplacedFromItsMirror(?array $kernel): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD]]);
		$apply['kernel']['pfB_Abuse_v4'] = $kernel;
		$apply['apply'] = ['request' => self::request([self::resource(self::ABUSE, '2', 3)]), 'core' => [self::unchanged(self::ABUSE, '2')]];
		$r = $this->applyOnce($apply);

		$this->assertCount(1, $r['coreRequests'], 'before: Core answered unchanged and no body was fetched');
		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame(['pfB_Abuse_v4 replace'], self::verbs($r));
		$this->assertSame(self::OLD, self::pushes($r)[0]['lines'], 'the mirror is what the table is replaced from');
		$this->assertSame(self::OLD, $r['kernel']['pfB_Abuse_v4'] ?? NULL);
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied']);
		$this->assertSame(['pfB_Abuse_v4'], $r['resultLines'][0]['changedAliases'] ?? NULL);
		$this->assertSame([self::ABUSE => '2'], self::generations($r));
	}

	/** @return array<string, array{0: array<string, mixed>, 1: int}> an apply that fetched a delta's parts, and its exit status */
	public static function appliesThatFetchedParts(): array
	{
		$both = self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '1', 3)]);
		return [
			'the apply completes'           => [['request' => self::request([self::resource(self::ABUSE, '2', 3)]), 'core' => self::abuseDelta()], 0],
			'Core stops serving: deferred'  => [['request' => $both, 'core' => [...self::abuseDelta(), self::unavailable()]], PFB_EXIT_LOCKED],
			'the next fetch throws'         => [['request' => $both, 'core' => self::abuseDelta(), 'seams' => ['fetchThrowAt' => 2]], 1],
		];
	}

	/** WHEN the apply ends, whether it completed, deferred or threw THEN none of the delta parts it fetched is left on disk. */
	#[DataProvider('appliesThatFetchedParts')]
	public function testNoDeltaPartIsLeftOnDisk(array $apply, int $exit): void
	{
		$r = $this->applyOnce(self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => $apply], ['Abuse', 'Beta']);

		$this->assertGreaterThanOrEqual(3, count($r['coreRequests']), 'before: both parts of the delta were fetched');
		$this->assertSame($exit, $r['exit'], $r['log']);
		$this->assertSame([], $r['workFiles']);
	}

	/** WHEN the cursor of a removed resource cannot be dropped THEN it is reported failed, not removed; its retry, with the table gone already, drops it. */
	public function testARemovalWhoseCursorCannotBeDroppedFailsAndItsRetryDropsIt(): void
	{
		$removal = ['config' => ['installedpackages/pfblockernglistsv4/config' => [self::group('Abuse')]],
			'apply' => ['request' => self::request([], ['removed' => [self::BETA]])]];
		$blocked = self::at([self::BETA => ['3', self::OLD]]);
		$blocked['files']['{dbdir}/pfb_apply_cursors.json.tmp/blocked'] = [];	// a folder where the cursor file's temporary goes
		[, $first, $retry] = $this->runSteps([self::prime([self::group('Abuse'), self::group('Beta')]), $blocked + $removal,
			['files' => ['{dbdir}/pfb_apply_cursors.json.tmp' => NULL]] + $removal]);

		$this->assertArrayNotHasKey('pfB_Beta_v4', $first['kernel'], 'before: the table was killed');
		$this->assertSame(1, $first['exit'], $first['log']);
		$this->assertSame([[self::BETA, 'apply']], self::failedPairs($first));
		$this->assertArrayNotHasKey('removed', $first['resultLines'][0]);
		$this->assertSame([self::BETA => '3'], self::generations($first), 'the cursor is still recorded');
		$this->assertSame(0, $retry['exit'], $retry['log']);
		$this->assertSame([self::BETA], $retry['resultLines'][0]['removed'] ?? NULL);
		$this->assertSame([], self::generations($retry));
	}

	/** WHEN a rule change makes the apply replace a table itself and pfctl fails, though no ledger entry records it, THEN the resource fails and keeps its cursor. */
	public function testARuleChangeReplaceThatFailsKeepsTheCursor(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]);
		$apply['files']['{dbdir}/pfb_sync_status.json/unwritable'] = [];	// a folder at the ledger's path: no entry is written
		$apply += ['pfctlFail' => ['pfB_Abuse_v4.replace'],
			'config' => ['installedpackages/pfblockernglistsv4/config' => [self::group('Abuse'), self::group('Beta')]],
			'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '1', 3)]),
				'core' => [self::full(self::ABUSE, '2', self::NEW), self::text(self::NEW), self::full(self::BETA, '1', self::NEW), self::text(self::NEW)]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(['pfB_Abuse_v4 replace'], self::verbs($r), 'before: the rule change replaced the loaded table directly');
		$this->assertArrayNotHasKey('pfb_sync_status.json', $r['syncStatus'], 'before: no ledger entry was written');
		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([[self::ABUSE, 'apply']], self::failedPairs($r));
		$this->assertSame([self::ABUSE => '1', self::BETA => '1'], self::generations($r));
		$this->assertSame(['pfB_Beta_v4'], $r['resultLines'][0]['changedAliases'], 'the table that failed is not reported changed');
	}

	/** WHEN one table's push fails THEN changedAliases names only the tables that were pushed. */
	public function testChangedAliasesNamesOnlyTheTablesPushed(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD], self::BETA => ['1', self::OLD]]) + ['pfctlFail' => ['pfB_Beta_v4.add'], 'apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3), self::resource(self::BETA, '2', 3)]),
			'core'    => [...self::abuseDelta(), self::delta(self::BETA, '2', '1', ['203.0.113.9'], ['192.0.2.2'], self::NEW),
				self::text(['203.0.113.9']), self::text(['192.0.2.2'])]]];
		$r = $this->applyOnce($apply, ['Abuse', 'Beta']);

		$this->assertSame([[self::BETA, 'apply']], self::failedPairs($r), 'before: the push of Beta failed');
		$this->assertSame(['pfB_Abuse_v4'], $r['resultLines'][0]['changedAliases']);
	}

	/** WHEN the settlement cannot clear the due flag THEN the apply exits 1; the result line still reports what was applied. */
	public function testASettlementThatCannotClearTheDueFlagFailsTheApply(): void
	{
		$apply = self::at([self::ABUSE => ['2', self::OLD]]);
		$apply['files']['{dbdir}/pfb_due_ledger.json'] = [json_encode(['cron' => ['last_run' => 0, 'next_due' => 0, 'jitter' => 0, 'pending_apply' => TRUE]])];
		$apply['files']['{dbdir}/pfb_due_ledger.json.lock/blocked'] = [];	// a folder at the ledger's lock: no ledger write succeeds
		$apply += ['openRecord' => TRUE, 'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)]),
			'core' => [self::unchanged(self::ABUSE, '2')]]];
		$r = $this->applyOnce($apply);

		$this->assertTrue($r['ledgerPending'], 'before: the due flag could not be cleared');
		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied'], 'the resources applied are still reported');
		$this->assertSame('failed', $r['applyRecord']['outcome'] ?? NULL);
	}

	/** WHEN Core's reply spells the requested generation otherwise ("7" for "007") THEN applied echoes the request's string and the cursor keeps Core's. */
	public function testAppliedEchoesTheRequestsGenerationString(): void
	{
		$rows = array_map(static fn (array $row): string => json_encode($row, JSON_THROW_ON_ERROR), [
			['kind' => 'country', 'page' => 'Africa', 'family' => 4, 'position' => 1, 'iso' => 'AA', 'country' => 'Alpha', 'networks' => 2],
			['kind' => 'page', 'page' => 'Africa', 'continent' => 'Africa']]);
		$apply = ['apply' => ['request' => self::request([self::resource(self::ABUSE, '007', 3), ['id' => 'geo-catalog', 'generation' => '003']]),
			'core' => [self::full(self::ABUSE, '7', self::NEW), self::text(self::NEW), self::full('geo-catalog', '3', $rows), self::text($rows)]]];
		$r = $this->applyOnce($apply);

		$this->assertSame(0, $r['exit'], $r['log']);
		$applied = $r['resultLines'][0]['applied'];
		ksort($applied);
		$cursors = self::generations($r);
		ksort($cursors);
		$this->assertSame(['geo-catalog' => '003', self::ABUSE => '007'], $applied);
		$this->assertSame(['geo-catalog' => '3', self::ABUSE => '7'], $cursors);
	}

	// ---- the version dispatch ------------------------------------------------------------------

	/** A version 2 request the contract refuses runs nothing, writes no result and no settings, and exits 2, with the version 2 reason. */
	public function testARefusedVersionTwoRequestExitsTwoWithItsReason(): void
	{
		$unset = ['config' => ['system/maximumtableentries' => '']];	// the settings step writes the table entries limit's default
		[, $r, $valid] = $this->runSteps([self::prime([self::group('Abuse')]),
			$unset + ['apply' => ['request' => self::request([]) + ['force' => 'none']]], ['apply' => ['request' => self::request([])]]]);
		$writes = static fn (array $record): array => array_map(static fn (mixed $call): string => is_array($call)
			? (string) ($call[0] ?? $call['desc'] ?? '') : (string) $call, $record['writeConfig']);

		$this->assertSame(2, $r['exit'], $r['log']);
		$this->assertNull($r['resultLines'], 'no result file');
		$this->assertStringContainsString('the request has the unknown field "force"', $r['log']);
		$this->assertSame([], $writes($r), 'a refused request writes no settings');
		$this->assertContains('pfBlockerNG: save max Firewall table entries limit', $writes($valid), 'before: a request that runs writes the default');
	}
}
