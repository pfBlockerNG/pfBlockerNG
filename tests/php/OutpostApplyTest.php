<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
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
		return ['version' => 2, 'trigger' => 'manual', 'scope' => 'ip', 'resources' => $resources] + $more;
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
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

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
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

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
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

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
		[, $r] = $this->runSteps([self::prime([self::group('Abuse'), self::group('Beta')]), $apply]);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([self::ABUSE => '2', self::BETA => '1'], self::generations($r));
		$this->assertSame([self::ABUSE => '2'], $r['resultLines'][0]['applied']);
		$this->assertSame([[self::BETA, 'apply']], array_map(static fn (array $f): array => [$f['id'], $f['stage']], $r['resultLines'][0]['failed']));
		$this->assertTrue($r['pending'], 'a failed apply settles no pending change');
	}

	// ---- deferral ------------------------------------------------------------------------------

	/** WHEN the apply lock is held THEN the apply exits 75, writes no result line and moves no cursor. */
	public function testAHeldApplyLockDefersWithNoResultLine(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)]), 'lockHeld' => TRUE]];
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertSame([], $r['resultLines']);
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
		$this->assertSame([], self::pushes($r));
	}

	/** WHEN the Core API does not answer GetResources THEN the apply exits 75. */
	public function testCoreNotAnsweringDefers(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)])]];
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(PFB_EXIT_LOCKED, $r['exit'], $r['log']);
		$this->assertSame([], $r['resultLines']);
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
		$this->assertSame(self::OLD, $r['mirrors']['pfB_Abuse_v4.txt']);
	}

	/** The apply trigger clears the due-ledger flag first and puts it back when the apply does not complete. */
	public function testTheApplyTriggerClearsTheDueFlagAndRestoresItWhenTheApplyDefers(): void
	{
		$cursor = self::at([self::ABUSE => ['2', self::OLD]]);
		$deferred = $cursor + ['pending' => TRUE, 'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => 'apply'])]];
		$applied = ['pending' => TRUE, 'apply' => ['request' => self::request([self::resource(self::ABUSE, '2', 3)], ['trigger' => 'apply']),
			'core' => [self::unchanged(self::ABUSE, '2')]]];
		[, $d, $a] = $this->runSteps([self::prime([self::group('Abuse')]), $deferred, $applied]);

		$this->assertSame(PFB_EXIT_LOCKED, $d['exit'], $d['log']);
		$this->assertTrue($d['ledgerPending'], 'a deferred apply keeps the pending apply flag');
		$this->assertSame(0, $a['exit'], $a['log']);
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
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertTrue($r['pending'], 'the later mark is still pending');
	}

	/** With pendingOutsideWindow the apply marks the changes pending, applies nothing and writes one line without applied. */
	public function testOutsideTheWindowTheChangesAreMarkedPendingAndNothingIsApplied(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3)], ['pendingOutsideWindow' => TRUE])]];
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertSame([['version' => 2]], $r['resultLines']);
		$this->assertSame([], $r['coreRequests']);
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
		$this->assertLessThanOrEqual(PFB_CORE_UPDATE_V2_MESSAGE_BYTES + 512, strlen($notice), 'the notice is bounded');
		$ledger = json_decode($first['syncStatus']['pfb_sync_status.json'], TRUE);
		$entry = $ledger['ip']['feed/ipv4:Foo_v4']['download'] ?? NULL;
		$this->assertIsArray($entry, 'the issue is an ADR-61 entry of its stage: ' . $first['syncStatus']['pfb_sync_status.json']);
		$this->assertLessThanOrEqual(PFB_CORE_UPDATE_V2_MESSAGE_BYTES + 512, strlen($entry['message']));

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
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([], $r['coreRequests']);
		$this->assertSame([['ip-set/Ghost/ipv4', 'apply']], array_map(static fn (array $f): array => [$f['id'], $f['stage']], $r['resultLines'][0]['failed']));
	}

	/** A full body that would exceed the firewall's table entries limit is not fetched and fails with stage apply. */
	public function testAResourceOverTheTableEntriesLimitIsNotFetched(): void
	{
		$apply = ['apply' => ['request' => self::request([self::resource(self::ABUSE, '9', 3000000)])]];
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([], $r['coreRequests']);
		$this->assertSame([[self::ABUSE, 'apply']], array_map(static fn (array $f): array => [$f['id'], $f['stage']], $r['resultLines'][0]['failed']));
		$this->assertStringContainsString('table entries limit', $r['resultLines'][0]['failed'][0]['message']);
	}

	/** Decision 2 on #4037: a resource whose action disagrees with config.xml is not applied and keeps its cursor. */
	public function testAResourceWhoseActionChangedSinceTheSnapshotFails(): void
	{
		$apply = self::at([self::ABUSE => ['1', self::OLD]]) + ['apply' => [
			'request' => self::request([self::resource(self::ABUSE, '2', 3, 'permit')])]];
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(1, $r['exit'], $r['log']);
		$this->assertSame([], $r['coreRequests']);
		$this->assertSame([[self::ABUSE, 'apply']], array_map(static fn (array $f): array => [$f['id'], $f['stage']], $r['resultLines'][0]['failed']));
		$this->assertSame([self::ABUSE => '1'], self::generations($r));
	}

	// ---- removal -------------------------------------------------------------------------------

	/** A removed resource's table is killed, its mirror unlinked and its cursor dropped; the removal is reported. */
	public function testARemovedResourceIsTornDown(): void
	{
		$apply = self::at([self::BETA => ['3', self::OLD]]) + ['config' => ['installedpackages/pfblockernglistsv4/config' => [self::group('Abuse')]],
			'apply' => ['request' => self::request([], ['removed' => [self::BETA]])]];
		[, $r] = $this->runSteps([self::prime([self::group('Abuse'), self::group('Beta')]), $apply]);

		$this->assertSame(0, $r['exit'], $r['log']);
		$this->assertArrayNotHasKey('pfB_Beta_v4', $r['kernel']);
		$this->assertArrayNotHasKey('pfB_Beta_v4.txt', $r['mirrors']);
		$this->assertSame([], self::generations($r));
		$this->assertSame([self::BETA], $r['resultLines'][0]['removed']);
		$this->assertNotContains('pfB_Beta_v4', array_column($r['aliases'], 'name'));
	}

	// ---- the version dispatch ------------------------------------------------------------------

	/** A version 2 request the contract refuses runs nothing, writes no result and exits 2, with the version 2 reason. */
	public function testARefusedVersionTwoRequestExitsTwoWithItsReason(): void
	{
		$apply = ['apply' => ['request' => self::request([]) + ['force' => 'none']]];
		[, $r] = $this->runSteps([self::prime([self::group('Abuse')]), $apply]);

		$this->assertSame(2, $r['exit'], $r['log']);
		$this->assertNull($r['resultLines'], 'no result file');
		$this->assertStringContainsString('the request has the unknown field "force"', $r['log']);
	}
}
