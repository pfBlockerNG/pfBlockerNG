<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsblNatWriterSeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3453 (owner fork 1, #3443) — copied pfB_* object detector: aliases, filter rules and
 * NAT rules that a pfSense HA copy or a manual edit changed after this node wrote them are
 * REPORTED (object identity + differing attribute names, never values), never re-owned and never
 * changed by the apply (docs/specs/xmlrpc-per-field-sync.md, "Reporting" item 5, acceptance 12).
 *
 * The external values are LEAK_*_SENTINEL strings: none may reach the diff, the state file, the
 * notice or the log.
 */
#[CoversFunction('pfb_sync_copied_diff')]
#[CoversFunction('pfb_sync_copied_digests')]
#[CoversFunction('pfb_sync_copied_check')]
#[CoversFunction('pfb_sync_copied_read')]
#[CoversFunction('pfb_create_dnsbl')]
#[CoversFunction('pfb_managed_obj_rows')]
final class SyncCopiedObjectsTest extends TestCase
{
	use DnsblNatWriterSeedTrait;

	private const SENTINELS = ['LEAK_IFACE_SENTINEL', 'LEAK_ADDR_SENTINEL', 'LEAK_DEST_SENTINEL', 'LEAK_LOCAL_SENTINEL', 'LEAK_GENERATED_SENTINEL'];

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;
		$this->dir         = $this->makeDir();

		$GLOBALS['pfb_test_file_notices']       = [];
		$GLOBALS['pfb_test_logger_calls']       = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		$this->removeDir($this->dir);
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->savedPfb === NULL) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		unset($GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_vip_list']);
	}

	private function makeDir(): string
	{
		$dir = sys_get_temp_dir() . '/pfb_sync_copied_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700);
		return $dir;
	}

	private function removeDir(string $dir): void
	{
		foreach (scandir($dir) ?: [] as $entry) {
			if ($entry !== '.' && $entry !== '..') {
				unlink("{$dir}/{$entry}");
			}
		}
		rmdir($dir);
	}

	// ---- fixtures ----------------------------------------------------------------------

	/** @return array<string,mixed> */
	private static function volatile(int $time): array
	{
		return ['created' => ['time' => (string) $time, 'username' => 'Auto'], 'updated' => ['time' => (string) $time, 'username' => 'node']];
	}

	/** @return array<string,mixed> */
	private static function base(string $kind, int $time = 100): array
	{
		return match ($kind) {
			'aliases' => [
				'name' => 'pfB_Alpha_v4', 'type' => 'urltable', 'address' => '/var/db/pfblockerng/deny/Alpha.txt',
				'updatefreq' => '32', 'descr' => 'Alpha', 'detail' => 'Alpha',
			] + self::volatile($time),
			'filter' => [
				'type' => 'block', 'interface' => 'wan', 'ipprotocol' => 'inet', 'tracker' => '1770000001',
				'descr' => 'pfB_Alpha auto rule', 'source' => ['address' => 'pfB_Alpha_v4'], 'destination' => ['any' => ''],
			] + self::volatile($time),
			'nat' => [
				'source' => ['any' => ''], 'destination' => ['address' => '10.10.10.1', 'port' => '53'], 'protocol' => 'tcp/udp',
				'target' => '127.0.0.1', 'interface' => 'lan', 'descr' => 'pfB_DNS_Redirect_lan_v4', 'associated-rule-id' => 'pass',
			] + self::volatile($time),
			'dnsbl_nat' => [
				'source' => ['any' => ''], 'destination' => ['address' => '10.10.10.2', 'port' => '80'], 'protocol' => 'tcp',
				'target' => '127.0.0.1', 'interface' => 'lan', 'descr' => 'pfB DNSBL - DO NOT EDIT', 'associated-rule-id' => 'pass',
			] + self::volatile($time),
			'dot_filter' => [
				'type' => 'block', 'interface' => 'lan', 'ipprotocol' => 'inet', 'tracker' => '1770000002',
				'descr' => 'pfB_DoT_Block_lan', 'protocol' => 'tcp/udp', 'destination' => ['any' => '', 'port' => '853'],
			] + self::volatile($time),
		};
	}

	/** @return array<string,mixed> the object as an external writer leaves it */
	private static function external(string $kind): array
	{
		$object = self::base($kind, 999);
		switch ($kind) {
			case 'aliases':
				$object['address'] = 'LEAK_ADDR_SENTINEL';
				break;
			case 'nat':
			case 'dnsbl_nat':
				$object['interface']              = 'LEAK_IFACE_SENTINEL';
				$object['destination']['address'] = 'LEAK_DEST_SENTINEL';
				break;
			default:
				$object['interface'] = 'LEAK_IFACE_SENTINEL';
		}
		return $object;
	}

	/** @return array<string,mixed> the expectation after a LOCAL settings change */
	private static function changedLocally(string $kind): array
	{
		return self::base($kind) + ['local_tweak' => 'LEAK_LOCAL_SENTINEL'];
	}

	private static function key(string $kind, int $occurrence = 0): string
	{
		$name = self::base($kind)[$kind === 'aliases' ? 'name' : 'descr'];
		return $kind === 'aliases' ? $name : "{$name}#{$occurrence}";
	}

	/** The identity hash a digest map is stored under, computed independently of production. */
	private static function id(string $kind, int $occurrence = 0): string
	{
		$base = self::base($kind);
		return hash('sha256', $kind === 'aliases' ? $base['name'] : "{$base['descr']}#{$occurrence}");
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array<string,mixed> the raw row without created/updated, every level key-sorted
	 */
	private static function canonical(array $row): array
	{
		unset($row['created'], $row['updated']);
		$sort = static function (array $node) use (&$sort): array {
			ksort($node, SORT_STRING);
			return array_map(static fn (mixed $child): mixed => is_array($child) ? $sort($child) : $child, $node);
		};
		return $sort($row);
	}

	/** @param array<string,mixed> $row */
	private static function digestOf(array $row): string
	{
		return hash('sha256', serialize(self::canonical($row)));
	}

	/**
	 * @param array<string,mixed> $node
	 * @return array<string,mixed> the same node with every level's key order reversed
	 */
	private static function reversed(array $node): array
	{
		return array_map(static fn (mixed $child): mixed => is_array($child) ? self::reversed($child) : $child, array_reverse($node, TRUE));
	}

	/** @return array<string,list<string>> */
	private static function externalAttrs(string $kind): array
	{
		return [self::key($kind) => match ($kind) {
			'aliases'              => ['address'],
			'nat', 'dnsbl_nat'     => ['destination/address', 'interface'],
			default                => ['interface'],
		}];
	}

	/** @return array<string,array{string}> */
	public static function kinds(): array
	{
		return ['aliases' => ['aliases'], 'filter' => ['filter'], 'nat' => ['nat'], 'dnsbl_nat' => ['dnsbl_nat'], 'dot_filter' => ['dot_filter']];
	}

	private function stateFile(?string $dir = NULL): string
	{
		return ($dir ?? $this->dir) . '/pfb_sync_copied.json';
	}

	private function stateBytes(): string
	{
		return (string) @file_get_contents($this->stateFile());
	}

	/** @return list<string> every notice, log and state text produced so far */
	private function emitted(): array
	{
		$texts = [$this->stateBytes()];
		foreach ($GLOBALS['pfb_test_file_notices'] as $notice) {
			$texts[] = $notice['notice'];
		}
		foreach ($GLOBALS['pfb_test_logger_calls'] as $call) {
			$texts[] = $call['message'];
		}
		return $texts;
	}

	private function assertNoValueLeak(mixed $diff = NULL): void
	{
		$texts = $this->emitted();
		$texts[] = json_encode($diff, JSON_THROW_ON_ERROR);
		foreach ($texts as $text) {
			foreach (self::SENTINELS as $sentinel) {
				$this->assertStringNotContainsString($sentinel, $text, "external value {$sentinel} leaked");
			}
		}
	}

	/** @return list<string> */
	private function copiedNotices(): array
	{
		$out = [];
		foreach ($GLOBALS['pfb_test_file_notices'] as $notice) {
			if ($notice['id'] === 'pfBlockerNG Sync') {
				$out[] = $notice['notice'];
			}
		}
		return $out;
	}

	// ---- pure diff: rows 1-3, 6-8, 11 -------------------------------------------------------

	#[DataProvider('kinds')]
	public function testOwnWriteIsSilentEvenWhenTheExpectationChanged(string $kind): void
	{
		$written = [self::base($kind)];
		$this->assertSame([], pfb_sync_copied_diff(pfb_sync_copied_digests($written), $written, [self::changedLocally($kind)]));
	}

	#[DataProvider('kinds')]
	public function testIdenticalCopyIsSilent(string $kind): void
	{
		$recorded = pfb_sync_copied_digests([self::base($kind)]);
		$copy     = [self::external($kind)];
		$this->assertSame([], pfb_sync_copied_diff($recorded, $copy, $copy));
	}

	#[DataProvider('kinds')]
	public function testExternalDifferingObjectReportsOnlyAttributeNames(string $kind): void
	{
		$diff = pfb_sync_copied_diff(pfb_sync_copied_digests([self::base($kind)]), [self::external($kind)], [self::base($kind)]);

		$this->assertSame(self::externalAttrs($kind), $diff);
		$this->assertNoValueLeak($diff);
	}

	#[DataProvider('kinds')]
	public function testTimestampOnlyDifferencesAreSilent(string $kind): void
	{
		$recorded = pfb_sync_copied_digests([self::base($kind, 100)]);
		$this->assertSame([], pfb_sync_copied_diff($recorded, [self::base($kind, 555)], [self::base($kind, 777)]));
		$this->assertSame($recorded, pfb_sync_copied_digests([self::base($kind, 555)]));
	}

	#[DataProvider('kinds')]
	public function testFirstRunWithoutRecordedStateInventsNoEvidence(string $kind): void
	{
		$this->assertSame([], pfb_sync_copied_diff(NULL, [self::external($kind)], [self::base($kind)]));
	}

	#[DataProvider('kinds')]
	public function testUnexpectedMissingAndNeverWrittenObjects(string $kind): void
	{
		$base     = self::base($kind);
		$extra    = ['descr' => 'pfB_Extra', 'name' => 'pfB_Extra'] + $base;
		$recorded = pfb_sync_copied_digests([$base]);

		$this->assertSame(['pfB_Extra' => ['(unexpected)']], pfb_sync_copied_diff($recorded, [$base, $extra], [$base]));
		$this->assertSame([self::key($kind) => ['(missing)']], pfb_sync_copied_diff($recorded, [], [$base]));
		$this->assertSame([], pfb_sync_copied_diff($recorded, [$base], [$base, $extra]), 'an expected-only object that was never recorded is not an external change');
		$this->assertSame([], pfb_sync_copied_diff($recorded, [], [$extra]), 'a missing object that was never written is not an external change');
	}

	public function testSameDescrRulesPairByOccurrence(): void
	{
		$wan  = self::base('filter');
		$opt1 = ['interface' => 'opt1'] + $wan;

		$recorded = pfb_sync_copied_digests([$wan, $opt1]);
		$ids      = [self::id('filter', 0), self::id('filter', 1)];
		sort($ids, SORT_STRING);
		$this->assertSame($ids, array_keys($recorded));

		$moved = ['interface' => 'LEAK_IFACE_SENTINEL'] + $opt1;
		$this->assertSame(
			['pfB_Alpha auto rule#1' => ['interface']],
			pfb_sync_copied_diff($recorded, [$wan, $moved], [$wan, $opt1])
		);
		$this->assertSame([], pfb_sync_copied_diff($recorded, [$wan, $opt1], [$wan, $opt1]));
	}

	public function testHostileAttributeKeyIsReportedAsWildcard(): void
	{
		$base    = self::base('filter');
		$hostile = $base + ['bad key<x>' => 'LEAK_LOCAL_SENTINEL', 'ok.key-1_a' => 'x'];

		$diff = pfb_sync_copied_diff(pfb_sync_copied_digests([$base]), [$hostile], [$base]);

		$this->assertSame(['pfB_Alpha auto rule#0' => ['*', 'ok.key-1_a']], $diff);
		$this->assertStringNotContainsString('bad key', json_encode($diff, JSON_THROW_ON_ERROR));
		$this->assertNoValueLeak($diff);
	}

	public function testHostileIdentityNeverReachesStateOrNoticeVerbatim(): void
	{
		$hostile = ['descr' => 'pfB_<script>alert(1)</script>'] + self::base('filter');
		pfb_sync_copied_check('filter', [$hostile], [$hostile], $this->dir);
		pfb_sync_copied_check('filter', [['interface' => 'LEAK_IFACE_SENTINEL'] + $hostile], [$hostile], $this->dir);

		foreach ($this->emitted() as $text) {
			$this->assertStringNotContainsString('<script>', $text);
		}
		$this->assertCount(1, $this->copiedNotices(), 'the finding itself is still reported');
	}

	public function testIdentityLabelsKeepOnlyTheDocumentedGrammar(): void
	{
		$cases = [
			"pfB_1\0x"       => 'pfB_1?x#0',
			"pfB_2\nx"       => 'pfB_2?x#0',
			'pfB_3<script>'  => 'pfB_3?script?#0',
			'pfB_4+5'        => 'pfB_4?5#0',
			"pfB_5\u{e9}"    => 'pfB_5??#0',
			'pfB_6a b.c-d_e' => 'pfB_6a b.c-d_e#0',
		];
		$objects = array_map(static fn (string $descr): array => ['descr' => $descr] + self::base('filter'), array_keys($cases));

		$this->assertSame(array_fill_keys(array_values($cases), ['(unexpected)']), pfb_sync_copied_diff([], $objects, []));
	}

	public function testIdentitiesThatShareALabelAreTrackedIndependently(): void
	{
		$first    = ['name' => 'pfB_<x>', 'address' => 'a'] + self::base('aliases');
		$second   = ['name' => 'pfB_>x<', 'address' => 'b'] + self::base('aliases');
		$recorded = pfb_sync_copied_digests([$first, $second]);
		$this->assertCount(2, $recorded, 'two identities that sanitize to one label keep two digests');

		$firstMoved  = ['address' => 'LEAK_ADDR_SENTINEL'] + $first;
		$secondMoved = ['type' => 'host'] + $second;
		$this->assertSame(['pfB_?x?' => ['address']], pfb_sync_copied_diff($recorded, [$firstMoved, $second], [$first, $second]), 'a change to the first is reported');
		$this->assertSame(['pfB_?x?' => ['type']], pfb_sync_copied_diff($recorded, [$first, $secondMoved], [$first, $second]), 'a change to the second is reported');
		$this->assertSame(['pfB_?x?' => ['address', 'type']], pfb_sync_copied_diff($recorded, [$firstMoved, $secondMoved], [$first, $second]));
		$this->assertSame([], pfb_sync_copied_diff($recorded, [$first, $second], [$first, $second]));
	}

	public function testNulAndControlBytesInAttributeKeysAreMaskedAndNeverCollideWithNestedPaths(): void
	{
		$base     = self::base('nat');
		$recorded = pfb_sync_copied_digests([$base]);

		$hostile = $base + ["LEAK_LOCAL_SENTINEL\0safe" => 'x', "bad\nkey" => 'x', "destination\0address" => 'safe'];
		$hostile['destination']['address'] = 'LEAK_DEST_SENTINEL';
		$diff = pfb_sync_copied_diff($recorded, [$hostile], [$base]);
		$this->assertSame([self::key('nat') => ['*', 'destination/address']], $diff);
		$this->assertNoValueLeak($diff);

		$flat = $base + ["destination\0address" => 'x'];
		$this->assertSame([self::key('nat') => ['*']], pfb_sync_copied_diff($recorded, [$flat], [$base]), 'a flat NUL key is neither the nested path nor lost');
	}

	public function testMissingSubtreeReportsEachLeafPathOfTheSideThatHasIt(): void
	{
		$base    = self::base('nat');
		$without = array_diff_key($base, ['destination' => TRUE]);
		$key     = self::key('nat');

		$this->assertSame([$key => ['destination/address', 'destination/port']], pfb_sync_copied_diff([], [$without], [$base]), 'the copy lacks the subtree');
		$this->assertSame([$key => ['destination/address', 'destination/port']], pfb_sync_copied_diff([], [$base], [$without]), 'the copy adds the subtree');

		$deep = $without + ['destination' => ['address' => 'LEAK_DEST_SENTINEL', "bad\0key" => ['inner' => 'x'], 'sub' => ['k' => 'y'], 'empty' => []]];
		$diff = pfb_sync_copied_diff([], [$deep], [$without]);
		$this->assertSame([$key => ['destination/*/inner', 'destination/address', 'destination/empty', 'destination/sub/k']], $diff, 'nested leaves, masked segments, an empty array is itself a leaf');
		$this->assertNoValueLeak($diff);
	}

	public function testAScalarAgainstASubtreeReportsTheSubtreeLeavesAndAMissingScalarItsOwnPath(): void
	{
		$base   = self::base('nat');
		$scalar = ['destination' => 'LEAK_DEST_SENTINEL'] + $base;
		$key    = self::key('nat');

		$this->assertSame([$key => ['destination/address', 'destination/port']], pfb_sync_copied_diff([], [$scalar], [$base]));
		$this->assertSame([$key => ['destination/address', 'destination/port']], pfb_sync_copied_diff([], [$base], [$scalar]));
		$this->assertSame([$key => ['target']], pfb_sync_copied_diff([], [array_diff_key($base, ['target' => TRUE])], [$base]), 'a missing scalar');
		$this->assertSame([$key => ['extra']], pfb_sync_copied_diff([], [$base + ['extra' => 'LEAK_LOCAL_SENTINEL']], [$base]), 'an extra scalar');
	}

	// ---- raw rows: digest and compare what config holds, no normalization -----------------------

	#[DataProvider('kinds')]
	public function testDigestIsTheHashOfTheRawKeySortedRowWithoutTimestamps(string $kind): void
	{
		$this->assertSame(
			[self::id($kind) => self::digestOf(self::base($kind))],
			pfb_sync_copied_digests([self::reversed(self::base($kind, 555))])
		);
	}

	/** @return array<string,array{array<string,mixed>,array<string,mixed>,list<string>}> */
	public static function rawDifferences(): array
	{
		$base = self::base('filter');
		return [
			'key case'        => [$base + ['MixedCase' => 'x'], $base + ['mixedcase' => 'x'], ['MixedCase', 'mixedcase']],
			'FALSE vs absent' => [$base + ['disabled' => FALSE], $base, ['disabled']],
			'int vs string'   => [['tracker' => 1770000001] + $base, $base, ['tracker']],
			'union order'     => [$base + ['zeta' => 'x'], $base + ['alpha' => 'x'], ['alpha', 'zeta']],
		];
	}

	/**
	 * @param array<string,mixed> $current
	 * @param array<string,mixed> $expected
	 * @param list<string>        $attrs
	 */
	#[DataProvider('rawDifferences')]
	public function testRawRowDifferencesAreDetected(array $current, array $expected, array $attrs): void
	{
		$this->assertNotSame(pfb_sync_copied_digests([$current]), pfb_sync_copied_digests([$expected]));
		$this->assertSame(
			[self::key('filter') => $attrs],
			pfb_sync_copied_diff(pfb_sync_copied_digests([self::base('filter')]), [$current], [$expected])
		);
	}

	// ---- order: nothing depends on how objects or keys are listed -----------------------------

	public function testObjectAndKeyOrderNeverChangeDigestsOrFindings(): void
	{
		$a = ['name' => 'pfB_A', 'address' => '1'] + self::base('aliases');
		$b = ['name' => 'pfB_B', 'address' => '2'] + self::base('aliases');

		$digests = pfb_sync_copied_digests([$a, $b]);
		$ids     = array_keys($digests);
		$sorted  = $ids;
		sort($sorted, SORT_STRING);
		$this->assertSame($sorted, $ids, 'the digest map is stored in key order');
		$this->assertSame($digests, pfb_sync_copied_digests([$b, $a]));
		$this->assertSame($digests, pfb_sync_copied_digests([self::reversed($b), self::reversed($a)]));

		$aMoved   = ['type' => 'host', 'address' => 'LEAK_ADDR_SENTINEL'] + $a;
		$bMoved   = ['type' => 'host', 'address' => 'LEAK_ADDR_SENTINEL'] + $b;
		$findings = ['pfB_A' => ['address', 'type'], 'pfB_B' => ['address', 'type']];
		$this->assertSame($findings, pfb_sync_copied_diff($digests, [$aMoved, $bMoved], [$a, $b]));
		$this->assertSame($findings, pfb_sync_copied_diff($digests, [$bMoved, $aMoved], [$b, $a]));
		$this->assertSame($findings, pfb_sync_copied_diff($digests, [self::reversed($bMoved), self::reversed($aMoved)], [self::reversed($b), self::reversed($a)]));
	}

	// ---- check(): rows 3-5, 9 ----------------------------------------------------------------

	#[DataProvider('kinds')]
	public function testOwnWriteAcrossRunsStaysSilent(string $kind): void
	{
		pfb_sync_copied_check($kind, [self::base($kind)], [self::base($kind)], $this->dir);
		pfb_sync_copied_check($kind, [self::base($kind)], [self::changedLocally($kind)], $this->dir);

		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
		$this->assertSame([], pfb_sync_copied_read($this->dir)['findings']);
	}

	#[DataProvider('kinds')]
	public function testFirstRunIsSilentThenRecordedThenExternalChangeIsReported(string $kind): void
	{
		$this->assertFileDoesNotExist($this->stateFile());
		pfb_sync_copied_check($kind, [self::external($kind)], [self::base($kind)], $this->dir);

		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'first run is silent');
		$this->assertSame([self::id($kind) => self::digestOf(self::base($kind))], pfb_sync_copied_read($this->dir)['recorded'][$kind]);
		$this->assertSame([], pfb_sync_copied_read($this->dir)['findings']);

		pfb_sync_copied_check($kind, [self::external($kind)], [self::base($kind)], $this->dir);

		$this->assertSame(self::externalAttrs($kind), pfb_sync_copied_read($this->dir)['findings'][$kind]);
		$this->assertCount(1, $this->copiedNotices());
		$this->assertStringContainsString(self::key($kind), $this->copiedNotices()[0]);
		$this->assertStringContainsString('(' . implode(', ', self::externalAttrs($kind)[self::key($kind)]) . ')', $this->copiedNotices()[0]);
		$this->assertNoValueLeak();
	}

	public function testStoredStateIsExactlyDigestsAndAttributeNames(): void
	{
		$recorded = ['filter' => [self::id('filter') => self::digestOf(self::base('filter'))]];

		pfb_sync_copied_check('filter', [self::base('filter')], [self::base('filter')], $this->dir);
		$this->assertSame(['recorded' => $recorded, 'findings' => []], json_decode($this->stateBytes(), TRUE));

		pfb_sync_copied_check('filter', [self::external('filter')], [self::base('filter')], $this->dir);
		$this->assertSame(
			['recorded' => $recorded, 'findings' => ['filter' => ['pfB_Alpha auto rule#0' => ['interface']]]],
			json_decode($this->stateBytes(), TRUE)
		);
	}

	#[DataProvider('kinds')]
	public function testGeneratedLocalValuesNeverReachStateNoticeOrLog(string $kind): void
	{
		$generated = array_replace(self::base($kind), ['interface' => 'LEAK_GENERATED_SENTINEL', 'address' => 'LEAK_GENERATED_SENTINEL']);

		pfb_sync_copied_check($kind, [$generated], [$generated], $this->dir);
		pfb_sync_copied_check($kind, [self::external($kind)], [$generated], $this->dir);

		$this->assertCount(1, $this->copiedNotices(), 'the external copy is still reported');
		$this->assertNoValueLeak();
	}

	public function testNoticeShapeAndValueFreeLogLine(): void
	{
		pfb_sync_copied_check('filter', [self::base('filter')], [self::base('filter')], $this->dir);
		pfb_sync_copied_check('filter', [self::external('filter')], [self::base('filter')], $this->dir);

		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertSame('pfBlockerNG Sync', $notice['id']);
		$this->assertSame('pfBlockerNG', $notice['category']);
		$this->assertSame('/pfblockerng/pfblockerng_sync.php', $notice['url']);
		$this->assertSame(2, $notice['priority']);
		$this->assertSame("Copied pfB objects differ from this node's generated objects: pfB_Alpha auto rule#0 (interface)", $notice['notice']);

		$logs = array_values(array_filter($GLOBALS['pfb_test_logger_calls'], static fn (array $call): bool => str_contains($call['message'], 'Copied pfB objects')));
		$this->assertCount(1, $logs);
		$this->assertSame(LOG_WARNING, $logs[0]['priority']);
		$this->assertStringContainsString('pfB_Alpha auto rule#0 (interface)', $logs[0]['message']);
	}

	public function testCorruptStateReadsAsFirstRunAndIsRewrittenValid(): void
	{
		file_put_contents($this->stateFile(), '{"recorded": CORRUPT');
		$this->assertSame(['recorded' => [], 'findings' => []], pfb_sync_copied_read($this->dir));

		pfb_sync_copied_check('filter', [self::external('filter')], [self::base('filter')], $this->dir);

		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'lost state invents no prior-writer evidence');
		$data = json_decode($this->stateBytes(), TRUE);
		$this->assertIsArray($data);
		$this->assertArrayHasKey('filter', $data['recorded']);
		$this->assertSame(0o600, fileperms($this->stateFile()) & 0o777, 'the state is root-only');
	}

	public function testNoticeDeDuplicationAcrossChangeRepeatNewFindingClearAndReappear(): void
	{
		$base = [self::base('filter')];
		$ext  = [self::external('filter')];
		$ext2 = [array_merge(self::external('filter'), ['type' => 'pass'])];

		pfb_sync_copied_check('filter', $base, $base, $this->dir);
		$this->assertCount(0, $this->copiedNotices(), 'baseline');

		pfb_sync_copied_check('filter', $ext, $base, $this->dir);
		$this->assertCount(1, $this->copiedNotices(), 'change -> one notice');

		pfb_sync_copied_check('filter', $ext, $base, $this->dir);
		$this->assertCount(1, $this->copiedNotices(), 'identical repeat -> no new notice');

		pfb_sync_copied_check('filter', $ext2, $base, $this->dir);
		$this->assertCount(2, $this->copiedNotices(), 'different finding -> one more notice');

		pfb_sync_copied_check('filter', $base, $base, $this->dir);
		$this->assertCount(2, $this->copiedNotices(), 'cleared -> no notice');
		$this->assertArrayNotHasKey('filter', pfb_sync_copied_read($this->dir)['findings'], 'a cleared kind is removed from the findings');
		$this->assertArrayHasKey('filter', pfb_sync_copied_read($this->dir)['recorded']);

		pfb_sync_copied_check('filter', $ext, $base, $this->dir);
		$this->assertCount(3, $this->copiedNotices(), 're-appearing finding -> one notice');
		$this->assertNoValueLeak();
	}

	public function testUnpublishableStateLogsOneValueFreeLineAndNeverThrows(): void
	{
		pfb_sync_copied_check('filter', [self::base('filter')], [self::base('filter')], "{$this->dir}/missing-dir");

		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
		$logs = array_values(array_filter($GLOBALS['pfb_test_logger_calls'], static fn (array $call): bool => str_contains($call['message'], 'Copied pfB objects')));
		$this->assertCount(1, $logs);
		$this->assertSame(LOG_WARNING, $logs[0]['priority']);
	}

	public function testReadHelperReturnsEmptyShapeForMissingState(): void
	{
		$this->assertSame(['recorded' => [], 'findings' => []], pfb_sync_copied_read($this->dir));
	}

	// ---- state file: a syntactically valid but malformed file is lost state ---------------------

	/** @return array<string,array{array<string,mixed>}> */
	public static function malformedStates(): array
	{
		$hex   = str_repeat('a', 64);
		$valid = ['filter' => [$hex => $hex]];
		return [
			'recorded is a scalar'     => [['recorded' => 'x', 'findings' => []]],
			'findings is missing'      => [['recorded' => $valid]],
			'unknown recorded kind'    => [['recorded' => $valid + ['other' => [$hex => $hex]], 'findings' => []]],
			'unknown findings kind'    => [['recorded' => $valid, 'findings' => ['other' => ['pfB_x#0' => ['interface']]]]],
			'recorded kind is a scalar' => [['recorded' => ['filter' => 'x'], 'findings' => []]],
			'findings kind is a scalar' => [['recorded' => $valid, 'findings' => ['nat' => 'x']]],
			'digest is not hex'        => [['recorded' => ['filter' => [$hex => 'LEAK_LOCAL_SENTINEL']], 'findings' => []]],
			'digest is too short'      => [['recorded' => ['filter' => [$hex => 'abc']], 'findings' => []]],
			'label carries markup'     => [['recorded' => $valid, 'findings' => ['nat' => ['pfB_<script>LEAK_LOCAL_SENTINEL</script>' => ['interface']]]]],
			'attribute carries markup' => [['recorded' => $valid, 'findings' => ['nat' => ['pfB_x#0' => ['LEAK_DEST_SENTINEL<b>']]]]],
			'attribute has a space'    => [['recorded' => $valid, 'findings' => ['nat' => ['pfB_x#0' => ['bad key']]]]],
			'attribute is not text'    => [['recorded' => $valid, 'findings' => ['nat' => ['pfB_x#0' => [1]]]]],
			'attribute list is a map'  => [['recorded' => $valid, 'findings' => ['nat' => ['pfB_x#0' => ['k' => 'interface']]]]],
			'attribute list is text'   => [['recorded' => $valid, 'findings' => ['nat' => ['pfB_x#0' => 'interface']]]],
			'recorded key is markup'   => [['recorded' => ['nat' => ['<script>LEAK_LOCAL_SENTINEL</script>' => $hex]], 'findings' => []]],
			'recorded key is too short' => [['recorded' => ['nat' => [substr($hex, 1) => $hex]], 'findings' => []]],
			'recorded key is upper case' => [['recorded' => ['nat' => [strtoupper($hex) => $hex]], 'findings' => []]],
		];
	}

	/** @param array<string,mixed> $state */
	#[DataProvider('malformedStates')]
	public function testMalformedStateReadsAsLostState(array $state): void
	{
		file_put_contents($this->stateFile(), json_encode($state, JSON_THROW_ON_ERROR));

		$this->assertSame(['recorded' => [], 'findings' => []], pfb_sync_copied_read($this->dir));
	}

	public function testWellFormedStateReadsBackUnchanged(): void
	{
		$hex   = str_repeat('a', 64);
		$state = [
			'recorded' => ['filter' => [$hex => $hex], 'nat' => []],
			'findings' => ['nat' => ['pfB_x y.z-1#12' => ['(unexpected)', '(missing)', '*', 'a/b_c.d-e/*']], 'aliases' => ['pfB_Alpha_v4' => ['address']]],
		];
		file_put_contents($this->stateFile(), json_encode($state, JSON_THROW_ON_ERROR));

		$this->assertSame($state, pfb_sync_copied_read($this->dir));
	}

	public function testMalformedStateNeverLeaksIntoANoticeOrLog(): void
	{
		// A genuine filter change while another kind's state is hostile: the hostile text must not ride along.
		file_put_contents($this->stateFile(), json_encode([
			'recorded' => ['filter' => pfb_sync_copied_digests([self::base('filter')])],
			'findings' => ['nat' => ['pfB_<script>LEAK_LOCAL_SENTINEL</script>' => ['LEAK_DEST_SENTINEL<b>']]],
		], JSON_THROW_ON_ERROR));

		pfb_sync_copied_check('filter', [self::external('filter')], [self::base('filter')], $this->dir);
		pfb_sync_copied_check('filter', [self::external('filter')], [self::base('filter')], $this->dir);

		$this->assertSame(["Copied pfB objects differ from this node's generated objects: pfB_Alpha auto rule#0 (interface)"], $this->copiedNotices());
		$this->assertNoValueLeak();
		foreach ($this->emitted() as $text) {
			$this->assertStringNotContainsString('<', $text);
		}
	}

	public function testMaskedIdentityFindingSurvivesRereadAndIsNeverRenotified(): void
	{
		$managed = ['descr' => 'pfB_A+B'] + self::base('filter');
		$copy    = ['interface' => 'LEAK_IFACE_SENTINEL'] + $managed;

		pfb_sync_copied_check('filter', [$managed], [$managed], $this->dir);
		for ($run = 1; $run <= 5; $run++) {
			pfb_sync_copied_check('filter', [$copy], [$managed], $this->dir);

			$this->assertSame(['filter' => ['pfB_A?B#0' => ['interface']]], pfb_sync_copied_read($this->dir)['findings'], "run {$run}: the finding is read back");
			$this->assertCount(1, $this->copiedNotices(), "run {$run}: one notice in total");
		}
		$this->assertNoValueLeak();
	}

	public function testEveryLabelTheIndexerProducesReadsBack(): void
	{
		$objects  = array_map(static fn (int $byte): array => ['descr' => 'pfB_' . chr($byte) . "x{$byte}"] + self::base('filter'), range(0, 255));
		$findings = pfb_sync_copied_diff([], $objects, []);
		$state    = ['recorded' => [], 'findings' => ['filter' => $findings]];
		file_put_contents($this->stateFile(), json_encode($state, JSON_THROW_ON_ERROR));

		$this->assertCount(256, $findings);
		$this->assertSame($state, pfb_sync_copied_read($this->dir));
	}

	public function testMalformedRecordedKeyIsLostStateAndNeverRepublishedByAnotherKind(): void
	{
		file_put_contents($this->stateFile(), json_encode([
			'recorded' => ['nat' => ['<script>LEAK_LOCAL_SENTINEL</script>' => str_repeat('a', 64)], 'filter' => pfb_sync_copied_digests([self::base('filter')])],
			'findings' => [],
		], JSON_THROW_ON_ERROR));
		$this->assertSame(['recorded' => [], 'findings' => []], pfb_sync_copied_read($this->dir));

		pfb_sync_copied_check('filter', [self::base('filter')], [self::base('filter')], $this->dir);

		$this->assertStringNotContainsString('LEAK_LOCAL_SENTINEL', $this->stateBytes());
		$this->assertSame(['filter'], array_keys(pfb_sync_copied_read($this->dir)['recorded']));
	}

	// ---- row 10: acceptance 12, the apply writes the same bytes -------------------------------

	/**
	 * Seeds the NAT writer with an externally edited copy of this node's NAT row in config.
	 */
	private function seedNatWriter(string $dir): void
	{
		$this->seedDnsblNatWriter($dir, [
			['descr' => 'user rule', 'interface' => 'wan', 'target' => '10.0.0.9'],
			['descr' => 'pfB DNSBL - DO NOT EDIT', 'interface' => 'LEAK_IFACE_SENTINEL', 'target' => 'LEAK_DEST_SENTINEL'],
		]);
	}

	/** @return array{nat: mixed, writes: mixed} */
	private function runNatWriter(string $dir): array
	{
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$this->seedNatWriter($dir);
		$this->applyDnsblEnabled();
		return ['nat' => config_get_path('nat/rule'), 'writes' => $GLOBALS['pfb_test_write_config_calls']];
	}

	public function testNatWriterWritesTheSameRulesWithAndWithoutDetectorState(): void
	{
		$cleanDir = $this->makeDir();
		$stateDir = $this->makeDir();
		try {
			// A prior write of this node: the copy in config now differs from it AND from the new expectation.
			$prior = self::base('dnsbl_nat');
			file_put_contents($this->stateFile($stateDir), json_encode([
				'recorded' => ['dnsbl_nat' => pfb_sync_copied_digests([$prior])],
				'findings' => [],
			], JSON_THROW_ON_ERROR));

			$clean = $this->runNatWriter($cleanDir);
			$this->assertSame([], $this->copiedNotices(), 'no state -> nothing reported');
			$this->assertFileExists($this->stateFile($cleanDir), 'the clean run still records its expectation');

			$divergent = $this->runNatWriter($stateDir);

			$this->assertSame($clean['nat'], $divergent['nat'], 'the stored nat/rule never depends on the detector');
			$this->assertSame($clean['writes'], $divergent['writes'], 'the write_config calls never depend on the detector');
			$this->assertSame(['pfB DNSBL - DO NOT EDIT#0'], array_keys(pfb_sync_copied_read($stateDir)['findings']['dnsbl_nat'] ?? []), 'the divergent run reported the copy');
			$this->assertCount(1, $this->copiedNotices());
			$this->assertNoValueLeak();
			// opt-double and the VIP are generated-local values: the interface double binds the first, the VIP list the second.
			foreach ([...self::SENTINELS, 'opt-double', '203.0.113.10'] as $value) {
				foreach ([$cleanDir, $stateDir] as $dir) {
					$this->assertStringNotContainsString($value, (string) file_get_contents($this->stateFile($dir)));
				}
				foreach ($this->emitted() as $text) {
					$this->assertStringNotContainsString($value, $text);
				}
			}
			$this->assertSame('user rule', $divergent['nat'][0]['descr'], 'user NAT rules are untouched');
			$this->assertSame('opt-double', $divergent['nat'][1]['interface'], 'the copy is overwritten as before, never re-owned or skipped');

			$written = array_slice($divergent['nat'], 1);
			$this->assertCount(2, $written);
			$recorded = [];
			foreach ($written as $n => $row) {
				$recorded[hash('sha256', "pfB DNSBL - DO NOT EDIT#{$n}")] = self::digestOf($row);
			}
			ksort($recorded, SORT_STRING);
			$this->assertSame($recorded, pfb_sync_copied_read($stateDir)['recorded']['dnsbl_nat'], 'the state records exactly the digests of what the writer left in config');
		} finally {
			$this->removeDir($cleanDir);
			$this->removeDir($stateDir);
		}
	}

	// ---- removal writers: the managed rows are read before anything removes them ---------------

	public function testManagedRowsAreExactlyWhatTheRemovalWouldRemove(): void
	{
		$rows = [
			['descr' => 'user rule'],
			['descr' => 'a pfB DNSBL note'],
			['descr' => 'pfB DNSBL - DO NOT EDIT'],
			['descr' => 'pfB_DNS_Redirect_lan_v4'],
			['descr' => 'pfB_DoT_Block_lan'],
			['interface' => 'wan'],
		];
		foreach ([PFB_MANAGED_NAT_DESCR, PFB_DNS_REDIR_DESCR_V4_PFX, PFB_DOT_BLOCK_DESCR_PFX] as $marker) {
			$GLOBALS['config'] = [];
			config_set_path('nat/rule', $rows);

			$managed = pfb_managed_obj_rows('nat/rule', $marker);

			$this->assertNotSame([], $managed, $marker);
			$this->assertSame($rows, config_get_path('nat/rule'), 'reading removes nothing');
			pfb_remove_managed_obj('nat/rule', $marker);
			$this->assertSame(
				array_values(array_filter($rows, static fn (array $row): bool => !in_array($row, $managed, TRUE))),
				config_get_path('nat/rule'),
				"{$marker}: the removal takes exactly the snapshot"
			);
		}
	}

	public function testDisabledDnsblWriterReportsTheExternalRowItRemoves(): void
	{
		file_put_contents($this->stateFile(), json_encode([
			'recorded' => ['dnsbl_nat' => pfb_sync_copied_digests([self::base('dnsbl_nat')])],
			'findings' => [],
		], JSON_THROW_ON_ERROR));
		$this->seedNatWriter($this->dir);

		pfb_create_dnsbl('disabled');

		$this->assertSame(['user rule'], array_column(config_get_path('nat/rule'), 'descr'), 'the removal itself is unchanged');
		$this->assertSame(['dnsbl_nat' => ['pfB DNSBL - DO NOT EDIT#0' => ['(unexpected)']]], pfb_sync_copied_read($this->dir)['findings']);
		$this->assertSame(['dnsbl_nat' => []], pfb_sync_copied_read($this->dir)['recorded'], 'a disabled writer records an empty expectation');
		$this->assertCount(1, $this->copiedNotices());
		$this->assertNoValueLeak();
	}

	/** @return array<string,mixed> */
	private static function writerSpec(string $writer): array
	{
		return $writer === 'redirect' ? [
			'from' => "\t\t\$redir_changed = FALSE;", 'to' => "\n\t}\n\n\t// Sync DoT/DoQ block filter rules",
			'kind' => 'nat', 'section' => 'nat/rule', 'toggle' => 'dnsbl/dnsbl_redir', 'ifaces' => 'dnsbl/dnsbl_redir_int',
			'stale' => 'pfB_DNS_Redirect_opt1_v4', 'kept' => ['pfB_DNS_Redirect_lan_v4', 'pfB_DNS_Redirect_lan_v6'],
		] : [
			'from' => "\t\t\$dot_changed = FALSE;", 'to' => "\n\t}\n\n\t// Fingerprint the loaded input files",
			'kind' => 'dot_filter', 'section' => 'filter/rule', 'toggle' => 'dnsbl/dnsbl_dot_block', 'ifaces' => 'dnsbl/dnsbl_dot_block_int',
			'stale' => 'pfB_DoT_Block_opt1', 'kept' => ['pfB_DoT_Block_lan'],
		];
	}

	/** Runs the real inline writer block of pfblockerng_apply.inc between two source markers (it is not a function). */
	private function runApplyBlock(string $from, string $to, string $mode): void
	{
		$apply = self::source('pfblockerng_apply.inc');
		$start = $this->pos($apply, $from);
		$end   = $this->pos($apply, $to);

		$writer = eval('return static function (string $mode): void { global $pfb; ' . substr($apply, $start, $end - $start) . ' };');
		$writer($mode);
	}

	/** @return array<string,array{string,string}> */
	public static function removalWriterScenarios(): array
	{
		$cases = [];
		foreach (['redirect', 'dot'] as $writer) {
			foreach (['disabled', 'no valid interface', 'stale interface'] as $scenario) {
				$cases["{$writer}: {$scenario}"] = [$writer, $scenario];
			}
		}
		return $cases;
	}

	#[DataProvider('removalWriterScenarios')]
	public function testRemovalWritersReportAnExternalRowBeforeTheyRemoveIt(string $writer, string $scenario): void
	{
		global $pfb;

		$spec     = self::writerSpec($writer);
		$original = ['descr' => $spec['stale'], 'interface' => 'opt1'] + self::base($spec['kind']);
		$external = ['interface' => 'LEAK_IFACE_SENTINEL'] + $original;
		file_put_contents($this->stateFile(), json_encode([
			'recorded' => [$spec['kind'] => pfb_sync_copied_digests([$original])],
			'findings' => [],
		], JSON_THROW_ON_ERROR));

		$GLOBALS['config'] = [];
		$pfb['dbdir']      = $this->dir;
		PfbConfig::write($spec['toggle'], $scenario === 'disabled' ? '' : 'on');
		PfbConfig::write($spec['ifaces'], $scenario === 'stale interface' ? 'lan' : '');
		config_set_path($spec['section'], [['descr' => 'user rule', 'interface' => 'wan'], $external]);

		$this->runApplyBlock($spec['from'], $spec['to'], 'enabled');

		$this->assertSame(
			$scenario === 'stale interface' ? ['user rule', ...$spec['kept']] : ['user rule'],
			array_column(config_get_path($spec['section']), 'descr'),
			'the writer removes and writes what it always did'
		);
		$this->assertSame([$spec['kind'] => ["{$spec['stale']}#0" => ['(unexpected)']]], pfb_sync_copied_read($this->dir)['findings']);
		$this->assertCount(1, $this->copiedNotices());
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
		$this->assertCount($scenario === 'stale interface' ? count($spec['kept']) : 0, pfb_sync_copied_read($this->dir)['recorded'][$spec['kind']] ?? [], 'it records what it left');
		$this->assertNoValueLeak();
	}

	/** The redirect writer with the DNS proxy off: IPv4 targets loopback, and an apply flags a pf reload only when the rows change. */
	public function testRedirectWriterWritesTheLoopbackIpv4RuleAndFlagsAReloadOnlyWhenItChanges(): void
	{
		global $pfb;

		$spec = self::writerSpec('redirect');
		$GLOBALS['config'] = [];
		$pfb['dbdir']      = $this->dir;
		PfbConfig::write($spec['toggle'], 'on');
		PfbConfig::write($spec['ifaces'], 'lan');

		// Runs one apply's redirect writer; TRUE iff it flagged a pf reload.
		$apply = function () use ($spec): bool {
			global $pfb;
			$pfb['filter_configure'] = FALSE;
			$this->runApplyBlock($spec['from'], $spec['to'], 'enabled');
			return $pfb['filter_configure'];
		};
		$targets = static fn (): array => array_column(config_get_path('nat/rule'), 'target', 'descr');

		$this->assertTrue($apply(), 'the first apply writes the rows');
		$this->assertSame(['pfB_DNS_Redirect_lan_v4' => '127.0.0.1', 'pfB_DNS_Redirect_lan_v6' => 'lanip'], $targets());
		$this->assertFalse($apply(), 'an apply that changes nothing flags no reload');
	}

	/** With the DNS proxy on (its Resolver snapshot present) the redirect writer still targets IPv4 at loopback. */
	public function testRedirectWriterKeepsIpv4LoopbackWhileTheProxyIsOn(): void
	{
		global $pfb;

		$spec = self::writerSpec('redirect');
		$GLOBALS['config'] = [];
		$pfb['dbdir']      = $this->dir;
		PfbConfig::write($spec['toggle'], 'on');
		PfbConfig::write($spec['ifaces'], 'lan');
		PfbConfig::writeSystem('dns/pfb_dns_saved', base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		])));

		$apply = function () use ($spec): void {
			global $pfb;
			$pfb['filter_configure'] = FALSE;
			$this->runApplyBlock($spec['from'], $spec['to'], 'enabled');
		};
		$apply();

		$this->assertSame(['pfB_DNS_Redirect_lan_v4' => '127.0.0.1', 'pfB_DNS_Redirect_lan_v6' => 'lanip'], array_column(config_get_path('nat/rule'), 'target', 'descr'));
	}

	public function testFilterAutoruleWriteKeepsTheRawTrackerAndOnlyTheCheckedCopyIsCast(): void
	{
		global $pfb;

		$block = ['permit_inbound', 'permit_outbound', 'deny_inbound', 'deny_outbound', 'match_inbound', 'match_outbound', 'permit_self', 'deny_self', 'match_self'];
		$rule  = ['descr' => 'pfB_Beta auto rule', 'type' => 'block', 'ipprotocol' => 'inet', 'source' => ['address' => 'pfB_Beta_v4'], 'destination' => ['any' => '']];
		$user  = ['descr' => 'user rule', 'type' => 'pass', 'interface' => 'wan', 'tracker' => 1700000001];
		$pfb   = [
			'dbdir' => $this->dir, 'autorules' => TRUE, 'enable' => PfbToggle::On, 'remove' => FALSE, 'dnsbl' => PfbToggle::Off,
			'order' => 'order_0', 'float' => PfbToggle::Off, 'inbound_interfaces' => ['lan'], 'outbound_interfaces' => [],
			'trackerids' => [], 'foreign_trackerids' => [], 'deny_inbound' => [$rule],
		];
		$generated = array_fill_keys($block, []) + ['inbound_floating' => '', 'outbound_floating' => '', 'dnsbl_float' => []];
		$generated['deny_inbound'] = [$rule];
		$oracle = pfb_build_autorule_list([$user], $generated, 'order_0', PfbToggle::Off, ['lan'], []);
		$pfb['trackerids'] = [];

		$GLOBALS['config'] = [];
		config_set_path('filter/rule', [$user]);
		$this->runApplyBlock(
			"\tif (\$pfb['autorules'] || \$pfb['enable'] !== PfbToggle::On || \$pfb['remove']) {",
			"\t#################################\n\t#\tpfSense Integration",
			'enabled'
		);

		$written = config_get_path('filter/rule');
		$this->assertSame($oracle, $written, 'the written rules are exactly what the builder returned, tracker types included');
		$this->assertSame(['pfB_Beta auto rule', 'user rule'], array_column($written, 'descr'));
		$this->assertIsInt($written[0]['tracker'], 'the written pfB tracker stays an integer');
		$this->assertSame(1700000001, $written[1]['tracker']);
		$this->assertSame(['pfBlockerNG: saving Firewall rules'], $GLOBALS['pfb_test_write_config_calls']);

		// Only the check's own expected copy compares the tracker as a string, as a config reread returns it.
		$cast = array_replace($written[0], ['tracker' => (string) $written[0]['tracker']]);
		$this->assertSame(
			[hash('sha256', 'pfB_Beta auto rule#0') => self::digestOf($cast)],
			pfb_sync_copied_read($this->dir)['recorded']['filter']
		);
		$this->assertNotSame(self::digestOf($written[0]), self::digestOf($cast));
	}

	// ---- helpers for the inline writer blocks ------------------------------------------------

	private static function source(string $file): string
	{
		return (string) file_get_contents(dirname(__DIR__, 2) . "/src/usr/local/pkg/pfblockerng/{$file}");
	}

	private function pos(string $haystack, string $needle): int
	{
		$pos = strpos($haystack, $needle);
		$this->assertIsInt($pos, "missing in source: {$needle}");
		return $pos;
	}

	// ---- a corrupt filter/rule entry and the deinstall sweep ---------------------------------

	public function testANonArrayRuleEntryIsAUserRuleNotAFatal(): void
	{
		$this->assertFalse(pfb_rule_is_pfb_owned(''));
		$block     = ['permit_inbound', 'permit_outbound', 'deny_inbound', 'deny_outbound', 'match_inbound', 'match_outbound', 'permit_self', 'deny_self', 'match_self'];
		$generated = array_fill_keys($block, []) + ['inbound_floating' => '', 'outbound_floating' => '', 'dnsbl_float' => []];
		$user      = ['descr' => 'user rule', 'type' => 'pass', 'interface' => 'wan'];

		$this->assertSame([$user, ''], pfb_build_autorule_list([$user, ''], $generated, 'order_0', PfbToggle::Off, ['lan'], []));
	}

	public function testDeinstallSweepRemovesTheOwnedRowsAndForgetsTheCopiedState(): void
	{
		global $pfb;

		$pfb['dbdir']      = $this->dir;
		$GLOBALS['config'] = [];
		$owned             = ['descr' => 'pfB_Beta auto rule', 'type' => 'block'];
		config_set_path('filter/rule', [$owned, ['descr' => 'user rule', 'type' => 'pass']]);
		config_set_path('nat/rule', [['descr' => PFB_MANAGED_NAT_DESCR], ['descr' => 'my pfB DNSBL test']]);
		file_put_contents($this->stateFile(), json_encode(['recorded' => ['filter' => pfb_sync_copied_digests([$owned])], 'findings' => []], JSON_THROW_ON_ERROR));

		pfb_deinstall_sweep_managed_objects();

		$this->assertSame(['user rule'], array_column(config_get_path('filter/rule'), 'descr'));
		$this->assertSame(['my pfB DNSBL test'], array_column(config_get_path('nat/rule'), 'descr'), 'the sweep removes the exact DNSBL NAT and keeps a user rule that merely contains pfB DNSBL');
		$this->assertSame(['pfBlockerNG: sweep orphan firewall objects on deinstall'], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertFileDoesNotExist($this->stateFile(), 'a reinstall must not report the swept rules as missing copies');
	}

	public function testMarkerMatchIsPrefixOnlyAndTheNatDescrIsExact(): void
	{
		$GLOBALS['config'] = [];
		config_set_path('nat/rule', [['descr' => 'a pfB DNSBL note'], ['descr' => 'pfB DNSBL - DO NOT EDIT'], ['descr' => 'pfB_DNS_Redirect_lan_v4'], ['descr' => 'pfB_X pfB_DNS_Redirect_lan_v4'], ['descr' => 'pfB DNSBL pfB_DoT_Block_lan']]);
		$this->assertSame(['pfB DNSBL - DO NOT EDIT'], array_column(pfb_managed_obj_rows('nat/rule', PFB_MANAGED_NAT_DESCR), 'descr'), 'only the exact NAT descr is owned; a descr merely containing pfB DNSBL is not');
		$this->assertSame(['pfB_DNS_Redirect_lan_v4'], array_column(pfb_managed_obj_rows('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX), 'descr'), 'a pfB_ marker matches only as the prefix');
		$this->assertSame([], pfb_managed_obj_rows('nat/rule', PFB_DOT_BLOCK_DESCR_PFX));
	}
}
