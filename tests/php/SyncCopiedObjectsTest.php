<?php

declare(strict_types=1);

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
final class SyncCopiedObjectsTest extends TestCase
{
	private const SENTINELS = ['LEAK_IFACE_SENTINEL', 'LEAK_ADDR_SENTINEL', 'LEAK_DEST_SENTINEL', 'LEAK_LOCAL_SENTINEL'];

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
		$extraKey = pfb_sync_copied_digests([$extra]);
		$extraKey = array_key_first($extraKey);

		$this->assertSame([$extraKey => ['(unexpected)']], pfb_sync_copied_diff($recorded, [$base, $extra], [$base]));
		$this->assertSame([self::key($kind) => ['(missing)']], pfb_sync_copied_diff($recorded, [], [$base]));
		$this->assertSame([], pfb_sync_copied_diff($recorded, [$base], [$base, $extra]), 'an expected-only object that was never recorded is not an external change');
		$this->assertSame([], pfb_sync_copied_diff($recorded, [], [$extra]), 'a missing object that was never written is not an external change');
	}

	public function testSameDescrRulesPairByOccurrence(): void
	{
		$wan  = self::base('filter');
		$opt1 = ['interface' => 'opt1'] + $wan;

		$recorded = pfb_sync_copied_digests([$wan, $opt1]);
		$this->assertSame(['pfB_Alpha auto rule#0', 'pfB_Alpha auto rule#1'], array_keys($recorded));

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
		$this->assertSame([self::key($kind) => pfb_sync_copied_digests([self::base($kind)])[self::key($kind)]], pfb_sync_copied_read($this->dir)['recorded'][$kind]);
		$this->assertSame([], pfb_sync_copied_read($this->dir)['findings']);

		pfb_sync_copied_check($kind, [self::external($kind)], [self::base($kind)], $this->dir);

		$this->assertSame(self::externalAttrs($kind), pfb_sync_copied_read($this->dir)['findings'][$kind]);
		$this->assertCount(1, $this->copiedNotices());
		$this->assertStringContainsString(self::key($kind), $this->copiedNotices()[0]);
		$this->assertStringContainsString('(' . implode(', ', self::externalAttrs($kind)[self::key($kind)]) . ')', $this->copiedNotices()[0]);
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

	// ---- row 10: acceptance 12, the apply writes the same bytes -------------------------------

	/**
	 * Seeds the minimum a manual-mode, valid-VIP DNSBL needs so pfb_create_dnsbl('enabled') reaches
	 * the NAT generation (mirrors DnsblVipDisableNoticeTest scenario C), with an externally edited
	 * copy of this node's NAT row in config.
	 */
	private function seedNatWriter(string $dir): void
	{
		global $pfb;

		$GLOBALS['config'] = [];
		$pfb['dbdir']      = $dir;
		$pfb['dnsbl_conf'] = "{$dir}/lighty.conf";
		$pfb['dnsbl_cert'] = "{$dir}/cert.pem";
		touch($pfb['dnsbl_cert']);

		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0'] as $key => $value) {
			config_set_path("{$gen}/{$key}", $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path("{$ip}/{$key}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		foreach ([
			'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '', 'pfb_cache' => '',
			'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '', 'pfb_py_nolog' => '',
			'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'pfb_dnsvip4' => '_vip_test_valid',
		] as $key => $value) {
			config_set_path("{$dnsbl}/{$key}", $value);
		}
		$GLOBALS['g']['unbound_chroot_path'] ??= '/var/unbound';
		PfbConfig::write('dnsbl/pfb_dnsbl', 'on');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		$GLOBALS['pfb_test_vip_list'] = ['_vip_test_valid' => '203.0.113.10'];
		config_set_path('virtualip/vip', [['uniqid' => '_test_valid', 'subnet' => '203.0.113.10']]);

		config_set_path('nat/rule', [
			['descr' => 'user rule', 'interface' => 'wan', 'target' => '10.0.0.9'],
			['descr' => 'pfB DNSBL - DO NOT EDIT', 'interface' => 'LEAK_IFACE_SENTINEL', 'target' => 'LEAK_DEST_SENTINEL'],
		]);
	}

	/** @return array{nat: mixed, writes: mixed} */
	private function runNatWriter(string $dir): array
	{
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$this->seedNatWriter($dir);

		// The restart branch link()s the real lighttpd binary, which the sandbox lacks.
		set_error_handler(static fn (int $no, string $message): bool => str_starts_with($message, 'link('));
		try {
			pfb_create_dnsbl('enabled');
		} finally {
			restore_error_handler();
		}
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
			foreach (self::SENTINELS as $sentinel) {
				$this->assertStringNotContainsString($sentinel, (string) file_get_contents($this->stateFile($stateDir)));
			}
			$this->assertSame('user rule', $divergent['nat'][0]['descr'], 'user NAT rules are untouched');
			$this->assertSame('opt-double', $divergent['nat'][1]['interface'], 'the copy is overwritten as before, never re-owned or skipped');
		} finally {
			$this->removeDir($cleanDir);
			$this->removeDir($stateDir);
		}
	}

	// ---- wiring: writers that tests cannot drive end to end (reported as a deviation) ----------

	private static function source(string $file): string
	{
		return (string) file_get_contents(dirname(__DIR__, 2) . "/src/usr/local/pkg/pfblockerng/{$file}");
	}

	public function testEveryWriterCallsTheDetectorWithPlainVariablesBeforeItsWriteDecision(): void
	{
		$apply = self::source('pfblockerng_apply.inc');
		$core  = self::source('pfblockerng.inc');

		$this->assertSame(1, preg_match_all("/pfb_sync_copied_check\('aliases', \\$\\w+, \\$\\w+, \\\$pfb\['dbdir'\]\);/", $apply));
		$this->assertSame(1, preg_match_all("/pfb_sync_copied_check\('filter', \\$\\w+, \\$\\w+, \\\$pfb\['dbdir'\]\);/", $apply));
		$this->assertSame(1, preg_match_all("/pfb_sync_copied_check\('nat', \\\$redir_ex_owned, \\\$redir_new_owned, \\\$pfb\['dbdir'\]\);/", $apply));
		$this->assertSame(2, preg_match_all("/pfb_sync_copied_check\('nat', \[\], \[\], \\\$pfb\['dbdir'\]\);/", $apply));
		$this->assertSame(1, preg_match_all("/pfb_sync_copied_check\('dot_filter', \\\$dot_ex_owned, \\\$dot_new_owned, \\\$pfb\['dbdir'\]\);/", $apply));
		$this->assertSame(2, preg_match_all("/pfb_sync_copied_check\('dot_filter', \[\], \[\], \\\$pfb\['dbdir'\]\);/", $apply));
		$this->assertSame(1, preg_match_all("/pfb_sync_copied_check\('dnsbl_nat', \\\$dnsbl_ex_nat, \\\$dnsbl_new_nat, \\\$pfb\['dbdir'\]\);/", $core));
		$this->assertSame(1, preg_match_all("/pfb_sync_copied_check\('dnsbl_nat', \[\], \[\], \\\$pfb\['dbdir'\]\);/", $core));

		// The call comes before the write decision it must not influence.
		$this->assertLessThan(strpos($apply, "config_set_path('filter/rule', \$new_rules);"), strpos($apply, "pfb_sync_copied_check('filter'"));
		$this->assertLessThan(strpos($apply, "config_set_path('aliases/alias', \$new_aliases);"), strpos($apply, "pfb_sync_copied_check('aliases'"));
		$this->assertLessThan(strpos($apply, "config_set_path('nat/rule', array_merge(\$redir_ex_other"), strpos($apply, "pfb_sync_copied_check('nat', \$redir_ex_owned"));
		$this->assertLessThan(strpos($apply, "config_set_path('filter/rule', array_merge(\$dot_ex_other"), strpos($apply, "pfb_sync_copied_check('dot_filter', \$dot_ex_owned"));
	}
}
