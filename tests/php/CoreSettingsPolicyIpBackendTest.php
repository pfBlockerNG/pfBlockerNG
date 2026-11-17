<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: the settings adapter writes Core's `policy/ip` projection into config.xml by merging, never by rewriting:
 *   - only the key of a field whose native value differs from what the read gives is written, in the one write_config() under the
 *     DNS config lock; an unchanged write is a no-op, and a value the read normalizes (a limit of abc reads 0) stays until Core changes it;
 *   - a limit of 0 and a blacklist action of none store an empty value;
 *   - a suppression list that changes its entries keeps the lines it does not own (comments, blank lines, invalid lines) and the
 *     comments of the entries that stay, drops the lines of the entries that went, and appends each new entry; a reorder alone writes nothing;
 *   - a malformed projection is invalid_argument naming policy/ip.<field>, changing nothing.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_table_faults')]
#[CoversFunction('pfb_core_table_merge')]
#[CoversFunction('pfb_core_table_text_rewrite')]
final class CoreSettingsPolicyIpBackendTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const IP = 'installedpackages/pfblockerngipsettings/config/0';
	private const REP = 'installedpackages/pfblockerngreputation/config/0';
	private const MESSAGE = '[pfBlockerNG] pfBlockerNG Core saved the settings';
	private const V4_TEXT = "10.0.0.0/8 # lan\n# keep me\nbogus-line\n192.168.0.0/16\n\n172.16.0.0/12 # old\n";

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_policy_ip_backend_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
		$this->arrange();
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** config.xml: every policy/ip key set to a value a field can change from, beside a key of each section no field maps to. */
	private function arrange(array $over = []): void
	{
		$sections = $over + [
			self::IP  => ['enable_dup' => 'on', 'enable_agg' => '', 'v4suppression' => base64_encode(self::V4_TEXT), 'v6suppression' => base64_encode("2001:db8::/32 # lab\n"),
				'inbound_deny_action' => 'block'],
			self::REP => ['enable_rep' => '', 'enable_pdup' => 'on', 'enable_dedup' => '', 'p24_max_var' => '10', 'p24_pmax_var' => '', 'p24_dmax_var' => 'abc',
				'ccwhite' => 'match', 'ccblack' => 'block', 'ccexclude' => 'US,DE', 'etblock' => 'ET_Cnc', 'etmatch' => '', 'et_update' => 'on'],
		];
		foreach ($sections as $path => $value) {
			config_set_path($path, $value);
		}
		$this->configXmlOnDisk();
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('policy/ip', $reply['settings'] ?? [], 'the read answers the policy/ip projection: ' . json_encode($reply));
		return $reply;
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to its `policy/ip` */
	private function writePolicy(callable $change): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['policy/ip'] = $change($settings['policy/ip']);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);
	}

	/** @return array<string, scalar> every leaf of config.xml by its path */
	private static function leaves(array $config, string $prefix = ''): array
	{
		$out = [];
		foreach ($config as $key => $value) {
			is_array($value) ? $out += self::leaves($value, "{$prefix}{$key}/") : $out["{$prefix}{$key}"] = $value;
		}
		return $out;
	}

	/** @return array<string, array{0: mixed, 1: mixed}> path => [before, after] for the leaves that differ, added or removed ones included (NULL) */
	private static function changes(array $before, array $after): array
	{
		$a = self::leaves($before);
		$b = self::leaves($after);
		$out = [];
		foreach (array_unique(array_merge(array_keys($a), array_keys($b))) as $path) {
			if (($a[$path] ?? NULL) !== ($b[$path] ?? NULL)) {
				$out[$path] = [$a[$path] ?? NULL, $b[$path] ?? NULL];
			}
		}
		ksort($out);
		return $out;
	}

	/** @param array<string, array{0: mixed, 1: mixed}> $expected */
	private function assertWrittenOnly(array $expected, array $before, array $reply, int $revisionBefore): void
	{
		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply, 'the reply is the revision config.xml projects now');
		$this->assertNotSame($revisionBefore, $reply['revision'], 'the revision moves with the change');
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config(), with the Core message');
		$this->assertSame('try_lock', $GLOBALS['pfb_test_lock_events'][0][0], 'the write holds the config lock');
		$this->assertSame(PFB_DNS_CONFIG_LOCK, $GLOBALS['pfb_test_lock_events'][0][1], 'the DNS config lock');
		$this->assertFileExists("{$this->dir}/pending", 'the change applies on the next Update');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
		$this->assertSame($this->disk, $GLOBALS['config'], 'what was written is what config.xml holds');
		ksort($expected);
		$this->assertSame($expected, self::changes($before, $GLOBALS['config']), 'exactly these keys of config.xml changed');
	}

	private function assertNothingWritten(array $before, string $why): void
	{
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$why}: write_config() was called");
		$this->assertSame([], self::changes($before, $GLOBALS['config']), "{$why}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$why}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$why}: the config lock is still held");
	}

	/** @return array<string, array{0: string, 1: mixed, 2: array<string, array{0: mixed, 1: mixed}>}> field, native value, the keys of config.xml that change */
	public static function fields(): array
	{
		$ip = self::IP . '/';
		$rep = self::REP . '/';
		return [
			'dedup off'                       => ['dedup', FALSE, [$ip . 'enable_dup' => ['on', '']]],
			'aggregate on'                    => ['aggregate', TRUE, [$ip . 'enable_agg' => ['', 'on']]],
			'max on'                          => ['max', TRUE, [$rep . 'enable_rep' => ['', 'on']]],
			'max limit'                       => ['maxLimit', 25, [$rep . 'p24_max_var' => ['10', '25']]],
			'max limit 0 stores empty'        => ['maxLimit', 0, [$rep . 'p24_max_var' => ['10', '']]],
			'pMax off'                        => ['pMax', FALSE, [$rep . 'enable_pdup' => ['on', '']]],
			'pMax limit'                      => ['pMaxLimit', 50, [$rep . 'p24_pmax_var' => ['', '50']]],
			'dMax on'                         => ['dMax', TRUE, [$rep . 'enable_dedup' => ['', 'on']]],
			'dMax limit over a stored abc'    => ['dMaxLimit', 5, [$rep . 'p24_dmax_var' => ['abc', '5']]],
			'whitelist action ignore'         => ['countryWhitelistAction', 'ignore', [$rep . 'ccwhite' => ['match', 'ignore']]],
			'blacklist action none stores empty' => ['countryBlacklistAction', 'none', [$rep . 'ccblack' => ['block', '']]],
			'blacklist action match'          => ['countryBlacklistAction', 'match', [$rep . 'ccblack' => ['block', 'match']]],
			'country added'                   => ['countryWhitelist', [['code' => 'US'], ['code' => 'DE'], ['code' => 'GB']], [$rep . 'ccexclude' => ['US,DE', 'US,DE,GB']]],
			'countries emptied'               => ['countryWhitelist', [], [$rep . 'ccexclude' => ['US,DE', '']]],
			'ET block added'                  => ['etBlock', [['category' => 'ET_Cnc'], ['category' => 'ET_Spam']], [$rep . 'etblock' => ['ET_Cnc', 'ET_Cnc,ET_Spam']]],
			'ET match from empty'             => ['etMatch', [['category' => 'ET_Bot']], [$rep . 'etmatch' => ['', 'ET_Bot']]],
			'IPv6 entry added'                => ['suppressionV6', [['cidr' => '2001:db8::/32'], ['cidr' => 'fd00::/32']],
				[$ip . 'v6suppression' => [base64_encode("2001:db8::/32 # lab\n"), base64_encode("2001:db8::/32 # lab\nfd00::/32")]]],
		];
	}

	/** @param array<string, array{0: mixed, 1: mixed}> $expected */
	#[DataProvider('fields')]
	public function testAChangedFieldReachesItsKeyAndOnlyIt(string $field, mixed $value, array $expected): void
	{
		$before = $GLOBALS['config'];
		$revision = $this->read()['revision'];

		$reply = $this->writePolicy(static function (array $policy) use ($field, $value): array {
			$policy[$field] = $value;
			return $policy;
		});

		$this->assertWrittenOnly($expected, $before, $reply, $revision);
		$this->assertSame($value, $this->read()['settings']['policy/ip'][$field], 'the read gives back what Core asked');
	}

	public function testAnUnchangedWriteIsANoOp(): void
	{
		$read = $this->read();
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $read['settings']]);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply);
		$this->assertNothingWritten($before, 'an unchanged write');
	}

	public function testAStoredValueTheReadNormalizesStaysUntilCoreChangesIt(): void
	{
		$this->arrange([self::REP => ['p24_max_var' => '05', 'p24_dmax_var' => 'abc', 'ccexclude' => 'US,USA,us', 'etblock' => 'Spam,ET_Cnc', 'ccwhite' => 'Match', 'ccblack' => 'x']]);
		$before = $GLOBALS['config'];

		$reply = $this->writePolicy(static fn(array $policy): array => $policy);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertNothingWritten($before, 'values read as their defaults and written back as they were read');
	}

	public function testASuppressionListKeepsItsCommentsAndInvalidLinesDropsTheEntriesThatWentAndAppendsTheNewOnes(): void
	{
		$before = $GLOBALS['config'];
		$revision = $this->read()['revision'];
		$this->assertSame([['cidr' => '10.0.0.0/8'], ['cidr' => '192.168.0.0/16'], ['cidr' => '172.16.0.0/12']], $this->read()['settings']['policy/ip']['suppressionV4'], 'before-state');

		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['suppressionV4'] = [['cidr' => '192.168.0.0/16'], ['cidr' => '10.0.0.0/8'], ['cidr' => '172.31.0.0/16']];
			return $policy;
		});

		$text = "10.0.0.0/8 # lan\n# keep me\nbogus-line\n192.168.0.0/16\n\n172.31.0.0/16";
		$this->assertWrittenOnly([self::IP . '/v4suppression' => [base64_encode(self::V4_TEXT), base64_encode($text)]], $before, $reply, $revision);
		$this->assertSame($text, base64_decode(config_get_path(self::IP . '/v4suppression')), 'the stored text');
	}

	public function testASuppressionListEmptiedKeepsOnlyTheLinesThatHoldNoEntry(): void
	{
		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['suppressionV4'] = [];
			return $policy;
		});

		$this->assertSame("# keep me\nbogus-line\n", base64_decode(config_get_path(self::IP . '/v4suppression')), 'the stored text');
		$this->assertSame([], $this->read()['settings']['policy/ip']['suppressionV4']);
		$this->assertArrayHasKey('revision', $reply);
	}

	public function testAReorderedSuppressionListWritesNothing(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['suppressionV4'] = array_reverse($policy['suppressionV4']);
			return $policy;
		});

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertNothingWritten($before, 'a reorder of a text area list');
	}

	public function testAWriteBeneathAStaleRevisionIsAConflictAndWritesNothing(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['policy/ip']['dedup'] = FALSE;
		config_set_path(self::REP . '/p24_max_var', '20');
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertNothingWritten($before, 'a stale revision');
	}

	public function testOneWriteCarriesADnsChangeAndAPolicyChange(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['dns']['control'] = !$settings['dns']['control'];
		$settings['policy/ip']['maxLimit'] = 15;

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config() for both projections');
		$this->assertSame('15', config_get_path(self::REP . '/p24_max_var'));
		$this->assertSame($settings['dns']['control'], $this->read()['settings']['dns']['control']);
	}

	/** @return array<string, array{0: callable, 1: string, 2: string}> a change of the written projection, the field it is named by, its message */
	public static function malformed(): array
	{
		return [
			'a field left out'      => [static function (array $p): array { unset($p['maxLimit']); return $p; }, 'policy/ip.maxLimit', 'required'],
			'an unknown field'      => [static fn(array $p): array => $p + ['bogus' => TRUE], 'policy/ip.bogus', 'no such field'],
			'a bool as a string'    => [static fn(array $p): array => ['dedup' => 'on'] + $p, 'policy/ip.dedup', 'not a bool'],
			'a limit as a string'   => [static fn(array $p): array => ['maxLimit' => '5'] + $p, 'policy/ip.maxLimit', 'not an integer from 0 to 50'],
			'a limit out of range'  => [static fn(array $p): array => ['dMaxLimit' => 51] + $p, 'policy/ip.dMaxLimit', 'not an integer from 0 to 50'],
			'an enum off its tokens' => [static fn(array $p): array => ['countryBlacklistAction' => 'Block'] + $p, 'policy/ip.countryBlacklistAction', 'not a valid value'],
			'a list that is a string' => [static fn(array $p): array => ['etBlock' => 'ET_Spam'] + $p, 'policy/ip.etBlock', 'not a list'],
			'an item that is a string' => [static fn(array $p): array => ['etBlock' => ['ET_Spam']] + $p, 'policy/ip.etBlock[0]', 'not an object'],
			'an invalid item'       => [static fn(array $p): array => ['countryWhitelist' => [['code' => 'usa']]] + $p, 'policy/ip.countryWhitelist[0].code', 'not a valid value'],
			'a repeated item'       => [static fn(array $p): array => ['suppressionV6' => [['cidr' => 'fd00::/32'], ['cidr' => 'fd00::/32']]] + $p, 'policy/ip.suppressionV6[1].cidr', "repeats an earlier item's"],
			'an item with a field the list lacks' => [static fn(array $p): array => ['etMatch' => [['category' => 'ET_Bot', 'x' => 1]]] + $p, 'policy/ip.etMatch[0].x', 'no such field'],
			'a projection that is no object' => [static fn(array $p): array => ['x'], 'policy/ip', 'not an object'],
		];
	}

	#[DataProvider('malformed')]
	public function testAMalformedPolicyIsInvalidArgumentNamingTheFieldAndChangesNothing(callable $change, string $field, string $message): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writePolicy($change);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains(['field' => $field, 'message' => $message], $reply['error']['fieldErrors'] ?? [], json_encode($reply));
		$this->assertNothingWritten($before, 'a malformed policy/ip');
	}

	public function testAWriteWithoutPolicyIpIsMalformedNamingTheProjections(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['policy/ip']);
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('policy/ip', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
		$this->assertNothingWritten($before, 'a write without policy/ip');
	}
}
