<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4164 -- the Alerts and Reports pipeline attributes drops by the CrowdSec bouncer's rules, by their fixed trackers
 * (#4159), as it attributes pfBlockerNG's own rules.
 *
 * Intent pinned here:
 *   - pfb_filterrules() lists each of the bouncer's loaded rules under its table, as it lists a pfB rule under its alias, so
 *     pfb_resolve_tracker() resolves the rule's tracker; a rule on the tables with another tracker, or one of the trackers on
 *     another table, stays someone else's; the bouncer's rules add no interface to Kill States' list;
 *   - the filterlog daemon writes such a drop to ip_block.log and unified.log under the table, the action, family and
 *     direction, with the origin of the decision that bans the address as the feed and the banned value (address or range)
 *     as the matched entry, read from the bouncer's per-origin decision files (no LAPI request); Unknown for both when no file
 *     names it, or the file's name is not a safe origin. A pfB feed that also lists the address did not drop it. A later drop
 *     of that address by a pfB rule keeps its own feed;
 *   - pfb_crowdsec_decision_origin() answers each address once until the decision files change.
 */
#[CoversFunction('pfb_filterrules')]
#[CoversFunction('pfb_crowdsec_rule_table')]
#[CoversFunction('pfb_daemon_filterlog')]
#[CoversFunction('pfb_crowdsec_decision_origin')]
final class CrowdsecAlertsAttributionTest extends TestCase
{
	private const DAEMON_DEADLINE_S = 15.0;

	// What `pfctl -vvsr` prints for the bouncer's four rules (D5, "all interfaces" off, logging on) and one pfB rule
	private const RULES = <<<'RULES'
		@3(0) block drop in log quick on vtnet0 inet from <crowdsec_v4:2> to any label "CrowdSec IPv4" label "descr=CrowdSec IPv4" ridentifier 177400401
		  [ Evaluations: 10        Packets: 0         Bytes: 0           States: 0     ]
		@4(0) block drop out log quick on vtnet0 inet from any to <crowdsec_v4:2> label "CrowdSec IPv4 out" label "descr=CrowdSec IPv4 out" ridentifier 177400402
		@5(0) block drop in log quick on vtnet0 inet6 from <crowdsec_v6:1> to any label "CrowdSec IPv6" label "descr=CrowdSec IPv6" ridentifier 177400601
		@6(0) block drop out log quick on vtnet0 inet6 from any to <crowdsec_v6:1> label "CrowdSec IPv6 out" label "descr=CrowdSec IPv6 out" ridentifier 177400602
		@7(0) block drop in log quick on vtnet0 inet from <pfB_Test_v4:1> to any label "USER_RULE: pfB_Test_v4" ridentifier 1770000001
		RULES;

	private string $root;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_crowdsec_alerts_' . getmypid() . '_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir("{$this->root}/deny", 0777, TRUE) && mkdir("{$this->root}/native", 0777, TRUE)
			&& mkdir("{$this->root}/decisions", 0777, TRUE), 'test setup: sandbox');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$GLOBALS['pfb']['pfctl'] = __DIR__ . '/fixtures/fake_pfctl.sh';
		putenv("PFB_FAKE_RULES={$this->root}/rules.txt");
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		putenv('PFB_FAKE_RULES');
		rmdir_recursive($this->root);
	}

	private function rules(string $rules): void
	{
		file_put_contents("{$this->root}/rules.txt", $rules . "\n");
	}

	public function testFilterrulesListsEachOfTheBouncersRulesUnderItsTable(): void
	{
		$this->rules(self::RULES);
		$list = pfb_filterrules();

		foreach (['177400401' => 'crowdsec_v4', '177400402' => 'crowdsec_v4', '177400601' => 'crowdsec_v6',
		    '177400602' => 'crowdsec_v6', '1770000001' => 'pfB_Test_v4'] as $tracker => $name) {
			$this->assertSame(['name' => $name, 'type' => 'block'], $list[$tracker] ?? NULL, "tracker {$tracker}");
			$this->assertArrayNotHasKey($tracker, $list['other'], "tracker {$tracker} is no other rule");
		}
		$this->assertSame(['vtnet0' => ''], $list['int'], 'only the pfB rule lists its interface for Kill States');

		$reparses = 0;
		$misses = [];
		$this->assertTrue(pfb_resolve_tracker($list, $misses, '177400402', 'block', static function () use (&$reparses): array {
			$reparses++;
			return [];
		}), 'the outbound IPv4 rule resolves');
		$this->assertSame(0, $reparses, 'from the parsed list, without a reparse');
	}

	public function testOtherRulesOnTheTablesAndTheTrackersOnOtherTablesStaySomeoneElses(): void
	{
		$this->rules(implode("\n", [
			// A user's rule on the bouncer's table
			'@1(0) block drop in quick inet from <crowdsec_v4:2> to any label "USER_RULE" ridentifier 1700000123',
			// The IPv4 tracker on the IPv6 table, and the IPv6 tracker on no table
			'@2(0) block drop in quick inet6 from <crowdsec_v6:1> to any label "x" ridentifier 177400401',
			'@3(0) block drop in quick inet6 from any to any label "y" ridentifier 177400601',
			// A table whose name only starts like the bouncer's
			'@4(0) block drop in quick inet from <crowdsec_v4_old:1> to any label "z" ridentifier 177400402',
		]));
		$list = pfb_filterrules();

		foreach (['1700000123', '177400401', '177400601', '177400402'] as $tracker) {
			$this->assertArrayNotHasKey($tracker, $list, "tracker {$tracker} is no pfBlockerNG rule");
			$this->assertArrayHasKey($tracker, $list['other'], "tracker {$tracker} is someone else's");
		}
	}

	public function testATableNotLoadedYetStillNamesTheRule(): void
	{
		// pfSense kills the tables on a filter reload (#4070) until the bouncer refills them: pfctl then prints no count
		$this->rules('@3(0) block drop in quick inet from <crowdsec_v4> to any label "CrowdSec IPv4" ridentifier 177400401');
		$this->assertSame(['name' => 'crowdsec_v4', 'type' => 'block'], pfb_filterrules()['177400401'] ?? NULL);
	}

	/**
	 * Runs the real pfb_daemon_filterlog() in a child process over $lines on stdin, against the fake pfctl and this test's
	 * sandbox, and returns ip_block.log and unified.log as CSV rows.
	 *
	 * @return array{0: list<list<string>>, 1: list<list<string>>}
	 */
	private function runDaemon(array $lines): array
	{
		$done = "{$this->root}/done";
		$stderr = "{$this->root}/stderr";
		$childCode = <<<'PHP'
			[, $root, $bootstrap, $done] = $argv;
			require $bootstrap;
			function convert_real_interface_to_friendly_descr($if) { return 'WAN'; }
			function dhcp_is_backend($backend) { return FALSE; }
			function system_get_kea4leases() { return ['lease' => []]; }
			$GLOBALS['config'] = [];
			// One LAN subnet, so a drop toward it is inbound
			config_set_path('interfaces', ['lan' => ['if' => 'vtnet1', 'ipaddr' => '10.0.0.1', 'subnet' => '24']]);
			$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'], [
				'pfctl' => __DIR__ . '/fixtures/fake_pfctl.sh',
				'denydir' => "{$root}/deny", 'nativedir' => "{$root}/native",
				'ip_blocklog' => "{$root}/ip_block.log", 'ip_permitlog' => "{$root}/ip_permit.log",
				'ip_matchlog' => "{$root}/ip_match.log", 'unilog' => "{$root}/unified.log",
				'ip_cache' => "{$root}/ip_cache.sqlite", 'geoipshare' => '', 'rdns' => FALSE,
				'crowdsec_decisions' => "{$root}/decisions",
				'asn_reporting' => 'disabled', 'asn_token' => '', 'sqlite_timeout' => 1000,
			]);
			pfb_daemon_filterlog();
			file_put_contents($done, 'done');
			PHP;
		$childCode = str_replace('__DIR__', var_export(__DIR__, TRUE), $childCode);
		$proc = proc_open([PHP_BINARY, '-r', $childCode, $this->root, __DIR__ . '/bootstrap.php', $done],
			[0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']], $pipes,
			NULL, ['PFB_FAKE_RULES' => "{$this->root}/rules.txt", 'PATH' => getenv('PATH')]);
		$this->assertIsResource($proc, 'test setup: failed to spawn the filterlog daemon child');
		fwrite($pipes[0], implode("\n", $lines) . "\n");
		fclose($pipes[0]);

		$deadline = microtime(TRUE) + self::DAEMON_DEADLINE_S;
		while (!is_file($done) && proc_get_status($proc)['running'] && microtime(TRUE) < $deadline) {
			usleep(10000);
		}
		if (!is_file($done)) {
			proc_terminate($proc, 9);
			proc_close($proc);
			$this->fail('the filterlog daemon child did not complete: ' . (string) @file_get_contents($stderr));
		}
		$this->assertSame(0, proc_close($proc), 'the filterlog daemon child exits cleanly: ' . (string) file_get_contents($stderr));

		$read = function (string $name): array {
			$path = "{$this->root}/{$name}";
			$text = is_file($path) ? (string) file_get_contents($path) : '';
			return array_map(static fn (string $l): array => str_getcsv($l, ',', '"', ''), array_values(array_filter(explode("\n", $text))));
		};
		return [$read('ip_block.log'), $read('unified.log')];
	}

	private static function filterlog(string $csv): string
	{
		return "<134>1 2026-11-21T10:00:00.000000+00:00 fw filterlog 123 - - {$csv}";
	}

	public function testTheDaemonLogsADropByTheBouncersRuleAsCrowdSec(): void
	{
		$this->rules(self::RULES);
		// A pfB feed lists the IPv4 address too: it is not what dropped it
		file_put_contents("{$this->root}/deny/Test_Feed.txt", "192.0.2.10\n");
		file_put_contents("{$this->root}/native/Placeholder.txt", "placeholder\n");
		// The bouncer's decision files: an address banned by CAPI, a range from a blocklist, and a file whose name is no origin
		file_put_contents("{$this->root}/decisions/CAPI.txt", "192.0.2.10\n198.51.100.7\n");
		file_put_contents("{$this->root}/decisions/lists:firehol_level1.txt", "2001:db8:4074::/48\n");
		file_put_contents("{$this->root}/decisions/bad,name.txt", "192.0.2.98\n");

		[$block, $unified] = $this->runDaemon([
			// Inbound IPv4 TCP from a banned address to a LAN host, by the inbound IPv4 rule
			self::filterlog('3,,,177400401,vtnet0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,192.0.2.10,10.0.0.5,51234,22,0,S,1,,64240,,mss'),
			// Outbound IPv6 UDP to a banned address, by the outbound IPv6 rule
			self::filterlog('6,,,177400602,vtnet0,match,block,out,6,0x00,0x00000,64,udp,17,40,2001:db8:1::5,2001:db8:4074::1,5353,53,40'),
			// Inbound drops of addresses no decision file names, or only a file whose name is no origin
			self::filterlog('3,,,177400401,vtnet0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,192.0.2.99,10.0.0.5,51234,22,0,S,1,,64240,,mss'),
			self::filterlog('3,,,177400401,vtnet0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,192.0.2.98,10.0.0.5,51234,22,0,S,1,,64240,,mss'),
			// The same IPv4 address later dropped by the pfB rule
			self::filterlog('7,,,1770000001,vtnet0,match,block,in,4,0x0,,64,12346,0,DF,6,tcp,60,192.0.2.10,10.0.0.5,51235,23,0,S,1,,64240,,mss'),
		]);

		// ip_block.log: [1] tracker, [4] action, [5] family, [12] direction, [14] alias, [15] matched entry, [16] feed
		$pick = static fn (array $r): array => [$r[1], $r[4], $r[5], $r[8], $r[9], $r[12], $r[14], $r[15], $r[16]];
		$this->assertSame([
			['177400401', 'block', '4', '192.0.2.10', '10.0.0.5', 'in', 'crowdsec_v4', '192.0.2.10', 'CAPI'],
			['177400602', 'block', '6', '2001:db8:1::5', '2001:db8:4074::1', 'out', 'crowdsec_v6', '2001:db8:4074::/48', 'lists:firehol_level1'],
			['177400401', 'block', '4', '192.0.2.99', '10.0.0.5', 'in', 'crowdsec_v4', 'Unknown', 'Unknown'],
			['177400401', 'block', '4', '192.0.2.98', '10.0.0.5', 'in', 'crowdsec_v4', 'Unknown', 'Unknown'],
			['1770000001', 'block', '4', '192.0.2.10', '10.0.0.5', 'in', 'pfB_Test_v4', '192.0.2.10', 'Test_Feed'],
		], array_map($pick, $block));
		// The Alerts page reads a row after popping its duplicate marker
		$this->assertTrue(pfb_ip_log_row_schema_ok(array_slice($block[0], 0, -1), 'non_unified'), 'the CrowdSec row has the current schema');

		// unified.log: the event type first, then the ip_block.log row
		$this->assertSame([['Block', 'crowdsec_v4', 'CAPI'], ['Block', 'crowdsec_v6', 'lists:firehol_level1'], ['Block', 'crowdsec_v4', 'Unknown'],
			['Block', 'crowdsec_v4', 'Unknown'], ['Block', 'pfB_Test_v4', 'Test_Feed']],
			array_map(static fn (array $r): array => [$r[0], $r[15], $r[17]], $unified));
	}

	public function testTheOriginLookupAnswersEachAddressOnceUntilTheDecisionFilesChange(): void
	{
		$dir = "{$this->root}/decisions";
		$GLOBALS['pfb']['crowdsec_decisions'] = $dir;
		$GLOBALS['pfb']['grep'] = '/usr/bin/grep';
		file_put_contents("{$dir}/CAPI.txt", "192.0.2.10\n");
		touch($dir, 1_000_000_000);
		$this->assertSame(['CAPI', '192.0.2.10'], pfb_crowdsec_decision_origin('192.0.2.10'));

		// The bouncer moves the address to another origin, but the folder still reads as unchanged: the answer is cached
		rename("{$dir}/CAPI.txt", "{$dir}/cscli.txt");
		touch($dir, 1_000_000_000);
		$this->assertSame(['CAPI', '192.0.2.10'], pfb_crowdsec_decision_origin('192.0.2.10'), 'cached');

		// The folder changed: looked up again
		touch($dir, 1_000_000_060);
		$this->assertSame(['cscli', '192.0.2.10'], pfb_crowdsec_decision_origin('192.0.2.10'), 'after the files changed');
		$this->assertSame(['Unknown', 'Unknown'], pfb_crowdsec_decision_origin('192.0.2.11'), 'no decision names it');
	}
}
