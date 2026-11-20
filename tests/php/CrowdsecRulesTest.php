<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4072 -- the bouncer's firewall rules and the signal after a filter reload (docs/specs/crowdsec-integration.md, D5).
 *
 * Intent pinned here:
 *   - pfblockerng.xml names pfb_crowdsec_rules as the package's filter_rules_needed, so pfSense calls it for every rule type;
 *   - it returns rules only for `pfearly`, and only while the bouncer should run (D4); otherwise nothing, and it signals nothing;
 *   - per enabled family, the inbound and outbound rule in D5's exact text: `on { <real interfaces> }` only with "all interfaces"
 *     off, `log` and `tag <tag>` only when set, and never a `table <...>` declaration;
 *   - #4159: each rule names itself twice, as its first label (what pfSense CE's firewall log shows) and as a `descr=` label (what
 *     pfSense versions with keyed labels show), and carries its own fixed tracker (`ridentifier`), which filterlog logs;
 *   - pfSense's filter reload never loads pfBlockerNG's globals, so "should run" reads the stored master enable there;
 *   - a filter reload kills both tables, so when it returns rules it registers a shutdown function, which runs after the kill and
 *     sends SIGUSR1 to the bouncer's own pid (/var/run/pfb_crowdsec.pid, never daemon(8)'s supervisor, #4069), only when
 *     isvalidpid() confirms that pid and only while its command line is the bouncer's (a stale pidfile may name a reused pid).
 */
#[CoversFunction('pfb_crowdsec_rules')]
#[CoversFunction('pfb_crowdsec_signal')]
#[CoversFunction('pfb_crowdsec_should_run')]
final class CrowdsecRulesTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngcrowdsec/config/0';
	private const PIDFILE = '/var/run/pfb_crowdsec.pid';
	private const SIGNAL = "/bin/pkill -USR1 -F '/var/run/pfb_crowdsec.pid' -f '^/usr/local/pkg/pfblockerng/crowdsec/bin/freebsd-[a-z0-9]+/pfb_crowdsec -c '";
	private const REAL = ['wan' => 'vtnet0', 'lan' => 'vtnet1', 'opt1' => 'vtnet2.10'];

	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		unset($GLOBALS['pfb']['crowdsec_pidfile']);
		$GLOBALS['pfb_test_real_interface'] = self::REAL;
		$GLOBALS['pfb_test_mwexec'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		unset($GLOBALS['pfb_test_real_interface'], $GLOBALS['pfb_test_real_interface_inet6'], $GLOBALS['pfb_test_mwexec'],
			$GLOBALS['pfb_test_valid_pids']);
	}

	private static function store(array $over = []): void
	{
		config_set_path(self::SECTION, array_replace(['enable' => 'on', 'lapi_url' => 'https://lapi.example.net/', 'api_key' => 'k3y',
			'log_level' => 'info', 'rules_all_interfaces' => 'on', 'rules_interfaces' => '', 'rules_log' => '', 'rules_tag' => '',
			'rule_v4' => 'on', 'rule_v6' => 'on'], $over));
	}

	// ---- the package hook --------------------------------------------------------------------

	public function testThePackageNamesTheHookAsItsFilterRuleFunction(): void
	{
		$xml = simplexml_load_file(__DIR__ . '/../../src/usr/local/pkg/pfblockerng.xml');
		$this->assertNotFalse($xml);
		$this->assertSame(['pfb_crowdsec_rules'], array_map('strval', $xml->xpath('/packagegui/filter_rules_needed')),
			'the name pfb_crowdsec_register_rule_hook() keeps in installedpackages/package/<n>/filter_rule_function');
	}

	// ---- D5 rule text ------------------------------------------------------------------------

	public function testTheFullShapeWithInterfacesLogAndTag(): void
	{
		self::store(['rules_all_interfaces' => '', 'rules_interfaces' => 'wan,opt1', 'rules_log' => 'on', 'rules_tag' => 'cs_ban-1']);
		$this->assertSame(
			"block drop in log quick on { vtnet0 vtnet2.10 } inet from <crowdsec_v4> to any label \"CrowdSec IPv4\" label \"descr=CrowdSec IPv4\" ridentifier 177400401 tag \"cs_ban-1\"\n"
			. "block drop out log quick on { vtnet0 vtnet2.10 } inet from any to <crowdsec_v4> label \"CrowdSec IPv4 out\" label \"descr=CrowdSec IPv4 out\" ridentifier 177400402 tag \"cs_ban-1\"\n"
			. "block drop in log quick on { vtnet0 vtnet2.10 } inet6 from <crowdsec_v6> to any label \"CrowdSec IPv6\" label \"descr=CrowdSec IPv6\" ridentifier 177400601 tag \"cs_ban-1\"\n"
			. "block drop out log quick on { vtnet0 vtnet2.10 } inet6 from any to <crowdsec_v6> label \"CrowdSec IPv6 out\" label \"descr=CrowdSec IPv6 out\" ridentifier 177400602 tag \"cs_ban-1\"\n",
			pfb_crowdsec_rules('pfearly'));
	}

	public function testTheDefaultsGiveTheFourRulesOnEveryInterfaceWithoutLogOrTag(): void
	{
		self::store();
		$this->assertSame(
			"block drop in quick inet from <crowdsec_v4> to any label \"CrowdSec IPv4\" label \"descr=CrowdSec IPv4\" ridentifier 177400401\n"
			. "block drop out quick inet from any to <crowdsec_v4> label \"CrowdSec IPv4 out\" label \"descr=CrowdSec IPv4 out\" ridentifier 177400402\n"
			. "block drop in quick inet6 from <crowdsec_v6> to any label \"CrowdSec IPv6\" label \"descr=CrowdSec IPv6\" ridentifier 177400601\n"
			. "block drop out quick inet6 from any to <crowdsec_v6> label \"CrowdSec IPv6 out\" label \"descr=CrowdSec IPv6 out\" ridentifier 177400602\n",
			pfb_crowdsec_rules('pfearly'));
	}

	public function testEachRuleCarriesItsOwnTrackerOutsidePfSensesAndPfBlockerNGsRanges(): void
	{
		// #4159: filterlog writes a rule's ridentifier as its tracker. pfSense numbers its fixed rules 10000-13999, its negated
		// rules from 10000000 and its own rules from 1000000000; a GUI rule takes its creation time (past 1000000000 since 2001);
		// pfBlockerNG's own rules take ten digits from 1700000010 (pfb_tracker) or 176xxxxxxx (pfb_managed_rule_tracker)
		self::store();
		preg_match_all('/ ridentifier (\d+)(?: |$)/m', pfb_crowdsec_rules('pfearly'), $m);
		$this->assertCount(4, $m[1], 'every rule carries a tracker');
		$this->assertSame($m[1], array_unique($m[1]), 'no two rules share one');
		foreach (array_map('intval', $m[1]) as $tracker) {
			$this->assertGreaterThan(10000000 + 1000000, $tracker, 'above pfSense negated rules, with a million to spare');
			$this->assertLessThan(1000000000, $tracker, "below pfSense's own rules, every GUI rule and pfBlockerNG's own");
		}
	}

	/** @return iterable<string, array{bool, bool, ?list<string>, bool, string}> v4, v6, selected interfaces (NULL: all), log, tag */
	public static function combinations(): iterable
	{
		$interfaces = ['all' => NULL, 'one' => ['lan'], 'two' => ['wan', 'lan']];
		foreach (['v4+v6' => [TRUE, TRUE], 'v4' => [TRUE, FALSE], 'v6' => [FALSE, TRUE], 'neither' => [FALSE, FALSE]] as $fn => [$v4, $v6]) {
			foreach ($interfaces as $in => $chosen) {
				foreach (['log' => TRUE, 'nolog' => FALSE] as $ln => $log) {
					foreach (['tag' => 'pfb_cs', 'notag' => ''] as $tn => $tag) {
						yield "{$fn} {$in} {$ln} {$tn}" => [$v4, $v6, $chosen, $log, $tag];
					}
				}
			}
		}
	}

	#[DataProvider('combinations')]
	public function testEveryCombinationOfFamiliesInterfacesLogAndTagGivesTheD5Text(bool $v4, bool $v6, ?array $chosen, bool $log, string $tag): void
	{
		self::store(['rule_v4' => $v4 ? 'on' : '', 'rule_v6' => $v6 ? 'on' : '', 'rules_all_interfaces' => $chosen === NULL ? 'on' : '',
			'rules_interfaces' => $chosen === NULL ? 'wan' : implode(',', $chosen), 'rules_log' => $log ? 'on' : '', 'rules_tag' => $tag]);

		$on = $chosen === NULL ? '' : ' on { ' . implode(' ', array_map(static fn (string $i): string => self::REAL[$i], $chosen)) . ' }';
		$opt = ($log ? ' log' : '') . ' quick' . $on;
		$end = $tag === '' ? '' : " tag \"{$tag}\"";
		$expected = '';
		foreach (['4' => [$v4, 'inet'], '6' => [$v6, 'inet6']] as $n => [$enabled, $af]) {
			if ($enabled) {
				$expected .= "block drop in{$opt} {$af} from <crowdsec_v{$n}> to any label \"CrowdSec IPv{$n}\" label \"descr=CrowdSec IPv{$n}\" ridentifier 177400{$n}01{$end}\n"
					. "block drop out{$opt} {$af} from any to <crowdsec_v{$n}> label \"CrowdSec IPv{$n} out\" label \"descr=CrowdSec IPv{$n} out\" ridentifier 177400{$n}02{$end}\n";
			}
		}

		$rules = pfb_crowdsec_rules('pfearly');
		$this->assertSame($expected, $rules);
		$this->assertStringNotContainsString('table', $rules, 'the tables are never declared in the ruleset');
	}

	public function testWithAllInterfacesTheStoredSelectionIsIgnored(): void
	{
		self::store(['rules_all_interfaces' => 'on', 'rules_interfaces' => 'wan,lan']);
		$this->assertStringNotContainsString(' on ', pfb_crowdsec_rules('pfearly'));
	}

	public function testASelectedInterfaceThatNoLongerExistsIsLeftOut(): void
	{
		self::store(['rules_all_interfaces' => '', 'rules_interfaces' => 'opt7,lan']);
		$GLOBALS['pfb_test_real_interface']['opt7'] = NULL;
		$this->assertStringStartsWith("block drop in quick on { vtnet1 } inet from <crowdsec_v4>", pfb_crowdsec_rules('pfearly'));
	}

	public function testEachFamilysRulesUseThatFamilysRealInterface(): void
	{
		// A 6rd or 6to4 WAN carries its IPv6 on wan_stf: pfSense answers that only when asked for inet6
		self::store(['rules_all_interfaces' => '', 'rules_interfaces' => 'wan,lan']);
		$GLOBALS['pfb_test_real_interface_inet6'] = ['wan' => 'wan_stf'];
		$this->assertSame(
			"block drop in quick on { vtnet0 vtnet1 } inet from <crowdsec_v4> to any label \"CrowdSec IPv4\" label \"descr=CrowdSec IPv4\" ridentifier 177400401\n"
			. "block drop out quick on { vtnet0 vtnet1 } inet from any to <crowdsec_v4> label \"CrowdSec IPv4 out\" label \"descr=CrowdSec IPv4 out\" ridentifier 177400402\n"
			. "block drop in quick on { wan_stf vtnet1 } inet6 from <crowdsec_v6> to any label \"CrowdSec IPv6\" label \"descr=CrowdSec IPv6\" ridentifier 177400601\n"
			. "block drop out quick on { wan_stf vtnet1 } inet6 from any to <crowdsec_v6> label \"CrowdSec IPv6 out\" label \"descr=CrowdSec IPv6 out\" ridentifier 177400602\n",
			pfb_crowdsec_rules('pfearly'));
	}

	public function testAFamilyWithNoSelectedInterfaceLeftGetsNoRulesAndTheOtherKeepsItsOwn(): void
	{
		self::store(['rules_all_interfaces' => '', 'rules_interfaces' => 'opt1']);
		$GLOBALS['pfb_test_real_interface_inet6'] = ['opt1' => NULL];
		$this->assertSame(
			"block drop in quick on { vtnet2.10 } inet from <crowdsec_v4> to any label \"CrowdSec IPv4\" label \"descr=CrowdSec IPv4\" ridentifier 177400401\n"
			. "block drop out quick on { vtnet2.10 } inet from any to <crowdsec_v4> label \"CrowdSec IPv4 out\" label \"descr=CrowdSec IPv4 out\" ridentifier 177400402\n",
			pfb_crowdsec_rules('pfearly'));
	}

	public function testNoSelectedInterfaceLeftGivesNoRulesRatherThanRulesOnEveryInterface(): void
	{
		self::store(['rules_all_interfaces' => '', 'rules_interfaces' => 'opt7']);
		$GLOBALS['pfb_test_real_interface']['opt7'] = NULL;
		$this->assertSame('', pfb_crowdsec_rules('pfearly'));
	}

	/** @return iterable<string, array{string}> stored tags the Settings refuse: a peer's sync or a hand edit can still store them */
	public static function hostileTags(): iterable
	{
		yield 'a newline and a rule' => ["pfb\npass in quick all"];
		yield 'a carriage return'    => ["pfb\rpass"];
		yield 'a space'              => ['pfb pass'];
		yield 'a quote'              => ['pfb"'];
		yield 'a brace'              => ['pfb}'];
		yield 'a semicolon'          => ['pfb;'];
		yield 'a hash'               => ['pfb#'];
		yield '64 characters'        => [str_repeat('a', 64)];
		yield 'a trailing newline'   => ["pfb\n"];
		yield 'non-ASCII'            => ['pfbé'];
	}

	#[DataProvider('hostileTags')]
	public function testAStoredTagTheSettingsWouldRefuseIsLeftOutAndTheRulesStay(string $tag): void
	{
		self::store(['rules_tag' => 'pfb_cs-1']);
		$this->assertStringContainsString(' tag "pfb_cs-1"', pfb_crowdsec_rules('pfearly'), 'before: a valid tag is rendered');

		self::store(['rules_tag' => $tag]);
		$rules = pfb_crowdsec_rules('pfearly');
		$this->assertSame(4, substr_count($rules, "\n"), 'four rules and nothing else');
		$this->assertStringNotContainsString(' tag', $rules);
		$this->assertStringNotContainsString('pass', $rules);
	}

	/** @return iterable<string, array{string}> tags the Settings accept that pf reads as a number, a keyword or an operator unquoted */
	public static function tagsPfWouldNotReadAsAString(): iterable
	{
		foreach (['123', '007', 'quick', 'all', 'log', 'label', 'pass', 'any', '-x', '_'] as $tag) {
			yield $tag => [$tag];
		}
	}

	#[DataProvider('tagsPfWouldNotReadAsAString')]
	public function testEveryTagTheSettingsAcceptIsQuotedSoPfReadsItAsTheTag(string $tag): void
	{
		$this->assertSame([], pfb_crowdsec_validate(['log_level' => 'info', 'rules_all_interfaces' => 'on', 'rules_tag' => $tag], 'k', [])['errors'],
			'the Settings accept it');
		self::store(['rules_tag' => $tag]);
		$rules = pfb_crowdsec_rules('pfearly');
		$this->assertSame(4, substr_count($rules, " label \"CrowdSec IPv"), $rules);
		$this->assertSame(4, substr_count($rules, " tag \"{$tag}\"\n"), 'each rule ends with the quoted tag: ' . $rules);
	}

	// ---- no output ---------------------------------------------------------------------------

	/** @return iterable<string, array{string}> */
	public static function otherTypes(): iterable
	{
		foreach (['filter', 'nat', 'pfearly ', 'PFEARLY', ''] as $type) {
			yield "'{$type}'" => [$type];
		}
	}

	#[DataProvider('otherTypes')]
	public function testOtherRuleTypesGetNothing(string $type): void
	{
		self::store();
		$this->assertNotSame('', pfb_crowdsec_rules('pfearly'), 'the same settings give pfearly its rules');
		$this->assertSame('', pfb_crowdsec_rules($type));
	}

	/** @return iterable<string, array{string, array<string, string>}> */
	public static function notRunning(): iterable
	{
		yield 'pfBlockerNG off'     => ['', []];
		yield 'CrowdSec off'        => ['on', ['enable' => '']];
		yield 'no key on this node' => ['on', ['api_key' => '']];
	}

	#[DataProvider('notRunning')]
	public function testNothingWhileTheBouncerShouldNotRun(string $master, array $over): void
	{
		unset($GLOBALS['pfb']['enable']);
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');
		self::store();
		$this->assertNotSame('', pfb_crowdsec_rules('pfearly'), 'before: the bouncer should run, and there are rules');

		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', $master);
		self::store($over);
		$this->assertSame('', pfb_crowdsec_rules('pfearly'));
	}

	// ---- should run, in pfSense's filter reload -------------------------------------------------

	public function testWithoutPfBlockerNGsGlobalsLoadedShouldRunReadsTheStoredMasterEnable(): void
	{
		self::store();
		unset($GLOBALS['pfb']['enable']);
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');
		$this->assertTrue(pfb_crowdsec_should_run(), 'stored on: it should run');
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', '');
		$this->assertFalse(pfb_crowdsec_should_run(), 'stored off: it should not');
	}

	public function testOncePfBlockerNGsGlobalsAreLoadedTheyDecide(): void
	{
		self::store();
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->assertFalse(pfb_crowdsec_should_run(), 'a removal turns pfBlockerNG off in its own process, whatever config.xml says');
	}

	// ---- the signal --------------------------------------------------------------------------

	public function testTheSignalGoesToTheBouncersOwnPidWhenIsvalidpidConfirmsIt(): void
	{
		$GLOBALS['pfb_test_valid_pids'] = [self::PIDFILE => TRUE, '/var/run/pfb_crowdsec_daemon.pid' => TRUE];
		pfb_crowdsec_signal();
		$this->assertSame([self::SIGNAL], $GLOBALS['pfb_test_mwexec'], 'SIGUSR1 to the bouncer, never to daemon(8)\'s supervisor');
	}

	public function testNoSignalWithoutALiveBouncer(): void
	{
		$GLOBALS['pfb_test_valid_pids'] = [self::PIDFILE => FALSE, '/var/run/pfb_crowdsec_daemon.pid' => TRUE];
		pfb_crowdsec_signal();
		$this->assertSame([], $GLOBALS['pfb_test_mwexec'], 'a supervisor between restarts is not signalled in its place');
	}

	/** @return array{stdout: string, stderr: string, exit: int} */
	private static function reload(array $scenario): array
	{
		return pfb_test_run_process([PHP_BINARY, '-d', 'display_errors=stderr', __DIR__ . '/support/CrowdsecShutdownWorker.php',
			json_encode($scenario, JSON_THROW_ON_ERROR)]);
	}

	public function testAReloadThatGotTheRulesSignalsOnceWhenItEnds(): void
	{
		$out = self::reload(['types' => ['filter', 'pfearly', 'nat', 'pfearly'], 'running' => TRUE, 'alive' => TRUE]);
		$this->assertSame(0, $out['exit'], $out['stderr']);
		$this->assertSame("rules filter none\nrules pfearly some\nrules nat none\nrules pfearly some\nreturned\nexec " . self::SIGNAL . "\n",
			$out['stdout'], 'nothing is sent while the reload runs, and one signal after it, however often the rules were asked for');
	}

	public function testAReloadWithoutTheRulesSignalsNothing(): void
	{
		$out = self::reload(['types' => ['filter', 'pfearly', 'nat'], 'running' => FALSE, 'alive' => TRUE]);
		$this->assertSame(0, $out['exit'], $out['stderr']);
		$this->assertSame("rules filter none\nrules pfearly none\nrules nat none\nreturned\n", $out['stdout']);
	}

	public function testAReloadWhileTheBouncerRunsWithBothFamiliesOffSignalsNothing(): void
	{
		$out = self::reload(['types' => ['pfearly'], 'running' => TRUE, 'alive' => TRUE, 'families' => FALSE]);
		$this->assertSame(0, $out['exit'], $out['stderr']);
		$this->assertSame("rules pfearly none\nreturned\n", $out['stdout'], 'no rules reference the tables, so there is nothing to restore');
	}

	public function testAReloadWithoutALiveBouncerSignalsNothing(): void
	{
		$out = self::reload(['types' => ['pfearly'], 'running' => TRUE, 'alive' => FALSE]);
		$this->assertSame(0, $out['exit'], $out['stderr']);
		$this->assertSame("rules pfearly some\nreturned\n", $out['stdout']);
	}
}
