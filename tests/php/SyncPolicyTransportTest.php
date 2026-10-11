<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Pre-change copy of pfblockerng_plugin_xmlrpc_send() (pfblockerng.inc at the parent of
 * issue #3452), renamed. The only edit: the removed `sync/syncinterfaces` toggle arrives as a
 * parameter, mapped from the scope under test (`lists` = the old checked box, `all` = unchecked).
 */
function pfb_test_prechange_plugin_xmlrpc_send(PfbToggle $syncinterfaces) {
	if (config_get_path('installedpackages/pfblockerngsync/config/0/varsynconchanges') != 'auto') {
		return [];
	}

	$section_paths_temp = [
		'installedpackages/pfblockerngsync/config/0/varsynconchanges'
	];
	// If User Disabled, remove 'General/IP/DNSBL Tab Customizations' from Sync (#2123).
	$sections = pfblockerng_sync_sections($syncinterfaces !== PfbToggle::On);
	foreach ($sections as $section) {
		$section_paths_temp[] = "installedpackages/{$section}";
	}

	$section_paths = [];
	foreach ($section_paths_temp as $path) {
		$section_config = config_get_path($path);
		if (!isset($section_config)) {
			continue;
		}
		$section_paths[] = $path;
	}

	return $section_paths;
}

/**
 * Pre-change copy of pfblockerng_do_xmlrpc_sync() (parent of issue #3452), renamed, with the
 * same single edit as pfb_test_prechange_plugin_xmlrpc_send().
 */
function pfb_test_prechange_do_xmlrpc_sync($sync_to_ip, $port, $protocol, $username, $password, $synctimeout, PfbToggle $syncinterfaces) {
	global $g;
	$success = TRUE;

	// Take care of IPv6 literal address
	if (is_ipaddrv6($sync_to_ip)) {
		$sync_to_ip = "[{$sync_to_ip}]";
	}

	// If User Disabled, remove 'General/IP/DNSBL Tab Customizations' from Sync.
	// issue #2123: read through the gateway, so the registered default and the
	// case-insensitive toggle vocabulary apply here as on the Sync page.
	$sections = pfblockerng_sync_sections($syncinterfaces !== PfbToggle::On);

	/* xml will hold the sections to sync */
	$xml = array();

	foreach ($sections as $section) {
		$section_config = config_get_path("installedpackages/{$section}");
		if (!isset($section_config)) {
			continue;
		}
		$xml[$section] = $section_config;
	}

	require_once('xmlrpc_client.inc');

	// xmlrpc cannot encode NULL objects/arrays
	foreach ($xml as $xmlkey => $xmlvalue) {
		if (gettype($xmlvalue) == 'NULL') {
			$xml[$xmlkey] = array();
		}
	}

	$synctimeout = intval($synctimeout);
	$rpc_client = new pfsense_xmlrpc_client();
	$rpc_client->setConnectionData($sync_to_ip, $port, $username, $password, $protocol);
	$resp = $rpc_client->xmlrpc_method('merge_installedpackages_section', $xml, $synctimeout);

	if (!isset($resp)) {
		return FALSE;
	} else {
		return TRUE;
	}
}

/**
 * Released pfblockerng_plugin_xmlrpc_recv() (identical on origin/main and tag v3.3.10; the
 * `varsynconchanges` gate is shared by every release from v3.2.15), renamed.
 */
function pfb_test_released_plugin_xmlrpc_recv($new_sections) {
	if (array_get_path($new_sections, 'installedpackages/pfblockerngsync/config/0/varsynconchanges') != 'auto') {
		return [];
	}

	$section_paths = [
		'installedpackages/pfblockerng',
		'installedpackages/pfblockerngipsettings',
		'installedpackages/pfblockerngdnsblsettings',
		'installedpackages/pfblockernglistsv4',
		'installedpackages/pfblockernglistsv6',
		'installedpackages/pfblockerngreputation',
		'installedpackages/pfblockerngtopspammers',
		'installedpackages/pfblockerngafrica',
		'installedpackages/pfblockerngantarctica',
		'installedpackages/pfblockerngasia',
		'installedpackages/pfblockerngeurope',
		'installedpackages/pfblockerngnorthamerica',
		'installedpackages/pfblockerngoceania',
		'installedpackages/pfblockerngsouthamerica',
		'installedpackages/pfblockerngproxyandsatellite',
		'installedpackages/pfblockerngdnsbl',
		'installedpackages/pfblockerngblacklist',
		'installedpackages/pfblockerngglobal',
		'installedpackages/pfblockerngsafesearch'
	];

	$ret = [
		'xmlrpc_recv_result' => false
	];
	foreach ($section_paths as $path) {
		$old_section = config_get_path($path, []);
		$new_section = array_get_path($new_sections, $path, []);

		// Don't save empty configuration sections.
		if (empty($old_section) && empty($new_section)) {
			continue;
		}
		// Ignore unchanged configuration sections.
		if ($old_section === $new_section) {
			continue;
		}

		$ret[$path] = array_merge($old_section, $new_section);
		$ret['xmlrpc_recv_result'] = true;
	}

	return $ret;
}

/**
 * Issue #3452 -- both send transports honour the stored `sync/syncscope`
 * (docs/specs/xmlrpc-per-field-sync.md, "Wire contract and transports").
 *
 * `all` and `lists` reproduce the pre-change transports byte for byte; `policy` sends the gate
 * leaf plus the policy projection (automatic: the path list; manual: one
 * `restore_config_section` call per enabled target carrying the `installedpackages` subtree);
 * any other stored value, including an unstored leaf, sends no pfBlockerNG content. The
 * registry default alone never sends: only the stored leaf counts.
 *
 * The real pfblockerng_sync_on_changes() drives the manual path through the recording
 * pfsense_xmlrpc_client double, so the assertions compare what a real client would be asked to
 * send with the expected method, payload and timeout.
 */
#[CoversFunction('pfblockerng_plugin_xmlrpc_send')]
#[CoversFunction('pfblockerng_do_xmlrpc_sync')]
#[CoversFunction('pfblockerng_sync_on_changes')]
final class SyncPolicyTransportTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private const SYNC_ROOT    = 'installedpackages/pfblockerngsync/config/0';
	private const GATE         = self::SYNC_ROOT . '/syncscope';
	private const GLOBAL_ROOT  = 'installedpackages/pfblockerngglobal';
	private const EMPTY_LEAF   = self::GLOBAL_ROOT . '/feed_Empty';
	private const ABSENT_LEAF  = self::GLOBAL_ROOT . '/feed_Absent';
	private const TIMEOUT      = '37';
	private const UNSTORED     = "\0unstored";
	private const ENABLED_IPS  = ['192.0.2.10', '192.0.2.11'];
	private const DISABLED_IP  = '192.0.2.12';

	private mixed $savedConfig = NULL;
	private bool $hadConfig    = FALSE;

	protected function setUp(): void
	{
		global $pfb;
		// The sync run logs through pfb_logger(); a missing log dir would raise a diagnostic.
		@mkdir($pfb['logdir'], 0777, TRUE);
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->resetClientRecords();
	}

	protected function tearDown(): void
	{
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		$this->resetClientRecords();
	}

	private function resetClientRecords(): void
	{
		unset(
			$GLOBALS['pfb_test_xmlrpc_connection'],
			$GLOBALS['pfb_test_xmlrpc_connections'],
			$GLOBALS['pfb_test_xmlrpc_calls']
		);
	}

	/** @return list<array{0:string,1:mixed,2:mixed}> every xmlrpc_method() call, in order */
	private function calls(): array
	{
		return $GLOBALS['pfb_test_xmlrpc_calls'] ?? [];
	}

	/** @return list<string> every peer address the client was pointed at, in order */
	private function dialled(): array
	{
		return array_column($GLOBALS['pfb_test_xmlrpc_connections'] ?? [], 'ip');
	}

	/** @return array<int,array<string,string>> two enabled targets and one disabled */
	private static function targets(): array
	{
		return [
			0 => [
				'varsyncdestinenable' => 'on',
				'varsyncipaddress'    => self::ENABLED_IPS[0],
				'varsyncport'         => '443',
				'varsyncprotocol'     => 'https',
				'varsyncusername'     => 'admin',
				'varsyncpassword'     => 'secret-a',
			],
			1 => [
				'varsyncdestinenable' => 'on',
				'varsyncipaddress'    => self::ENABLED_IPS[1],
				'varsyncport'         => '8443',
				'varsyncprotocol'     => 'http',
				'varsyncusername'     => 'syncuser',
				'varsyncpassword'     => 'secret-b',
			],
			2 => [
				'varsyncdestinenable' => '',
				'varsyncipaddress'    => self::DISABLED_IP,
				'varsyncport'         => '443',
				'varsyncprotocol'     => 'https',
				'varsyncusername'     => 'admin',
				'varsyncpassword'     => 'secret-c',
			],
		];
	}

	/**
	 * Installs $sections as the node's config with a Sync section carrying $scope (omitted for
	 * UNSTORED) and sync mode $mode.
	 *
	 * @param array<string,mixed> $sections
	 */
	private function seed(array $sections, mixed $scope, string $mode): void
	{
		$sync = ['varsynconchanges' => $mode, 'varsynctimeout' => self::TIMEOUT, 'row' => self::targets()];
		if ($scope !== self::UNSTORED) {
			$sync = ['syncscope' => $scope] + $sync;
		}
		$sections['pfblockerngsync'] = ['config' => [0 => $sync]];
		$GLOBALS['config']           = ['installedpackages' => $sections];
		$this->resetClientRecords();
	}

	/**
	 * The disk-shaped fixture (every leaf a string) plus one stored '' policy leaf.
	 *
	 * @return array{sections: array<string,mixed>, policy: array<string,string>, nonpolicy: array<string,string>}
	 */
	private static function node(): array
	{
		$fx = self::diskFixture();
		self::setPath($fx['sections'], ['pfblockerngglobal', 'feed_Empty'], '');
		$policy = [];
		foreach ($fx['policy'] as $path => $value) {
			$policy[$path] = $value;
			if ($path === self::GLOBAL_ROOT . '/feed_alt_Foo') {
				$policy[self::EMPTY_LEAF] = '';
			}
		}
		$fx['policy'] = $policy;
		// The Sync section is replaced by seed(); its fixture leaves never reach the config.
		foreach (array_keys($fx['nonpolicy']) as $path) {
			if (str_starts_with($path, 'installedpackages/pfblockerngsync/')) {
				unset($fx['nonpolicy'][$path]);
			}
		}

		return $fx;
	}

	/** Independent oracle: the payload core ends up with for path => stored-leaf, '' arriving as []. */
	private static function expectedPayload(array $leaves): array
	{
		$payload = [];
		foreach ($leaves as $path => $value) {
			self::setPath($payload, explode('/', $path), $value === '' ? [] : $value);
		}

		return $payload;
	}

	/** @return list<string> */
	private function autoPaths(): array
	{
		return $this->assertNoDiagnostics(static fn (): array => pfblockerng_plugin_xmlrpc_send());
	}

	private function runManual(): void
	{
		$this->assertNoDiagnostics(static function (): void {
			pfblockerng_sync_on_changes();
		});
	}

	/** @return list<array{0:string,1:mixed,2:mixed}> the calls one manual run made */
	private function manualCalls(): array
	{
		$this->runManual();

		return $this->calls();
	}

	/** @return iterable<string,array{0:mixed}> */
	public static function nonSendingScopeProvider(): iterable
	{
		yield 'unstored leaf (registry default alone never sends)' => [self::UNSTORED];
		yield "empty string"                                    => [''];
		yield 'case variant Policy'                              => ['Policy'];
		yield 'trailing space'                                   => ['policy '];
		yield 'unknown token'                                    => ['bogus'];
		yield 'array'                                            => [['policy']];
	}

	/** @return iterable<string,array{0:string}> */
	public static function legacyScopeProvider(): iterable
	{
		yield 'all' => ['all'];
		yield 'lists' => ['lists'];
	}

	// --- automatic transport ---------------------------------------------------

	public function testAutoPolicyReturnsTheGateThenTheProjectionAndMakesNoClientCall(): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], 'policy', 'auto');

		$paths = $this->autoPaths();

		$this->assertSame([self::GATE, ...array_keys($fx['policy'])], $paths, 'gate first, then the projection in order');
		$this->assertSame(1, array_count_values($paths)[self::GATE], 'the gate leaf is listed once');
		$this->assertSame([], array_filter($paths, static fn (string $p): bool => str_ends_with($p, '/varsynconchanges')), 'varsynconchanges never travels');
		$this->assertSame([], $this->calls(), 'the automatic hook hands pfSense a path list and never calls a client');
	}

	#[DataProvider('legacyScopeProvider')]
	public function testAutoLegacyScopesEqualThePreChangePaths(string $scope): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], $scope, 'auto');

		$paths = $this->autoPaths();

		$expected = pfb_test_prechange_plugin_xmlrpc_send($scope === 'lists' ? PfbToggle::On : PfbToggle::Off);
		$this->assertSame($expected, $paths);
		$this->assertCount($scope === 'lists' ? 17 : 20, $paths, 'varsynconchanges plus the 16 or 19 whole sections');
		$this->assertSame(self::SYNC_ROOT . '/varsynconchanges', $paths[0]);
		$this->assertSame($scope === 'all', in_array('installedpackages/pfblockerng', $paths, TRUE), 'only all carries the General section');
		$this->assertNotContains(self::GATE, $paths, 'legacy scopes never carry the gate leaf');
	}

	#[DataProvider('nonSendingScopeProvider')]
	public function testAutoSendsNothingForAnyOtherStoredScope(mixed $scope): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], $scope, 'auto');

		$this->assertSame([], $this->autoPaths());
		$this->assertSame([], $this->calls());
	}

	public function testAutoStaysSilentUnlessChangeSyncIsAuto(): void
	{
		$fx = self::node();
		foreach (['manual', 'disabled', ''] as $mode) {
			$this->seed($fx['sections'], 'policy', $mode);
			$this->assertSame([], $this->autoPaths(), "varsynconchanges '{$mode}' must not return paths");
		}
	}

	// --- manual transport ------------------------------------------------------

	public function testManualPolicySendsRestoreConfigSectionOncePerEnabledTarget(): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], 'policy', 'manual');

		$calls = $this->manualCalls();

		$payload = self::expectedPayload([self::GATE => 'policy'] + $fx['policy']);
		$this->assertSame(
			[['restore_config_section', $payload, 37], ['restore_config_section', $payload, 37]],
			$calls,
			'one restore_config_section per enabled target, the payload itself, the configured timeout'
		);
		$this->assertSame(self::ENABLED_IPS, $this->dialled(), 'the disabled target is never dialled');
		$this->assertSame(['installedpackages'], array_keys($calls[0][1]), 'core strips the installedpackages key itself; the payload is never wrapped again');
		$this->assertArrayNotHasKey('installedpackages', $calls[0][1]['installedpackages']);
		$this->assertSame(1, substr_count(serialize($calls[0][1]), '"syncscope"'), 'the gate leaf travels once');
		$this->assertSame('policy', array_get_path($calls[0][1], self::GATE));
		$this->assertSame('MISSING', array_get_path($calls[0][1], self::SYNC_ROOT . '/varsynconchanges', 'MISSING'));
		$this->assertSame([], array_diff(array_column($calls, 0), ['restore_config_section']), 'no probe, no exec, no merge');
	}

	#[DataProvider('legacyScopeProvider')]
	public function testManualLegacyScopesEqualThePreChangeCalls(string $scope): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], $scope, 'manual');

		$actual = $this->manualCalls();
		$this->assertCount(2, $actual, 'one merge per enabled target');
		$actualDialled = $this->dialled();

		$this->seed($fx['sections'], $scope, 'manual');
		foreach (array_slice(self::targets(), 0, 2) as $t) {
			pfb_test_prechange_do_xmlrpc_sync(
				$t['varsyncipaddress'],
				$t['varsyncport'],
				$t['varsyncprotocol'],
				$t['varsyncusername'],
				$t['varsyncpassword'],
				self::TIMEOUT,
				$scope === 'lists' ? PfbToggle::On : PfbToggle::Off
			);
		}

		$this->assertSame($this->calls(), $actual, 'identical method, payload and timeout per target');
		$this->assertSame($this->dialled(), $actualDialled);
		$this->assertSame('merge_installedpackages_section', $actual[0][0]);
		$this->assertSame(37, $actual[0][2]);
		$this->assertCount($scope === 'lists' ? 16 : 19, $actual[0][1], 'the 16 or 19 whole sections');
		foreach ($actual[0][1] as $section => $blob) {
			$this->assertSame($GLOBALS['config']['installedpackages'][$section], $blob, "{$section} is sent whole");
		}
	}

	#[DataProvider('nonSendingScopeProvider')]
	public function testManualSendsNothingForAnyOtherStoredScope(mixed $scope): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], $scope, 'manual');

		$this->assertSame([], $this->manualCalls());
		$this->assertSame([], $this->dialled(), 'no client is even pointed at a peer');
	}

	/** @return iterable<string,array{0:string,1:string}> scope => the per-target status line format */
	public static function statusLineProvider(): iterable
	{
		yield 'policy: core returns true whatever the peer did' => ['policy', 'XMLRPC policy sync to [ %s ] sent, acceptance unconfirmed.'];
		yield 'all: the legacy line, byte-exact'                  => ['all', 'XMLRPC sync to [ %s ] completed successfully.'];
		yield 'lists: the legacy line, byte-exact'                => ['lists', 'XMLRPC sync to [ %s ] completed successfully.'];
	}

	#[DataProvider('statusLineProvider')]
	public function testManualSyncStatusLineNeverClaimsPolicyAcceptance(string $scope, string $format): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], $scope, 'manual');
		$GLOBALS['pfb_test_logger_calls'] = [];

		$this->runManual();

		$lines = array_values(array_filter(
			array_column($GLOBALS['pfb_test_logger_calls'], 'message'),
			static fn (string $message): bool => str_contains($message, ' sync to [ ')
		));
		$this->assertSame([sprintf($format, self::ENABLED_IPS[0] . ':443'), sprintf($format, self::ENABLED_IPS[1] . ':8443')], $lines);
	}

	// --- both transports derive from one path list ------------------------------

	public function testCoreDefaultBranchOverTheAutoPathsBuildsTheManualPayload(): void
	{
		$fx = self::node();

		$this->seed($fx['sections'], 'policy', 'auto');
		$paths      = $this->autoPaths();
		$configCopy = $GLOBALS['config'];
		$xml        = [];
		foreach ($paths as $path) {
			array_set_path($xml, $path, array_get_path($configCopy, $path, []));
		}

		$this->seed($fx['sections'], 'policy', 'manual');
		$manual = $this->manualCalls()[0][1];

		$this->assertSame($manual, $xml, 'both transports put the same array on the wire');
		$this->assertContains(self::EMPTY_LEAF, $paths, 'a stored empty string is listed');
		$this->assertSame([], array_get_path($xml, self::EMPTY_LEAF, 'MISSING'), 'and arrives as an empty array');
		$this->assertNotContains(self::ABSENT_LEAF, $paths, 'an absent key has no path');
		$this->assertSame('MISSING', array_get_path($manual, self::ABSENT_LEAF, 'MISSING'));
	}

	public function testManualBuilderNormalizesInMemoryLeavesAsWriteConfigPersistsThem(): void
	{
		$memory = ['pfblockerngglobal' => [
			'feed_True'  => TRUE,
			'feed_False' => FALSE,
			'feed_Int'   => 7,
			'feed_Float' => 1.5,
			'feed_Empty' => '',
			'feed_Arr'   => [],
			'feed_Str'   => 'x',
		]];
		$persisted = ['pfblockerngglobal' => [
			'feed_True'  => '',
			'feed_Int'   => '7',
			'feed_Float' => '1.5',
			'feed_Empty' => '',
			'feed_Arr'   => [],
			'feed_Str'   => 'x',
		]];

		$this->seed($memory, 'policy', 'manual');
		$fromMemory = $this->manualCalls();
		$this->assertSame(FALSE, $GLOBALS['config']['installedpackages']['pfblockerngglobal']['feed_False'], 'the sender\'s own configuration is not rewritten');
		$this->assertSame(TRUE, $GLOBALS['config']['installedpackages']['pfblockerngglobal']['feed_True']);

		$this->seed($persisted, 'policy', 'manual');
		$fromPersisted = $this->manualCalls();

		$this->assertSame($fromPersisted, $fromMemory, 'the in-memory configuration sends what its persisted form would');
		$this->assertSame(
			[
				'pfblockerngsync'   => ['config' => [0 => ['syncscope' => 'policy']]],
				'pfblockerngglobal' => [
					'feed_True'  => [],
					'feed_Int'   => '7',
					'feed_Float' => '1.5',
					'feed_Empty' => [],
					'feed_Arr'   => [],
					'feed_Str'   => 'x',
				],
			],
			$fromMemory[0][1]['installedpackages'],
			'true and the empty string arrive as [], false is omitted, other scalars are strings'
		);
	}

	// --- what never leaves the node ----------------------------------------------

	public function testCredentialsAndLocalLeavesNeverTravelButAFeedUrlKeyDoes(): void
	{
		$fx = self::node();
		$this->assertNotEmpty($fx['nonpolicy'], 'vacuity guard: the fixture holds non-policy leaves');
		$fixtureText = serialize($fx['sections']);

		$sentinels = array_values(self::credentialValues());
		foreach (self::blacklistCredentials() as [$user, $pass]) {
			array_push($sentinels, $user, $pass);
		}
		$this->assertCount(8, $sentinels, 'the four registry credentials plus two Blacklist rows of username and password');
		foreach (array_merge($sentinels, array_values($fx['nonpolicy'])) as $needle) {
			$this->assertStringContainsString($needle, $fixtureText, "vacuity guard: the fixture holds {$needle}");
		}

		$this->seed($fx['sections'], 'policy', 'auto');
		$paths = $this->autoPaths();
		$this->seed($fx['sections'], 'policy', 'manual');
		$payload = $this->manualCalls()[0][1];
		$wire    = serialize($payload);

		foreach (array_keys($fx['nonpolicy']) as $path) {
			$this->assertNotContains($path, $paths, "{$path} must not be an automatic path");
			$this->assertSame('MISSING', array_get_path($payload, $path, 'MISSING'), "{$path} must not be in the payload");
		}
		foreach (array_merge($sentinels, array_values($fx['nonpolicy'])) as $needle) {
			$this->assertStringNotContainsString($needle, $wire, "{$needle} leaked into the manual payload");
			$this->assertSame([], array_filter($paths, static fn (string $p): bool => str_contains($p, $needle)), "{$needle} leaked into the paths");
		}

		$this->assertContains(self::EMBEDDED_KEY_PATH, $paths, 'a feed URL embedding a key stays list policy');
		$this->assertStringContainsString(self::EMBEDDED_KEY_VALUE, $wire);
	}

	// --- receivers released before this change ----------------------------------------

	public function testReleasedReceiveHookIgnoresThePolicyPayload(): void
	{
		$fx = self::node();
		$this->seed($fx['sections'], 'policy', 'manual');
		$call    = $this->manualCalls()[0];
		$payload = $call[1];
		$this->assertSame('restore_config_section', $call[0], 'vacuity guard: the payload under test is the policy payload');
		$this->assertSame('policy', array_get_path($payload, self::GATE), 'vacuity guard: it carries the gate leaf');

		$legacy = ['installedpackages' => [
			'pfblockerngsync'   => ['config' => [0 => ['varsynconchanges' => 'auto']]],
			'pfblockerngglobal' => ['feed_Foo' => 'changed on the sender'],
		]];
		$live = pfb_test_released_plugin_xmlrpc_recv($legacy);
		$this->assertTrue($live['xmlrpc_recv_result'] ?? NULL, 'vacuity guard: the released hook applies a legacy auto payload');

		$this->assertSame([], pfb_test_released_plugin_xmlrpc_recv($payload));
	}
}
