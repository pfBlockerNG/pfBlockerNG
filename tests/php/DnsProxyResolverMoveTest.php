<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the experimental DNS proxy takes the Resolver's client-facing place, so
 * pfb_dns_proxy_resolver() moves the Resolver onto loopback (its port stays 53: the firewall resolves through the
 * proxy, which takes that port on loopback too) and adds a marked server clause to custom_options that moves
 * Unbound's own listener to loopback port 5354 (plain, unused) and has it listen on 127.0.0.1 and ::1 port 5353 for
 * the proxy's PROXYv2 stream. It remembers every key it changed (presence AND value) in the
 * registered marker dns/pfb_dns_saved; turning it off restores them exactly. pfb_dns_proxy_saved() is
 * the strict reader of that marker: anything but the documented shape is "no snapshot".
 *
 * The moved Resolver is the persistent outcome (config.xml): these tests assert the config
 * after each call, never the mechanics of how it got there.
 */
final class DnsProxyResolverMoveTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const KEYS  = ['active_interface', 'enablessl', 'custom_options'];
	private const MARKER = '# pfBlockerNG DNS proxy';
	/** The Python side's copy of the clause (tests/dns_proxy checks Unbound against the same file): one source of truth. */
	private const BLOCK_FIXTURE = __DIR__ . '/../dns_proxy/fixtures/resolver_clause.conf';
	/** The stored form of an older block of ours: the same lines with an IPv6 grant that is no longer current. */
	private const STALE_BLOCK = "server:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
		. "proxy-protocol-port: 5353\naccess-control: 2001:db8::/64 allow\n# end pfBlockerNG DNS proxy";
	/** The block as releases before the loopback front end wrote it: no `port:` line, so Unbound stayed on the Listen Port. */
	private const LEGACY_BLOCK = "server:\n# pfBlockerNG DNS proxy\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
		. "proxy-protocol-port: 5353\n# end pfBlockerNG DNS proxy";

	/** The clause the move appends when the Resolver has no IPv6 subnet to grant: the fixture's text without its final newline. */
	private static function block(): string
	{
		$text = (string) file_get_contents(self::BLOCK_FIXTURE);
		self::assertStringEndsWith("\n", $text, 'the fixture ends with one newline');
		return substr($text, 0, -1);
	}

	private string $tmp;
	private bool $hadPfb = FALSE;
	private bool $hadConfig = FALSE;
	private array $originalPfb = [];
	private array $originalConfig = [];
	private array $originalInterfaceIp = [];
	private bool $hadInterfaceIp = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$this->hadInterfaceIp = array_key_exists('pfb_test_interface_ip', $GLOBALS);
		$this->originalInterfaceIp = $GLOBALS['pfb_test_interface_ip'] ?? [];
		$GLOBALS['pfb_test_interface_ip'] = ['lo0' => '127.0.0.1'];
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_proxy_move_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'logdir' => $this->tmp,
			'log'    => "{$this->tmp}/pfb.log",
			'errlog' => "{$this->tmp}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadInterfaceIp) {
			$GLOBALS['pfb_test_interface_ip'] = $this->originalInterfaceIp;
		} else {
			unset($GLOBALS['pfb_test_interface_ip']);
		}
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_write_config_hook'],
			$GLOBALS['pfb_test_write_config_result'], $GLOBALS['pfb_test_config_read_hook'], $GLOBALS['pfb_test_config_read_calls'],
			$GLOBALS['pfb_test_config_read_lock_held'], $GLOBALS['pfb_test_lock_held']);
		rmdir_recursive($this->tmp);
	}

	/**
	 * The Resolver as pfSense stores it: unrelated keys (they must never be touched) plus the
	 * keys the move owns. A NULL override deletes the key, so "absent" is a real state.
	 *
	 * @param  array<string,?string> $override
	 * @return array<string,string> the seeded `unbound` array
	 */
	private function seedResolver(array $override = []): array
	{
		$unbound = [
			'enable'           => '',
			'dnssec'           => '',
			'sslcertref'       => 'cert123',
			'tlsport'          => '853',
			'port'             => '53',
			'active_interface' => 'lan,opt1',
			'enablessl'        => '',
			'custom_options'   => base64_encode("do-ip6: no\nprefetch: yes"),
		];
		foreach ($override as $key => $value) {
			if ($value === NULL) {
				unset($unbound[$key]);
			} else {
				$unbound[$key] = $value;
			}
		}
		$GLOBALS['config']['unbound'] = $unbound;
		return $unbound;
	}

	/** @param array<string,mixed> $unbound */
	private static function sorted(array $unbound): array
	{
		ksort($unbound);
		return $unbound;
	}

	private function writeCalls(): int
	{
		return count($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	/** The marker as stored (raw leaf: the on-disk location is part of the contract), '' when absent. */
	private function savedRaw(): string
	{
		return (string) config_get_path(self::SAVED, '');
	}

	private function errorLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['errlog']);
	}

	/** The marker's stored form for a given per-key map, exactly as the contract documents it. */
	private static function snapshotOf(array $keys): string
	{
		return base64_encode((string) json_encode($keys));
	}

	/** @return list<string> custom_options decoded to its lines */
	private function customLines(): array
	{
		return explode("\n", (string) base64_decode((string) config_get_path('unbound/custom_options'), TRUE));
	}

	private function markerCount(): int
	{
		return count(array_filter($this->customLines(), static fn (string $l): bool => trim($l) === self::MARKER));
	}

	/**
	 * The Unbound clause (`server`, `forward-zone`, ...) our marker sits in, NULL when absent. pfSense 2.8.1
	 * writes custom_options after its Forwarding block, so the text starts inside that `forward-zone:` clause (live
	 * run, unbound.conf:105: a bare option there is a syntax error). A bare `name:` line holds a value;
	 * only a line that ends at its colon opens a clause.
	 */
	private function markerClause(): ?string
	{
		$clause = 'forward-zone';
		foreach ($this->customLines() as $line) {
			if (preg_match('/^\s*([a-z][a-z-]*):\s*$/', $line, $m)) {
				$clause = $m[1];
			} elseif (trim($line) === self::MARKER) {
				return $clause;
			}
		}
		return NULL;
	}

	/** @return array<string,array{0:string,1:?string}> key => [name, value]; NULL = absent */
	public static function resolverShapes(): array
	{
		$cases = [];
		$values = [
			'active_interface' => ['lan,opt1', 'all', ''],
			'enablessl'        => ['', 'yes'],
			'custom_options'   => [base64_encode("do-ip6: no\nprefetch: yes"), ''],
		];
		foreach ($values as $key => $list) {
			foreach ($list as $value) {
				$cases["{$key} present " . var_export($value, TRUE)] = [$key, $value];
			}
			$cases["{$key} absent"] = [$key, NULL];
		}
		return $cases;
	}

	public function testAnIpv6OnlyHostDoesNotAskUnboundToBindTheMissingIpv4Loopback(): void
	{
		$this->seedResolver(['custom_options' => '']);
		$GLOBALS['pfb_test_interface_ip']['lo0'] = NULL;
		$this->assertSame('', $this->savedRaw(), 'before: native Resolver with no saved move');

		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		$this->assertContains('interface: ::1@5353', $this->customLines(), 'the backend is reachable on IPv6 loopback');
		$this->assertNotContains('interface: 127.0.0.1@5353', $this->customLines(), 'Unbound must not bind an address absent from lo0');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the original Resolver remains available for rollback');
	}

	// -----------------------------------------------------------------------
	// M1 / M5 -- move on, move off: the Resolver round-trips exactly
	// -----------------------------------------------------------------------

	#[DataProvider('resolverShapes')]
	public function testMoveOnRecordsEachKeyExactlyAsItWasPresentOrAbsentAndMovesTheResolverOntoLoopback(string $key, ?string $value): void
	{
		// Given a Resolver whose $key is in this shape, still on its own interfaces.
		$before = $this->seedResolver([$key => $value]);
		$this->assertNotSame('lo0', config_get_path('unbound/active_interface'), 'before: the Resolver is not moved');
		$this->assertSame('', $this->savedRaw(), 'before: no snapshot');

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then it reports a config change, written once, with a snapshot of exactly the keys it changes.
		$this->assertTrue($changed);
		$this->assertSame(1, $this->writeCalls(), 'one write_config for the whole move');
		$saved = pfb_dns_proxy_saved();
		$this->assertIsArray($saved);
		$this->assertSame(self::KEYS, array_keys($saved));
		foreach (self::KEYS as $k) {
			$expected = array_key_exists($k, $before)
				? ['present' => TRUE, 'value' => $before[$k]]
				: ['present' => FALSE, 'value' => NULL];
			$this->assertSame($expected, $saved[$k], "snapshot of {$k}");
		}

		// And the Resolver sits on loopback, without DoT, with our marked block inside a server clause.
		$after = config_get_path('unbound');
		$this->assertSame('lo0', $after['active_interface']);
		$this->assertArrayNotHasKey('enablessl', $after);
		$this->assertSame('server', $this->markerClause());
		$this->assertSame(1, $this->markerCount());
		foreach (['enable', 'dnssec', 'sslcertref', 'tlsport', 'port'] as $untouched) {
			$this->assertSame($before[$untouched], $after[$untouched], "{$untouched} is not the move's to change");
		}
	}

	/** @return array<string,array{0:?string}> the Resolver's listen port as the user left it */
	public static function listenPorts(): array
	{
		return [
			'the default 53'                  => ['53'],
			'an own port'                     => ['5300'],
			'one below the proxy port'        => ['5352'],
			'one above the plain port'        => ['5355'],
			'a longer port starting with it'  => ['53530'],
			'a longer port starting with 5354' => ['53540'],
			'empty'                           => [''],
			'absent'                          => [NULL],
		];
	}

	#[DataProvider('listenPorts')]
	public function testTheListenPortIsNeverChangedByTheMoveOrTheRestore(?string $port): void
	{
		// Given a Resolver with this listen port: the firewall's own resolver entry (127.0.0.1) needs it to stay.
		$this->seedResolver(['port' => $port]);
		$had = config_get_path('unbound/port', 'ABSENT');

		// When the proxy is turned on, then off again.
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$this->assertSame($had, config_get_path('unbound/port', 'ABSENT'), 'moved: the listen port is as it was');
		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));

		// Then it is still as it was.
		$this->assertSame($had, config_get_path('unbound/port', 'ABSENT'), 'restored: the listen port is as it was');
	}

	#[DataProvider('resolverShapes')]
	public function testMoveOffRestoresTheResolverByteForByteAndClearsTheSnapshot(string $key, ?string $value): void
	{
		// Given a Resolver moved by the proxy (its before-state kept for comparison).
		$before = $this->seedResolver([$key => $value]);
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$this->assertNotSame($before, config_get_path('unbound'), 'before: the move changed the Resolver');
		$this->assertNotSame('', $this->savedRaw(), 'before: a snapshot exists');

		// When the proxy is turned off.
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then every key is back as it was -- absent stays absent -- and the marker is cleared.
		$this->assertTrue($changed);
		$this->assertSame(2, $this->writeCalls(), 'one write_config per call');
		$this->assertSame(self::sorted($before), self::sorted(config_get_path('unbound')));
		$this->assertSame('', $this->savedRaw());
		$this->assertNull(pfb_dns_proxy_saved());
	}

	// -----------------------------------------------------------------------
	// M2 / M3 -- idempotent, and re-applied after drift without re-snapshotting
	// -----------------------------------------------------------------------

	public function testMoveOnTwiceChangesNothingTheSecondTime(): void
	{
		// Given a moved Resolver with its snapshot.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$snapshot = config_get_path(self::SAVED);
		$unbound = config_get_path('unbound');
		$this->assertSame(1, $this->writeCalls());

		// When it is applied again.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing is written and nothing differs.
		$this->assertFalse($changed);
		$this->assertSame(1, $this->writeCalls(), 'no second write_config');
		$this->assertSame($snapshot, config_get_path(self::SAVED), 'snapshot byte-identical');
		$this->assertSame($unbound, config_get_path('unbound'));
	}

	/** @return array<string,array{0:string,1:string}> drifted key => value a user could set */
	public static function drifts(): array
	{
		return [
			'interfaces back to a LAN'    => ['unbound/active_interface', 'lan'],
			'DoT switched back on'        => ['unbound/enablessl', ''],
			'our block removed'           => ['unbound/custom_options', base64_encode("do-ip6: no\nprefetch: yes")],
		];
	}

	#[DataProvider('drifts')]
	public function testMoveOnReappliesADriftedKeyAndKeepsTheOriginalSnapshot(string $path, string $drifted): void
	{
		// Given a moved Resolver whose snapshot holds the pre-toggle values.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$snapshot = config_get_path(self::SAVED);
		$moved = config_get_path('unbound');

		// When a user edits the Resolver page and the proxy is applied again.
		config_set_path($path, $drifted);
		$this->assertNotSame($moved, config_get_path('unbound'), 'before: the Resolver drifted');
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the moved values are back, and the snapshot is NOT replaced by the drifted values.
		$this->assertTrue($changed);
		$this->assertSame(1, $this->markerCount(), 'one block, never two');
		$this->assertSame($snapshot, config_get_path(self::SAVED));
		$this->assertSame(2, $this->writeCalls());
	}

	// -----------------------------------------------------------------------
	// M4 -- never save moved values as the "previous" ones; a refused move is announced
	// -----------------------------------------------------------------------

	public function testMoveOnRefusesWhenTheResolverAlreadyCarriesOurBlockAndNoSnapshotExists(): void
	{
		// Given a Resolver carrying our block, on loopback, with no snapshot (the snapshot was lost).
		$this->seedResolver([
			'active_interface' => 'lo0',
			'enablessl'        => NULL,
			'custom_options'   => base64_encode("do-ip6: no\nprefetch: yes\n" . self::block()),
		]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then it changes nothing and says why, instead of recording the moved values ...
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertStringContainsString('refusing to snapshot', $this->errorLog());

		// ... and tells the operator that pfB-DNS is not active and the Resolver unchanged (nothing is lost: DNSBL, when it is on,
		// stays in the Resolver; this move runs with DNSBL off, so the notice claims none)
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('DNS proxy', $notice['notice']);
		$this->assertStringContainsString('pfB-DNS is not active', $notice['notice'], 'it says the takeover did not happen');
		$this->assertStringNotContainsString('DNSBL', $notice['notice'], 'DNSBL is off here: no claim about it');
		$this->assertSame('/services_unbound.php', $notice['url'], 'it points at the Resolver page');
		$this->assertSame(2, $notice['priority']);
	}

	/** @return array<string,array{0:string}> a stored marker that is no snapshot: the malformed shapes, plus what a truthiness test or a short read would let through */
	public static function unusableMarkers(): array
	{
		$valid = self::snapshotOf(self::validSnapshot());
		return self::malformedSnapshots() + [
			'the single character 0'                   => ['0'],
			'the text of an interrupted write'         => ['!!!truncated-snapshot!!!'],
			'a snapshot cut off inside its JSON'       => [substr($valid, 0, 40)],
			'a snapshot cut off inside a base64 group' => [substr($valid, 0, 41)],
		];
	}

	/** @return array<string,array{0:string,1:array<string,string>}> each unusable marker on a Resolver on loopback and on one still on its own interfaces */
	public static function unusableMarkersOnEveryResolver(): array
	{
		$rows = [];
		foreach (self::unusableMarkers() as $name => [$marker]) {
			$rows["{$name}, Resolver on loopback"] = [$marker, ['active_interface' => 'lo0']];
			$rows["{$name}, Resolver on its own interfaces"] = [$marker, []];
		}
		return $rows;
	}

	#[DataProvider('unusableMarkersOnEveryResolver')]
	public function testMoveOnRefusesAStoredMarkerThatIsNoSnapshotAndKeepsItAndTheResolverAsTheyAre(string $marker, array $resolver): void
	{
		// Given a stored marker nothing can read as a snapshot and no block of ours in Custom Options: whether an earlier
		// takeover already moved this Resolver is unknown, and the marker is the only evidence of what it was.
		$this->seedResolver($resolver);
		config_set_path(self::SAVED, $marker);
		$config = $GLOBALS['config'];
		$this->assertNull(pfb_dns_proxy_saved(), 'before: the marker is no snapshot');
		$this->assertFalse(pfb_dns_proxy_block_present(), 'before: no block of ours');

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the move is refused and nothing is written: the marker, every Resolver key and Custom Options are as they were,
		// and the Resolver as it stands is not recorded as the previous one.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($marker, $this->savedRaw(), 'the stored marker is kept verbatim');
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertNull(pfb_dns_proxy_saved(), 'no snapshot was invented from the current Resolver');

		// ... and the operator is told that pfB-DNS is not active and recovery is required, never that anything was restored.
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('pfB-DNS is not active', $notice['notice']);
		$this->assertStringContainsString('recovery is required', $notice['notice']);
		$this->assertStringNotContainsString('restored', $notice['notice']);
		$this->assertStringContainsString('cannot be confirmed', $notice['notice'], 'it says what the Resolver was before cannot be told');
		$this->assertStringContainsString('manual repair is required', $notice['notice']);
		$this->assertStringNotContainsString('still carries', $notice['notice'], 'and never that the Resolver carries our settings');
		$this->assertSame('/services_unbound.php', $notice['url']);
		$this->assertSame(2, $notice['priority']);
	}

	/** @return array<string,array{0:?string}> a marker with nothing in it: never stored, or stored empty (the normal state) */
	public static function emptyMarkers(): array
	{
		return ['no marker stored' => [NULL], 'an empty marker' => ['']];
	}

	#[DataProvider('emptyMarkers')]
	public function testMoveOnStillTakesALoopbackOnlyResolverThatWasNeverFrontedWhoseMarkerIsEmpty(?string $marker): void
	{
		// Given a Resolver that has always sat on loopback (an earlier takeover never touched it): no block, an empty marker.
		$this->seedResolver(['active_interface' => 'lo0']);
		if ($marker !== NULL) {
			config_set_path(self::SAVED, $marker);
		}
		$this->assertNull(pfb_dns_proxy_saved(), 'before: no snapshot');

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the move goes ahead and records loopback as what the Resolver was: loopback alone is no evidence of an earlier move.
		$this->assertTrue($changed);
		$this->assertSame(['present' => TRUE, 'value' => 'lo0'], pfb_dns_proxy_saved()['active_interface']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testMoveOnWithOurBlockAndAMarkerThatIsNoSnapshotKeepsTheBlockRefusal(): void
	{
		// Given our complete block on a Resolver on loopback, and a stored marker that is no snapshot.
		$this->seedResolver([
			'active_interface' => 'lo0',
			'enablessl'        => NULL,
			'custom_options'   => base64_encode("do-ip6: no\nprefetch: yes\n" . self::block()),
		]);
		config_set_path(self::SAVED, '!!!not-a-snapshot!!!');
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then it is the block's refusal that answers, with nothing written and the marker kept for a hand recovery.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertStringContainsString('refusing to snapshot the moved values', $this->errorLog());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertStringContainsString('recovery is required', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	public function testMoveOnSnapshotsAResolverThatOnlyHalfLooksMoved(): void
	{
		// Given the admin's own loopback Resolver, with their own PROXYv2 line but without our marked block.
		$this->seedResolver([
			'active_interface' => 'lo0',
			'custom_options'   => base64_encode("server:\nproxy-protocol-port: 5353"),
		]);

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the user's values are recorded and our block is added after their text. The Resolver was already on loopback, so
		// pfSense's own automatic size for it was the loopback one (16316), and the block carries exactly that, not the LAN's 1432.
		$this->assertTrue($changed);
		$this->assertSame(['present' => TRUE, 'value' => 'lo0'], pfb_dns_proxy_saved()['active_interface']);
		$this->assertSame("server:\nproxy-protocol-port: 5353\n" . str_replace('edns-buffer-size: 1432', 'edns-buffer-size: 16316', self::block()),
			implode("\n", $this->customLines()));
		$this->assertSame('', $this->errorLog());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	/** @return array<string,array{array<string,mixed>}> */
	public static function unrepresentableResolvers(): array
	{
		return [
			'a non-scalar DoT flag'                => [['enablessl' => ['x']]],
			'a non-UTF-8 interface list'           => [['active_interface' => "lan\xff"]],
		];
	}

	#[DataProvider('unrepresentableResolvers')]
	public function testMoveOnRefusesAValueThatCannotBeStoredVerbatimAndTellsTheOperator(array $override): void
	{
		// Given a Resolver key whose value a JSON snapshot could not restore as it was.
		$this->seedResolver($override);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then it refuses rather than moving a Resolver it could not restore, and says so in a notice.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertStringContainsString('pfb_dns_saved', $this->errorLog());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$this->assertStringContainsString('pfB-DNS is not active', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	public function testAMoveThatSucceedsRaisesNoNotice(): void
	{
		$this->seedResolver();

		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	// -----------------------------------------------------------------------
	// Port 5353 -- our clause binds it on loopback, and Unbound cannot bind it twice
	// -----------------------------------------------------------------------

	public function testMoveOnRefusesWhenTheListenPortIsTheProxysLoopbackPortAndNamesTheListenPort(): void
	{
		// Given a Resolver whose Listen Port is 5353: our clause would bind 127.0.0.1 and ::1 on it a second time,
		// which makes Unbound exit at start (live: "address already in use").
		$this->seedResolver(['port' => '5353']);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing moves and no snapshot is kept ...
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);

		// ... and the operator is told which setting to change, and that nothing was taken over.
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('Listen Port', $notice['notice']);
		$this->assertStringContainsString('5353', $notice['notice']);
		$this->assertStringContainsString('pfB-DNS is not active', $notice['notice']);
		$this->assertSame('/services_unbound.php', $notice['url']);
		$this->assertStringContainsString('Listen Port', $this->errorLog());
	}

	public function testARefusalThatRepeatsOnEveryApplyRaisesOneNoticeNotOnePerApply(): void
	{
		// Given a Resolver whose Listen Port is 5353: every apply and cron tick refuses the move again
		$this->seedResolver(['port' => '5353']);

		// When three applies run
		pfb_dns_proxy_resolver(TRUE);
		pfb_dns_proxy_resolver(TRUE);
		pfb_dns_proxy_resolver(TRUE);

		// Then the operator is told once: the notice stays pending until it is closed, so a repeat adds nothing
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the same refusal is one notice');
	}

	public function testMoveOnSignalsAMovedResolverWhoseListenPortWasLaterSetToTheProxysLoopbackPort(): void
	{
		// Given a moved Resolver, then an admin who sets its Listen Port to 5353 on the Resolver page.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		config_set_path('unbound/port', '5353');
		$config = $GLOBALS['config'];
		$writes = $this->writeCalls();

		// When the proxy is applied again.
		$unsafe = NULL;
		$changed = pfb_dns_proxy_resolver(TRUE, $unsafe);

		// Then nothing changes, the setting is named for the caller's rollback, and no notice is raised here: a notice would
		// say the proxy keeps serving the Resolver, which the rollback that follows ends
		$this->assertFalse($changed);
		$this->assertSame('Listen Port 5353', $unsafe);
		$this->assertSame($writes, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	/** @return array<string,array{0:string}> the loopback ports our clause owns: 5353 (PROXYv2) and 5354 (Unbound's plain listener) */
	public static function ownedPorts(): array
	{
		return ['the PROXYv2 port' => ['5353'], 'the plain listener port' => ['5354']];
	}

	#[DataProvider('ownedPorts')]
	public function testMoveOnRefusesEitherOfTheClausesLoopbackPortsAsTheListenPortAndNamesIt(string $port): void
	{
		// Given a Resolver whose Listen Port is one of the two loopback ports our clause gives Unbound: the proxy
		// would need that port for the firewall's own lookups on loopback.
		$this->seedResolver(['port' => $port]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing moves, and the notice names the Listen Port and the port to change.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertStringContainsString('Listen Port', $GLOBALS['pfb_test_file_notices'][0]['notice']);
		$this->assertStringContainsString($port, $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	#[DataProvider('ownedPorts')]
	public function testMoveOnSignalsAMovedResolverWhoseListenPortWasLaterSetToOneOfThem(string $port): void
	{
		// Given a moved Resolver, then an admin who sets its Listen Port to that port on the Resolver page.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		config_set_path('unbound/port', $port);
		$config = $GLOBALS['config'];
		$writes = $this->writeCalls();

		// When the proxy is applied again.
		$unsafe = NULL;
		$changed = pfb_dns_proxy_resolver(TRUE, $unsafe);

		// Then nothing changes, and the setting is named for the caller's rollback instead of a notice
		$this->assertFalse($changed);
		$this->assertSame("Listen Port {$port}", $unsafe);
		$this->assertSame($writes, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}


	/** @return array<string,array{0:string}> the admin's own `interface:` directives, wherever they sit and on whatever address or port: each is refused */
	public static function userInterfaceLines(): array
	{
		return [
			'IPv4 loopback on the proxy port'             => ["server:\ninterface: 127.0.0.1@5353"],
			'IPv6 loopback on the proxy port'             => ["server:\ninterface: ::1@5353\n"],
			'indented, with a comment'                    => ["server:\n  interface:   127.0.0.1@5353   # my own\nprefetch: yes"],
			'quoted'                                      => ["server:\ninterface: \"::1@5353\""],
			'CRLF line endings'                           => ["server:\r\ninterface: 127.0.0.1@5353\r\n"],
			'IPv4 loopback on the plain port'             => ["server:\ninterface: 127.0.0.1@5354"],
			'IPv6 loopback on the plain port'             => ["server:\ninterface: ::1@5354\n"],
			'quoted, plain port, with a comment'          => ["server:\ninterface: \"127.0.0.1@5354\"   # mine"],
			'expanded loopback on the proxy port'         => ["server:\ninterface: 127.0.0.2@5353"],
			'IPv4 wildcard on the proxy port'             => ["server:\ninterface: 0.0.0.0@5353"],
			'IPv6 wildcard on the proxy port'             => ["server:\ninterface: ::@5353"],
			'LAN address on the proxy port'               => ["server:\ninterface: 192.0.2.1@5353"],
			'scoped IPv6 address on the proxy port'       => ["server:\ninterface: fe80::1%em0@5353"],
			'IPv4 wildcard on the Listen Port'            => ["server:\ninterface: 0.0.0.0@53"],
			'LAN address on the Listen Port'              => ["server:\ninterface: 192.0.2.1@53"],
			'LAN address on a non-reserved port'          => ["server:\ninterface: 192.0.2.1@8053"],
			'loopback on a non-reserved port'             => ["server:\ninterface: 127.0.0.1@5300"],
			'wildcard without a port'                     => ["server:\ninterface: 0.0.0.0"],
			'interface-automatic'                         => ["server:\ninterface-automatic: yes"],
			'interface-automatic-ports on the proxy port' => ["server:\ninterface-automatic-ports: 5353"],
			'after another directive on the same line'    => ["prefetch: yes interface: 0.0.0.0@53"],
			'after a lone CR'                             => ["server:\rinterface: 0.0.0.0@53"],
			'an interface after a quoted hash'                  => ["server:\nlog-identity: \"#\" interface: 0.0.0.0@5300"],
			'an interface after a hash inside a word'           => ["server:\nlog-identity: a#b interface: 0.0.0.0@5300"],
			'an interface after a single-quoted hash'           => ["server:\nlog-identity: '#' interface: 0.0.0.0@5300"],
			'an interface after an escaped quote inside quotes' => ["server:\nlog-identity: \"a\\\" # \" interface: 0.0.0.0@5300"],
			'an interface after a quoted phrase with a spaced hash' => ["server:\nlog-identity: \"a #\" interface: 10.0.0.1@53"],
			'an interface after a directive on its line'        => ["server:\nprefetch: yes interface: 0.0.0.0@5300"],
			'an outgoing-interface line (refused too: every interface key is)' => ["server:\noutgoing-interface: 192.0.2.1"],
			'the admin\'s control-interface'                    => ["remote-control:\n    control-enable: no\n    control-interface: 127.0.0.1"],
		];
	}

	#[DataProvider('userInterfaceLines')]
	public function testMoveOnRefusesEveryInterfaceDirectiveOfTheAdminsOwnAndChangesNothing(string $custom): void
	{
		// Given Custom options of the admin's own with an interface directive. Unbound's listen addresses come from
		// Network Interfaces and ours from the proxy, so a line of the admin's can take a reserved port or a LAN address.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing moves (no snapshot, no write, the Resolver as it was) and the notice says where to fix it.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('Custom Options', $notice['notice']);
		$this->assertStringContainsString('interface:', $notice['notice']);
		$this->assertStringContainsString('Network Interfaces', $notice['notice']);
		$this->assertSame('/services_unbound.php', $notice['url']);
	}

	/** @return array<string,array{0:string}> the admin's own `port:` lines: our clause's `port:` would override or be overridden by them */
	public static function userPortLines(): array
	{
		return [
			'plain'                    => ["server:\nport: 5300"],
			'indented, with a comment' => ["server:\n  port:   53   # mine\nprefetch: yes"],
			'no space after the colon' => ["server:\nport:5300\n"],
			'CRLF line endings'        => ["server:\r\nport: 5300\r\n"],
			'a tab after the colon'    => ["server:\nport:\t5300"],
			'the admin\'s tls-port'    => ["server:\ntls-port: 8530"],
			'the admin\'s https-port'  => ["server:\nhttps-port: 8443"],
			'a port after a directive on its line'        => ["server:\nprefetch: yes port: 5300"],
			'a port after the clause name'                => ["server: port: 5300"],
			'a port after a quoted hash'                  => ["server:\nlog-identity: \"#\" port: 5300"],
			'a port after a hash inside a word'           => ["server:\nlog-identity: a#b port: 5300"],
			'a port after an escaped space and a hash'    => ["server:\nlog-identity: a\\ #x port: 5300"],
			'a port after a single-quoted hash'           => ["server:\nlog-identity: '#' port: 5300"],
			'a port after an escaped quote inside quotes' => ["server:\nlog-identity: \"a\\\" # \" port: 5300"],
			'a port after an escaped single quote'        => ["server:\nlog-identity: 'a\\' # x' port: 5300"],
			'a port key after another option (Unbound rejects the line)' => ["server:\nlog-identity: port: 53"],
		];
	}

	#[DataProvider('userPortLines')]
	public function testMoveOnRefusesWhenTheAdminsOwnCustomOptionsSetPort(string $custom): void
	{
		// Given Custom options that set `port:` themselves, outside our block.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing moves and the notice names the Custom options and the line to remove.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('Custom Options', $notice['notice']);
		$this->assertStringContainsString('port:', $notice['notice']);
		$this->assertSame('/services_unbound.php', $notice['url']);
	}

	/** @return array<string,array{0:string}> the admin's own `port:`, `interface:` and `include:` lines, each appended after our block once it was written */
	public static function unsafeLinesAddedAfterTheMove(): array
	{
		return [
			'a port line'                    => ['port: 5300'],
			'an interface on the proxy port' => ['interface: ::1@5353'],
			'an interface on the Listen Port' => ['interface: 0.0.0.0@53'],
			'an include'                     => ['include: /tmp/extra.conf'],
			'an include-toplevel'            => ['include-toplevel: /tmp/extra.conf'],
		];
	}

	#[DataProvider('unsafeLinesAddedAfterTheMove')]
	public function testAnUnsafeLineAddedAfterTheMoveIsReportedForRollbackAndTheAdminsLineIsKeptInTheSnapshot(string $line): void
	{
		// Given a moved Resolver, then an admin who appends a line that can take a listener, a second port or another file.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$this->assertSame(['present' => TRUE, 'value' => base64_encode("do-ip6: no\nprefetch: yes")], pfb_dns_proxy_saved()['custom_options'], 'before: the snapshot holds the original text');
		$edited = base64_encode(implode("\n", $this->customLines()) . "\nserver:\n{$line}\n");
		config_set_path('unbound/custom_options', $edited);

		// When the proxy is applied again.
		$unsafe = NULL;
		$changed = pfb_dns_proxy_resolver(TRUE, $unsafe);

		// Then the line is reported to the caller, which rolls pfB-DNS back (a refusal that keeps serving would leave Unbound one
		// restart away from a bind collision): nothing here refuses, and the Resolver text is not touched ...
		$this->assertSame($line, $unsafe);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'the rollback speaks, not a refusal');
		$this->assertSame($edited, config_get_path('unbound/custom_options'));
		$this->assertSame(1, $this->markerCount());

		// ... and the snapshot now holds the admin's text as it stands, minus our block, so that the restore keeps the line.
		$this->assertTrue($changed, 'the snapshot was rewritten');
		$saved = pfb_dns_proxy_saved();
		$this->assertNotNull($saved);
		$kept = (string) base64_decode($saved['custom_options']['value'] ?? '', TRUE);
		$this->assertStringNotContainsString(self::MARKER, $kept);
		$this->assertSame(["do-ip6: no", "prefetch: yes", "server:", $line], array_values(array_filter(explode("\n", $kept), 'strlen')));
		$this->assertSame(['present' => TRUE, 'value' => 'lan,opt1'], $saved['active_interface'], 'the other saved keys are as they were');
	}

	public function testALineThatIsNotUnsafeAddedAfterTheMoveIsNotReportedAndNothingIsRewritten(): void
	{
		// Given a moved Resolver, then an admin who appends a harmless line.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$snapshot = config_get_path(self::SAVED);
		$edited = base64_encode(implode("\n", $this->customLines()) . "\nserver:\nlocal-data: \"x.example. A 192.0.2.1\"\n");
		config_set_path('unbound/custom_options', $edited);
		$writes = $this->writeCalls();

		// When the proxy is applied again.
		$unsafe = NULL;
		$changed = pfb_dns_proxy_resolver(TRUE, $unsafe);

		// Then nothing is reported and nothing is written.
		$this->assertNull($unsafe);
		$this->assertFalse($changed);
		$this->assertSame($writes, $this->writeCalls());
		$this->assertSame($snapshot, config_get_path(self::SAVED));
		$this->assertSame($edited, config_get_path('unbound/custom_options'));
	}

	/** @return array<string,array{0:string}> lines that are not the admin's own `port:`: other option names, comments, and a quoted phrase with the word */
	public static function otherPortLines(): array
	{
		return [
			'proxy-protocol-port'           => ["server:\nproxy-protocol-port: 5300"],
			'outgoing-port-avoid'           => ["server:\noutgoing-port-avoid: 5353"],
			'commented out'                 => ["server:\n# port: 5300"],
			'a quoted phrase with the word' => ["server:\nlog-identity: \"my port 53\""],
		];
	}

	#[DataProvider('otherPortLines')]
	public function testMoveOnIgnoresLinesThatAreNotThePortOption(string $custom): void
	{
		// Given Custom options with lines that merely contain "port".
		$this->seedResolver(['custom_options' => base64_encode($custom)]);

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the Resolver is moved as usual, without a notice.
		$this->assertTrue($changed);
		$this->assertSame(1, $this->markerCount());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testMoveOnRefusesAStrayCopyOfOurMarkerThatWouldHideAnInterfaceLine(): void
	{
		// Given a moved Resolver, then an admin who puts a stray copy of our marker line in front of an interface line.
		// Our block's text would then run from the stray line to our end line, and the interface line would look like ours.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$edited = base64_encode("# pfBlockerNG DNS proxy\ninterface: 0.0.0.0@53\n" . implode("\n", $this->customLines()));
		config_set_path('unbound/custom_options', $edited);

		// When the proxy is applied again.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the admin's text is left as written and the operator is told to remove the extra marker line.
		$this->assertFalse($changed);
		$this->assertSame($edited, config_get_path('unbound/custom_options'));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertStringContainsString('Custom Options', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	/** @return array<string,array{0:string}> lines that name an interface, port or include but bind nothing: a comment, quoted text, or a word with no colon */
	public static function nonInterfaceLines(): array
	{
		return [
			'a comment naming an interface'            => ["server:\n# interface: 0.0.0.0@53"],
			'a comment after a quoted value'           => ["server:\nlog-identity: \"x\" # interface: 0.0.0.0@53"],
			'a comment after a value on the same line' => ["server:\nprefetch: yes # interface: 0.0.0.0@5353"],
			'a comment naming an include'              => ["server:\n# include: /tmp/extra.conf"],
			'a quoted hash with no directive'          => ["server:\nlog-identity: \"# not a comment\""],
			'a quoted phrase with the word interface'  => ["server:\nlog-identity: \"my interface 0.0.0.0@5353\""],
		];
	}

	#[DataProvider('nonInterfaceLines')]
	public function testMoveOnIgnoresLinesThatAreNotAnInterfaceDirective(string $custom): void
	{
		// Given Custom options with lines that only mention an interface: Unbound binds none of them.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the Resolver is moved as usual, without a notice.
		$this->assertTrue($changed);
		$this->assertSame(1, $this->markerCount());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	/** @return array<string,array{0:string}> the admin's own `include:` lines, wherever they sit: the file they name can hold any listener, which the proxy cannot read */
	public static function userIncludeLines(): array
	{
		return [
			'include'                               => ["server:\ninclude: /tmp/extra.conf"],
			'include-toplevel'                      => ["server:\ninclude-toplevel: /tmp/extra.conf"],
			'include after a value on its line'     => ["server:\nlog-identity: \"x\" include: /tmp/extra.conf"],
			'include after a quoted hash'           => ["server:\nlog-identity: \"#\" include: /tmp/extra.conf"],
			'include with a space before its colon' => ["server:\ninclude : /tmp/extra.conf"],
			'an include-like word in quotes'        => ["server:\nlog-identity: \"include: x\""],
		];
	}

	#[DataProvider('userIncludeLines')]
	public function testMoveOnRefusesAnIncludeOfTheAdminsOwnAndChangesNothing(string $custom): void
	{
		// Given Custom options of the admin's own with an include. The file it names can hold any listener and the
		// proxy cannot read it, so the move is refused rather than guessed.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing moves (no snapshot, no write, the Resolver as it was) and the notice names the include.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('Custom Options', $notice['notice']);
		$this->assertStringContainsString('include:', $notice['notice']);
		$this->assertSame('/services_unbound.php', $notice['url']);
	}

	public function testMoveOffIsNeverRefusedForAnIncludeTheAdminKeeps(): void
	{
		// Given a moved Resolver, then an admin who appends an include to its Custom options.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		config_set_path('unbound/custom_options', base64_encode(implode("\n", $this->customLines()) . "\ninclude: /tmp/extra.conf\n"));

		// When the proxy is turned off.
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the Resolver is restored with no notice: an include only blocks turning the proxy on.
		$this->assertTrue($changed);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
		$this->assertNull(pfb_dns_proxy_saved());
	}

	/** @return array<string,array{0:string}> our marker lines in a shape that is not exactly one complete block, with the admin's own text after them */
	public static function malformedBlocks(): array
	{
		$suffix = "\nforward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.1";
		return [
			'a start line without its end line'  => ["do-ip6: no\nserver:\n# pfBlockerNG DNS proxy\nport: 5354\nprefetch: yes" . $suffix],
			'an end line without its start line' => ["do-ip6: no\nprefetch: yes\n# end pfBlockerNG DNS proxy" . $suffix],
			'the end line before the start line' => ["# end pfBlockerNG DNS proxy\n# pfBlockerNG DNS proxy\nprefetch: yes" . $suffix],
			'two end lines'                      => ["server:\n# pfBlockerNG DNS proxy\nprefetch: yes\n# end pfBlockerNG DNS proxy\n# end pfBlockerNG DNS proxy" . $suffix],
			'a start line with trailing spaces'  => ["server:\n# pfBlockerNG DNS proxy   \nprefetch: yes\n# end pfBlockerNG DNS proxy" . $suffix],
		];
	}

	#[DataProvider('malformedBlocks')]
	public function testMoveOnRefusesAMarkerBlockThatIsNotExactlyOneCompleteBlockAndKeepsEveryLine(string $custom): void
	{
		// Given Custom options whose pfBlockerNG marker lines are not exactly one start line and one end line, in order.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing is removed or moved: every line of the admin's text stays as it is, and the notice names both marker lines.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$this->assertStringContainsString('# pfBlockerNG DNS proxy', $GLOBALS['pfb_test_file_notices'][0]['notice']);
		$this->assertStringContainsString('# end pfBlockerNG DNS proxy', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	public function testMoveOnRefusesAMovedBlockWhoseEndLineWasDeletedAndKeepsTheSuffixByteForByte(): void
	{
		// Given a moved Resolver, then an admin who deletes its end line and keeps writing Custom options below it.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$saved = pfb_dns_proxy_saved();
		$lines = $this->customLines();
		$this->assertSame('# end pfBlockerNG DNS proxy', end($lines), 'before the edit our block ends with its end line');
		array_pop($lines);
		$edited = base64_encode(implode("\n", $lines) . "\nforward-zone:\n  name: \"example.org\"\n  forward-addr: 192.0.2.53");
		config_set_path('unbound/custom_options', $edited);
		$writes = $this->writeCalls();

		// When the proxy is applied again.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing is removed: the admin's forward-zone is stored byte for byte, the snapshot is kept, and the notice names the end line.
		$this->assertFalse($changed);
		$this->assertSame($writes, $this->writeCalls());
		$this->assertSame($edited, config_get_path('unbound/custom_options'));
		$this->assertSame($saved, pfb_dns_proxy_saved());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertStringContainsString('# end pfBlockerNG DNS proxy', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	/** @return array<string,array{0:string}> lines Unbound rejects: a quote or a backslash that does not end on its line */
	public static function unclosedLines(): array
	{
		return [
			'a double quote not closed on its line' => ["server:\nlog-identity: \"abc\nprefetch: yes"],
			'a single quote not closed on its line' => ["server:\nlog-identity: 'abc\nprefetch: yes"],
			'a backslash ending a line'             => ["server:\nlog-identity: abc\\\nprefetch: yes"],
		];
	}

	#[DataProvider('unclosedLines')]
	public function testMoveOnRefusesALineUnboundRejectsAndChangesNothing(string $custom): void
	{
		// Given Custom options with a line Unbound would reject: an unclosed quote, or a backslash at the end of a line.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing moves and the notice says which line to fix.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the refusal is an operator-visible notice');
		$this->assertStringContainsString('quote', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	public function testOurOwnLoopbackLinesAreNotTheAdminsSoReplacingAStaleBlockIsNotRefused(): void
	{
		// Given a moved Resolver whose block of ours (with its own 5353 interface lines) holds a grant that is stale.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		config_set_path('unbound/custom_options', base64_encode("do-ip6: no\nprefetch: yes\n" . self::STALE_BLOCK));

		// When the proxy is applied again.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the block is rewritten in place, without a notice.
		$this->assertTrue($changed);
		$this->assertSame("do-ip6: no\nprefetch: yes\n" . self::block(), implode("\n", $this->customLines()));
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testABlockWrittenBeforeTheLoopbackFrontEndIsRewrittenInPlaceWithItsPortLine(): void
	{
		// Given a Resolver moved by a release that wrote no `port:` line, its block still current otherwise.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		config_set_path('unbound/custom_options', base64_encode("do-ip6: no\nprefetch: yes\n" . self::LEGACY_BLOCK));
		$this->assertNotContains('port: 5354', $this->customLines(), 'before: the stored block has no port line');

		// When the proxy is applied again.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the block is rewritten in place with the port line, once, without a notice, and the snapshot is untouched.
		$this->assertTrue($changed);
		$this->assertSame("do-ip6: no\nprefetch: yes\n" . self::block(), implode("\n", $this->customLines()));
		$this->assertSame(1, $this->markerCount());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
		$this->assertSame(base64_encode("do-ip6: no\nprefetch: yes"), pfb_dns_proxy_saved()['custom_options']['value']);
	}

	/** @return array<string,array{0:string}> our block as it is stored after the Resolver page re-saved the text */
	public static function blocksOfOurs(): array
	{
		return ['the current block' => [self::block()], 'a stale block' => [self::STALE_BLOCK]];
	}

	#[DataProvider('blocksOfOurs')]
	public function testABlockOfOursStoredWithCrlfEndingsIsKeptOrReplacedAsExactlyOneBlock(string $block): void
	{
		// Given a moved Resolver whose Custom options came back from the Resolver page with CRLF line endings
		// (a browser text area submits them), our block among them.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$crlf = str_replace("\n", "\r\n", "do-ip6: no\nprefetch: yes\n" . $block);
		config_set_path('unbound/custom_options', base64_encode($crlf));

		// When the proxy is applied again.
		pfb_dns_proxy_resolver(TRUE);

		// Then there is exactly one block, never a second one appended beside the CRLF one.
		$text = (string) base64_decode((string) config_get_path('unbound/custom_options'), TRUE);
		$this->assertSame(1, $this->markerCount(), 'one block');
		$this->assertSame(1, substr_count($text, 'proxy-protocol-port'), 'one PROXYv2 line');
		$this->assertSame(1, substr_count($text, '# end pfBlockerNG DNS proxy'), 'one end marker');
	}

	// -----------------------------------------------------------------------
	// M6 -- off without a snapshot is a no-op
	// -----------------------------------------------------------------------

	public function testMoveOffWithoutASnapshotChangesNothing(): void
	{
		// Given a Resolver that happens to sit on loopback but has no snapshot and no block of ours.
		$this->seedResolver(['active_interface' => 'lo0']);
		$config = $GLOBALS['config'];

		// When the proxy is turned off.
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then there is nothing to restore: nothing is guessed and nothing is written.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
	}

	#[DataProvider('unusableMarkers')]
	public function testMoveOffKeepsAStoredMarkerThatIsNoSnapshotAndTheResolverAsTheyAre(string $marker): void
	{
		// Given a Resolver on loopback, no block of ours, and a stored marker nothing can read as a snapshot.
		$this->seedResolver(['active_interface' => 'lo0']);
		config_set_path(self::SAVED, $marker);
		$config = $GLOBALS['config'];

		// When the proxy is turned off.
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the unknown saved state is not erased and nothing is restored from it.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($marker, $this->savedRaw());
		$this->assertSame($config, $GLOBALS['config']);
	}

	// -----------------------------------------------------------------------
	// M7 -- our block in custom_options
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:?string,1:string}> original custom_options (NULL absent), expected decoded text after ON */
	public static function customOptionShapes(): array
	{
		$added = self::block();
		$forward = "do-ip6: no\nforward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.1";
		return [
			'absent'                            => [NULL, $added],
			'present empty'                     => ['', $added],
			'existing option lines'             => [base64_encode("do-ip6: no\nprefetch: yes"), "do-ip6: no\nprefetch: yes\n" . $added],
			'starting with a server clause'     => [base64_encode("server:\nlog-queries: yes\n"), "server:\nlog-queries: yes\n" . $added],
			'ending in a forward-zone clause'   => [base64_encode($forward), $forward . "\n" . $added],
			'a commented-out marker'            => [base64_encode("# # pfBlockerNG DNS proxy\ndo-ip6: no"), "# # pfBlockerNG DNS proxy\ndo-ip6: no\n" . $added],
			'CRLF line endings'                 => [base64_encode("do-ip6: no\r\nprefetch: yes\r\n"), "do-ip6: no\nprefetch: yes\n" . $added],
		];
	}

	#[DataProvider('customOptionShapes')]
	public function testMoveOnAppendsOurServerClauseExactlyOnceAndMoveOffRestoresTheOriginalVerbatim(
		?string $original,
		string $expectedText
	): void {
		// Given a Resolver with this custom_options.
		$this->seedResolver(['custom_options' => $original]);

		// When the proxy is turned on.
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		// Then our marker occurs exactly once, in a server clause opened after the user's own text, wherever
		// that text ends.
		$this->assertSame(1, $this->markerCount());
		$this->assertSame($expectedText, implode("\n", $this->customLines()));
		$this->assertSame('server', $this->markerClause());

		// And turning it off puts the original value back verbatim (or removes the key again).
		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));
		$this->assertSame($original, config_get_path('unbound/custom_options'));
		$this->assertSame($original !== NULL, array_key_exists('custom_options', config_get_path('unbound')));
	}

	public function testAUsersOwnProxyProtocolLineIsNotOursSoOurBlockIsStillAdded(): void
	{
		// Given an admin who already runs their own PROXYv2 line (no marker of ours).
		$own = "server:\nproxy-protocol-port: 5353";
		$this->seedResolver(['custom_options' => base64_encode($own)]);

		// When the proxy is turned on.
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		// Then our block follows their text and the marker is ours alone.
		$this->assertSame($own . "\n" . self::block(), implode("\n", $this->customLines()));
		$this->assertSame(1, $this->markerCount());
	}

	// -----------------------------------------------------------------------
	// M8 -- pfb_dns_proxy_saved() is strict
	// -----------------------------------------------------------------------

	private static function entry(mixed $present, mixed $value): array
	{
		return ['present' => $present, 'value' => $value];
	}

	/** @return array<string,array{present:bool,value:?string}> */
	private static function validSnapshot(): array
	{
		return [
			'active_interface' => self::entry(TRUE, 'lan,opt1'),
			'enablessl'        => self::entry(TRUE, ''),
			'custom_options'   => self::entry(FALSE, NULL),
		];
	}

	/** @return array<string,array{0:string}> stored marker text => (must read as "no snapshot") */
	public static function malformedSnapshots(): array
	{
		$valid = self::validSnapshot();
		$without = static function (string $key) use ($valid): array {
			unset($valid[$key]);
			return $valid;
		};
		$with = static fn (string $key, mixed $entry): array => [$key => $entry] + $valid;
		return [
			'not base64'                         => ['!!!not base64!!!'],
			'valid base64 with a stray character' => [substr(self::snapshotOf($valid), 0, 8) . '!' . substr(self::snapshotOf($valid), 8)],
			'base64 of text that is not JSON'    => [base64_encode('not json')],
			'a JSON string'                      => [base64_encode('"active_interface"')],
			'an empty JSON list'                 => [base64_encode('[]')],
			'a key missing'                      => [self::snapshotOf($without('custom_options'))],
			'an extra key'                       => [self::snapshotOf($valid + ['extra' => self::entry(FALSE, NULL)])],
			'a snapshot that still holds the port' => [self::snapshotOf($valid + ['port' => self::entry(TRUE, '53')])],
			'present as the string yes'          => [self::snapshotOf($with('active_interface', self::entry('yes', 'lan')))],
			'present as 1'                       => [self::snapshotOf($with('active_interface', self::entry(1, 'lan')))],
			'a value that is not a string'       => [self::snapshotOf($with('active_interface', self::entry(TRUE, 53)))],
			'present with a NULL value'          => [self::snapshotOf($with('active_interface', self::entry(TRUE, NULL)))],
			'absent with a non-NULL value'       => [self::snapshotOf($with('custom_options', self::entry(FALSE, 'x')))],
			'an entry that is not an object'     => [self::snapshotOf($with('active_interface', 'lan'))],
			'an entry without present'           => [self::snapshotOf($with('active_interface', ['value' => 'lan']))],
			'an entry with an extra key'         => [self::snapshotOf($with('active_interface', self::entry(TRUE, 'lan') + ['junk' => 1]))],
		];
	}

	#[DataProvider('malformedSnapshots')]
	public function testSavedReadsAMalformedMarkerAsNoSnapshotAndLogsTheField(string $stored): void
	{
		// Given a marker that is not the documented shape.
		config_set_path(self::SAVED, $stored);
		$this->assertSame($stored, config_get_path(self::SAVED), 'before: the marker is stored');

		// When it is read.
		$saved = pfb_dns_proxy_saved();

		// Then it is "no snapshot", and the log names the field.
		$this->assertNull($saved);
		$this->assertStringContainsString('pfb_dns_saved', $this->errorLog());
	}

	public function testAMalformedMarkerIsLoggedOnceForAsLongAsItIsUnchangedAndAgainWhenItChanges(): void
	{
		// Given a marker that is not the documented shape, read by every apply and page load
		config_set_path(self::SAVED, 'not-a-snapshot');
		for ($read = 0; $read < 3; $read++) {
			$this->assertNull(pfb_dns_proxy_saved());
		}
		$this->assertSame(1, substr_count($this->errorLog(), 'pfb_dns_saved is not a valid Resolver snapshot'), 'logged once, not per read');

		// When the marker changes to another malformed value
		config_set_path(self::SAVED, 'still-not-a-snapshot');
		$this->assertNull(pfb_dns_proxy_saved());

		// Then that change is logged
		$this->assertSame(2, substr_count($this->errorLog(), 'pfb_dns_saved is not a valid Resolver snapshot'), 'a new malformed value is logged');
	}

	public function testSavedReadsAValidMarkerBackExactly(): void
	{
		config_set_path(self::SAVED, self::snapshotOf(self::validSnapshot()));

		$this->assertSame(self::validSnapshot(), pfb_dns_proxy_saved());
		$this->assertSame('', $this->errorLog(), 'a valid marker logs nothing');
	}

	public function testSavedAcceptsAMarkerWrappedByWhitespace(): void
	{
		// An XML pretty-printer or an HA copy can wrap the base64 text; the payload is intact.
		$wrapped = chunk_split(self::snapshotOf(self::validSnapshot()), 16, "\n");
		config_set_path(self::SAVED, "  {$wrapped}  ");

		$this->assertSame(self::validSnapshot(), pfb_dns_proxy_saved());
	}

	public function testSavedIsSilentlyNullWhenThereIsNoMarker(): void
	{
		$this->assertNull(pfb_dns_proxy_saved(), 'absent marker');

		config_set_path(self::SAVED, '');
		$this->assertNull(pfb_dns_proxy_saved(), 'empty marker');
		$this->assertSame('', $this->errorLog(), 'no snapshot is the normal state, not an error');
	}

	// -----------------------------------------------------------------------
	// W -- config.xml does not take the write: nothing is reported as moved, restored or kept
	// -----------------------------------------------------------------------

	private function noticeTexts(): string
	{
		return implode("\n", array_column($GLOBALS['pfb_test_file_notices'] ?? [], 'notice'));
	}

	#[DataProvider('refusedWrites')]
	public function testMoveOffWhoseWriteIsRefusedKeepsTheSnapshotAndTheMovedResolverAndTellsTheOperator(mixed $answer): void
	{
		// Given a moved Resolver, and a config.xml that then refuses every write
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE), 'before: the Resolver is moved');
		$this->configXmlOnDisk($answer);
		$snapshot = $this->savedRaw();
		$moved = config_get_path('unbound');

		// When the Resolver is put back
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then it is not reported as put back: the snapshot and the moved Resolver are what config.xml holds, here and on disk,
		// so nothing that reads this process's copy (a package removal, the wizard's reset) takes the Resolver for restored
		$this->assertFalse($changed);
		$this->assertSame($snapshot, $this->savedRaw(), 'the snapshot is kept');
		$this->assertTrue(pfb_dns_proxy_owns_resolver(), 'pfB-DNS still owns the Resolver');
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')), 'the Resolver is still the moved one');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'config.xml keeps the snapshot');
		$this->assertSame('lo0', $this->onDisk('unbound/active_interface'), 'and the moved Resolver');
		$this->assertFalse(!empty($GLOBALS['pfb_test_lock_held']), 'the config lock is released');

		// And the operator is told why the Resolver was not put back (the proxy's restart may add notices of its own)
		$notices = array_values(array_filter($GLOBALS['pfb_test_file_notices'], static fn (array $n): bool => str_contains($n['notice'], 'not put back')));
		$this->assertCount(1, $notices, $this->noticeTexts());
		$this->assertStringContainsString('could not be written', $notices[0]['notice']);
		$this->assertSame('/services_unbound.php', $notices[0]['url']);
	}

	#[DataProvider('refusedWrites')]
	public function testMoveOnWhoseWriteIsRefusedIsNotReportedAndLeavesTheResolverAsStored(mixed $answer): void
	{
		// Given a Resolver on its own interfaces, and a config.xml that refuses every write
		$before = $this->seedResolver();
		$this->configXmlOnDisk($answer);

		// When the proxy is turned on
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the move is not reported (the apply would regenerate unbound.conf and start a proxy for a Resolver config.xml
		// does not hold moved): this process holds the stored Resolver, with no snapshot and no block of ours
		$this->assertFalse($changed);
		$this->assertSame(self::sorted($before), self::sorted(config_get_path('unbound')));
		$this->assertSame('', $this->savedRaw());
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertFalse(pfb_dns_proxy_owns_resolver());
		$this->assertSame(self::sorted($before), self::sorted($this->onDisk('unbound')), 'config.xml holds the Resolver as it was');

		// And the operator is told the Resolver was not moved
		$notices = $GLOBALS['pfb_test_file_notices'];
		$this->assertCount(1, $notices, $this->noticeTexts());
		$this->assertStringContainsString('not moved', $notices[0]['notice']);
		$this->assertStringContainsString('could not be written', $notices[0]['notice']);
	}

	#[DataProvider('refusedWrites')]
	public function testAnUnsafeLineWhoseKeepWriteIsRefusedIsNotReportedForRollbackAndChangesNothing(mixed $answer): void
	{
		// Given a moved Resolver, an admin who then added an unsafe line, and a config.xml that refuses every write
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE), 'before: the Resolver is moved');
		$edited = base64_encode(implode("\n", $this->customLines()) . "\nserver:\nport: 5300\n");
		config_set_path('unbound/custom_options', $edited);
		$this->configXmlOnDisk($answer);
		$snapshot = $this->savedRaw();

		// When the proxy is applied again
		$unsafe = NULL;
		$changed = pfb_dns_proxy_resolver(TRUE, $unsafe);

		// Then no rollback is asked for (it would restore from a snapshot that does not hold the admin's line, and drop it)
		$this->assertNull($unsafe);
		$this->assertFalse($changed, 'the snapshot was not rewritten');
		$this->assertSame($snapshot, $this->savedRaw());
		$this->assertSame($snapshot, $this->onDisk(self::SAVED));
		$this->assertSame($edited, config_get_path('unbound/custom_options'), 'the admin\'s text is as saved');
		$notices = $GLOBALS['pfb_test_file_notices'];
		$this->assertCount(1, $notices, $this->noticeTexts());
		$this->assertStringContainsString('not re-applied', $notices[0]['notice']);
		$this->assertStringContainsString('could not be written', $notices[0]['notice']);
	}
}
