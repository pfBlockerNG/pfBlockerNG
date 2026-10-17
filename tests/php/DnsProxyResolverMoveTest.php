<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the experimental DNS proxy takes the Resolver's client-facing place, so
 * pfb_dns_proxy_resolver() moves the Resolver to loopback 5353 through config.xml and
 * remembers every key it changed (presence AND value) in the registered marker
 * dnsbl/pfb_dns_proxy_saved; turning it off restores them exactly. pfb_dns_proxy_saved()
 * is the strict reader of that marker: anything but the documented shape is "no snapshot".
 *
 * The moved Resolver is the persistent outcome (config.xml): these tests assert the config
 * after each call, never the mechanics of how it got there.
 */
final class DnsProxyResolverMoveTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dns_proxy_saved';
	private const KEYS  = ['port', 'active_interface', 'enablessl', 'custom_options'];
	private const LINE  = 'proxy-protocol-port: 5353';

	private string $tmp;
	private bool $hadPfb = FALSE;
	private bool $hadConfig = FALSE;
	private array $originalPfb = [];
	private array $originalConfig = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_proxy_move_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'logdir' => $this->tmp,
			'log'    => "{$this->tmp}/pfb.log",
			'errlog' => "{$this->tmp}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
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
		unset($GLOBALS['pfb_test_write_config_calls']);
		rmdir_recursive($this->tmp);
	}

	/**
	 * The Resolver as pfSense stores it: unrelated keys (they must never be touched) plus the
	 * four keys the move owns. A NULL override deletes the key, so "absent" is a real state.
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

	private function proxyLineCount(): int
	{
		return count(array_filter($this->customLines(), static fn (string $l): bool => trim($l) === self::LINE));
	}

	/** @return array<string,array{0:string,1:?string}> key => [name, value]; NULL = absent */
	public static function resolverShapes(): array
	{
		$cases = [];
		$values = [
			'port'             => ['53', '', 'abc'],
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

	// -----------------------------------------------------------------------
	// M1 / M5 -- move on, move off: the Resolver round-trips exactly
	// -----------------------------------------------------------------------

	#[DataProvider('resolverShapes')]
	public function testMoveOnRecordsEachKeyExactlyAsItWasPresentOrAbsentAndMovesTheResolver(string $key, ?string $value): void
	{
		// Given a Resolver whose $key is in this shape, still on its own port.
		$before = $this->seedResolver([$key => $value]);
		$this->assertNotSame('5353', config_get_path('unbound/port'), 'before: the Resolver is not moved');
		$this->assertSame('', $this->savedRaw(), 'before: no snapshot');

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then it reports a config change, written once, with a snapshot of every key.
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

		// And the Resolver sits on loopback 5353, without DoT, with the PROXY line first.
		$after = config_get_path('unbound');
		$this->assertSame('5353', $after['port']);
		$this->assertSame('lo0', $after['active_interface']);
		$this->assertArrayNotHasKey('enablessl', $after);
		$this->assertSame(self::LINE, $this->customLines()[0]);
		$this->assertSame(1, $this->proxyLineCount());
		foreach (['enable', 'dnssec', 'sslcertref', 'tlsport'] as $untouched) {
			$this->assertSame($before[$untouched], $after[$untouched], "{$untouched} is not the move's to change");
		}
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
			'port back to 53'             => ['unbound/port', '53'],
			'interfaces back to a LAN'    => ['unbound/active_interface', 'lan'],
			'DoT switched back on'        => ['unbound/enablessl', ''],
			'custom option line removed'  => ['unbound/custom_options', base64_encode("do-ip6: no\nprefetch: yes")],
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
		$this->assertSame(self::sorted($moved), self::sorted(config_get_path('unbound')));
		$this->assertSame($snapshot, config_get_path(self::SAVED));
		$this->assertSame(2, $this->writeCalls());
	}

	// -----------------------------------------------------------------------
	// M4 -- never save moved values as the "previous" ones
	// -----------------------------------------------------------------------

	public function testMoveOnRefusesWhenTheResolverAlreadyLooksMovedAndNoSnapshotExists(): void
	{
		// Given a Resolver already on 5353/lo0 with no snapshot (the snapshot was lost).
		$this->seedResolver(['port' => '5353', 'active_interface' => 'lo0', 'enablessl' => NULL]);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then it changes nothing and says why, instead of recording the moved values.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertStringContainsString('refusing to snapshot', $this->errorLog());
	}

	public function testMoveOnSnapshotsAResolverThatOnlyHalfLooksMoved(): void
	{
		// Given a Resolver on port 5353 but a LAN interface: not the moved shape.
		$this->seedResolver(['port' => '5353']);

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the user's values are recorded and the Resolver is moved.
		$this->assertTrue($changed);
		$this->assertSame(['present' => TRUE, 'value' => 'lan,opt1'], pfb_dns_proxy_saved()['active_interface']);
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame('', $this->errorLog());
	}

	/** @return array<string,array{0:array<string,mixed>}> */
	public static function unrepresentableResolvers(): array
	{
		return [
			'a non-scalar port'                    => [['port' => ['53']]],
			'a non-UTF-8 interface list'           => [['active_interface' => "lan\xff"]],
		];
	}

	#[DataProvider('unrepresentableResolvers')]
	public function testMoveOnRefusesAValueThatCannotBeStoredVerbatim(array $override): void
	{
		// Given a Resolver key whose value a JSON snapshot could not restore as it was.
		$this->seedResolver($override);
		$config = $GLOBALS['config'];

		// When the proxy is turned on.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then it refuses rather than moving a Resolver it could not restore.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
		$this->assertStringContainsString('pfb_dns_proxy_saved', $this->errorLog());
	}

	// -----------------------------------------------------------------------
	// M6 -- off without a snapshot is a no-op
	// -----------------------------------------------------------------------

	public function testMoveOffWithoutASnapshotChangesNothing(): void
	{
		// Given a Resolver that happens to sit on the moved values but has no snapshot.
		$this->seedResolver(['port' => '5353', 'active_interface' => 'lo0']);
		$config = $GLOBALS['config'];

		// When the proxy is turned off.
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then there is nothing to restore: nothing is guessed and nothing is written.
		$this->assertFalse($changed);
		$this->assertSame(0, $this->writeCalls());
		$this->assertSame($config, $GLOBALS['config']);
	}

	// -----------------------------------------------------------------------
	// M7 -- the PROXY line in custom_options
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:?string,1:?string,2:bool}> original custom_options (NULL absent), expected decoded text after ON (NULL = unchanged), proxy line first? */
	public static function customOptionShapes(): array
	{
		$forward = "do-ip6: no\nforward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.1";
		return [
			'absent'                            => [NULL, self::LINE, TRUE],
			'present empty'                     => ['', self::LINE, TRUE],
			'existing option lines'             => [base64_encode("do-ip6: no\nprefetch: yes"), self::LINE . "\ndo-ip6: no\nprefetch: yes", TRUE],
			'ending in a forward-zone clause'   => [base64_encode($forward), self::LINE . "\n" . $forward, TRUE],
			'already holding the proxy line'    => [base64_encode(self::LINE . "\ndo-ip6: no"), NULL, TRUE],
			'proxy line with surrounding blanks' => [base64_encode("  " . self::LINE . "  \ndo-ip6: no"), NULL, TRUE],
			'proxy line in the middle, padded'  => [base64_encode("do-ip6: no\n \t" . self::LINE . " \nprefetch: yes"), NULL, FALSE],
			'a commented-out proxy line'        => [base64_encode("# " . self::LINE . "\ndo-ip6: no"), self::LINE . "\n# " . self::LINE . "\ndo-ip6: no", TRUE],
			'CRLF line endings'                 => [base64_encode("do-ip6: no\r\nprefetch: yes\r\n"), self::LINE . "\ndo-ip6: no\nprefetch: yes\n", TRUE],
		];
	}

	#[DataProvider('customOptionShapes')]
	public function testMoveOnPutsTheProxyLineFirstExactlyOnceAndMoveOffRestoresTheOriginalVerbatim(
		?string $original,
		?string $expectedText,
		bool $first
	): void {
		// Given a Resolver with this custom_options.
		$this->seedResolver(['custom_options' => $original]);

		// When the proxy is turned on.
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		// Then the proxy line occurs exactly once (a line equal to it after trimming), and sits
		// before any user clause when it was added.
		$this->assertSame(1, $this->proxyLineCount());
		if ($expectedText === NULL) {
			$this->assertSame($original, config_get_path('unbound/custom_options'), 'an existing proxy line is left alone');
		} else {
			$this->assertSame($expectedText, implode("\n", $this->customLines()));
		}
		if ($first) {
			$this->assertSame(self::LINE, trim($this->customLines()[0]));
		}

		// And turning it off puts the original value back verbatim (or removes the key again).
		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));
		$this->assertSame($original, config_get_path('unbound/custom_options'));
		$this->assertSame($original !== NULL, array_key_exists('custom_options', config_get_path('unbound')));
	}

	// -----------------------------------------------------------------------
	// M8 -- pfb_dns_proxy_saved() is strict
	// -----------------------------------------------------------------------

	private static function entry(mixed $present, mixed $value): array
	{
		return ['present' => $present, 'value' => $value];
	}

	/** @return array<string,array<string,array{present:bool,value:?string}>> */
	private static function validSnapshot(): array
	{
		return [
			'port'             => self::entry(TRUE, '53'),
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
			'base64 of text that is not JSON'    => [base64_encode('not json')],
			'a JSON string'                      => [base64_encode('"port"')],
			'an empty JSON list'                 => [base64_encode('[]')],
			'a key missing'                      => [self::snapshotOf($without('custom_options'))],
			'an extra key'                       => [self::snapshotOf($valid + ['extra' => self::entry(FALSE, NULL)])],
			'present as the string yes'          => [self::snapshotOf($with('port', self::entry('yes', '53')))],
			'present as 1'                       => [self::snapshotOf($with('port', self::entry(1, '53')))],
			'a value that is not a string'       => [self::snapshotOf($with('port', self::entry(TRUE, 53)))],
			'present with a NULL value'          => [self::snapshotOf($with('port', self::entry(TRUE, NULL)))],
			'absent with a non-NULL value'       => [self::snapshotOf($with('custom_options', self::entry(FALSE, 'x')))],
			'an entry that is not an object'     => [self::snapshotOf($with('port', '53'))],
			'an entry without present'           => [self::snapshotOf($with('port', ['value' => '53']))],
			'an entry with an extra key'         => [self::snapshotOf($with('port', self::entry(TRUE, '53') + ['junk' => 1]))],
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
		$this->assertStringContainsString('pfb_dns_proxy_saved', $this->errorLog());
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
}
