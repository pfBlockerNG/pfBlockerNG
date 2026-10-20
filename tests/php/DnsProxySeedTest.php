<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3538 -- pfB-DNS owns its listener settings. The interface, the DoT on/port/interface, the certificate and the
 * DoH/DoQ interface lists are seeded once, from the DNS Resolver or from its snapshot once pfB-DNS has moved it. A later
 * Resolver change never reaches them, and a seed never overwrites a stored value.
 */
#[CoversFunction('pfb_dns_proxy_seed_values')]
#[CoversFunction('pfb_dns_proxy_setting')]
#[CoversFunction('pfb_dns_proxy_seed')]
#[CoversFunction('pfb_dns_proxy_resolver')]
final class DnsProxySeedTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngdns/config/0/';
	/** The keys the seed fills, bare; a box turned on by this release has all of them set. */
	private const SEEDED = [
		'pfb_dns_interface', 'pfb_dns_dot', 'pfb_dns_dot_port', 'pfb_dns_dot_interface', 'pfb_dns_sslcertref',
		'pfb_dns_doh_interface', 'pfb_dns_doq_interface',
	];
	private const GLOBALS = ['pfb', 'config', 'pfb_test_write_config_calls', 'pfb_test_file_notices', 'pfb_test_interface_mtu',
		'pfb_test_interfaces', 'pfb_test_configured_ipv6', 'pfb_test_interface_subnetv6'];

	private string $tmp;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_seed_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'logdir' => $this->tmp, 'log' => "{$this->tmp}/pfb.log", 'errlog' => "{$this->tmp}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_interface_mtu'] = ['lan' => '1500', 'opt1' => '1500', 'lo0' => '16384'];
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'OPT1'];
		$GLOBALS['pfb_test_configured_ipv6'] = [];
		$GLOBALS['pfb_test_interface_subnetv6'] = ['opt1' => '64'];
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->tmp);
	}

	/**
	 * A box as pfSense keeps it: the Resolver's own keys (absent keys are left out) and the pfB-DNS section.
	 *
	 * @param array<string,mixed>  $unbound
	 * @param array<string,string> $dns     leaf => stored value of installedpackages/pfblockerngdns/config/0
	 */
	private function seedBox(array $unbound, array $dns = []): void
	{
		$GLOBALS['config'] = [
			'unbound' => $unbound + ['enable' => '', 'port' => '53', 'custom_options' => base64_encode("do-ip6: no\nprefetch: yes")],
			'installedpackages' => ['pfblockerngdns' => ['config' => [0 => $dns]]],
		];
	}

	/** The marker a move keeps: the Resolver's active_interface and enablessl as they were before pfB-DNS took it. */
	private static function snapshotMarker(?string $active, bool $ssl): string
	{
		$saved = [
			'active_interface' => ['present' => $active !== NULL, 'value' => $active],
			'enablessl' => ['present' => $ssl, 'value' => $ssl ? 'on' : NULL],
			'custom_options' => ['present' => TRUE, 'value' => base64_encode("do-ip6: no\nprefetch: yes")],
		];
		return base64_encode((string) json_encode($saved));
	}

	/** The seed of a Resolver with these values: one interface list for the listener and the three lists. */
	private static function expect(string $interface, PfbToggle $dot, string $port, string $cert): array
	{
		return [
			'pfb_dns_interface' => $interface,
			'pfb_dns_dot' => $dot,
			'pfb_dns_dot_port' => $port,
			'pfb_dns_sslcertref' => $cert,
			'pfb_dns_dot_interface' => $interface,
			'pfb_dns_doh_interface' => $interface,
			'pfb_dns_doq_interface' => $interface,
		];
	}

	/** @param array<string,mixed> $expected the values pfb_dns_proxy_seed_values() must return, whatever their order */
	private function assertSeedValues(array $expected): void
	{
		$actual = pfb_dns_proxy_seed_values();
		ksort($actual);
		ksort($expected);
		$this->assertSame($expected, $actual);
	}

	private function writes(): int
	{
		return count($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	// -----------------------------------------------------------------------
	// The seed values, from the live Resolver (not moved yet) or the snapshot (moved)
	// -----------------------------------------------------------------------

	public function testAnUnmovedResolverSeedsEveryListenerSettingFromItsLiveValues(): void
	{
		// Given a Resolver on two LANs with SSL on, a TLS port and a certificate, not moved yet.
		$this->seedBox(['active_interface' => 'lan,opt1', 'enablessl' => 'on', 'tlsport' => '8853', 'sslcertref' => 'abc']);

		// Then the seed is the Resolver's own listener.
		$this->assertSeedValues(self::expect('lan,opt1', PfbToggle::On, '8853', 'abc'));
	}

	/** @return array<string,array{0:?string}> the live active_interface: absent and empty both mean every interface */
	public static function unsetInterfaces(): array
	{
		return ['absent' => [NULL], 'empty' => ['']];
	}

	#[DataProvider('unsetInterfaces')]
	public function testAnUnmovedResolverWithoutInterfacesOrTlsSeedsAllWithDotOff(?string $active): void
	{
		// Given a Resolver with no interface list, no SSL and no TLS port.
		$this->seedBox($active === NULL ? [] : ['active_interface' => $active]);

		// Then the seed listens on every interface, DoT is off, and the port is the 853 default.
		$this->assertSeedValues(self::expect('all', PfbToggle::Off, '853', ''));
	}

	/** @return array<string,array{0:mixed}> TLS ports that are not a 1-65535 decimal: each seeds the 853 default */
	public static function unusableTlsPorts(): array
	{
		return [
			'zero'                 => ['0'],
			'above the port range' => ['65536'],
			'not a number'         => ['abc'],
			'padded with a space'  => [' 853'],
			'not a scalar'         => [['853']],
		];
	}

	#[DataProvider('unusableTlsPorts')]
	public function testAnUnusableTlsPortSeedsTheDefault(mixed $tlsport): void
	{
		$this->seedBox(['active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => $tlsport, 'sslcertref' => 'abc']);

		$this->assertSeedValues(self::expect('lan', PfbToggle::On, '853', 'abc'));
	}

	public function testASnapshotWinsOverTheLiveResolverOnceItHasMoved(): void
	{
		// Given a moved box: the snapshot says lan with no SSL; the live Resolver (on lo0) has SSL on.
		$this->seedBox(
			['active_interface' => 'lo0', 'enablessl' => 'on', 'tlsport' => '8853', 'sslcertref' => 'abc'],
			['pfb_dns_saved' => self::snapshotMarker('lan', FALSE)],
		);

		// Then the interface and DoT come from the snapshot, while the port and certificate are read live.
		$this->assertSeedValues(self::expect('lan', PfbToggle::Off, '8853', 'abc'));
	}

	public function testASnapshotWithoutAnInterfaceSeedsAllAndItsSslOnTurnsDotOn(): void
	{
		// Given a moved box whose snapshot holds no active_interface, and SSL on in the snapshot only.
		$this->seedBox(['active_interface' => 'lo0', 'tlsport' => '853'], ['pfb_dns_saved' => self::snapshotMarker(NULL, TRUE)]);

		$this->assertSeedValues(self::expect('all', PfbToggle::On, '853', ''));
	}

	/** @return array<string,array{0:bool}> the live Resolver, or the snapshot of a moved one, carries the list */
	public static function listSources(): array
	{
		return ['live' => [FALSE], 'snapshot' => [TRUE]];
	}

	#[DataProvider('listSources')]
	public function testAnInterfaceListIsReducedToItsDistinctTokens(bool $moved): void
	{
		// Given the list " lan , ,opt1 " as the source holds it (padding, empty words and no duplicate).
		if ($moved) {
			$this->seedBox(['active_interface' => 'lo0'], ['pfb_dns_saved' => self::snapshotMarker(' lan , ,opt1 ', FALSE)]);
		} else {
			$this->seedBox(['active_interface' => ' lan , ,opt1 ', 'enablessl' => 'on']);
		}

		$this->assertSeedValues(self::expect('lan,opt1', $moved ? PfbToggle::Off : PfbToggle::On, '853', ''));
	}

	public function testANonScalarLiveInterfaceCountsAsUnsetAndSeedsAll(): void
	{
		// Given a live active_interface that is an array (not a string).
		$this->seedBox(['active_interface' => ['lan'], 'enablessl' => 'on']);

		// Then it is read as unset: every interface, and no type error.
		$this->assertSeedValues(self::expect('all', PfbToggle::On, '853', ''));
	}

	public function testANonScalarCertificateCountsAsEmpty(): void
	{
		$this->seedBox(['active_interface' => 'lan', 'sslcertref' => ['abc']]);

		$this->assertSeedValues(self::expect('lan', PfbToggle::Off, '853', ''));
	}

	public function testAStoredInterfaceSkipsTheGroupAndOnlyFillsTheEmptyLists(): void
	{
		// Given the listener interface already stored (so the group is done) and the DoH list empty.
		$this->seedBox(['active_interface' => 'lan'], [
			'pfb_dns_interface' => 'opt1', 'pfb_dns_doh_interface' => '',
			'pfb_dns_dot_interface' => 'lan', 'pfb_dns_doq_interface' => 'lan',
		]);

		// Then only the DoH list is seeded, from the stored interface.
		$this->assertSeedValues(['pfb_dns_doh_interface' => 'opt1']);
	}

	/** @return array<string,array{string,string}> the two boxes that cannot say what the Resolver was: a junk marker, or our block with none */
	public static function recoveryRequired(): array
	{
		$block = "server:\n" . PFB_DNS_PROXY_MARKER . "\nport: 5354\n" . PFB_DNS_PROXY_MARKER_END . "\n";
		return [
			'junk marker'              => ['junk', base64_encode("do-ip6: no\nprefetch: yes")],
			'block without a snapshot' => ['', base64_encode($block)],
		];
	}

	#[DataProvider('recoveryRequired')]
	public function testARecoveryRequiredBoxSeedsNothingAndWritesNothing(string $marker, string $custom): void
	{
		// Given a box that cannot say what the Resolver was before (junk marker, or our block with no snapshot).
		$this->seedBox(['active_interface' => 'lo0', 'custom_options' => $custom], $marker === '' ? [] : ['pfb_dns_saved' => $marker]);
		$this->assertTrue(pfb_dns_proxy_recovery_required(), 'before: recovery required');
		$before = $GLOBALS['config'];

		// Then nothing is seeded, nothing is written, and the config is unchanged.
		$this->assertSame([], pfb_dns_proxy_seed_values());
		$this->assertFalse(pfb_dns_proxy_seed());
		$this->assertSame($before, $GLOBALS['config'], 'config unchanged');
		$this->assertSame(0, $this->writes(), 'no write_config');
	}

	public function testTheSeedIsWrittenOnceAndALaterResolverChangeDoesNotReachIt(): void
	{
		// Given an unseeded box with the Resolver on lan.
		$this->seedBox(['active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => '853', 'sslcertref' => 'abc']);
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_interface'), 'before: not seeded');

		// When the first seed runs.
		$this->assertTrue(pfb_dns_proxy_seed(), 'the first seed writes');

		// Then the stored values are the Resolver's values at that time.
		$this->assertSame('lan', PfbConfig::read('dns/pfb_dns_interface'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns_dot'));

		// When the Resolver then changes (interface and SSL), the stored values hold.
		$this->assertSame('lan', config_get_path('unbound/active_interface'), 'before the change: the Resolver is on lan');
		config_set_path('unbound/active_interface', 'opt1');
		config_del_path('unbound/enablessl');
		$this->assertFalse(pfb_dns_proxy_seed(), 'the second seed writes nothing');
		$this->assertSame('lan', PfbConfig::read('dns/pfb_dns_interface'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns_dot'));
	}

	// -----------------------------------------------------------------------
	// The served value: the seed on an unseeded box, the stored value once seeded
	// -----------------------------------------------------------------------

	public function testASettingIsTheSeedValueOnAnUnseededBoxWithoutWritingIt(): void
	{
		$this->seedBox(['active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => '8853', 'sslcertref' => 'abc']);
		$writes = $this->writes();
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_interface'), 'before: not seeded');

		$this->assertSame('8853', pfb_dns_proxy_setting('pfb_dns_dot_port'), 'the seed value');
		$this->assertSame(PfbToggle::On, pfb_dns_proxy_setting('pfb_dns_dot'), 'the seed value');

		$this->assertNull(config_get_path(self::SECTION . 'pfb_dns_dot_port'), 'not written: the key stays absent');
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_interface'), 'not written: still unseeded');
		$this->assertSame($writes, $this->writes(), 'no write_config');
	}

	public function testASettingIsTheStoredValueOnceTheBoxIsSeeded(): void
	{
		// Given a seeded box whose stored port differs from what the live Resolver would seed now.
		$this->seedBox(['active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => '8853', 'sslcertref' => 'abc'], [
			'pfb_dns_interface' => 'opt1', 'pfb_dns_dot' => 'off', 'pfb_dns_dot_port' => '8443',
			'pfb_dns_dot_interface' => 'opt1', 'pfb_dns_sslcertref' => 'def', 'pfb_dns_doh_interface' => 'opt1',
			'pfb_dns_doq_interface' => 'opt1',
		]);

		$this->assertSame('8443', pfb_dns_proxy_setting('pfb_dns_dot_port'));
		$this->assertSame(PfbToggle::Off, pfb_dns_proxy_setting('pfb_dns_dot'));
		$this->assertSame('opt1', pfb_dns_proxy_setting('pfb_dns_interface'));
	}

	// -----------------------------------------------------------------------
	// The turn-on wiring: the seed is written in the same apply that moves the Resolver
	// -----------------------------------------------------------------------

	public function testTurningTheProxyOnSeedsFromTheResolverBeforeItMovesIt(): void
	{
		// Given an unmoved, unseeded box: SSL on and the Resolver on lan.
		$this->seedBox(['active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => '8853', 'sslcertref' => 'abc']);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns_dot'), 'before: DoT off');
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_interface'), 'before: not seeded');
		$writes = $this->writes();

		// When the proxy takes the Resolver.
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE), 'the move changed config.xml');

		// Then the seed holds the Resolver's values, the Resolver is moved, and one write covered both.
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns_dot'));
		$this->assertSame('lan', PfbConfig::read('dns/pfb_dns_interface'));
		$this->assertSame('8853', PfbConfig::read('dns/pfb_dns_dot_port'));
		$this->assertSame('abc', PfbConfig::read('dns/pfb_dns_sslcertref'));
		$this->assertNull(config_get_path('unbound/enablessl'), 'enablessl deleted by the move');
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame($writes + 1, $this->writes(), 'one write_config for the whole turn-on');
	}

	public function testTurningOnAnAlreadyMovedBoxSeedsFromTheSnapshotAndIsNotAMove(): void
	{
		// Given a box the proxy has already moved, whose keys were never seeded (a release before the seed).
		$this->seedBox(['active_interface' => 'lan', 'enablessl' => 'on', 'tlsport' => '8853', 'sslcertref' => 'abc']);
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE), 'precondition: the first turn-on moves the Resolver');
		foreach (self::SEEDED as $leaf) {
			config_del_path(self::SECTION . $leaf);
		}
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_interface'), 'before: unseeded');
		$writes = $this->writes();

		// When the proxy is turned on again: nothing moves, but the keys are seeded from the snapshot.
		$this->assertFalse(pfb_dns_proxy_resolver(TRUE), 'a seed alone is not a move');

		// Then the snapshot's interface and the live TLS settings are stored, in one write with the seed text.
		$this->assertSame('lan', PfbConfig::read('dns/pfb_dns_interface'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns_dot'));
		$this->assertSame($writes + 1, $this->writes(), 'one write_config');
		$this->assertSame(
			'pfBlockerNG: pfB-DNS took its listener settings from the DNS Resolver',
			end($GLOBALS['pfb_test_write_config_calls']),
		);
	}
}
