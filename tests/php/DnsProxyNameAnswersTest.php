<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694 -- the DNS Name and the gateway flags it drives. pfB-DNS answers A and AAAA for exactly that name, from the address
 * the query arrived on; the PHP side decides, for each address the gateway listens on, which addresses it answers with
 * (pfb_dns_proxy_name_answers()) and passes the result as --dns-name-answer LOCAL=ADDR[,ADDR] beside --dns-name and --ddr
 * (pfb_dns_proxy_ddr_flags()).
 *
 * The rules pinned here: a query on an interface address is answered with that interface's own addresses (a VIP never replaces
 * them); a query on a Resolver VIP with the VIP and the other family's active VIP; an address no interface carries and a loopback
 * address get no entry at all (the gateway then lets Unbound answer); no DNS Name means no flag of any kind, DDR on or not.
 */
#[CoversFunction('pfb_dns_proxy_name_answers')]
#[CoversFunction('pfb_dns_proxy_ddr_flags')]
final class DnsProxyNameAnswersTest extends TestCase
{
	private const NAME = 'fw.example.lan';
	private const LAN4 = '192.0.2.1';
	private const LAN6 = '2001:db8::1';
	private const OPT4 = '198.51.100.1';
	private const OPT6 = 'fd12:3456::1';
	private const VIP4 = '172.16.53.53';
	private const VIP6 = 'fd00:53:53:53:53:53:53:53';

	private const GLOBALS = [
		'config', 'pfb', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6',
		'pfb_test_interface_info', 'pfb_test_configured_ip_addresses', 'pfb_test_interfaces',
	];

	/** @var array<string,array{0:bool,1:mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		unset($GLOBALS['pfb_test_configured_ip_addresses']);
		// lan and opt1 are up, each with an IPv4 and an IPv6 address
		$this->interfaces(['lan' => [self::LAN4, self::LAN6], 'opt1' => [self::OPT4, self::OPT6]]);
		$this->store('pfb_dns_interface', 'lan'); // seeded: an unseeded list makes every setting read as the Resolver's
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $name => [$exists, $value]) {
			if ($exists) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	/** @param array<string,list<string>> $interfaces interface => its addresses (at most one IPv4 and one IPv6) */
	private function interfaces(array $interfaces): void
	{
		$v4 = $v6 = $info = [];
		foreach ($interfaces as $name => $addresses) {
			$info[$name] = ['status' => 'up', 'enable' => TRUE];
			foreach ($addresses as $address) {
				if (str_contains($address, ':')) {
					$v6[$name] = $address;
				} else {
					$v4[$name] = $address;
				}
			}
		}
		$GLOBALS['pfb_test_interface_ip'] = $v4 + ['lo0' => '127.0.0.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = $v6;
		$GLOBALS['pfb_test_interface_info'] = $info + ['lo0' => ['status' => 'up', 'enable' => TRUE]];
		$GLOBALS['pfb_test_interfaces'] = array_fill_keys(array_keys($interfaces), '');
	}

	/** One stored pfB-DNS setting, straight into config.xml: the DNS Name is read from there whatever the page validated. */
	private function store(string $key, string $value): void
	{
		config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key($key), 2)[0]] . '/' . $key, $value);
	}

	/** The Resolver addresses option on, with a VIP for each family that is asked for. */
	private function vips(bool $v4, bool $v6): void
	{
		$row = static fn (string $address, string $id): array => ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
			'subnet_bits' => str_contains($address, ':') ? '128' : '32', 'descr' => 'operator VIP', 'uniqid' => $id];
		config_set_path('virtualip/vip', array_values(array_filter([$v4 ? $row(self::VIP4, 'v4') : NULL, $v6 ? $row(self::VIP6, 'v6') : NULL])));
		$this->store('pfb_dns_listen_vip', 'on');
		$this->store('pfb_dns_listen_vip4', $v4 ? '_vipv4' : '');
		$this->store('pfb_dns_listen_vip6', $v6 ? '_vipv6' : '');
		$this->assertSame(
			array_values(array_filter([$v4 ? self::VIP4 : NULL, $v6 ? self::VIP6 : NULL])),
			array_keys(pfb_dns_listen_vips()),
			'premise: the Resolver VIPs of the case are the active ones'
		);
	}

	/** An encrypted transport on, listening on these interfaces. */
	private function transport(string $kind, string $interfaces): void
	{
		$this->store("pfb_dns_{$kind}", 'on');
		$this->store("pfb_dns_{$kind}_interface", $interfaces);
	}

	// -----------------------------------------------------------------------
	// which addresses answer a query that arrived on an interface address
	// -----------------------------------------------------------------------

	public function testAQueryOnAnInterfaceAddressIsAnsweredWithThatInterfacesIpv4AndIpv6(): void
	{
		// Given the plain DNS list names lan, which carries both families
		$this->assertSame([self::LAN4, self::LAN6], pfb_dns_proxy_listen(), 'premise: plain DNS listens on both of the interface\'s addresses');

		// Then each of them is answered with the pair: an A query gets the IPv4 address, an AAAA query the IPv6 one (rows N6, N7)
		$this->assertSame(
			[self::LAN4 => [self::LAN4, self::LAN6], self::LAN6 => [self::LAN4, self::LAN6]],
			pfb_dns_proxy_name_answers()
		);
	}

	public function testAnInterfaceWithoutIpv6IsAnsweredWithItsIpv4Alone(): void
	{
		// Given the same interface with its IPv6 address gone
		$this->assertSame([self::LAN4 => [self::LAN4, self::LAN6], self::LAN6 => [self::LAN4, self::LAN6]], pfb_dns_proxy_name_answers(), 'before: both families');
		$this->interfaces(['lan' => [self::LAN4], 'opt1' => [self::OPT4, self::OPT6]]);

		// Then an AAAA query finds no address of its family: the entry carries the IPv4 address only
		$this->assertSame([self::LAN4 => [self::LAN4]], pfb_dns_proxy_name_answers());
	}

	public function testAnInterfaceThatHoldsOnlyAnIpv6AddressIsAnsweredWithItAlone(): void
	{
		$this->interfaces(['lan' => [self::LAN6], 'opt1' => [self::OPT4, self::OPT6]]);

		$this->assertSame([self::LAN6 => [self::LAN6]], pfb_dns_proxy_name_answers());
	}

	public function testAnInterfaceAddressKeepsItsOwnAnswersWhileAResolverVipIsActive(): void
	{
		// Given lan before any VIP (row N5: an A query on 10.0.0.1 gets 10.0.0.1)
		$before = pfb_dns_proxy_name_answers();
		$this->assertSame([self::LAN4, self::LAN6], $before[self::LAN4] ?? NULL, 'before: lan answers with its own addresses');

		// When an IPv4 VIP becomes active
		$this->vips(TRUE, FALSE);
		$after = pfb_dns_proxy_name_answers();

		// Then lan still answers with its own addresses, never the VIP; the VIP is one more entry that answers with itself
		$this->assertSame($before[self::LAN4], $after[self::LAN4] ?? NULL, 'the interface address is not answered with the VIP');
		$this->assertSame($before[self::LAN6], $after[self::LAN6] ?? NULL);
		$this->assertSame([self::LAN4 => [self::LAN4, self::LAN6], self::LAN6 => [self::LAN4, self::LAN6], self::VIP4 => [self::VIP4]], $after);
	}

	// -----------------------------------------------------------------------
	// which addresses answer a query that arrived on a Resolver VIP
	// -----------------------------------------------------------------------

	public function testAQueryOnTheIpv4VipIsAnsweredWithTheVipAndTheIpv6VipOnlyWhileThatOneIsActive(): void
	{
		// Given an IPv4 VIP alone: an AAAA query on it has no address of its family (row N9, no IPv6 VIP)
		$this->vips(TRUE, FALSE);
		$this->assertSame([self::VIP4], pfb_dns_proxy_name_answers()[self::VIP4] ?? NULL, 'the IPv4 VIP alone answers with itself');

		// When the IPv6 VIP is active too, an AAAA query on the IPv4 VIP gets it (row N9, with an IPv6 VIP)
		$this->vips(TRUE, TRUE);
		$answers = pfb_dns_proxy_name_answers();

		// Then each VIP answers with itself and the other family's VIP
		$this->assertSame([self::VIP4, self::VIP6], $answers[self::VIP4] ?? NULL);
		$this->assertSame([self::VIP6, self::VIP4], $answers[self::VIP6] ?? NULL);
	}

	public function testAQueryOnTheIpv6VipAloneIsAnsweredWithItself(): void
	{
		$this->vips(FALSE, TRUE);

		$this->assertSame([self::VIP6], pfb_dns_proxy_name_answers()[self::VIP6] ?? NULL);
	}

	public function testALoopbackOnlyListGivesTheVipsTheirOwnEntriesAndLoopbackNone(): void
	{
		// Given plain DNS on Localhost only, and no VIP: nothing but loopback listens, which is never answered
		$this->store('pfb_dns_interface', 'lo0');
		$this->assertSame([], pfb_dns_proxy_name_answers(), 'before: no VIP, no entry');

		// When both VIPs are active
		$this->vips(TRUE, TRUE);

		// Then the VIPs are the entries and 127.0.0.1 and ::1 are not
		$answers = pfb_dns_proxy_name_answers();
		$this->assertSame([self::VIP4, self::VIP6], array_keys($answers));
		$this->assertArrayNotHasKey('127.0.0.1', $answers);
		$this->assertArrayNotHasKey('::1', $answers);
	}

	// -----------------------------------------------------------------------
	// addresses that are not answered
	// -----------------------------------------------------------------------

	public function testAnAddressNoInterfaceCarriesAndAnInterfaceThatDoesNotExistGetNoEntry(): void
	{
		// Given lan, an IP entry no interface carries, and an interface name that is none
		$this->store('pfb_dns_interface', 'lan,203.0.113.9,em9');
		$this->assertSame([self::LAN4, self::LAN6, '203.0.113.9'], pfb_dns_proxy_listen(), 'premise: the gateway listens on the IP entry too');

		// Then only lan's addresses are answered (row N10: a query on 203.0.113.9 reaches Unbound)
		$this->assertSame([self::LAN4, self::LAN6], array_keys(pfb_dns_proxy_name_answers()));
	}

	public function testALinkLocalInterfaceAddressIsNeverAnAnswer(): void
	{
		// Given an interface whose IPv6 address is link-local: it is not listened on, and not an answer either
		$this->interfaces(['lan' => [self::LAN4, 'fe80::1']]);

		$this->assertSame([self::LAN4], pfb_dns_proxy_listen(), 'premise: the link-local address is not listened on');
		$this->assertSame([self::LAN4 => [self::LAN4]], pfb_dns_proxy_name_answers());
	}

	public function testAddressesAreSpelledAsTheGatewayTakesThem(): void
	{
		// Given an interface whose IPv6 address is stored in its long form
		$this->interfaces(['lan' => [self::LAN4, '2001:DB8:0:0:0:0:0:1']]);
		$this->assertContains('2001:DB8:0:0:0:0:0:1', pfb_dns_proxy_listen(), 'premise: the listener keeps the stored spelling');

		// Then both the key and the answer are spelled inet_ntop(inet_pton())
		$this->assertSame([self::LAN4 => [self::LAN4, self::LAN6], self::LAN6 => [self::LAN4, self::LAN6]], pfb_dns_proxy_name_answers());
	}

	// -----------------------------------------------------------------------
	// the union of the addresses the gateway listens on
	// -----------------------------------------------------------------------

	public function testAnEncryptedTransportAddsItsInterfacesAddressesOnlyWhileItIsOn(): void
	{
		// Given DoT configured on opt1, but off
		$this->store('pfb_dns_dot_interface', 'opt1');
		$this->assertSame([self::LAN4, self::LAN6], array_keys(pfb_dns_proxy_name_answers()), 'before: DoT off, only plain DNS\'s addresses');

		// When DoT is on
		$this->transport('dot', 'opt1');

		// Then opt1's addresses follow plain DNS's, in the order the gateway listens, each answered with its own interface's pair
		$this->assertSame(
			[self::LAN4 => [self::LAN4, self::LAN6], self::LAN6 => [self::LAN4, self::LAN6], self::OPT4 => [self::OPT4, self::OPT6], self::OPT6 => [self::OPT4, self::OPT6]],
			pfb_dns_proxy_name_answers()
		);
	}

	public function testAnAddressListenedOnByTwoTransportsIsOneEntry(): void
	{
		// Given plain DNS and DoT and DoQ all on lan
		$this->transport('dot', 'lan');
		$this->transport('doq', 'lan');

		$this->assertSame([self::LAN4, self::LAN6], array_keys(pfb_dns_proxy_name_answers()));
	}

	public function testDohOnPort443IsNotAnAddressOfTheInterfaceItReplacesWithTheVip(): void
	{
		// Given plain DNS on opt1 and DoH on lan with DoH on port 443, so that lan's DoH addresses are the VIPs' (pfb_dns_proxy_vip_only_families())
		$this->store('pfb_dns_interface', 'opt1');
		$this->transport('doh', 'lan');
		$this->store('pfb_dns_doh_port', '443');
		$this->assertSame([self::OPT4, self::OPT6, self::LAN4, self::LAN6], array_keys(pfb_dns_proxy_name_answers()), 'before: with no VIP, DoH on 443 still listens on lan');

		// When both VIPs are active
		$this->vips(TRUE, TRUE);

		// Then lan's own addresses are no entries any more: the VIPs stand in for them, and plain DNS is on opt1
		$this->assertSame([self::OPT4, self::OPT6, self::VIP4, self::VIP6], array_keys(pfb_dns_proxy_name_answers()));
	}

	// -----------------------------------------------------------------------
	// the flags
	// -----------------------------------------------------------------------

	/** The pairs of lan, as the flags spell them. */
	private static function lanFlags(): string
	{
		return " --dns-name-answer '" . self::LAN4 . '=' . self::LAN4 . ',' . self::LAN6 . "'"
			. " --dns-name-answer '" . self::LAN6 . '=' . self::LAN4 . ',' . self::LAN6 . "'";
	}

	public function testNoDnsNameMeansNoFlagAtAllEvenWithDdrOn(): void
	{
		// Given a name, DDR on and a transport: the full flag set (before-state, so that the empty result below is the name's doing)
		$this->store('pfb_dns_name', self::NAME);
		$this->store('pfb_dns_ddr', 'on');
		$this->store('pfb_dns_ddr_doh_443', 'on');
		$this->assertSame(" --dns-name '" . self::NAME . "' --ddr --ddr-doh-443 --ddr-doh-4436" . self::lanFlags(), pfb_dns_proxy_ddr_flags(), 'before');

		// When the name is empty
		$this->store('pfb_dns_name', '');

		// Then there is no --dns-name, no --ddr, no --ddr-doh-* and no --dns-name-answer (row N2)
		$this->assertSame('', pfb_dns_proxy_ddr_flags());
	}

	public function testANameWithDdrOffGivesTheNameAndTheAnswersButNoDdrFlag(): void
	{
		$this->store('pfb_dns_name', self::NAME);
		$this->store('pfb_dns_ddr_doh_443', 'on'); // stored, but it only means something beside --ddr

		$this->assertSame(" --dns-name '" . self::NAME . "'" . self::lanFlags(), pfb_dns_proxy_ddr_flags());
	}

	public function testANameWithDdrOnGivesTheDdrFlagsBetweenTheNameAndTheAnswers(): void
	{
		$this->store('pfb_dns_name', self::NAME);
		$this->store('pfb_dns_ddr', 'on');
		$this->assertSame(" --dns-name '" . self::NAME . "' --ddr" . self::lanFlags(), pfb_dns_proxy_ddr_flags(), 'DDR alone');

		$this->store('pfb_dns_ddr_doh_443', 'on');
		$this->assertSame(" --dns-name '" . self::NAME . "' --ddr --ddr-doh-443 --ddr-doh-4436" . self::lanFlags(), pfb_dns_proxy_ddr_flags(), 'with the 443 options');
	}

	public function testANameWithNothingToAnswerOnGivesTheNameAlone(): void
	{
		// Given a plain DNS list that names no address (an interface that does not exist)
		$this->store('pfb_dns_name', self::NAME);
		$this->assertSame(" --dns-name '" . self::NAME . "'" . self::lanFlags(), pfb_dns_proxy_ddr_flags(), 'before: lan listens');
		$this->store('pfb_dns_interface', 'em9');

		// Then the name is given with no answer
		$this->assertSame(" --dns-name '" . self::NAME . "'", pfb_dns_proxy_ddr_flags());
	}

	public function testEachAnswerOfTheFlagsIsOneQuotedWordOfLocalAndItsAddresses(): void
	{
		// Given both VIPs and a name
		$this->store('pfb_dns_name', self::NAME);
		$this->vips(TRUE, TRUE);

		// Then each VIP's flag is one word: LOCAL=ADDR,ADDR in single quotes
		$this->assertStringContainsString(" --dns-name-answer '" . self::VIP4 . '=' . self::VIP4 . ',' . self::VIP6 . "'", pfb_dns_proxy_ddr_flags());
		$this->assertStringContainsString(" --dns-name-answer '" . self::VIP6 . '=' . self::VIP6 . ',' . self::VIP4 . "'", pfb_dns_proxy_ddr_flags());
	}

	/** @return array<string,array{string}> stored names the page never saves: a hand-edited config.xml */
	public static function storedNamesThatAreNoName(): array
	{
		return [
			'text a shell would run' => ["fw.example.lan'; rm -rf /"],
			'a wildcard' => ['*.example.lan'],
			'an IPv4 literal' => ['10.0.0.1'],
			'one label' => ['fw'],
			'under resolver.arpa' => ['fw.resolver.arpa'],
			'not ASCII' => ['bücher.example'],
			'two trailing dots' => ['fw.example.lan..'],
		];
	}

	#[DataProvider('storedNamesThatAreNoName')]
	public function testAStoredNameThatIsNoValidNameGivesNoFlagAtAll(string $stored): void
	{
		// Given DDR on and a valid name: the flags are there
		$this->store('pfb_dns_ddr', 'on');
		$this->store('pfb_dns_name', self::NAME);
		$this->assertNotSame('', pfb_dns_proxy_ddr_flags(), 'before: a valid name gives flags');

		// When config.xml holds one the gateway would refuse to start with
		$this->store('pfb_dns_name', $stored);

		// Then nothing reaches the gateway
		$this->assertSame('', pfb_dns_proxy_ddr_flags());
	}
}
