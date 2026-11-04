<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694 -- "Advertise DoH on port 443" is one multi-select (`dns/pfb_dns_ddr_doh_443_interfaces`) instead of two per-family
 * checkboxes. On the addresses of a selected entry DDR advertises DoH without a `port` (the gateway's --ddr-doh-443 ADDR), while pfB-DNS
 * keeps listening on its configured DoH port there; every other address advertises the configured port. An automatically created
 * Resolver VIP serves DoH on 443 itself (--doh-listen-443), so it advertises 443 without being selected, and is never offered.
 *
 * Functions under test, through their production surface:
 *   - pfb_dns_proxy_ddr_doh_443_options(): the DoH interfaces (no Localhost), then each user-selected Resolver VIP, never the automatic one.
 *   - pfb_validate_dns_proxy_listeners_post() / pfb_dns_proxy_listeners_stored(): every entry must be an option of the POSTED DoH list; stored
 *     as a deduplicated comma list; the two retired toggles are stored no more.
 *   - pfb_dns_proxy_ddr_doh_443_addresses(): which DoH listen addresses DDR advertises on 443.
 *   - pfb_dns_proxy_ddr_flags() / pfb_dns_proxy_tls_flags(): one --ddr-doh-443 per such address after --ddr, and one --doh-listen-443 per
 *     active automatic VIP whose family's DoH port is not 443 already.
 */
#[CoversFunction('pfb_dns_proxy_ddr_doh_443_options')]
#[CoversFunction('pfb_dns_proxy_ddr_doh_443_addresses')]
#[CoversFunction('pfb_dns_proxy_ddr_flags')]
#[CoversFunction('pfb_dns_proxy_tls_flags')]
#[CoversFunction('pfb_dns_proxy_listeners_stored')]
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
final class DnsProxyDdrDoh443InterfacesTest extends TestCase
{
	private const NAME = 'fw.example.lan';
	private const LAN4 = '192.0.2.1';
	private const LAN6 = '2001:db8::1';
	private const OPT4 = '198.51.100.1';
	private const OPT6 = 'fd12:3456::1';
	private const AUTO4 = '172.16.53.53';
	private const AUTO6 = 'fd00:53:53:53:53:53:53:1';
	private const USER4 = '172.16.99.9';
	private const FIELD = 'pfb_dns_ddr_doh_443_interfaces';
	private const IFACES = ['all', 'lo0', 'lan', 'opt1'];

	private const GLOBALS = [
		'config', 'pfb', 'pfb_test_vip_list', 'pfb_test_configured_subnets', 'pfb_test_interface_ip', 'pfb_test_configured_ipv6',
		'pfb_test_interface_info', 'pfb_test_configured_ip_addresses', 'pfb_test_interfaces',
		'pfb_test_file_notices', 'pfb_test_write_config_calls',
	];

	/** @var array<string,array{0:bool,1:mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_vip_list'] = [];
		$GLOBALS['pfb_test_configured_subnets'] = [];
		unset($GLOBALS['pfb_test_configured_ip_addresses']);
		// lan and opt1 are up, each with an IPv4 and an IPv6 address
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => self::LAN4, 'opt1' => self::OPT4, 'lo0' => '127.0.0.1'];
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => self::LAN6, 'opt1' => self::OPT6];
		$GLOBALS['pfb_test_interface_info'] = array_fill_keys(['lan', 'opt1', 'lo0'], ['status' => 'up', 'enable' => TRUE]);
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'OPT1'];
		$this->store('pfb_dns_interface', 'lan'); // seeded: an unseeded list makes every setting read as the Resolver's
		$this->store('pfb_dns_name', self::NAME);
		$this->store('pfb_dns_ddr', 'on');
		$this->doh('lan');
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

	/** One stored pfB-DNS setting, straight into config.xml. */
	private function store(string $key, string $value): void
	{
		config_set_path(PFB_SECTIONS[explode('/', pfb_dns_config_key($key), 2)[0]] . '/' . $key, $value);
	}

	/** DoH on, at its default port, listening on these interfaces. */
	private function doh(string $interfaces): void
	{
		$this->store('pfb_dns_doh', 'on');
		$this->store('pfb_dns_doh_port', '4443');
		$this->store('pfb_dns_doh_interface', $interfaces);
	}

	private function select(string $tokens): void
	{
		$this->store(self::FIELD, $tokens);
	}

	/**
	 * Resolver VIPs, one per family: 'auto' is the one the package created (marked row, published address), anything else the id of a VIP
	 * the operator chose. The Resolver addresses option is on.
	 *
	 * @param array<int,array{string,string}> $byFamily family => [selection, address]
	 */
	private function vips(array $byFamily): void
	{
		$rows = [];
		foreach ($byFamily as $family => [$selection, $address]) {
			$auto = $selection === 'auto';
			$rows[] = ['mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $address,
				'subnet_bits' => ($family === 6) ? '128' : '32', 'descr' => $auto ? "pfB_DNS_LISTEN_VIP_v{$family}" : 'operator VIP',
				'uniqid' => $auto ? "auto{$family}" : substr($selection, 4)];
			$this->store("pfb_dns_listen_vip{$family}", $selection);
			if ($auto) {
				$this->store("pfb_dns_listen_auto{$family}", $address);
			}
		}
		foreach (array_diff([4, 6], array_keys($byFamily)) as $family) {
			$this->store("pfb_dns_listen_vip{$family}", '');
		}
		config_set_path('virtualip/vip', $rows);
		$this->store('pfb_dns_listen_vip', 'on');
		$this->assertSame(
			array_values(array_map(static fn (array $vip): string => $vip[1], $byFamily)),
			array_keys(pfb_dns_listen_vips()),
			'premise: the Resolver VIPs of the case are the active ones'
		);
	}

	// -----------------------------------------------------------------------
	// the options of the select
	// -----------------------------------------------------------------------

	public function testTheOptionsAreTheDohInterfacesWithoutLocalhostLabelledAsTheInterfaceListsLabelThem(): void
	{
		// Given DoH on Localhost, lan and opt1
		$this->store('pfb_dns_doh_interface', 'lo0,lan,opt1');
		$labels = pfb_dns_proxy_interface_options();

		// Then lan and opt1 are offered under the labels the interface lists give them, and Localhost is not
		$this->assertSame(['lan' => $labels['lan'], 'opt1' => $labels['opt1']], pfb_dns_proxy_ddr_doh_443_options());
		$this->assertSame(['LAN', 'OPT1'], array_values(pfb_dns_proxy_ddr_doh_443_options()), 'premise: the labels are the descriptions');
	}

	public function testAUserSelectedResolverVipIsOfferedByItsAddressAndTheAutomaticOneNever(): void
	{
		// Given no VIP: the interface only
		$this->assertSame(['lan' => 'LAN'], pfb_dns_proxy_ddr_doh_443_options(), 'before: no VIP');

		// When the operator chose the IPv4 VIP and the package created the IPv6 one
		$this->vips([4 => ['_vipuser4', self::USER4], 6 => ['auto', self::AUTO6]]);

		// Then the chosen VIP follows the interface under its address, and the created one is not offered
		$this->assertSame(['lan' => 'LAN', '_vipuser4' => self::USER4], pfb_dns_proxy_ddr_doh_443_options());

		// And with the created VIP alone, there is nothing to add
		$this->vips([6 => ['auto', self::AUTO6]]);
		$this->assertSame(['lan' => 'LAN'], pfb_dns_proxy_ddr_doh_443_options());
	}

	public function testAVipThatTheDohListAlreadyNamesIsOfferedOnce(): void
	{
		// Given the VIP is among the DoH interface tokens
		$GLOBALS['pfb_test_vip_list'] = ['_vipuser4' => self::USER4];
		$this->store('pfb_dns_doh_interface', 'lan,_vipuser4');
		$this->assertSame(['lan' => 'LAN', '_vipuser4' => self::USER4], pfb_dns_proxy_ddr_doh_443_options(), 'before: no Resolver VIP chosen');

		// When the same VIP is the operator's chosen Resolver VIP
		$this->vips([4 => ['_vipuser4', self::USER4]]);

		// Then it is still offered once
		$this->assertSame(['lan' => 'LAN', '_vipuser4' => self::USER4], pfb_dns_proxy_ddr_doh_443_options());
	}

	public function testAChosenVipThatNoLongerExistsIsOfferedAsNotAvailableSoThatASaveKeepsIt(): void
	{
		$this->vips([4 => ['_vipuser4', self::USER4]]);
		config_set_path('virtualip/vip', []);

		$this->assertSame(['lan' => 'LAN', '_vipuser4' => '_vipuser4 (not currently available)'], pfb_dns_proxy_ddr_doh_443_options());
	}

	public function testTheOptionsFollowThePostedDohListWhenOneIsGiven(): void
	{
		$this->doh('lan,opt1');
		$this->assertSame(['lan' => 'LAN', 'opt1' => 'OPT1'], pfb_dns_proxy_ddr_doh_443_options(), 'before: the stored list');

		$this->assertSame(['opt1' => 'OPT1'], pfb_dns_proxy_ddr_doh_443_options(['opt1']), 'a posted list');
		$this->assertSame(['all' => 'All'], pfb_dns_proxy_ddr_doh_443_options(['all', 'lo0']), 'All is offered, Localhost never');
	}

	// -----------------------------------------------------------------------
	// validation and storage
	// -----------------------------------------------------------------------

	/** @param array<string,mixed> $over */
	private function post(array $over = []): array
	{
		return $over + [
			'pfb_dns_interface' => ['lan'],
			'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853', 'pfb_dns_dot_interface' => ['lan'],
			'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '4443', 'pfb_dns_doh_interface' => ['lan', 'opt1'],
			'pfb_dns_doh_trusted' => '',
			'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '853', 'pfb_dns_doq_interface' => ['lan'],
			'pfb_dns_sslcertref' => '', 'pfb_dns_name' => self::NAME, 'pfb_dns_ddr' => '',
		];
	}

	/** @return list<string> */
	private function errors(array $post): array
	{
		return pfb_validate_dns_proxy_listeners_post($post, self::IFACES, []);
	}

	/** @return array<string,array{array<int,mixed>,string}> posted entries, what is stored */
	public static function acceptedSelections(): array
	{
		return [
			'one interface' => [['lan'], 'lan'],
			'both interfaces, in the order posted' => [['opt1', 'lan'], 'opt1,lan'],
			'a duplicate entry' => [['lan', 'lan', 'opt1', 'lan'], 'lan,opt1'],
			'nothing selected' => [[], ''],
		];
	}

	/** @param array<int,mixed> $posted */
	#[DataProvider('acceptedSelections')]
	public function testAnEntryThatIsAnOptionIsAcceptedAndStoredAsADeduplicatedCommaList(array $posted, string $stored): void
	{
		$post = $this->post([self::FIELD => $posted]);

		$this->assertSame([], $this->errors($post));
		$this->assertSame($stored, pfb_dns_proxy_listeners_stored($post)[self::FIELD] ?? NULL);
	}

	public function testAChosenVipIsAnAcceptedEntry(): void
	{
		$post = $this->post([self::FIELD => ['lan', '_vipuser4']]);
		$this->assertSame(["Advertise DoH on port 443: Invalid selection: _vipuser4"], $this->errors($post), 'before: no such VIP is chosen');

		$this->vips([4 => ['_vipuser4', self::USER4]]);

		$this->assertSame([], $this->errors($post));
		$this->assertSame('lan,_vipuser4', pfb_dns_proxy_listeners_stored($post)[self::FIELD] ?? NULL);
	}

	/** @return array<string,array{array<int,mixed>,list<string>}> posted entries, the errors */
	public static function refusedSelections(): array
	{
		$invalid = static fn (string $token): string => "Advertise DoH on port 443: Invalid selection: {$token}";
		return [
			'Localhost' => [['lo0'], [$invalid('lo0')]],
			'an interface the DoH list does not name' => [['em9'], [$invalid('em9')]],
			'the automatic VIP' => [['_vipauto4'], [$invalid('_vipauto4')]],
			'a VIP that does not exist' => [['_vipnobody'], [$invalid('_vipnobody')]],
			'markup, escaped in the error' => [['<script>alert(1)</script>'], [$invalid('&lt;script&gt;alert(1)&lt;/script&gt;')]],
			'a quote, escaped in the error' => [["lan'\""], [$invalid('lan&#039;&quot;')]],
			'an entry that is not text' => [[5], [$invalid('')]],
			'an array entry' => [[['lan']], [$invalid('')]],
			'a valid entry beside an invalid one' => [['lan', 'lo0', 'opt1'], [$invalid('lo0')]],
			'two invalid entries' => [['lo0', 'em9'], [$invalid('lo0'), $invalid('em9')]],
		];
	}

	/**
	 * @param array<int,mixed> $posted
	 * @param list<string> $errors
	 */
	#[DataProvider('refusedSelections')]
	public function testAnEntryThatIsNoOptionIsAnInputErrorThatNamesItEscapedAndRaisesNoPhpWarning(array $posted, array $errors): void
	{
		// Given a VIP the package created, so that the automatic VIP is an id that exists and still is no option
		$this->vips([4 => ['auto', self::AUTO4]]);
		$this->assertSame([], $this->errors($this->post([self::FIELD => ['lan']])), 'before: a valid entry');

		$warnings = [];
		set_error_handler(static function (int $_number, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		});
		try {
			$found = $this->errors($this->post([self::FIELD => $posted]));
			$stored = pfb_dns_proxy_listeners_stored($this->post([self::FIELD => $posted]));
		} finally {
			restore_error_handler();
		}

		$this->assertSame($errors, $found);
		$this->assertSame([], $warnings, 'no PHP warning');
		$this->assertIsString($stored[self::FIELD] ?? NULL, 'whatever was posted, a text is stored');
	}

	public function testAnEntryIsJudgedAgainstThePostedDohListNotTheStoredOne(): void
	{
		// Given opt1 on the stored DoH list, and a post that takes it off while selecting it
		$this->doh('lan,opt1');
		$this->assertSame([], $this->errors($this->post(['pfb_dns_doh_interface' => ['lan', 'opt1'], self::FIELD => ['opt1']])), 'before: opt1 is on the posted list');

		$this->assertSame(
			['Advertise DoH on port 443: Invalid selection: opt1'],
			$this->errors($this->post(['pfb_dns_doh_interface' => ['lan'], self::FIELD => ['opt1']]))
		);
	}

	public function testAnAbsentOrNotAnArraySelectionIsStoredEmptyWithoutAnError(): void
	{
		$post = $this->post();
		unset($post[self::FIELD]);
		$this->assertSame([], $this->errors($post), 'absent');
		$this->assertSame('', pfb_dns_proxy_listeners_stored($post)[self::FIELD] ?? NULL, 'absent');

		foreach (['lan', '', 7, TRUE, NULL] as $notAnArray) {
			$post = $this->post([self::FIELD => $notAnArray]);
			$this->assertSame([], $this->errors($post), 'a ' . get_debug_type($notAnArray));
			$this->assertSame('', pfb_dns_proxy_listeners_stored($post)[self::FIELD] ?? NULL, 'a ' . get_debug_type($notAnArray));
		}
	}

	public function testTheTwoRetiredTogglesAreNotStoredAnyMoreWhateverIsPosted(): void
	{
		$stored = pfb_dns_proxy_listeners_stored($this->post(['pfb_dns_ddr_doh_443' => 'on', 'pfb_dns_ddr_doh_443_6' => 'on', self::FIELD => ['lan']]));

		$this->assertArrayNotHasKey('pfb_dns_ddr_doh_443', $stored);
		$this->assertArrayNotHasKey('pfb_dns_ddr_doh_443_6', $stored);
		$this->assertSame('lan', $stored[self::FIELD] ?? NULL);
	}

	// -----------------------------------------------------------------------
	// which addresses DDR advertises on 443
	// -----------------------------------------------------------------------

	public function testNothingSelectedAdvertisesNothing(): void
	{
		// Given DoH on lan and opt1 and an interface selected (before), then nothing selected (row D1: the configured port everywhere)
		$this->doh('lan,opt1');
		$this->select('lan');
		$this->assertSame([self::LAN4, self::LAN6], pfb_dns_proxy_ddr_doh_443_addresses(), 'before: lan selected');

		$this->select('');

		$this->assertSame([], pfb_dns_proxy_ddr_doh_443_addresses());
	}

	public function testASelectedInterfaceAdvertisesItsDohAddressesAndAnotherOneDoesNot(): void
	{
		$this->doh('lan,opt1');

		$this->select('lan');
		$this->assertSame([self::LAN4, self::LAN6], pfb_dns_proxy_ddr_doh_443_addresses(), 'lan alone (row D2)');
		$this->select('opt1');
		$this->assertSame([self::OPT4, self::OPT6], pfb_dns_proxy_ddr_doh_443_addresses(), 'opt1 alone');
		$this->select('opt1,lan');
		$this->assertSame([self::LAN4, self::LAN6, self::OPT4, self::OPT6], pfb_dns_proxy_ddr_doh_443_addresses(), 'both, in the order DoH listens');
	}

	public function testNothingIsAdvertisedWhileDohIsOffOrForAnInterfaceThatLeftTheDohList(): void
	{
		$this->doh('lan,opt1');
		$this->select('opt1');
		$this->assertSame([self::OPT4, self::OPT6], pfb_dns_proxy_ddr_doh_443_addresses(), 'before');

		// When opt1 leaves the DoH list: the selection stays stored and no longer advertises
		$this->doh('lan');
		$this->assertSame([], pfb_dns_proxy_ddr_doh_443_addresses(), 'opt1 does not listen for DoH');

		// And with DoH off, nothing is advertised whatever is selected
		$this->doh('lan,opt1');
		$this->store('pfb_dns_doh', '');
		$this->assertSame([], pfb_dns_proxy_ddr_doh_443_addresses(), 'DoH off');
	}

	public function testAChosenVipIsAdvertisedOnlyWhileItsIdIsSelectedAndNeverByItsInterfaceBeingSelected(): void
	{
		$this->vips([4 => ['_vipuser4', self::USER4]]);
		$this->select('');
		$this->assertSame([], pfb_dns_proxy_ddr_doh_443_addresses(), 'nothing selected (row D5, not selected)');

		$this->select('_vipuser4');
		$this->assertSame([self::USER4], pfb_dns_proxy_ddr_doh_443_addresses(), 'the VIP selected (row D5, selected)');

		// The VIP joins the lan addresses DoH listens on, but selecting lan does not advertise it
		$this->select('lan');
		$this->assertSame([self::LAN4, self::LAN6], pfb_dns_proxy_ddr_doh_443_addresses(), 'lan selected, the VIP not');

		$this->select('lan,_vipuser4');
		$this->assertSame([self::LAN4, self::LAN6, self::USER4], pfb_dns_proxy_ddr_doh_443_addresses(), 'both');
	}

	public function testTheAutomaticVipIsNeverAmongTheAddressesAndTheInterfaceItJoinsDoesNotBringItIn(): void
	{
		// Given the package's VIP, which DoH listens on beside lan's addresses
		$this->vips([4 => ['auto', self::AUTO4]]);
		$this->assertContains(self::AUTO4, pfb_dns_proxy_interface_addresses(['lan'], []), 'premise: DoH listens on the VIP too');

		// When lan is selected, then the interface's addresses are advertised and the VIP is not: it serves 443 itself (row D3)
		$this->select('lan');

		$this->assertSame([self::LAN4, self::LAN6], pfb_dns_proxy_ddr_doh_443_addresses());
	}

	public function testAnInterfaceAddressDohDoesNotListenOnBecauseItsFamilyIsOnPort443IsNotAdvertised(): void
	{
		// Given DoH on port 443 for IPv4 and 4443 for IPv6, and the package's IPv4 VIP: DoH leaves lan's IPv4 address to the VIP (row D7)
		$this->vips([4 => ['auto', self::AUTO4]]);
		$this->store('pfb_dns_doh_port', '443');
		$this->store('pfb_dns_doh_port6', '4443');
		$this->select('lan');

		$this->assertSame([self::LAN6], pfb_dns_proxy_ddr_doh_443_addresses());
	}

	// -----------------------------------------------------------------------
	// the flags
	// -----------------------------------------------------------------------

	/** @return list<string> the addresses of every --ddr-doh-443 of the flags, in order */
	private static function doh443Flags(string $flags): array
	{
		preg_match_all("/ --ddr-doh-443 '([^']*)'/", $flags, $found);
		return $found[1];
	}

	public function testEachAdvertisedAddressIsOneQuotedFlagAfterDdrAndBeforeTheNameAnswers(): void
	{
		// Given DDR on and nothing selected: the name flags carry no 443 flag (row D1)
		$this->doh('lan,opt1');
		$this->assertSame([], self::doh443Flags(pfb_dns_proxy_ddr_flags()), 'before: nothing selected');

		// When lan is selected (row D2)
		$this->select('lan');
		$flags = pfb_dns_proxy_ddr_flags();

		// Then each of its addresses is a flag of its own, after --ddr and before the first name answer
		$this->assertSame([self::LAN4, self::LAN6], self::doh443Flags($flags));
		$this->assertStringContainsString(" --ddr --ddr-doh-443 '" . self::LAN4 . "' --ddr-doh-443 '" . self::LAN6 . "' --dns-name-answer '", $flags);
		$this->assertStringNotContainsString('--ddr-doh-4436', $flags, 'the per-family flag is gone');
	}

	public function testNoAddressFlagWithoutDdrAndTheRetiredTogglesChangeNothing(): void
	{
		$this->select('lan');
		$this->assertSame([self::LAN4, self::LAN6], self::doh443Flags(pfb_dns_proxy_ddr_flags()), 'before: DDR on');

		// When DDR is off, the selection is kept and advertises nothing
		$this->store('pfb_dns_ddr', '');
		$this->assertSame([], self::doh443Flags(pfb_dns_proxy_ddr_flags()), 'DDR off');
		$this->assertStringNotContainsString('--ddr', pfb_dns_proxy_ddr_flags(), 'DDR off');

		// And a retired toggle a hand-edit or a restored backup left behind is ignored
		$this->store('pfb_dns_ddr', 'on');
		$this->select('');
		config_set_path(PFB_SECTIONS['dns_shared'] . '/pfb_dns_ddr_doh_443', 'on');
		config_set_path(PFB_SECTIONS['dns_shared'] . '/pfb_dns_ddr_doh_443_6', 'on');
		$this->assertSame([], self::doh443Flags(pfb_dns_proxy_ddr_flags()), 'a retired toggle on');
		$this->assertStringNotContainsString('--ddr-doh-4436', pfb_dns_proxy_ddr_flags());
	}

	/**
	 * @return array<string,list<string>> a retired switch, the section it is stored in, its value, and optionally a second switch kept
	 *                                    in that section with the same value; a key of '' stores no switch at all
	 */
	public static function retiredSwitches(): array
	{
		return [
			'the IPv4 switch On, in the shared section' => ['pfb_dns_ddr_doh_443', 'dns_shared', 'on'],
			'the IPv6 switch On, in the shared section' => ['pfb_dns_ddr_doh_443_6', 'dns_shared', 'on'],
			'the IPv4 switch On, in the pfB-DNS section (before the split)' => ['pfb_dns_ddr_doh_443', 'dns', 'on'],
			'the IPv4 switch Off' => ['pfb_dns_ddr_doh_443', 'dns_shared', ''],
			'both switches On, in the shared section' => ['pfb_dns_ddr_doh_443', 'dns_shared', 'on', 'pfb_dns_ddr_doh_443_6'],
			'no switch stored at all' => ['', 'dns_shared', ''],
		];
	}

	/**
	 * Issue #3694: a retired Nightly switch is never copied into the selection. The ordinary upgrade leaves the selection unset, advertises
	 * nothing on 443 by choice, and files no notice.
	 */
	#[DataProvider('retiredSwitches')]
	public function testARetiredSwitchNeverSeedsTheSelectionOnTheOrdinaryUpgrade(string $key, string $section, string $value, string $other = ''): void
	{
		// Given DoH on lan with DDR on, the retired switch(es) stored, and the selection never set
		foreach (array_filter([$key, $other]) as $name) {
			config_set_path(PFB_SECTIONS[$section] . '/' . $name, $value);
		}
		$this->assertNull(config_get_path(PFB_SECTIONS['dns'] . '/' . self::FIELD), 'before: the selection is never set');

		// When the ordinary upgrade runs
		pfb_run_migrations();

		// Then the selection stays unset, nothing is advertised on 443 by choice, and no notice is filed
		$this->assertNull(config_get_path(PFB_SECTIONS['dns'] . '/' . self::FIELD), 'the switch is not copied into the selection');
		$this->assertSame([], pfb_dns_proxy_ddr_doh_443_addresses());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice about the retired switch');
	}

	/** Issue #3694: an explicit selection is kept on the ordinary upgrade, whatever the retired switches say. */
	public function testAnExplicitSelectionSurvivesTheOrdinaryUpgradeWhateverTheRetiredSwitches(): void
	{
		// Given lan chosen under the new selection, and the Nightly switch On beside it
		$this->select('lan');
		config_set_path(PFB_SECTIONS['dns_shared'] . '/pfb_dns_ddr_doh_443', 'on');

		// When the ordinary upgrade runs
		pfb_run_migrations();

		// Then lan stays chosen and is still advertised on 443 on its addresses, and no notice is filed
		$this->assertSame('lan', PfbConfig::read('dns/' . self::FIELD));
		$this->assertSame([self::LAN4, self::LAN6], pfb_dns_proxy_ddr_doh_443_addresses());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice: nothing was seeded');
	}

	public function testTheAutomaticVipIsNeverInTheNameFlagsAndAChosenOneIsWhenSelected(): void
	{
		$this->vips([4 => ['auto', self::AUTO4], 6 => ['_vipuser6', 'fd00:99::9']]);
		$this->select('lan');
		$this->assertSame([self::LAN4, self::LAN6], self::doh443Flags(pfb_dns_proxy_ddr_flags()), 'the created VIP and the unselected chosen one stay out');

		$this->select('lan,_vipuser6');
		$this->assertSame([self::LAN4, self::LAN6, 'fd00:99::9'], self::doh443Flags(pfb_dns_proxy_ddr_flags()));
	}

	/** @return list<string> the addresses of every --doh-listen-443 of the DoH flags, in order */
	private static function dohListen443(string $flags): array
	{
		preg_match_all("/ --doh-listen-443 '([^']*)'/", $flags, $found);
		return $found[1];
	}

	public function testTheAutomaticVipServesDohOn443BesideItsConfiguredPortRightAfterTheDohListeners(): void
	{
		// Given DoH on lan, and no VIP: no 443 listener
		$warnings = [];
		$this->assertSame([], self::dohListen443(pfb_dns_proxy_tls_flags($warnings)), 'before: no VIP');

		// When the package's IPv4 VIP is active (row D3)
		$this->vips([4 => ['auto', self::AUTO4]]);
		$flags = pfb_dns_proxy_tls_flags($warnings);

		// Then DoH listens on it at its configured port as before, and also on 443, the flag following the --doh-listen group
		$this->assertStringContainsString(" --doh-listen '" . self::AUTO4 . "'", $flags);
		$this->assertSame([self::AUTO4], self::dohListen443($flags));
		$this->assertStringContainsString(" --doh-listen '::1' --doh-listen-443 '" . self::AUTO4 . "' --doh-port '4443'", $flags);
	}

	public function testBothAutomaticVipsGetTheirOwnFlagInFamilyOrder(): void
	{
		$this->vips([4 => ['auto', self::AUTO4], 6 => ['auto', self::AUTO6]]);
		$warnings = [];

		$this->assertSame([self::AUTO4, self::AUTO6], self::dohListen443(pfb_dns_proxy_tls_flags($warnings)));
	}

	public function testAChosenVipGetsNoFlagBecauseOnlyTheAutomaticOneServes443(): void
	{
		$this->vips([4 => ['_vipuser4', self::USER4]]);
		$warnings = [];

		$flags = pfb_dns_proxy_tls_flags($warnings);

		$this->assertStringContainsString(" --doh-listen '" . self::USER4 . "'", $flags, 'premise: DoH listens on the chosen VIP');
		$this->assertSame([], self::dohListen443($flags));
	}

	public function testAFamilyWhoseDohPortIs443AlreadyGetsNoSecondListenerOnItsVip(): void
	{
		// Given both created VIPs, DoH on 443 for IPv4 and 4443 for IPv6 (row D7)
		$this->vips([4 => ['auto', self::AUTO4], 6 => ['auto', self::AUTO6]]);
		$warnings = [];
		$this->assertSame([self::AUTO4, self::AUTO6], self::dohListen443(pfb_dns_proxy_tls_flags($warnings)), 'before: both ports are 4443');
		$this->store('pfb_dns_doh_port', '443');
		$this->store('pfb_dns_doh_port6', '4443');

		$flags = pfb_dns_proxy_tls_flags($warnings);

		// Then the IPv4 VIP serves 443 once, as its DoH port, and only the IPv6 one is given the extra listener
		$this->assertSame([self::AUTO6], self::dohListen443($flags));
		$this->assertStringContainsString(" --doh-listen '" . self::AUTO4 . "'", $flags);
	}

	public function testNoVipListenerOnPort443WhileDohIsOffOrDoesNotListenOnTheVip(): void
	{
		$this->vips([4 => ['auto', self::AUTO4]]);
		$warnings = [];
		$this->assertSame([self::AUTO4], self::dohListen443(pfb_dns_proxy_tls_flags($warnings)), 'before');

		// DoH off: no DoH flag of any kind
		$this->store('pfb_dns_doh', '');
		$this->assertSame('', pfb_dns_proxy_tls_flags($warnings), 'DoH off');

		// DoH on an interface list that names no usable address: loopback only, and the VIP is not joined, so it gets no 443 listener either
		$this->store('pfb_dns_doh', 'on');
		$this->store('pfb_dns_doh_interface', 'em9');
		$flags = pfb_dns_proxy_tls_flags($warnings);
		$this->assertStringContainsString(" --doh-listen '127.0.0.1'", $flags, 'premise: DoH still listens on loopback');
		$this->assertStringNotContainsString(self::AUTO4, $flags);
		$this->assertSame([], self::dohListen443($flags));
	}
}
