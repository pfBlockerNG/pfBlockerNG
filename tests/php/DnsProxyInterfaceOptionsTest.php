<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3557 -- the pfB-DNS page offers and accepts the interface tokens the DNS Resolver's Network Interfaces do
 * (configured interfaces and virtual IPs, `_vip<uniqid>`), and keeps every token it already stores selectable, labelled
 * "not currently available" when nothing offers it any more (a removed or disabled interface, a deleted VIP). A save
 * that leaves the selection alone therefore stores every token it read; a token neither offered nor stored is rejected.
 *
 * Page-level round trip: the page's own load statements (from `$pconfig = array();` to the option lists) run against a
 * seeded config, a browser POST is derived from what they render (a multi-select submits each selected value that is an
 * option, in option order), and that POST goes through the validation and the canonical store the page's save calls
 * with the keys of the same option list (the call shape is pinned by PfbDnsPageWiringTest).
 */
#[CoversFunction('pfb_dns_proxy_interface_options')]
#[CoversFunction('pfb_validate_dns_proxy_listeners_post')]
#[CoversFunction('pfb_dns_proxy_listeners_stored')]
final class DnsProxyInterfaceOptionsTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_dns.php';
	private const LISTS = ['pfb_dns_interface', 'pfb_dns_dot_interface', 'pfb_dns_doh_interface', 'pfb_dns_doq_interface'];
	private const VIP = '_vip5f3a1b2c3d4e5';
	private const GLOBALS = ['pfb', 'config', 'pfb_test_interfaces', 'pfb_test_vip_list'];

	private string $tmp;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_iface_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'logdir' => $this->tmp, 'log' => "{$this->tmp}/pfb.log", 'errlog' => "{$this->tmp}/pfb.err",
		]);
		// The box: LAN configured, one CARP/IP-alias virtual IP; OPT2 was removed or disabled.
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN'];
		$GLOBALS['pfb_test_vip_list'] = [self::VIP => '192.0.2.5'];
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

	/** A box whose Resolver listens on $active and whose pfB-DNS section stores $stored in each of its four interface lists ('' = not seeded yet). */
	private function seedBox(string $active, string $stored): void
	{
		$dns = $stored === '' ? [] : array_fill_keys(self::LISTS, $stored);
		$GLOBALS['config'] = [
			'unbound' => ['enable' => '', 'port' => '53', 'active_interface' => $active],
			'installedpackages' => ['pfblockerngdns' => ['config' => [0 => $dns]]],
		];
	}

	/**
	 * Run the page's load statements and return what its form renders: the selected values and the option lists.
	 *
	 * @return array{0: array<string,mixed>, 1: array<string,string>, 2: array<string,string>} $pconfig, interface options, certificate options
	 */
	private static function pageLoad(): array
	{
		$page = (string) file_get_contents(self::PAGE);
		$from = strpos($page, '$pconfig = array();');
		$to = strpos($page, '$input_errors = array();');
		self::assertNotFalse($from, 'the page builds $pconfig');
		self::assertNotFalse($to, 'the page starts its input errors after the option lists');
		$pconfig = $options_dns_interface = $options_dns_cert = NULL;
		eval(substr($page, $from, $to - $from));
		self::assertIsArray($options_dns_interface, 'the page builds $options_dns_interface');
		self::assertIsArray($options_dns_cert, 'the page builds $options_dns_cert');
		return [$pconfig, $options_dns_interface, $options_dns_cert];
	}

	/**
	 * The POST a browser sends when Save is clicked without touching the interface lists: each list submits its selected
	 * values that are options, in option order; every transport is off.
	 *
	 * @param array<string,mixed>  $pconfig
	 * @param array<string,string> $options
	 * @return array<string,mixed>
	 */
	private static function unchangedPost(array $pconfig, array $options): array
	{
		$post = [
			'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853', 'pfb_dns_doh' => '', 'pfb_dns_doh_port' => '4443',
			'pfb_dns_doh_trusted' => '', 'pfb_dns_doq' => '', 'pfb_dns_doq_port' => '853', 'pfb_dns_sslcertref' => '',
		];
		foreach (self::LISTS as $list) {
			$post[$list] = array_values(array_filter(
				array_map('strval', array_keys($options)),
				static fn (string $value): bool => in_array($value, (array) $pconfig[$list], TRUE)
			));
		}
		return $post;
	}

	/** @return list<string> the save's input errors, validated as the page does: against the keys of the lists it offers */
	private static function validate(array $post, array $options, array $certs): array
	{
		return pfb_validate_dns_proxy_listeners_post($post, array_map('strval', array_keys($options)), array_map('strval', array_keys($certs)));
	}

	/** @return array<string,array{string,string}> Resolver active_interface, stored pfB-DNS lists */
	public static function vipBoxes(): array
	{
		return [
			'stored lan,_vip'                       => ['lo0', 'lan,' . self::VIP],
			'seeded from the Resolver on first use' => ['lan,' . self::VIP, ''],
		];
	}

	/**
	 * Scenario: a listener on a virtual IP.
	 * Given the stored (or about-to-be-seeded) lists are `lan,_vip<id>` and the VIP is configured,
	 * When the page loads and Save is clicked without changing the selection,
	 * Then the VIP is offered with the address the Resolver shows, the save has no input error and both tokens are stored.
	 */
	#[DataProvider('vipBoxes')]
	public function testAStoredVirtualIpIsOfferedAndAnUnchangedSaveKeepsIt(string $active, string $stored): void
	{
		$this->seedBox($active, $stored);
		[$pconfig, $options, $certs] = self::pageLoad();

		$this->assertSame('192.0.2.5', $options[self::VIP] ?? NULL, 'the VIP is offered as the Resolver offers it: ' . json_encode($options));
		$post = self::unchangedPost($pconfig, $options);
		$this->assertSame([], self::validate($post, $options, $certs), 'an unchanged save has no input error');
		$saved = pfb_dns_proxy_listeners_stored($post);
		foreach (self::LISTS as $list) {
			$this->assertSame('lan,' . self::VIP, $saved[$list], "{$list}: the unchanged save keeps both tokens");
		}
	}

	/**
	 * Scenario: listeners on interfaces that are gone.
	 * Given the stored lists name `lan`, a removed or disabled `opt2` and a deleted VIP,
	 * When the page loads and Save is clicked without changing the selection,
	 * Then each gone token is still an option, labelled not currently available, and the save stores every token.
	 */
	public function testAStoredTokenNothingOffersAnyMoreStaysSelectableAsUnavailableAndSurvivesAnUnchangedSave(): void
	{
		$this->seedBox('lo0', 'lan,opt2,_vipgone');
		[$pconfig, $options, $certs] = self::pageLoad();

		$this->assertSame('LAN', $options['lan'] ?? NULL, 'an offered interface keeps its own description');
		$this->assertSame('opt2 (not currently available)', $options['opt2'] ?? NULL, 'the removed interface: ' . json_encode($options));
		$this->assertSame('_vipgone (not currently available)', $options['_vipgone'] ?? NULL, 'the deleted VIP: ' . json_encode($options));
		$post = self::unchangedPost($pconfig, $options);
		$this->assertSame([], self::validate($post, $options, $certs), 'an unchanged save has no input error');
		$saved = pfb_dns_proxy_listeners_stored($post);
		foreach (self::LISTS as $list) {
			$this->assertSame('lan,opt2,_vipgone', $saved[$list], "{$list}: the unchanged save keeps every stored token");
		}
	}

	/** @return array<string,array{string}> a token the page neither offers nor stores */
	public static function strangers(): array
	{
		return ['an unknown interface' => ['opt3'], 'an unknown VIP' => ['_vipnothere'], 'markup' => ['<b>lan</b>']];
	}

	/**
	 * Scenario: a token that is neither offered nor stored.
	 * Given the stored lists are `lan,opt2`,
	 * When a save posts them plus a token nothing offers or stores,
	 * Then that token, and only it, is an input error in each list.
	 */
	#[DataProvider('strangers')]
	public function testATokenNeitherOfferedNorStoredIsStillAnInputError(string $stranger): void
	{
		$this->seedBox('lo0', 'lan,opt2');
		[$pconfig, $options, $certs] = self::pageLoad();
		$post = self::unchangedPost($pconfig, $options);
		$this->assertSame([], self::validate($post, $options, $certs), 'before: the stored tokens are accepted');

		foreach (['pfb_dns_interface' => 'DNS', 'pfb_dns_dot_interface' => 'DoT', 'pfb_dns_doh_interface' => 'DoH', 'pfb_dns_doq_interface' => 'DoQ'] as $list => $label) {
			$errors = self::validate([$list => array_merge($post[$list], [$stranger])] + $post, $options, $certs);

			$this->assertSame(["{$label}: Invalid interface selection: " . htmlspecialchars($stranger, ENT_QUOTES)], $errors, $list);
		}
	}
}
