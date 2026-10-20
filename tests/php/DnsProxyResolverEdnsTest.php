<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the Resolver move must not change the EDNS buffer size Unbound advertises.
 *
 * pfSense's automatic `edns-buffer-size` is the smallest MTU of the Resolver's Network Interfaces minus the IPv4 and UDP
 * headers (unbound_auto_ednsbufsize(), CE 2.8). A Resolver moved onto lo0 has loopback as its only interface, so unmoved
 * 1432 (a 1500-byte LAN) became 16316 on the wire (measured on CE 2.8.1: the stub upstream saw OPT payload 16316). Our
 * marked clause comes last in unbound.conf, and Unbound takes the last `edns-buffer-size:`, so the clause carries the size
 * pfSense's own function gives for the SAVED interfaces, and only while nothing else sets one:
 *
 *   - setting absent, empty or `auto`, and no directive of the admin's: the clause carries the line;
 *   - an explicit setting on the Advanced page, or an `edns-buffer-size:` directive in the admin's own Custom Options
 *     (Unbound reads those words the way it reads `port:`, wherever they stand on a line): the clause carries none, so the
 *     setting or the directive wins as it did before the move;
 *   - every apply that writes the clause computes it afresh: an MTU change, a changed setting or a new admin directive
 *     rewrites the clause in place, and a clause written by an earlier release (no line) gains it.
 */
#[CoversFunction('pfb_dns_proxy_edns_line')]
#[CoversFunction('pfb_dns_proxy_resolver_locked')]
final class DnsProxyResolverEdnsTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const MARKER = '# pfBlockerNG DNS proxy';
	private const MARKER_END = '# end pfBlockerNG DNS proxy';
	/** What a clause written before the size line existed looks like. */
	private const CLAUSE_WITHOUT_SIZE = "server:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
		. "proxy-protocol-port: 5353\n# end pfBlockerNG DNS proxy";
	private const GLOBALS = ['pfb', 'config', 'pfb_test_write_config_calls', 'pfb_test_file_notices', 'pfb_test_interface_mtu',
		'pfb_test_interfaces', 'pfb_test_configured_ipv6', 'pfb_test_interface_subnetv6'];

	private string $tmp;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_edns_' . uniqid('', TRUE);
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

	/** @param array<string,?string> $override a NULL deletes the key */
	private function seedResolver(array $override = []): void
	{
		$unbound = [
			'enable' => '', 'dnssec' => '', 'sslcertref' => 'cert123', 'tlsport' => '853', 'port' => '53',
			'active_interface' => 'lan,opt1', 'enablessl' => '',
			'custom_options' => base64_encode("do-ip6: no\nprefetch: yes"),
		];
		foreach ($override as $key => $value) {
			if ($value === NULL) {
				unset($unbound[$key]);
			} else {
				$unbound[$key] = $value;
			}
		}
		$GLOBALS['config']['unbound'] = $unbound;
	}

	/** @return list<string> custom_options decoded to its lines */
	private function customLines(): array
	{
		return explode("\n", (string) base64_decode((string) config_get_path('unbound/custom_options'), TRUE));
	}

	/** @return list<string> the lines of our clause, from its marker to its end marker */
	private function clauseLines(): array
	{
		$lines = $this->customLines();
		$start = array_search(self::MARKER, array_map('trim', $lines), TRUE);
		$end = array_search(self::MARKER_END, array_map('trim', $lines), TRUE);
		$this->assertIsInt($start, 'our clause is in Custom Options');
		$this->assertIsInt($end, 'and it is closed');
		return array_slice($lines, $start, $end - $start + 1);
	}

	/** @return list<string> the `edns-buffer-size:` lines of our clause */
	private function sizeLines(): array
	{
		return array_values(array_filter($this->clauseLines(), static fn (string $l): bool => str_starts_with(trim($l), 'edns-buffer-size:')));
	}

	/** The admin's own text: Custom Options with our clause (and the `server:` line that opens it) cut out. */
	private function adminText(): string
	{
		$text = implode("\n", $this->customLines());
		return (string) preg_replace('/\n?(?:^server:\n)?^' . preg_quote(self::MARKER, '/') . '$\n?.*?^' . preg_quote(self::MARKER_END, '/') . '$/ms', '', $text);
	}

	private function writes(): int
	{
		return count($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	// -----------------------------------------------------------------------
	// Automatic size: the clause carries pfSense's own value for the SAVED interfaces
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:?string}> the Advanced page's "automatic": absent, empty and the word */
	public static function automaticSettings(): array
	{
		return ['absent' => [NULL], 'empty' => [''], 'auto' => ['auto']];
	}

	#[DataProvider('automaticSettings')]
	public function testAnAutomaticSizeIsComputedOverTheSavedInterfacesNotOverLoopback(?string $setting): void
	{
		// Given a Resolver on two 1500-byte LANs with the size on automatic: native pfSense advertises 1432, and the value
		// pfSense would compute once the Resolver is on lo0 is far above that (the regression this pins).
		$this->seedResolver(['edns_buffer_size' => $setting]);
		$this->assertSame(1432, unbound_auto_ednsbufsize(['lan', 'opt1']), 'before: native auto');
		$this->assertSame(16316, unbound_auto_ednsbufsize(['lo0']), 'before: auto over loopback is the value to avoid');

		// When the proxy takes the Resolver.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the Resolver is moved and our clause carries the native size, once.
		$this->assertTrue($changed);
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines());
		$this->assertSame(1, $this->writes(), 'still one write_config for the whole move');
		$this->assertSame("do-ip6: no\nprefetch: yes", rtrim($this->adminText(), "\n"), "the admin's text is untouched");
	}

	/** @return array<string,array{0:string,1:array<string,string>,2:array<string,string>,3:int}> saved interfaces, MTUs, IPv6 addresses, expected size */
	public static function savedInterfaceShapes(): array
	{
		return [
			'two LANs'                              => ['lan,opt1', ['lan' => '1500', 'opt1' => '1500'], [], 1432],
			'the smaller LAN decides'               => ['lan,opt1', ['lan' => '1500', 'opt1' => '1400'], [], 1332],
			'a jumbo LAN beside a standard one'     => ['lan,opt1', ['lan' => '9000', 'opt1' => '1500'], [], 1432],
			'only a jumbo LAN'                      => ['lan', ['lan' => '9000'], [], 8932],
			'all: every configured interface'       => ['all', ['lan' => '1500', 'opt1' => '1400'], [], 1332],
			'empty: every configured interface'     => ['', ['lan' => '1500', 'opt1' => '1400'], [], 1332],
			'IPv6 on the smallest raises the floor' => ['lan,opt1', ['lan' => '1500', 'opt1' => '1280'], ['opt1' => '2001:db8::1'], 1232],
			'IPv4-only floor stays 512'             => ['lan', ['lan' => '500'], [], 512],
		];
	}

	/**
	 * @param array<string,string> $mtus
	 * @param array<string,string> $ipv6
	 */
	#[DataProvider('savedInterfaceShapes')]
	public function testTheSizeFollowsPfSensesOwnFunctionForTheSavedInterfaces(string $saved, array $mtus, array $ipv6, int $expected): void
	{
		// Given a Resolver whose saved interfaces have these MTUs.
		$GLOBALS['pfb_test_interface_mtu'] = $mtus + ['lo0' => '16384'];
		$GLOBALS['pfb_test_configured_ipv6'] = $ipv6;
		$this->seedResolver(['active_interface' => $saved]);

		// When the proxy takes the Resolver.
		pfb_dns_proxy_resolver(TRUE);

		// Then the clause carries what pfSense's function gives for exactly those tokens.
		$this->assertSame(["edns-buffer-size: {$expected}"], $this->sizeLines());
	}

	public function testAResolverWithNoSavedInterfacesGetsTheSizeOverEveryConfiguredOne(): void
	{
		// Given a Resolver with no active_interface key at all (pfSense then binds every interface).
		$GLOBALS['pfb_test_interface_mtu'] = ['lan' => '1500', 'opt1' => '1400', 'lo0' => '16384'];
		$this->seedResolver(['active_interface' => NULL]);

		// When the proxy takes the Resolver.
		pfb_dns_proxy_resolver(TRUE);

		// Then the size is the native one for all interfaces, not the loopback one.
		$this->assertSame(['edns-buffer-size: 1332'], $this->sizeLines());
	}

	public function testTheSizeIsComputedOverPfbDnsOwnInterfaceListNotTheSavedResolversInterfaces(): void
	{
		// Given a Resolver that listened on opt1 (a 1400-byte interface) and pfB-DNS's own plain DNS list: lan (1500 bytes).
		$GLOBALS['pfb_test_interface_mtu'] = ['lan' => '1500', 'opt1' => '1400', 'lo0' => '16384'];
		$this->seedResolver(['active_interface' => 'opt1']);
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_interface', 'lan');

		// When the proxy takes the Resolver.
		pfb_dns_proxy_resolver(TRUE);

		// Then the size is lan's (1500 - 68), not the saved opt1's (1400 - 68).
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines());
	}

	// -----------------------------------------------------------------------
	// Nothing else may be overridden: an explicit setting and the admin's directive win, as before the move
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:string}> the sizes the Advanced page offers besides automatic */
	public static function explicitSizes(): array
	{
		return ['512' => ['512'], '1220' => ['1220'], '1232' => ['1232'], '1432' => ['1432'], '1480' => ['1480'], '4096' => ['4096']];
	}

	#[DataProvider('explicitSizes')]
	public function testAnExplicitSizeIsLeftToPfSenseAndTheClauseCarriesNone(string $size): void
	{
		// Given a Resolver with an explicit size on the Advanced page.
		$this->seedResolver(['edns_buffer_size' => $size]);

		// When the proxy takes the Resolver.
		pfb_dns_proxy_resolver(TRUE);

		// Then the clause has no size line, and the Advanced setting is as it was.
		$this->assertSame([], $this->sizeLines());
		$this->assertSame($size, config_get_path('unbound/edns_buffer_size'));
	}

	/** @return array<string,array{0:string}> Custom Options text with an `edns-buffer-size:` directive of the admin's own, wherever it stands */
	public static function adminSizeDirectives(): array
	{
		return [
			'on its own line'             => ["server:\nedns-buffer-size: 4096"],
			'indented, with a comment'    => ["server:\n    edns-buffer-size:   4096   # mine\nprefetch: yes"],
			'no space after the colon'    => ["server:\nedns-buffer-size:4096"],
			'a tab after the colon'       => ["server:\nedns-buffer-size:\t4096"],
			'CRLF line endings'           => ["server:\r\nedns-buffer-size: 4096\r\n"],
			'after another directive'     => ["server:\nprefetch: yes edns-buffer-size: 4096"],
			'after a quoted hash'         => ["server:\nlog-identity: \"#\" edns-buffer-size: 4096"],
			'with a space before its colon' => ["server:\nedns-buffer-size : 4096"],
		];
	}

	#[DataProvider('adminSizeDirectives')]
	public function testAnAdminSizeDirectiveWinsAndTheClauseCarriesNone(string $custom): void
	{
		// Given Custom Options with a size directive of the admin's own, and the size on automatic.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);

		// When the proxy takes the Resolver.
		pfb_dns_proxy_resolver(TRUE);

		// Then the clause has no size line (ours would come last and override the admin's), and the admin's text survives.
		$this->assertSame([], $this->sizeLines());
		$this->assertSame(rtrim(str_replace("\r\n", "\n", $custom), "\n"), rtrim($this->adminText(), "\n"));
	}

	/** @return array<string,array{0:string}> text that only mentions the directive: Unbound reads none of it as one */
	public static function notASizeDirective(): array
	{
		return [
			'a comment'                    => ["server:\n# edns-buffer-size: 4096"],
			'a comment after a value'      => ["server:\nprefetch: yes # edns-buffer-size: 4096"],
			'another option with the word' => ["server:\nlog-identity: a#b"],
			'a longer option name'         => ["server:\nmy-edns-buffer-size: 4096"],
		];
	}

	#[DataProvider('notASizeDirective')]
	public function testTextThatIsNotASizeDirectiveDoesNotSuppressTheClausesSize(string $custom): void
	{
		// Given Custom Options that only mention the directive in a comment or inside another word.
		$this->seedResolver(['custom_options' => base64_encode($custom)]);

		// When the proxy takes the Resolver.
		pfb_dns_proxy_resolver(TRUE);

		// Then the clause still carries the size.
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines());
	}

	// -----------------------------------------------------------------------
	// Every apply that writes the clause recomputes it
	// -----------------------------------------------------------------------

	public function testASteadyStateAppliesNothingTheSecondTime(): void
	{
		// Given a moved Resolver whose clause carries the size.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines(), 'before: the clause carries the size');
		$custom = config_get_path('unbound/custom_options');
		$writes = $this->writes();

		// When it is applied again with nothing changed.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then nothing is written.
		$this->assertFalse($changed);
		$this->assertSame($writes, $this->writes());
		$this->assertSame($custom, config_get_path('unbound/custom_options'));
	}

	public function testAnMtuChangeRewritesTheClauseInPlaceWithTheNewSize(): void
	{
		// Given a moved Resolver on two 1500-byte LANs.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines(), 'before: 1432');

		// When both LANs go to jumbo frames and the proxy is applied again.
		$GLOBALS['pfb_test_interface_mtu'] = ['lan' => '9000', 'opt1' => '9000', 'lo0' => '16384'];
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the clause is replaced where it stood, with the new size, still one clause.
		$this->assertTrue($changed);
		$this->assertSame(['edns-buffer-size: 8932'], $this->sizeLines());
		$this->assertSame(1, count(array_keys(array_map('trim', $this->customLines()), self::MARKER, TRUE)), 'one clause, never two');
		$this->assertSame("do-ip6: no\nprefetch: yes", rtrim($this->adminText(), "\n"));
	}

	public function testSwitchingTheAdvancedSettingToExplicitRemovesTheLineOnTheNextApply(): void
	{
		// Given a moved Resolver whose clause carries the size.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines(), 'before: the clause has the line');

		// When the admin picks an explicit size on the Advanced page and the proxy is applied again.
		config_set_path('unbound/edns_buffer_size', '1232');
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the line is gone, so pfSense's explicit size applies.
		$this->assertTrue($changed);
		$this->assertSame([], $this->sizeLines());
	}

	public function testAnAdminDirectiveAddedAfterTheMoveRemovesTheLineOnTheNextApply(): void
	{
		// Given a moved Resolver whose clause carries the size.
		$this->seedResolver();
		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines(), 'before: the clause has the line');

		// When the admin adds their own size directive to Custom Options and the proxy is applied again.
		config_set_path('unbound/custom_options', base64_encode(implode("\n", $this->customLines()) . "\nserver:\nedns-buffer-size: 4096\n"));
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then our line is gone and the admin's directive is untouched.
		$this->assertTrue($changed);
		$this->assertSame([], $this->sizeLines());
		$this->assertStringContainsString("server:\nedns-buffer-size: 4096", $this->adminText());
	}

	public function testAClauseWrittenByAnEarlierReleaseGainsTheLineOnTheNextApply(): void
	{
		// Given a Resolver moved by a release whose clause has no size line (a snapshot exists, the clause is complete).
		$this->seedResolver([
			'active_interface' => 'lo0', 'enablessl' => NULL,
			'custom_options' => base64_encode("do-ip6: no\nprefetch: yes\n" . self::CLAUSE_WITHOUT_SIZE),
		]);
		config_set_path(self::SAVED, base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan,opt1'],
			'enablessl' => ['present' => TRUE, 'value' => ''],
			'custom_options' => ['present' => TRUE, 'value' => base64_encode("do-ip6: no\nprefetch: yes")],
		])));
		$this->assertStringNotContainsString('edns-buffer-size', (string) base64_decode((string) config_get_path('unbound/custom_options')), 'before');

		// When the proxy is applied.
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the clause is replaced in place and now carries the size computed over the SAVED interfaces.
		$this->assertTrue($changed);
		$this->assertSame(['edns-buffer-size: 1432'], $this->sizeLines());
		$this->assertSame("do-ip6: no\nprefetch: yes", rtrim($this->adminText(), "\n"));
	}
}
