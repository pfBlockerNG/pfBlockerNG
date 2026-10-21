<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3555 -- the pfB-DNS tab's status panel renders what pfb_dns_status() returns: the service and the mode, then one heading per
 * transport (Plain DNS, DNS over TLS, DNS over HTTPS, DNS over QUIC) with a table of Interface | Address | State rows, an empty table
 * when the transport is off, or one line of notice when it is on and has no listener. The state is an icon that says what it means to a
 * screen reader and in its hover title, so colour or shape never carries it alone; a refusal also shows its reason. Every dynamic value
 * is escaped exactly once. The panel is read back as markup (DOM), never as source text.
 */
#[CoversFunction('pfb_dns_status_panel')]
final class PfbDnsStatusPanelTest extends TestCase
{
	private const MODE = 'On, with DNSBL: the proxy answers DNSBL blocks and forwards everything else';
	private const NOTICE = 'On, but the service has no listener for it: see the notices, or run an Update';
	private const REASON = 'listen tcp 192.0.2.1:853: bind: address already in use';
	private const HOSTILE = '<script>alert("x")</script> & \'q\'';

	/**
	 * @param array<string,mixed>|null $transports
	 * @return array<string,mixed>
	 */
	private static function statusOf(?array $transports, string $service = 'Running', string $mode = self::MODE): array
	{
		return ['service' => $service, 'mode' => $mode, 'transports' => $transports];
	}

	/**
	 * @param list<string> $addresses
	 * @return array{interface:string,addresses:list<string>,state:string,reason:string}
	 */
	private static function row(string $interface, array $addresses, string $state = 'listening', string $reason = ''): array
	{
		return ['interface' => $interface, 'addresses' => $addresses, 'state' => $state, 'reason' => $reason];
	}

	/** @return array{state:string,rows:list<array<string,mixed>>} */
	private static function rows(array ...$rows): array
	{
		return ['state' => 'rows', 'rows' => $rows];
	}

	/** The status of a Running service with all four transports: plain DNS served on loopback and lan, the rest as given. */
	private static function withTransports(array $dot, array $doh, array $doq): array
	{
		return self::statusOf([
			'plain' => self::rows(self::row('Localhost', ['127.0.0.1:53', '[::1]:53']), self::row('LAN', ['192.0.2.1:53'])),
			'dot'   => $dot,
			'doh'   => $doh,
			'doq'   => $doq,
		]);
	}

	/** The panel for $status as a document: it must be well-formed markup, which proves every tag is closed. */
	private function panel(array $status): DOMXPath
	{
		$document = new DOMDocument();
		$previous = libxml_use_internal_errors(TRUE);
		$loaded = $document->loadXML('<root>' . pfb_dns_status_panel($status) . '</root>');
		$errors = array_map(static fn (LibXMLError $error): string => trim($error->message), libxml_get_errors());
		libxml_clear_errors();
		libxml_use_internal_errors($previous);
		$this->assertTrue($loaded, 'the panel is well-formed markup: ' . implode('; ', $errors));

		return new DOMXPath($document);
	}

	/** The transport's own block of the panel, as an XPath prefix. */
	private static function block(string $transport): string
	{
		return "//div[@id='pfb-dns-status']//div[@id='pfb-dns-status-{$transport}']";
	}

	/** @return array<string,array{string,string}> the service and mode of a status that claims no transport */
	public static function statusesWithNoTransport(): array
	{
		return [
			'nothing moved' => ['Not in use', 'On, but not active: pfBlockerNG is disabled'],
			'recovery required' => ['Stopped', 'Recovery required: the saved copy of the DNS Resolver\'s previous settings (pfb_dns_saved) is invalid'],
		];
	}

	#[DataProvider('statusesWithNoTransport')]
	public function testAStatusWithNoTransportsShowsTheServiceAndTheModeAndNoTransportHeadingOrTable(string $service, string $mode): void
	{
		$panel = $this->panel(self::statusOf(NULL, $service, $mode));

		$this->assertSame('pfB-DNS Status', $panel->evaluate("string(//div[@id='pfb-dns-status']/div[@class='panel-heading']/h2[@class='panel-title'])"));
		$this->assertSame('Service', $panel->evaluate("string(//tr[@id='pfb-dns-status-service']/th)"));
		$this->assertSame($service, $panel->evaluate("string(//tr[@id='pfb-dns-status-service']/td)"));
		$this->assertSame('Mode', $panel->evaluate("string(//tr[@id='pfb-dns-status-mode']/th)"));
		$this->assertSame($mode, $panel->evaluate("string(//tr[@id='pfb-dns-status-mode']/td)"));
		$this->assertSame(0, $panel->query('//h3')->length, 'no transport heading');
		$this->assertSame(0, $panel->query('//thead')->length, 'no transport table');
	}

	public function testTheFourTransportsFollowTheServiceAndTheModeInOrderEachUnderItsOwnHeading(): void
	{
		$panel = $this->panel(self::withTransports(['state' => 'off'], ['state' => 'off'], ['state' => 'off']));

		$headings = [];
		$ids = [];
		foreach ($panel->query("//div[@id='pfb-dns-status']//h3") as $heading) {
			$headings[] = $heading->textContent;
			$ids[] = $heading->parentNode instanceof DOMElement ? $heading->parentNode->getAttribute('id') : '';
		}
		$this->assertSame(['Plain DNS', 'DNS over TLS', 'DNS over HTTPS', 'DNS over QUIC'], $headings);
		$this->assertSame(['pfb-dns-status-plain', 'pfb-dns-status-dot', 'pfb-dns-status-doh', 'pfb-dns-status-doq'], $ids);
		$this->assertSame(4, (int) $panel->evaluate("count(//tr[@id='pfb-dns-status-mode']/following::h3)"), 'the service and the mode come before the four transports');
	}

	public function testAnOffTransportIsAnEmptyTableWithItsHeadingAndColumnsAndNoStateText(): void
	{
		$panel = $this->panel(self::withTransports(['state' => 'off'], ['state' => 'off'], ['state' => 'off']));
		$dot = self::block('dot');

		$this->assertSame('DNS over TLS', $panel->evaluate("string({$dot}/h3)"));
		$columns = [];
		foreach ($panel->query("{$dot}//thead//th") as $column) {
			$columns[] = $column->textContent;
		}
		$this->assertSame(['Interface', 'Address', 'State'], $columns);
		$this->assertSame(1, $panel->query("{$dot}//tbody")->length, 'the table has its body');
		$this->assertSame(0, $panel->query("{$dot}//tbody/tr")->length, 'and no row');
		$this->assertSame(0, $panel->query("{$dot}//i")->length, 'no icon');
		$this->assertSame('DNS over TLSInterfaceAddressState', $panel->evaluate("string({$dot})"), 'and no state text');
		$this->assertGreaterThan(0, $panel->query(self::block('plain') . '//tbody/tr')->length, 'a transport that is on keeps its rows beside the off ones');
	}

	public function testATransportThatIsOnWithNoListenerShowsTheNoticeAndNoTable(): void
	{
		$panel = $this->panel(self::withTransports(['state' => 'no_listener', 'notice' => self::NOTICE], ['state' => 'off'], ['state' => 'off']));
		$dot = self::block('dot');

		$this->assertSame('DNS over TLS', $panel->evaluate("string({$dot}/h3)"));
		$this->assertSame(self::NOTICE, $panel->evaluate("string({$dot}/p)"));
		$this->assertSame(0, $panel->query("{$dot}//table")->length, 'a fault is one line, not a table');
	}

	public function testEachAddressOfARowIsOnItsOwnLineUnderItsInterface(): void
	{
		$panel = $this->panel(self::withTransports(
			self::rows(self::row('Localhost', ['127.0.0.1:853', '[::1]:853']), self::row('LAN', ['192.0.2.1:853'])),
			['state' => 'off'],
			['state' => 'off']
		));
		$rows = self::block('dot') . '//tbody/tr';

		$this->assertSame(2, $panel->query($rows)->length);
		$this->assertSame('Localhost', $panel->evaluate("string({$rows}[1]/td[1])"));
		$lines = [];
		foreach ($panel->query("{$rows}[1]/td[2]/text()") as $line) {
			$lines[] = $line->textContent;
		}
		$this->assertSame(['127.0.0.1:853', '[::1]:853'], $lines);
		$this->assertSame(1, (int) $panel->evaluate("count({$rows}[1]/td[2]/br)"), 'a line break between the two, none after the last');
		$this->assertSame('LAN', $panel->evaluate("string({$rows}[2]/td[1])"));
		$this->assertSame('192.0.2.1:853', $panel->evaluate("string({$rows}[2]/td[2])"));
	}

	/** @return array<string,array{string,string,string,string}> the state, its icon's classes, its title and the visible text after the icon */
	public static function states(): array
	{
		return [
			'listening' => ['listening', 'fa-solid fa-check-circle text-success', 'Listening', ''],
			'not listening, with the logged reason' => ['not_listening', 'fa-solid fa-times-circle text-danger', 'Not listening', self::REASON],
			'not listening, none logged' => ['not_listening', 'fa-solid fa-times-circle text-danger', 'Not listening', 'the gateway did not report it'],
			'configured, the service is not running' => ['configured_not_bound', 'fa-solid fa-exclamation-circle text-warning', 'Configured, not bound', ''],
			'configured, the log does not confirm it' => ['configured_unconfirmed', 'fa-solid fa-exclamation-circle text-warning', 'Configured, not confirmed by the log', ''],
		];
	}

	#[DataProvider('states')]
	public function testEachStateIsAnIconWhoseMeaningIsInItsTitleAndForScreenReadersAndAReasonIsVisible(string $state, string $icon, string $title, string $reason): void
	{
		$panel = $this->panel(self::withTransports(
			self::rows(self::row('LAN', ['192.0.2.1:853'], $state, $reason)),
			['state' => 'off'],
			['state' => 'off']
		));
		$cell = self::block('dot') . '//tbody/tr[1]/td[3]';

		$this->assertSame($icon, $panel->evaluate("string({$cell}/i/@class)"));
		$this->assertSame($title, $panel->evaluate("string({$cell}/i/@title)"), 'the hover title');
		$this->assertSame('true', $panel->evaluate("string({$cell}/i/@aria-hidden)"), 'the icon itself is skipped by a screen reader');
		$this->assertSame($title, $panel->evaluate("string({$cell}/span[@class='sr-only'])"), 'what a screen reader says instead');
		$this->assertSame($title . ($reason === '' ? '' : " {$reason}"), $panel->evaluate("string({$cell})"), 'the cell says nothing else than the meaning and the reason');
	}

	public function testAnAddressOfNoInterfaceIsLabelledWithTheBareAddressAndKeepsItsBrackets(): void
	{
		$panel = $this->panel(self::withTransports(
			self::rows(self::row('2001:db8:ffff::9', ['[2001:db8:ffff::9]:853'])),
			['state' => 'off'],
			['state' => 'off']
		));
		$row = self::block('dot') . '//tbody/tr[1]';

		$this->assertSame('2001:db8:ffff::9', $panel->evaluate("string({$row}/td[1])"));
		$this->assertSame('[2001:db8:ffff::9]:853', $panel->evaluate("string({$row}/td[2])"));
	}

	public function testEveryDynamicValueIsEscapedExactlyOnce(): void
	{
		// Given markup, an ampersand and quotes in the service, the mode, an interface description, an address, a reason and a notice
		$hostile = self::HOSTILE;
		$status = self::statusOf([
			'plain' => self::rows(self::row("{$hostile}if", ["{$hostile}addr"], 'not_listening', "{$hostile}why")),
			'dot'   => ['state' => 'no_listener', 'notice' => "{$hostile}notice"],
			'doh'   => ['state' => 'off'],
			'doq'   => ['state' => 'off'],
		], "{$hostile}service", "{$hostile}mode");

		$panel = $this->panel($status);
		$row = self::block('plain') . '//tbody/tr[1]';

		// Then each reads back as the text it was, so none became markup and none was escaped twice
		$this->assertSame(0, $panel->query('//script')->length, 'no element came from a value');
		$this->assertSame("{$hostile}service", $panel->evaluate("string(//tr[@id='pfb-dns-status-service']/td)"));
		$this->assertSame("{$hostile}mode", $panel->evaluate("string(//tr[@id='pfb-dns-status-mode']/td)"));
		$this->assertSame("{$hostile}if", $panel->evaluate("string({$row}/td[1])"));
		$this->assertSame("{$hostile}addr", $panel->evaluate("string({$row}/td[2])"));
		$this->assertSame("Not listening {$hostile}why", $panel->evaluate("string({$row}/td[3])"));
		$this->assertSame("{$hostile}notice", $panel->evaluate('string(' . self::block('dot') . '/p)'));
	}
}
