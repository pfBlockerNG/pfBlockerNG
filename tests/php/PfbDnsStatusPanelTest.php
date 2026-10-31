<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3555 -- the pfB-DNS tab's status panel renders what pfb_dns_status() returns: the service and the mode, then one section per
 * transport (Plain DNS, DNS over TLS, DNS over HTTPS, DNS over QUIC listeners) with a table of Interface | Address | State rows, an empty
 * table when the transport is off, or one line of notice when it is on and has no listener. The state is an icon that says what it means
 * to a screen reader and in its hover title, so colour or shape never carries it alone; a refusal also shows its reason. Every dynamic
 * value is escaped exactly once. The panel is read back as markup (DOM), never as source text.
 *
 * issue #3586 -- each of those blocks is a section like the page's own: a collapsible pfSense panel, open, whose title carries the
 * collapse toggle, and a transport's table sits in a table-responsive container so a wide table scrolls inside its section rather
 * than widening the page on a phone.
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

	/** The transport's own section of the panel, as an XPath prefix. */
	private static function block(string $transport): string
	{
		return "//div[@id='pfb-dns-status']/div[@id='pfb-dns-status-{$transport}']";
	}

	/** The title of a section, without the collapse toggle (which has no text). */
	private static function title(string $section): string
	{
		return "string(//div[@id='pfb-dns-status']/div[@id='{$section}']/div[@class='panel-heading']/h2[@class='panel-title'])";
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

		$this->assertSame('pfB-DNS Status', $panel->evaluate(self::title('pfb-dns-status-overview')));
		$this->assertSame('Service', $panel->evaluate("string(//tr[@id='pfb-dns-status-service']/th)"));
		$this->assertSame($service, $panel->evaluate("string(//tr[@id='pfb-dns-status-service']/td)"));
		$this->assertSame('Mode', $panel->evaluate("string(//tr[@id='pfb-dns-status-mode']/th)"));
		$this->assertSame($mode, $panel->evaluate("string(//tr[@id='pfb-dns-status-mode']/td)"));
		$this->assertSame(1, $panel->query("//div[@id='pfb-dns-status']/div[contains(@class, 'panel')]")->length, 'no transport section');
		$this->assertSame(0, $panel->query('//thead')->length, 'no transport table');
	}

	public function testTheFourTransportsFollowTheServiceAndTheModeInOrderEachAsItsOwnSection(): void
	{
		$panel = $this->panel(self::withTransports(['state' => 'off'], ['state' => 'off'], ['state' => 'off']));

		$titles = [];
		$ids = [];
		foreach ($panel->query("//div[@id='pfb-dns-status']/div") as $section) {
			$ids[] = $section->getAttribute('id');
			$titles[] = $panel->evaluate('string(div[@class=\'panel-heading\']/h2)', $section);
		}
		$this->assertSame(['pfB-DNS Status', 'Plain DNS Listeners', 'DNS over TLS Listeners', 'DNS over HTTPS Listeners', 'DNS over QUIC Listeners'], $titles);
		$this->assertSame(['pfb-dns-status-overview', 'pfb-dns-status-plain', 'pfb-dns-status-dot', 'pfb-dns-status-doh', 'pfb-dns-status-doq'], $ids);
		$this->assertSame(1, $panel->query("//div[@id='pfb-dns-status-overview']//tr[@id='pfb-dns-status-mode']")->length, 'the service and the mode are the first section');
		$this->assertSame('', $panel->evaluate("string(//div[@id='pfb-dns-status']/@class)"), 'the sections sit in a bare container, never a panel nesting panels');
	}

	/** @return array<string,array{array<string,mixed>,list<string>}> a status and the ids of the sections it shows */
	public static function sectionsShown(): array
	{
		return [
			'no transport' => [self::statusOf(NULL, 'Not in use'), ['pfb-dns-status-overview']],
			'rows, off and no listener' => [
				self::withTransports(['state' => 'no_listener', 'notice' => self::NOTICE], ['state' => 'off'], self::rows(self::row('LAN', ['192.0.2.1:853']))),
				['pfb-dns-status-overview', 'pfb-dns-status-plain', 'pfb-dns-status-dot', 'pfb-dns-status-doh', 'pfb-dns-status-doq'],
			],
		];
	}

	/** @param list<string> $ids */
	#[DataProvider('sectionsShown')]
	public function testEverySectionIsAnOpenCollapsiblePfSensePanelToggledFromItsTitle(array $status, array $ids): void
	{
		$panel = $this->panel($status);

		foreach ($ids as $id) {
			$section = "//div[@id='pfb-dns-status']/div[@id='{$id}']";
			$this->assertSame('panel panel-default', $panel->evaluate("string({$section}/@class)"), "{$id} is a pfSense panel");
			$toggle = "{$section}/div[@class='panel-heading']/h2[@class='panel-title']/span[@class='widget-heading-icon']/a[@data-toggle='collapse']";
			$this->assertSame("#{$id}_panel-body", $panel->evaluate("string({$toggle}/@href)"), "{$id}'s title toggles its body");
			$this->assertSame(1, $panel->query("{$toggle}/i[@class='fa-solid fa-plus-circle']")->length, "{$id}'s toggle has pfSense's icon");
			// The icon is the link's only content, so the link names the section it toggles for a screen reader
			$title = trim((string) $panel->evaluate("string({$section}/div[@class='panel-heading']/h2)"));
			$this->assertSame("Toggle {$title}", $panel->evaluate("string({$toggle}/@aria-label)"), "{$id}'s toggle has an accessible name");
			$this->assertSame(1, $panel->query("{$section}/div[@id='{$id}_panel-body'][@class='panel-body collapse in']")->length, "{$id}'s body is collapsible and open");
		}
	}

	public function testATransportTableIsAPfSenseTableThatScrollsInsideItsSection(): void
	{
		$panel = $this->panel(self::withTransports(self::rows(self::row('LAN', ['192.0.2.1:853'])), ['state' => 'off'], self::rows(self::row('LAN', ['192.0.2.1:853']))));

		foreach (['plain', 'dot', 'doh', 'doq'] as $transport) {
			$this->assertSame(
				1,
				$panel->query(self::block($transport) . "/div[@class='panel-body collapse in']/div[@class='table-responsive']"
				    . "/table[@class='table table-striped table-hover table-condensed']")->length,
				"{$transport}'s table, with rows or without, is inside a table-responsive container"
			);
			$this->assertSame(1, $panel->query(self::block($transport) . '//table')->length);
		}
	}

	public function testAnOffTransportIsATableOfItsHeaderOnlyWithNoBodyAndNoStateText(): void
	{
		$panel = $this->panel(self::withTransports(['state' => 'off'], ['state' => 'off'], ['state' => 'off']));
		$dot = self::block('dot');

		$this->assertSame('DNS over TLS Listeners', $panel->evaluate(self::title('pfb-dns-status-dot')));
		$columns = [];
		foreach ($panel->query("{$dot}//thead//th") as $column) {
			$columns[] = $column->textContent;
		}
		$this->assertSame(['Interface', 'Address', 'State'], $columns);
		// pfSense's pfSenseHelpers.js fills every empty <tbody> with a blank row, so an off table must have no <tbody> at all
		$this->assertSame(0, $panel->query("{$dot}//tbody")->length, 'no body for the page script to fill');
		$this->assertSame(0, $panel->query("{$dot}//tr[not(parent::thead)]")->length, 'and no row');
		$this->assertSame(0, $panel->query("{$dot}//table//i")->length, 'no state icon');
		$this->assertSame('DNS over TLS ListenersInterfaceAddressState', $panel->evaluate("string({$dot})"), 'and no state text');
		$this->assertGreaterThan(0, $panel->query(self::block('plain') . '//tbody/tr')->length, 'a transport that is on keeps its rows beside the off ones');
	}

	public function testATransportThatIsOnWithNoListenerShowsTheNoticeAndNoTable(): void
	{
		$panel = $this->panel(self::withTransports(['state' => 'no_listener', 'notice' => self::NOTICE], ['state' => 'off'], ['state' => 'off']));
		$dot = self::block('dot');

		$this->assertSame('DNS over TLS Listeners', $panel->evaluate(self::title('pfb-dns-status-dot')));
		$this->assertSame(self::NOTICE, $panel->evaluate("string({$dot}//p)"));
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
			'not listening, with the gateway\'s reason' => ['not_listening', 'fa-solid fa-times-circle text-danger', 'Not listening', self::REASON],
			'not listening, no reason given' => ['not_listening', 'fa-solid fa-times-circle text-danger', 'Not listening', 'the gateway did not report it'],
			'configured, the service is not running' => ['configured_not_bound', 'fa-solid fa-exclamation-circle text-warning', 'Configured, not bound', ''],
			'configured, the gateway does not confirm it' => ['configured_unconfirmed', 'fa-solid fa-exclamation-circle text-warning', 'Configured, not confirmed by the gateway', ''],
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
		$this->assertSame("{$hostile}notice", $panel->evaluate('string(' . self::block('dot') . '//p)'));
	}
}
