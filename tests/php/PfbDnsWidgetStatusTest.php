<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3588 -- the dashboard widget's pfB-DNS status row: one cell for the service and one per transport (DNS, DoT, DoH, DoQ), each an
 * icon (green: on and working, yellow: on with a fault, red: off) with a hover title that says why. pfb_dns_widget_status() decides colour
 * and title from a pfb_dns_status() result; pfb_dns_widget_row() renders the cells as the one table row the widget header prints, every
 * title escaped once. A title never carries a newline or `||`, which the widget's line- and `||`-delimited AJAX payload could not hold.
 */
#[CoversFunction('pfb_dns_widget_status')]
#[CoversFunction('pfb_dns_widget_row')]
final class PfbDnsWidgetStatusTest extends TestCase
{
	private const GREEN = 'fa-solid fa-check-circle text-success';
	private const YELLOW = 'fa-solid fa-exclamation-circle text-warning';
	private const RED = 'fa-solid fa-times-circle text-danger';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	private const MODE = 'On, with DNSBL: the proxy answers DNSBL blocks and forwards everything else';
	private const NOTICE = 'On, but the service has no listener for it: see the notices, or run an Update';
	private const ANCHORS = ['PFBDNSSTATUS_service', 'PFBDNSSTATUS_plain', 'PFBDNSSTATUS_dot', 'PFBDNSSTATUS_doh', 'PFBDNSSTATUS_doq'];

	private const GLOBALS = ['pfb', 'config'];

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$GLOBALS['pfb'] = ['enable' => PfbToggle::On, 'pfb_dns' => PfbToggle::On];
		$GLOBALS['config'] = [];
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
	}

	private static function row(string $state, string $interface = 'LAN', string $reason = ''): array
	{
		return ['interface' => $interface, 'addresses' => ['192.0.2.1:53'], 'state' => $state, 'reason' => $reason];
	}

	/** @return array{state:string,rows:list<array<string,mixed>>} */
	private static function rows(string ...$states): array
	{
		return ['state' => 'rows', 'rows' => array_map(static fn (string $state): array => self::row($state), $states)];
	}

	/**
	 * @param array<string,mixed>|null $transports
	 * @return array<string,mixed>
	 */
	private static function statusOf(?array $transports, string $service = 'Running', string $mode = self::MODE): array
	{
		return ['service' => $service, 'mode' => $mode, 'transports' => $transports];
	}

	/** A Running service whose transports are plain DNS listening and the rest as given (off when omitted). */
	private static function running(array $transports = []): array
	{
		return self::statusOf($transports + ['plain' => self::rows('listening'), 'dot' => ['state' => 'off'], 'doh' => ['state' => 'off'], 'doq' => ['state' => 'off']]);
	}

	/** @return array<string,array{icon:string,title:string}> the cells of $status keyed by anchor */
	private static function cells(array $status): array
	{
		$cells = [];
		foreach (pfb_dns_widget_status($status) as $cell) {
			$cells[$cell['anchor']] = $cell;
		}

		return $cells;
	}

	private function assertCell(array $cells, string $anchor, string $icon, string $title): void
	{
		$this->assertSame(['icon' => $icon, 'title' => $title], ['icon' => $cells[$anchor]['icon'], 'title' => $cells[$anchor]['title']], $anchor);
	}

	public function testTheCellsAreTheServiceThenDnsDotDohAndDoqEachWithItsLabel(): void
	{
		$cells = pfb_dns_widget_status(self::running());

		$this->assertSame(self::ANCHORS, array_column($cells, 'anchor'));
		$this->assertSame(['pfB-DNS', 'DNS', 'DoT', 'DoH', 'DoQ'], array_column($cells, 'label'));
	}

	/** @return array<string,array{array<string,mixed>,string,string}> */
	public static function serviceCells(): array
	{
		return [
			'running with its transports' => [self::running(), self::GREEN, 'Running: ' . self::MODE],
			'starting' => [self::statusOf(self::running()['transports'], 'Starting'), self::YELLOW, 'Starting: ' . self::MODE],
			'stopped' => [self::statusOf(self::running()['transports'], 'Stopped'), self::YELLOW, 'Stopped: ' . self::MODE],
			'not in use' => [self::statusOf(NULL, 'Not in use', 'On, not active: the DNS Resolver has not been moved'), self::YELLOW, 'Not in use: On, not active: the DNS Resolver has not been moved'],
			'running but claiming no transport' => [self::statusOf(NULL, 'Running'), self::YELLOW, 'Running: ' . self::MODE],
		];
	}

	#[DataProvider('serviceCells')]
	public function testTheServiceCellIsGreenOnlyForARunningServiceWithTransports(array $status, string $icon, string $title): void
	{
		$this->assertCell(self::cells($status), 'PFBDNSSTATUS_service', $icon, $title);
	}

	public function testPfBlockerNgDisabledMakesEveryCellRedIncludingPlainDns(): void
	{
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		config_set_path(self::SETTINGS . 'pfb_dns_dot', 'on');
		$status = self::statusOf(NULL, 'Not in use', 'On, but not active: pfBlockerNG is disabled');

		$cells = self::cells($status);

		$this->assertSame(self::ANCHORS, array_keys($cells));
		foreach ($cells as $anchor => $cell) {
			$this->assertSame(self::RED, $cell['icon'], $anchor);
		}
		$this->assertSame('Not in use: On, but not active: pfBlockerNG is disabled', $cells['PFBDNSSTATUS_service']['title']);
	}

	public function testPfBlockerNgDisabledMakesEveryCellRedEvenWhileTheProxyStillListensForThePendingRestore(): void
	{
		// Given pfBlockerNG is disabled while the moved Resolver's restore is pending, and the proxy still answers on every transport
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$listening = self::rows('listening');
		$status = self::running(['plain' => $listening, 'dot' => $listening, 'doh' => $listening, 'doq' => $listening]);

		// Then nothing is green: pfBlockerNG is off, so is every cell
		foreach (self::cells($status) as $anchor => $cell) {
			$this->assertSame(self::RED, $cell['icon'], $anchor);
		}
	}

	/** @return array<string,array{array<string,string>,array<string,string>}> toggles that are on, and the expected colours of the transports */
	public static function notActiveToggles(): array
	{
		return [
			'plain only' => [[], ['plain' => self::YELLOW, 'dot' => self::RED, 'doh' => self::RED, 'doq' => self::RED]],
			'DoT on' => [['pfb_dns_dot' => 'on'], ['plain' => self::YELLOW, 'dot' => self::YELLOW, 'doh' => self::RED, 'doq' => self::RED]],
			'DoH and DoQ on' => [['pfb_dns_doh' => 'on', 'pfb_dns_doq' => 'on'], ['plain' => self::YELLOW, 'dot' => self::RED, 'doh' => self::YELLOW, 'doq' => self::YELLOW]],
		];
	}

	#[DataProvider('notActiveToggles')]
	public function testWithNoTransportsATransportIsYellowWhenItsToggleIsOnAndRedWhenOff(array $settings, array $expected): void
	{
		// A stored interface makes the saved toggles authoritative; without it the Resolver's own settings seed them
		foreach ($settings + ['pfb_dns_interface' => 'lan'] as $key => $value) {
			config_set_path(self::SETTINGS . $key, $value);
		}
		$labels = ['plain' => 'DNS', 'dot' => 'DoT', 'doh' => 'DoH', 'doq' => 'DoQ'];

		$cells = self::cells(self::statusOf(NULL, 'Not in use', 'On, not active: the DNS Resolver has not been moved'));

		foreach ($expected as $key => $icon) {
			$title = $icon === self::RED ? "{$labels[$key]} is off" : "{$labels[$key]} is on, but pfB-DNS is not active";
			$this->assertCell($cells, "PFBDNSSTATUS_{$key}", $icon, $title);
		}
	}

	/** @return array<string,array{array<string,mixed>,string,string}> a DoT transport state, and its colour and title */
	public static function dotStates(): array
	{
		return [
			'off' => [['state' => 'off'], self::RED, 'DoT is off'],
			'no listener' => [['state' => 'no_listener', 'notice' => self::NOTICE], self::YELLOW, 'DoT: ' . self::NOTICE],
			'every row listening' => [self::rows('listening', 'listening'), self::GREEN, 'DoT is listening on LAN'],
			'one row not listening' => [self::rows('listening', 'not_listening'), self::YELLOW, 'DoT: 1 of 2 listener rows are not confirmed listening; see the pfB-DNS tab'],
			'every row not listening' => [self::rows('not_listening'), self::YELLOW, 'DoT: 1 of 1 listener rows are not confirmed listening; see the pfB-DNS tab'],
			'configured but not confirmed' => [self::rows('configured_unconfirmed'), self::YELLOW, 'DoT: 1 of 1 listener rows are not confirmed listening; see the pfB-DNS tab'],
			'configured but not bound' => [self::rows('configured_not_bound'), self::YELLOW, 'DoT: 1 of 1 listener rows are not confirmed listening; see the pfB-DNS tab'],
		];
	}

	#[DataProvider('dotStates')]
	public function testATransportOfARunningServiceIsColouredByItsOwnState(array $dot, string $icon, string $title): void
	{
		$cells = self::cells(self::running(['dot' => $dot]));

		$this->assertCell($cells, 'PFBDNSSTATUS_dot', $icon, $title);
		$this->assertCell($cells, 'PFBDNSSTATUS_plain', self::GREEN, 'DNS is listening on LAN');
		$this->assertCell($cells, 'PFBDNSSTATUS_service', self::GREEN, 'Running: ' . self::MODE);
	}

	public function testAListeningTransportNamesEveryInterfaceOnceInOrder(): void
	{
		$rows = ['state' => 'rows', 'rows' => [self::row('listening', 'Localhost'), self::row('listening', 'LAN'), self::row('listening', 'Localhost')]];

		$this->assertSame('DoT is listening on Localhost, LAN', self::cells(self::running(['dot' => $rows]))['PFBDNSSTATUS_dot']['title']);
	}

	public function testATitleNeverCarriesANewlineOrTheAjaxDelimiter(): void
	{
		$notice = "line one\r\nline two || line three\n";
		$status = self::running(['dot' => ['state' => 'no_listener', 'notice' => $notice]]);
		$status['mode'] = "mode\nwith || breaks";

		foreach (pfb_dns_widget_status($status) as $cell) {
			$this->assertDoesNotMatchRegularExpression('/[\r\n]|\|\|/', $cell['title'], $cell['anchor']);
		}
		$cells = self::cells($status);
		$this->assertStringContainsString('line one', $cells['PFBDNSSTATUS_dot']['title']);
		$this->assertStringContainsString('line three', $cells['PFBDNSSTATUS_dot']['title']);
		$this->assertStringContainsString('with', $cells['PFBDNSSTATUS_service']['title']);
	}

	/** The widget row for $cells as a document: well-formed markup, which proves every tag is closed. */
	private function row_of(array $cells): DOMXPath
	{
		$document = new DOMDocument();
		$previous = libxml_use_internal_errors(TRUE);
		$loaded = $document->loadXML('<table>' . str_replace('&nbsp;', '&#160;', pfb_dns_widget_row($cells)) . '</table>');
		$errors = array_map(static fn (LibXMLError $error): string => trim($error->message), libxml_get_errors());
		libxml_clear_errors();
		libxml_use_internal_errors($previous);
		$this->assertTrue($loaded, 'the row is well-formed markup: ' . implode('; ', $errors));

		return new DOMXPath($document);
	}

	public function testTheRowIsOneTrOfSixCellsTheFiveStatusesInOrderThenALinkToThePfbDnsTab(): void
	{
		$row = $this->row_of(pfb_dns_widget_status(self::running(['dot' => self::rows('not_listening')])));

		$this->assertSame(1, $row->query('//tr')->length);
		$this->assertSame(6, $row->query('//tr/td')->length);
		$classes = [];
		foreach ($row->query('//tr/td[position() <= 5]/i/@class') as $class) {
			$classes[] = $class->nodeValue;
		}
		$this->assertSame([
			'PFBDNSSTATUS_service ' . self::GREEN,
			'PFBDNSSTATUS_plain ' . self::GREEN,
			'PFBDNSSTATUS_dot ' . self::YELLOW,
			'PFBDNSSTATUS_doh ' . self::RED,
			'PFBDNSSTATUS_doq ' . self::RED,
		], $classes);
		$this->assertSame('pfB-DNS', $row->evaluate('string(//tr/td[1]/strong)'));
		foreach ([2 => 'DNS', 3 => 'DoT', 4 => 'DoH', 5 => 'DoQ'] as $position => $label) {
			$this->assertSame($label, $row->evaluate("string(//tr/td[{$position}]/small)"), "cell {$position}");
		}
		$this->assertSame('pfblockerng/pfblockerng_dns.php', $row->evaluate('string(//tr/td[6]/a/@href)'));
		$this->assertSame('_blank', $row->evaluate('string(//tr/td[6]/a/@target)'));
		$this->assertSame('noopener noreferrer', $row->evaluate('string(//tr/td[6]/a/@rel)'));
		$this->assertSame('Click to open the pfB-DNS tab', $row->evaluate('string(//tr/td[6]/a/@title)'));
		$this->assertSame(1, $row->query('//tr/td[6]/a/i[@class="fa-regular fa-rectangle-list"]')->length);
	}

	public function testAHostileTitleIsEscapedExactlyOnce(): void
	{
		$hostile = '<script>alert("x")</script> & \'q\' &amp;';
		$cells = pfb_dns_widget_status(self::running(['dot' => ['state' => 'no_listener', 'notice' => $hostile]]));

		$row = $this->row_of($cells);

		$this->assertSame(0, $row->query('//script')->length, 'no markup came out of a title');
		$this->assertSame("DoT: {$hostile}", $row->evaluate('string(//tr/td[3]/@title)'), 'reads back as the original text, escaped once');
	}
}
