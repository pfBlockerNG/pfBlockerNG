<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3849: the applied reader parses each numeric address once, by its bytes, and returns it in PHP's spelling
 * (pfb_dns_proxy_host_port(), inet_ntop). The gateway prints an IPv4-compatible address as ::c000:201 where PHP prints ::192.0.2.1,
 * so a textual comparison refused the gateway's actual wire. Mapped, zero-padded and uppercase spellings are numeric-equivalence
 * inputs of the same rows: the gateway never prints them, so they are labelled test inputs, not captured output. Every duplicate
 * case has a sibling that differs only by a distinct address and is accepted, so a rejection is attributable to the duplicate alone.
 */
#[CoversFunction('pfb_dns_proxy_applied_status')]
#[CoversFunction('pfb_dns_proxy_endpoint')]
#[CoversFunction('pfb_dns_proxy_upstream_ready')]
final class PfbDnsAppliedStatusAddressBytesTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_valid_pids', 'pfb_test_rcfile_dir',
		'pfb_test_interface_ip', 'pfb_test_interface_info',
	];

	private string $dir;
	private array $savedGlobals = [];
	private array $servers = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->dir = sys_get_temp_dir() . '/pfb_address_bytes_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->dir,
			'log' => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
			'dns_proxy_ctl' => "{$this->dir}/ctl.sock",
			'dns_proxy_activation_failed' => "{$this->dir}/activation_failed",
			'pfb_dns' => PfbToggle::On,
			'enable' => PfbToggle::On,
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		@unlink(PFB_DNS_PROXY_RCFILE);
		$this->clearProxyFiles();
		$this->setUpUpstreamFixture();
		$this->setProxyMode();
		$this->proxyServes();
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as [$process, $pipes]) {
			foreach ($pipes as $pipe) {
				fclose($pipe);
			}
			proc_close($process);
		}
		$this->servers = [];
		$this->tearDownUpstreamFixture();
		$this->clearProxyFiles();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		@unlink(PFB_DNS_PROXY_RCFILE);
		rmdir_recursive($this->dir);
	}

	/** The Resolver as pfB-DNS leaves it on a proxy-mode box: a valid saved snapshot of a Resolver that listened on lan. */
	private function setProxyMode(): void
	{
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1'];
		$GLOBALS['pfb_test_interface_info'] = ['lan' => ['status' => 'up', 'enable' => TRUE]];
	}

	/** The gateway's captured wire, as the gateway serves it, with only its pid and executable replaced: this box's package binary and the pid the marker names. */
	private function captured(string $file): string
	{
		$body = json_decode(substr((string) file_get_contents(__DIR__ . '/support/' . $file), 0, -4), FALSE, 16, JSON_THROW_ON_ERROR);
		$body->pid = 4242;
		$body->executable = PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns';
		return json_encode($body, JSON_THROW_ON_ERROR) . "\nok\n";
	}

	/** Answer the applied-status requests on this test's control socket with $wire, as the gateway does. */
	private function serve(string $wire): void
	{
		$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $GLOBALS['pfb']['dns_proxy_ctl'],
			"{$this->dir}/frames", base64_encode($wire)], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$process, $pipes];
	}

	private function read(): ?array
	{
		return pfb_dns_proxy_applied_status(NULL, 0.5);
	}

	/** The house spelling of one numeric address: its bytes as inet_ntop prints them. */
	private static function house(string $address): string
	{
		return (string) inet_ntop((string) inet_pton($address));
	}

	/** A valid snapshot with no upstream and DDR off; a test overrides only the fields it is about. */
	private static function snapshot(array $fields = []): array
	{
		return $fields + [
			'version' => 1, 'pid' => 4242, 'executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns', 'ready' => TRUE,
			'dns_name' => '', 'ddr' => FALSE,
			'listeners' => [['kind' => 'udp+tcp', 'address' => '192.0.2.1:53', 'state' => 'listening', 'reason' => '']],
			'name_answers' => (object) [],
			'advertisements' => (object) ['192.0.2.1' => ['records' => [], 'additional' => []]],
		];
	}

	/** A DoH record advertising $hint, in the shape the gateway's status prints. */
	private static function record(string $hint): array
	{
		return ['priority' => 1, 'target' => 'applied.example.com', 'alpn' => 'h2', 'port' => 443, 'hint' => $hint, 'path' => '/dns-query{?dns}'];
	}

	/** One name answer: the family named by $family holds $values and the other is owned NODATA. */
	private static function answers(string $family, array $values): object
	{
		return (object) ['a' => $family === 'a' ? $values : [], 'aaaa' => $family === 'aaaa' ? $values : []];
	}

	/** One UDP+TCP listener row at $address, listening. */
	private static function listening(string $address): array
	{
		return ['kind' => 'udp+tcp', 'address' => $address, 'state' => 'listening', 'reason' => ''];
	}

	private static function wire(array $snapshot): string
	{
		return json_encode($snapshot, JSON_THROW_ON_ERROR) . "\nok\n";
	}

	public function testTheBaseSnapshotIsAValidControl(): void
	{
		// Given a valid snapshot whose one listener is in plain dotted IPv4 form
		$this->serve(self::wire(self::snapshot()));

		// When the applied status is read
		$status = $this->read();

		// Then it is accepted with the listener and its advertisement exactly as written
		$this->assertNotNull($status, 'the control spelling is accepted; every other case here is judged against it');
		$this->assertSame('192.0.2.1:53', $status['listeners'][0]['address']);
		$this->assertSame(['192.0.2.1'], array_keys($status['advertisements']));
	}

	public function testActualGoUpstreamWithAnIpv4CompatibleSpellingIsReadAsItsBytes(): void
	{
		// Given the gateway's actual wire for --upstream '[::c000:201]:5353', which it prints in the IPv4-compatible spelling
		$this->serve($this->captured('real-status-ipv4-compatible-upstream.wire'));

		// When the applied status is read
		$status = $this->read();

		// Then the snapshot is accepted, and the upstream is the house spelling of the same bytes
		$this->assertNotNull($status, 'the same bytes in the gateway spelling are a valid snapshot');
		$this->assertSame('[' . self::house('::c000:201') . ']:5353', $status['upstream']);
	}

	public function testActualGoListenerWithAnIpv4CompatibleSpellingKeysItsAdvertisementByTheSameBytes(): void
	{
		// Given the gateway's actual wire for a listener on [::c000:201]:53, with its advertisement under the gateway's spelling
		$this->serve($this->captured('real-status-ipv4-compatible-listener.wire'));

		// When the applied status is read
		$status = $this->read();

		// Then the listener and the advertisement key are both the house spelling of those bytes
		$local = self::house('::c000:201');
		$this->assertNotNull($status, 'the same bytes in the gateway spelling are a valid snapshot');
		$this->assertSame("[{$local}]:53", $status['listeners'][0]['address']);
		$this->assertSame([$local], array_keys($status['advertisements']));
		$this->assertSame('127.0.0.1:5353', $status['upstream']);
	}

	public function testADerivedMappedVariantOfTheGoListenerIsTheSameRow(): void
	{
		// Given the gateway's actual listener capture, with its row and key rewritten to the IPv4-mapped spelling: a derived
		// numeric-equivalence input, not Go output (the gateway unmaps before it prints)
		$body = json_decode(substr($this->captured('real-status-ipv4-compatible-listener.wire'), 0, -4), FALSE, 16, JSON_THROW_ON_ERROR);
		$body->listeners[0]->address = '[::ffff:192.0.2.1]:53';
		$body->advertisements = (object) ['::ffff:192.0.2.1' => ['records' => [], 'additional' => []]];
		$this->serve(json_encode($body, JSON_THROW_ON_ERROR) . "\nok\n");

		// When the applied status is read
		$status = $this->read();

		// Then the mapped row is the IPv4 row, keyed by that IPv4 address
		$this->assertNotNull($status, 'the mapped spelling of the same bytes is a valid snapshot');
		$this->assertSame('192.0.2.1:53', $status['listeners'][0]['address']);
		$this->assertSame(['192.0.2.1'], array_keys($status['advertisements']));
	}

	public static function upstreamSpellingsAsUnboundReportsThem(): array
	{
		return [
			'Unbound owns it in the gateway spelling' => ['[::c000:201]:5353', TRUE],
			'Unbound owns it in the PHP spelling' => ['[' . self::house('::c000:201') . ']:5353', TRUE],
			'Unbound owns another IPv4-compatible address' => ['[::c000:202]:5353', FALSE],
		];
	}

	#[DataProvider('upstreamSpellingsAsUnboundReportsThem')]
	public function testUpstreamReadinessComparesBytesWhateverSpellingUnboundReports(string $owned, bool $ready): void
	{
		// Given the gateway's actual wire for --upstream '[::c000:201]:5353'
		$this->serve($this->captured('real-status-ipv4-compatible-upstream.wire'));
		$status = $this->read();
		$this->assertNotNull($status, 'the gateway wire is a valid snapshot before its upstream is judged');

		// And Unbound's TCP and UDP sockets on that port are reported in the given spelling
		$this->seedUnbound($owned);

		// When readiness is judged, then it holds exactly when Unbound owns the same bytes
		$this->assertSame($ready, pfb_dns_proxy_upstream_ready($status));
	}

	public function testEverySpellingInOneSnapshotIsReadAsItsHouseForm(): void
	{
		// Given one snapshot with the gateway spelling, a mapped spelling, an uppercase spelling, and records and answers spelled alike
		$compat = self::house('::c000:201');
		$this->serve(self::wire(self::snapshot([
			'upstream' => '[::c000:201]:5353', 'dns_name' => 'applied.example.com', 'ddr' => TRUE,
			'listeners' => [
				self::listening('[::c000:201]:53'),
				self::listening('[::ffff:192.0.2.2]:53'),
				['kind' => 'dot', 'address' => '[2001:DB8::3]:853', 'state' => 'listening', 'reason' => ''],
			],
			'name_answers' => (object) ['::ffff:192.0.2.2' => ['a' => ['::ffff:192.0.2.2'], 'aaaa' => ['2001:0DB8::3']]],
			'advertisements' => (object) [
				'::c000:201' => ['records' => [self::record('::c000:201')], 'additional' => ['::c000:201']],
				'::ffff:192.0.2.2' => ['records' => [], 'additional' => []],
				'2001:DB8::3' => ['records' => [['priority' => 2, 'target' => 'applied.example.com', 'alpn' => 'dot', 'port' => 853,
					'hint' => '2001:DB8::3', 'path' => '']], 'additional' => ['2001:DB8::3']],
			],
		])));

		// When the applied status is read
		$status = $this->read();

		// Then every address is in its house spelling and every map is keyed by that spelling
		$this->assertNotNull($status, 'every spelling is one of the same numeric addresses');
		$this->assertSame('[' . $compat . ']:5353', $status['upstream']);
		$this->assertSame(['[' . $compat . ']:53', '192.0.2.2:53', '[2001:db8::3]:853'], array_column($status['listeners'], 'address'));
		$this->assertSame(['192.0.2.2' => ['a' => ['192.0.2.2'], 'aaaa' => ['2001:db8::3']]], $status['name_answers']);
		$this->assertSame([$compat, '192.0.2.2', '2001:db8::3'], array_keys($status['advertisements']));
		$this->assertSame([self::record($compat)], $status['advertisements'][$compat]['records']);
		$this->assertSame([$compat], $status['advertisements'][$compat]['additional']);
		$this->assertSame('2001:db8::3', $status['advertisements']['2001:db8::3']['records'][0]['hint']);
		$this->assertSame(['2001:db8::3'], $status['advertisements']['2001:db8::3']['additional']);
	}

	public static function equivalentListeners(): array
	{
		return [
			'uppercase hex' => ['[2001:DB8::1]:53', '2001:DB8::1', '[2001:db8::1]:53', '2001:db8::1'],
			'zero-padded groups' => ['[2001:0db8:0000::1]:53', '2001:0db8::1', '[2001:db8::1]:53', '2001:db8::1'],
			'mapped IPv4' => ['[::ffff:192.0.2.1]:53', '::ffff:192.0.2.1', '192.0.2.1:53', '192.0.2.1'],
			'mapped IPv4 in hex' => ['[::FFFF:c000:201]:53', '::FFFF:c000:201', '192.0.2.1:53', '192.0.2.1'],
			'IPv4-compatible IPv6' => ['[::c000:201]:53', '::c000:201', '[' . self::house('::c000:201') . ']:53', self::house('::c000:201')],
			'leading-zero port' => ['192.0.2.1:053', '192.0.2.1', '192.0.2.1:53', '192.0.2.1'],
			'five-digit port with zeros' => ['192.0.2.1:00053', '192.0.2.1', '192.0.2.1:53', '192.0.2.1'],
		];
	}

	#[DataProvider('equivalentListeners')]
	public function testOneNumericListenerIsReadAsItsHouseSpellingWhateverSpellingItsBytesHave(
		string $address,
		string $key,
		string $expected,
		string $expectedKey,
	): void {
		// Given a listener and its advertisement key, both in one non-house numeric spelling of the same bytes
		$this->serve(self::wire(self::snapshot([
			'listeners' => [self::listening($address)],
			'advertisements' => (object) [$key => ['records' => [], 'additional' => []]],
		])));

		// When the applied status is read
		$status = $this->read();

		// Then the listener and its key are the house spelling of those bytes
		$this->assertNotNull($status, 'the same bytes in another numeric spelling are a valid snapshot');
		$this->assertSame($expected, $status['listeners'][0]['address']);
		$this->assertSame([$expectedKey], array_keys($status['advertisements']));
	}

	public static function distinctOrAliasedRows(): array
	{
		$empty = ['records' => [], 'additional' => []];
		return [
			'a mapped and an ordinary address are two rows' => [self::snapshot([
				'listeners' => [self::listening('[::ffff:192.0.2.2]:53'), self::listening('192.0.2.1:53')],
				'advertisements' => (object) ['::ffff:192.0.2.2' => $empty, '192.0.2.1' => $empty],
			]), TRUE],
			'a mapped alias of a row is that row again' => [self::snapshot([
				'listeners' => [self::listening('192.0.2.1:53'), self::listening('[::ffff:192.0.2.1]:53')],
			]), FALSE],
			'a leading-zero port on another address is a second row' => [self::snapshot([
				'listeners' => [self::listening('192.0.2.1:53'), self::listening('192.0.2.2:053')],
				'advertisements' => (object) ['192.0.2.1' => $empty, '192.0.2.2' => $empty],
			]), TRUE],
			'a leading-zero port on the same address is that row again' => [self::snapshot([
				'listeners' => [self::listening('192.0.2.1:53'), self::listening('192.0.2.1:053')],
			]), FALSE],
			'a zero-padded IPv6 alias repeats a row' => [self::snapshot([
				'listeners' => [self::listening('[2001:db8::1]:53'), self::listening('[2001:0db8::1]:53')],
				'advertisements' => (object) ['2001:db8::1' => $empty],
			]), FALSE],
			'a zero-padded IPv6 on another address is a second row' => [self::snapshot([
				'listeners' => [self::listening('[2001:db8::1]:53'), self::listening('[2001:0db8::2]:53')],
				'advertisements' => (object) ['2001:db8::1' => $empty, '2001:0db8::2' => $empty],
			]), TRUE],
			'two advertisement keys for two addresses' => [self::snapshot([
				'listeners' => [self::listening('192.0.2.1:53'), self::listening('[::ffff:192.0.2.2]:53')],
				'advertisements' => (object) ['192.0.2.1' => $empty, '::ffff:192.0.2.2' => $empty],
			]), TRUE],
			'two advertisement keys for one address' => [self::snapshot([
				'advertisements' => (object) ['192.0.2.1' => $empty, '::ffff:192.0.2.1' => $empty],
			]), FALSE],
			'two name-answer keys for two addresses' => [self::snapshot([
				'listeners' => [self::listening('192.0.2.1:53'), self::listening('[::ffff:192.0.2.2]:53')],
				'advertisements' => (object) ['192.0.2.1' => $empty, '::ffff:192.0.2.2' => $empty],
				'name_answers' => (object) ['192.0.2.1' => self::answers('a', []), '::ffff:192.0.2.2' => self::answers('a', [])],
			]), TRUE],
			'two name-answer keys for one address' => [self::snapshot([
				'name_answers' => (object) ['192.0.2.1' => self::answers('a', []), '::ffff:192.0.2.1' => self::answers('a', [])],
			]), FALSE],
			'two additional addresses that are distinct' => [self::snapshot([
				'ddr' => TRUE,
				'advertisements' => (object) ['192.0.2.1' => ['records' => [self::record('192.0.2.1')],
					'additional' => ['192.0.2.1', '::ffff:192.0.2.2']]],
			]), TRUE],
			'a mapped and an ordinary additional address are one' => [self::snapshot([
				'ddr' => TRUE,
				'advertisements' => (object) ['192.0.2.1' => ['records' => [self::record('192.0.2.1')],
					'additional' => ['192.0.2.1', '::ffff:192.0.2.1']]],
			]), FALSE],
		];
	}

	#[DataProvider('distinctOrAliasedRows')]
	public function testRowsAndKeysAreUniqueByAddressBytes(array $snapshot, bool $accepted): void
	{
		// Given a snapshot in which two spellings either name one address or name two addresses
		$this->serve(self::wire($snapshot));

		// When the applied status is read
		// Then it is accepted exactly when its addresses are distinct
		$this->assertSame($accepted, $this->read() !== NULL, 'two spellings of one address are one row or key; distinct addresses are two');
	}

	public static function answerValues(): array
	{
		return [
			'a mapped IPv4 address is an A answer' => ['a', ['::ffff:192.0.2.1'], ['192.0.2.1']],
			'a zero-padded AAAA answer is the same IPv6' => ['aaaa', ['2001:0db8::1'], ['2001:db8::1']],
			'an IPv4-compatible address is an AAAA answer' => ['aaaa', ['::c000:202'], [self::house('::c000:202')]],
			'an uppercase AAAA answer is the same IPv6' => ['aaaa', ['2001:0DB8::3'], ['2001:db8::3']],
		];
	}

	#[DataProvider('answerValues')]
	public function testAnAnswerIsReadAsItsHouseSpellingWithinItsFamily(string $family, array $values, array $expected): void
	{
		// Given an owned name answer whose one value is in a non-house spelling of its family's bytes
		$this->serve(self::wire(self::snapshot(['name_answers' => (object) ['192.0.2.1' => self::answers($family, $values)]])));

		// When the applied status is read
		$status = $this->read();

		// Then the value is the house spelling, and it is still that family's answer
		$this->assertNotNull($status, 'the family check is on the bytes, so the spelling is no reason to refuse');
		$this->assertSame($expected, $status['name_answers']['192.0.2.1'][$family]);
	}

	public static function answersOfAnotherFamily(): array
	{
		return [
			'a mapped IPv4 address is not an AAAA answer' => ['aaaa', ['::ffff:192.0.2.1']],
			'an IPv6 address is not an A answer' => ['a', ['2001:0db8::1']],
			'an IPv4-compatible address is not an A answer' => ['a', ['::c000:201']],
			'an IPv4 address is not an AAAA answer' => ['aaaa', ['192.0.2.1']],
			'a zone is not an answer' => ['aaaa', ['fe80::1%em0']],
		];
	}

	#[DataProvider('answersOfAnotherFamily')]
	public function testAnAnswerOfTheWrongFamilyFailsClosed(string $family, array $values): void
	{
		$this->serve(self::wire(self::snapshot(['name_answers' => (object) ['192.0.2.1' => self::answers($family, $values)]])));
		$this->assertNull($this->read());
	}

	public function testAMappedHintAndAdditionalAddressAreTheLocalAddress(): void
	{
		// Given a DDR record whose hint, and an additional answer, spell the local 192.0.2.1 in the mapped form
		$this->serve(self::wire(self::snapshot([
			'ddr' => TRUE,
			'advertisements' => (object) ['192.0.2.1' => ['records' => [self::record('::ffff:192.0.2.1')], 'additional' => ['::ffff:192.0.2.1']]],
		])));

		// When the applied status is read
		$status = $this->read();

		// Then both are the local address in the house spelling
		$this->assertNotNull($status, 'the hint names the local address by its bytes');
		$this->assertSame('192.0.2.1', $status['advertisements']['192.0.2.1']['records'][0]['hint']);
		$this->assertSame(['192.0.2.1'], $status['advertisements']['192.0.2.1']['additional']);
	}

	public function testAHintOfOtherBytesFailsClosed(): void
	{
		$this->serve(self::wire(self::snapshot([
			'ddr' => TRUE,
			'advertisements' => (object) ['192.0.2.1' => ['records' => [self::record('::ffff:192.0.2.2')], 'additional' => []]],
		])));
		$this->assertNull($this->read());
	}

	public static function malformedListeners(): array
	{
		return [
			'zone' => ['[fe80::1%em0]:53'], 'escaped zone' => ['[fe80::1%25em0]:53'],
			'hostname' => ['dns.example:53'], 'localhost' => ['localhost:53'],
			'leading space' => [' 192.0.2.1:53'], 'trailing space' => ['192.0.2.1:53 '], 'space before the colon' => ['192.0.2.1 :53'],
			'space inside brackets' => ['[ 2001:db8::1]:53'], 'tab' => ["192.0.2.1\t:53"], 'newline' => ["192.0.2.1:53\n"],
			'NUL' => ["192.0.2.1\u{0}:53"], 'NUL inside brackets' => ["[2001:db8::1\u{0}]:53"],
			'unclosed bracket' => ['[2001:db8::1:53'], 'unopened bracket' => ['2001:db8::1]:53'],
			'unbracketed IPv6' => ['2001:db8::1:53'], 'doubled brackets' => ['[[2001:db8::1]]:53'], 'empty brackets' => ['[]:53'],
			'bracketed IPv4' => ['[192.0.2.1]:53'],
			'port zero' => ['192.0.2.1:0'], 'zero in five digits' => ['192.0.2.1:00000'], 'port 65536' => ['192.0.2.1:65536'],
			'six-digit port' => ['192.0.2.1:000053'], 'signed port' => ['192.0.2.1:+53'], 'negative port' => ['192.0.2.1:-53'],
			'port with a space' => ['192.0.2.1:5 3'], 'port with a letter' => ['192.0.2.1:53x'], 'no port' => ['192.0.2.1:'],
			'IPv4 out of range' => ['192.0.2.256:53'], 'short IPv4' => ['192.0.2:53'], 'hex IPv4' => ['0xc0.0.2.1:53'],
			'zero-padded IPv4 octet' => ['192.000.2.1:53'],
			'empty string' => [''],
			'non-hex IPv6' => ['[2001:db8::g]:53'], 'IPv6 group out of range' => ['[2001:db8::12345]:53'],
		];
	}

	#[DataProvider('malformedListeners')]
	public function testAMalformedListenerEndpointFailsClosed(string $address): void
	{
		$this->serve(self::wire(self::snapshot(['listeners' => [self::listening($address)]])));
		$this->assertNull($this->read());
	}

	public static function numericUpstreams(): array
	{
		return [
			'IPv4' => ['127.0.0.1:5353', '127.0.0.1:5353'],
			'IPv6' => ['[::1]:5353', '[::1]:5353'],
			'IPv4-compatible IPv6' => ['[::c000:201]:5353', '[' . self::house('::c000:201') . ']:5353'],
			'uppercase IPv6 with a zero-padded port' => ['[2001:DB8::1]:05353', '[2001:db8::1]:5353'],
		];
	}

	#[DataProvider('numericUpstreams')]
	public function testAPresentNumericUpstreamIsKeptInTheHouseSpelling(string $upstream, string $expected): void
	{
		$this->serve(self::wire(self::snapshot(['upstream' => $upstream])));
		$status = $this->read();
		$this->assertNotNull($status, 'a canonical numeric endpoint is a valid optional upstream');
		$this->assertSame($expected, $status['upstream']);
	}

	public static function malformedUpstreams(): array
	{
		return [
			'zone' => ['[fe80::1%em0]:5353'], 'hostname' => ['localhost:5353'], 'bracketed IPv4' => ['[127.0.0.1]:5353'],
			'unbracketed IPv6' => ['::1:5353'], 'port zero' => ['[::1]:0'], 'leading space' => [' [::1]:5353'],
			'null' => [NULL], 'boolean' => [TRUE], 'number' => [5353],
			'empty string' => [''],
		];
	}

	#[DataProvider('malformedUpstreams')]
	public function testAPresentUpstreamThatIsNotANumericEndpointFailsClosed(mixed $upstream): void
	{
		$this->serve(self::wire(self::snapshot(['upstream' => $upstream])));
		$this->assertNull($this->read());
	}

	public function testAnAbsentUpstreamIsNotReadyWithoutAWarningOrDeprecation(): void
	{
		// Given a valid snapshot with no upstream field, as the gateway sends when it cannot canonicalise the spelling
		$this->serve(self::wire(self::snapshot()));
		$status = $this->read();
		$this->assertNotNull($status);
		$this->assertArrayNotHasKey('upstream', $status);

		// And a live Unbound on its pidfile, so readiness reaches the upstream check rather than returning on a dead backend
		$this->seedUnbound();
		$this->assertTrue(isvalidpid($this->unboundPidfile()), 'the Unbound pidfile must read live, or the check below never runs');

		// When readiness is judged with every warning and deprecation raised as an exception
		set_error_handler(static function (int $number, string $message): bool {
			throw new ErrorException($message, 0, $number);
		}, E_WARNING | E_DEPRECATED);
		try {
			// Then no endpoint is proven, so readiness is not claimed, and reading the missing key raised nothing
			$this->assertFalse(pfb_dns_proxy_upstream_ready($status), 'with no endpoint to prove, readiness is not claimed');
		} finally {
			restore_error_handler();
		}
	}
}
