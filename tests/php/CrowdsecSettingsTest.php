<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4071 -- the CrowdSec tab's Settings (docs/specs/crowdsec-integration.md, D2 and D4).
 *
 * Pinned here:
 *   - the ten settings are registered in their own section (alias `crowdsec`), with the spec's defaults and sync classes: the key,
 *     the interfaces and the log level are local, everything else is policy;
 *   - the save's validation (pfb_crowdsec_validate()): every rule of the D2 table, with hostile values for the URL, key, tag and
 *     interfaces; an empty key field keeps the stored key, and no message ever carries the key; the URL is sanitized once at
 *     ingestion, while a key or tag holding a control or format character or outer whitespace is refused, never cleaned into a
 *     different value;
 *   - "should run" (pfb_crowdsec_should_run()): pfBlockerNG's master enable, the CrowdSec enable and a stored key, all three.
 */
#[CoversFunction('pfb_crowdsec_validate')]
#[CoversFunction('pfb_crowdsec_should_run')]
#[CoversFunction('pfb_crowdsec_settings')]
final class CrowdsecSettingsTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngcrowdsec/config/0';
	private const KEY = 'Zk9-stored_KEY.0123456789abcdef';
	private const IFACES = ['wan', 'lan', 'opt1'];

	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	// ---- registry ------------------------------------------------------------------------

	/** @return iterable<string, array{string, string, string, bool}> key => [default stored value, sync class, toggle?] */
	public static function fields(): iterable
	{
		yield 'enable'               => ['crowdsec/enable', '', 'policy', TRUE];
		yield 'lapi_url'             => ['crowdsec/lapi_url', '', 'policy', FALSE];
		yield 'api_key'              => ['crowdsec/api_key', '', 'local', FALSE];
		yield 'log_level'            => ['crowdsec/log_level', 'info', 'local', FALSE];
		yield 'rules_all_interfaces' => ['crowdsec/rules_all_interfaces', 'on', 'local', TRUE];
		yield 'rules_interfaces'     => ['crowdsec/rules_interfaces', '', 'local', FALSE];
		yield 'rules_log'            => ['crowdsec/rules_log', '', 'policy', TRUE];
		yield 'rules_tag'            => ['crowdsec/rules_tag', '', 'policy', FALSE];
		yield 'rule_v4'              => ['crowdsec/rule_v4', 'on', 'policy', TRUE];
		yield 'rule_v6'              => ['crowdsec/rule_v6', 'on', 'policy', TRUE];
	}

	public function testTheSectionHasItsOwnAlias(): void
	{
		$this->assertSame(self::SECTION, PFB_SECTIONS['crowdsec'] ?? NULL);
		$registered = array_values(array_filter(array_keys(pfb_cfg_registry()), static fn (string $k): bool => str_starts_with($k, 'crowdsec/')));
		$this->assertSame(array_column(iterator_to_array(self::fields()), 0), $registered, 'exactly the ten D2 settings, in the table order');
	}

	#[DataProvider('fields')]
	public function testEachSettingHasTheSpecDefaultAndSyncClass(string $key, string $default, string $sync, bool $toggle): void
	{
		$entry = pfb_cfg_registry()[$key] ?? NULL;
		$this->assertIsArray($entry, "{$key} is registered");
		$this->assertSame($default, $entry['default']);
		$this->assertSame($sync, $entry['sync']);
		$this->assertSame($toggle ? 'pfb_cfg_toggle_read' : NULL, $entry['read_adapter']);

		// Absent reads the default; the stored value reads back as stored (a toggle as its enum)
		$read = PfbConfig::read($key);
		$this->assertSame($toggle ? ($default === 'on' ? PfbToggle::On : PfbToggle::Off) : $default, $read, "{$key} absent");
	}

	public function testTheKeyIsTheOnlyCredentialAndNeverPolicy(): void
	{
		$policy = array_keys(array_filter(pfb_cfg_registry(), static fn (array $e, string $k): bool => str_starts_with($k, 'crowdsec/') && $e['sync'] === 'policy', ARRAY_FILTER_USE_BOTH));
		$this->assertSame(['crowdsec/enable', 'crowdsec/lapi_url', 'crowdsec/rules_log', 'crowdsec/rules_tag', 'crowdsec/rule_v4', 'crowdsec/rule_v6'], $policy);
	}

	// ---- validation ----------------------------------------------------------------------

	/** A complete, valid post of the form with the bouncer on. */
	private static function post(array $over = []): array
	{
		return array_replace([
			'enable'               => 'on',
			'lapi_url'             => 'https://lapi.example.net:8080/',
			'api_key'              => '',
			'log_level'            => 'info',
			'rules_all_interfaces' => 'on',
			'rules_log'            => '',
			'rules_tag'            => '',
			'rule_v4'              => 'on',
			'rule_v6'              => 'on',
		], $over);
	}

	/** @return array{values: array<string,string>, errors: list<string>} */
	private static function validate(array $post, string $stored = self::KEY): array
	{
		return pfb_crowdsec_validate($post, $stored, self::IFACES);
	}

	public function testAValidPostStoresEveryFieldAndAnEmptyKeyKeepsTheStoredOne(): void
	{
		$out = self::validate(self::post(['rules_all_interfaces' => '', 'rules_interfaces' => ['lan', 'opt1'], 'rules_log' => 'on',
			'rules_tag' => 'cs_block-1', 'rule_v6' => '', 'log_level' => 'debug']));
		$this->assertSame([], $out['errors']);
		$this->assertSame([
			'enable'               => 'on',
			'lapi_url'             => 'https://lapi.example.net:8080/',
			'api_key'              => self::KEY,
			'log_level'            => 'debug',
			'rules_all_interfaces' => '',
			'rules_interfaces'     => 'lan,opt1',
			'rules_log'            => 'on',
			'rules_tag'            => 'cs_block-1',
			'rule_v4'              => 'on',
			'rule_v6'              => '',
		], $out['values']);
	}

	public function testAPastedKeyReplacesTheStoredOneAndAbsentCheckboxesStoreOff(): void
	{
		$out = self::validate(['lapi_url' => 'http://10.0.0.5:8080', 'api_key' => 'new-KEY_1', 'log_level' => 'error', 'rules_interfaces' => ['wan']]);
		$this->assertSame([], $out['errors']);
		$this->assertSame('wan', $out['values']['rules_interfaces']);
		$this->assertSame('new-KEY_1', $out['values']['api_key']);
		foreach (['enable', 'rules_all_interfaces', 'rules_log', 'rule_v4', 'rule_v6'] as $toggle) {
			$this->assertSame('', $out['values'][$toggle], "{$toggle} unchecked");
		}
	}

	public function testAKeyAndAUrlAreRequiredOnlyWhenEnabled(): void
	{
		$off = self::validate(self::post(['enable' => '', 'lapi_url' => '']), '');
		$this->assertSame([], $off['errors'], 'off: neither is required');

		$on = self::validate(self::post(['lapi_url' => '']), '');
		$this->assertCount(2, $on['errors'], implode(' | ', $on['errors']));
		$this->assertStringContainsString('LAPI URL', $on['errors'][0]);
		$this->assertStringContainsString('API key', $on['errors'][1]);
	}

	/** @return iterable<string, array{mixed}> */
	public static function badUrls(): iterable
	{
		yield 'no scheme'          => ['lapi.example.net:8080'];
		yield 'ftp'                => ['ftp://lapi.example.net/'];
		yield 'no host'            => ['http:///v1'];
		yield 'credentials'        => ['https://user:pass@lapi.example.net/'];
		yield 'query'              => ['https://lapi.example.net/?a=1'];
		yield 'fragment'           => ['https://lapi.example.net/#x'];
		yield 'inner space'        => ['https://lapi.example.net/a b'];
		yield 'shell metachar'     => ['https://lapi.example.net/$(reboot)`id`;'];
		yield 'quote'              => ['https://lapi.example.net/"\''];
		yield 'oversized'          => ['https://' . str_repeat('a', 2100) . '.net/'];
		yield 'array'              => [['https://lapi.example.net/']];
		yield 'javascript'         => ['javascript:alert(1)'];
	}

	#[DataProvider('badUrls')]
	public function testAnUrlThatIsNotAnHttpUrlWithAHostIsRefused(mixed $url): void
	{
		$out = self::validate(self::post(['lapi_url' => $url]));
		$this->assertCount(1, $out['errors'], var_export($url, TRUE));
		$this->assertStringContainsString('LAPI URL', $out['errors'][0]);
	}

	public function testAnIdnHostAndAnIpv6HostAreUrls(): void
	{
		foreach (['https://bücher.example/', 'http://[2001:db8::5]:8080', 'HTTPS://LAPI.EXAMPLE.NET'] as $url) {
			$this->assertSame([], self::validate(self::post(['lapi_url' => $url]))['errors'], $url);
		}
	}

	/** @return iterable<string, array{mixed}> */
	public static function badKeys(): iterable
	{
		yield 'inner space'    => ['abc def'];
		yield 'non-ASCII'      => ['clé-secrète'];
		yield '257 characters' => [str_repeat('k', 257)];
		yield 'array'          => [['abc']];
	}

	#[DataProvider('badKeys')]
	public function testAKeyThatIsNotOneTo256PrintableAsciiIsRefusedAndNeverEchoed(mixed $key): void
	{
		$out = self::validate(self::post(['api_key' => $key]));
		$this->assertCount(1, $out['errors']);
		$this->assertStringContainsString('API key', $out['errors'][0]);
		if (is_string($key)) {
			$this->assertStringNotContainsString(trim($key), $out['errors'][0], 'the message never carries the key');
		}
		$this->assertSame(self::KEY, $out['values']['api_key'], 'a refused key leaves the stored one');
	}

	/**
	 * The URL is sanitized once, at ingestion (issue #1723): a control character or outer whitespace pasted into it is dropped before
	 * validation, as on every other pfBlockerNG page. The key and the tag are not: see the refusal tests below.
	 */
	public function testControlCharactersInTheUrlArePasteNoiseDroppedAtIngestion(): void
	{
		$out = self::validate(self::post(['lapi_url' => " https://lapi.exa\tmple.net/\r\n"]));
		$this->assertSame([], $out['errors']);
		$this->assertSame('https://lapi.example.net/', $out['values']['lapi_url']);
	}

	/** @return iterable<string, array{string}> */
	public static function noisyKeys(): iterable
	{
		yield 'leading tab'        => ["\tabc"];
		yield 'trailing space'     => ['abc '];
		yield 'leading space'      => [' abc'];
		yield 'control character'  => ["ab\x01c"];
		yield 'DEL'                => ["abc\x7f"];
		yield 'zero-width space'   => ["ab\u{200B}c"];
		yield 'byte order mark'    => ["\u{FEFF}abc"];
		yield 'bidi override'      => ["ab\u{202E}c"];
		yield 'trailing line break' => ["abc\r\n"];
		yield 'trailing newline'   => ["abc\n"];
		yield 'only a space'       => [' '];
		yield 'no-break space'     => ["\u{00A0}abc"];
	}

	/**
	 * The key travels in a request header, and a stripped credential is a different value than the one typed: D2 refuses a key holding
	 * anything but printable ASCII, outer whitespace and control or format characters included.
	 */
	#[DataProvider('noisyKeys')]
	public function testAKeyHoldingControlOrFormatCharactersOrOuterWhitespaceIsRefusedNotCleaned(string $key): void
	{
		$out = self::validate(self::post(['api_key' => $key]));

		$this->assertCount(1, $out['errors'], json_encode($key));
		$this->assertStringContainsString('API key', $out['errors'][0]);
		$visible = preg_replace('/[^\x21-\x7e]/', '', $key);
		if ($visible !== '') {
			$this->assertStringNotContainsString($visible, $out['errors'][0], 'the message never carries the key');
		}
		$this->assertSame(self::KEY, $out['values']['api_key'], 'a refused key leaves the stored one');
	}

	/** @return iterable<string, array{string}> */
	public static function noisyTags(): iterable
	{
		yield 'leading space'     => [' cs'];
		yield 'trailing space'    => ['cs '];
		yield 'inner tab'         => ["c\ts"];
		yield 'NUL'               => ["cs\x00"];
		yield 'zero-width joiner' => ["c\u{200D}s"];
		yield 'trailing newline'  => ["cs\n"];
	}

	#[DataProvider('noisyTags')]
	public function testATagHoldingControlOrFormatCharactersOrOuterWhitespaceIsRefusedNotCleaned(string $tag): void
	{
		$out = self::validate(self::post(['rules_tag' => $tag]));

		$this->assertCount(1, $out['errors'], json_encode($tag));
		$this->assertStringContainsString('Tag', $out['errors'][0]);
		$this->assertSame('', $out['values']['rules_tag'], 'a refused tag is not stored');
	}

	public function testA256CharacterKeyOfEveryPrintableCharacterIsAccepted(): void
	{
		$printable = implode('', array_map('chr', range(0x21, 0x7e)));
		$key = substr(str_repeat($printable, 3), 0, 256);
		$out = self::validate(self::post(['api_key' => $key]));
		$this->assertSame([], $out['errors']);
		$this->assertSame($key, $out['values']['api_key']);
	}

	/** @return iterable<string, array{mixed}> */
	public static function badTags(): iterable
	{
		yield 'space'      => ['cs block'];
		yield 'dot'        => ['cs.block'];
		yield 'quote'      => ['cs"block'];
		yield 'semicolon'  => ['cs;block'];
		yield '64 long'    => [str_repeat('t', 64)];
		yield 'non-ASCII'  => ['tág'];
		yield 'array'      => [['cs']];
	}

	#[DataProvider('badTags')]
	public function testATagOutsideTheCharsetIsRefused(mixed $tag): void
	{
		$out = self::validate(self::post(['rules_tag' => $tag]));
		$this->assertCount(1, $out['errors']);
		$this->assertStringContainsString('Tag', $out['errors'][0]);
	}

	public function testASixtyThreeCharacterTagIsAccepted(): void
	{
		$this->assertSame([], self::validate(self::post(['rules_tag' => str_repeat('T', 63)]))['errors']);
	}

	/** @return iterable<string, array{mixed}> */
	public static function badLevels(): iterable
	{
		yield 'warn'   => ['warn'];
		yield 'empty'  => [''];
		yield 'upper'  => ['INFO'];
		yield 'array'  => [['info']];
	}

	#[DataProvider('badLevels')]
	public function testALogLevelOutsideTheFourIsRefused(mixed $level): void
	{
		$out = self::validate(self::post(['log_level' => $level]));
		$this->assertCount(1, $out['errors']);
		$this->assertStringContainsString('log level', $out['errors'][0]);
	}

	/** @return iterable<string, array{mixed}> */
	public static function badInterfaces(): iterable
	{
		yield 'none'            => [[]];
		yield 'absent'          => [NULL];
		yield 'not configured'  => [['lan', 'opt9']];
		yield 'real name'       => [['em0']];
		yield 'injection'       => [['lan; pfctl -d']];
		yield 'a string'        => ['lan'];
		yield 'nested array'    => [[['lan']]];
	}

	#[DataProvider('badInterfaces')]
	public function testSelectedInterfacesMustAllBeConfiguredAndAtLeastOneWhenNotAll(mixed $ifaces): void
	{
		$post = self::post(['rules_all_interfaces' => '']);
		if ($ifaces !== NULL) {
			$post['rules_interfaces'] = $ifaces;
		}
		$out = self::validate($post);
		$this->assertCount(1, $out['errors']);
		$this->assertStringContainsString('interface', $out['errors'][0]);
	}

	public function testWithAllInterfacesTheSelectionIsKeptButNotRequired(): void
	{
		$out = self::validate(self::post(['rules_all_interfaces' => 'on']));
		$this->assertSame([], $out['errors']);
		$this->assertSame('', $out['values']['rules_interfaces']);
	}

	// ---- should run ----------------------------------------------------------------------

	/** @return iterable<string, array{PfbToggle, string, string, bool}> */
	public static function shouldRun(): iterable
	{
		yield 'all three'             => [PfbToggle::On, 'on', self::KEY, TRUE];
		yield 'pfBlockerNG off'       => [PfbToggle::Off, 'on', self::KEY, FALSE];
		yield 'CrowdSec off'          => [PfbToggle::On, '', self::KEY, FALSE];
		yield 'no key on this node'   => [PfbToggle::On, 'on', '', FALSE];
		yield 'nothing'               => [PfbToggle::Off, '', '', FALSE];
	}

	#[DataProvider('shouldRun')]
	public function testTheBouncerShouldRunOnlyWithTheMasterEnableTheCrowdsecEnableAndAKey(PfbToggle $master, string $enable, string $key, bool $expected): void
	{
		$GLOBALS['pfb']['enable'] = $master;
		config_set_path(self::SECTION, ['enable' => $enable, 'api_key' => $key, 'lapi_url' => 'https://lapi.example.net/']);
		$this->assertSame($expected, pfb_crowdsec_should_run());
	}

	public function testSettingsReadsEveryFieldThroughTheGatewayWithTheKeyOnlyAsStored(): void
	{
		config_set_path(self::SECTION, ['enable' => 'on', 'api_key' => self::KEY, 'rules_interfaces' => 'lan,opt1', 'rule_v6' => '']);
		$s = pfb_crowdsec_settings();
		$this->assertSame(PfbToggle::On, $s['enable']);
		$this->assertSame(self::KEY, $s['api_key']);
		$this->assertSame('info', $s['log_level'], 'absent reads the default');
		$this->assertSame(PfbToggle::On, $s['rules_all_interfaces']);
		$this->assertSame('lan,opt1', $s['rules_interfaces']);
		$this->assertSame(PfbToggle::On, $s['rule_v4']);
		$this->assertSame(PfbToggle::Off, $s['rule_v6']);
		$this->assertSame(array_column(iterator_to_array(self::fields()), 0), array_map(static fn (string $k): string => "crowdsec/{$k}", array_keys($s)));
	}
}
