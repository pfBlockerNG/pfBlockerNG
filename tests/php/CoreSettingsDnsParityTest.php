<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3842: freezes today's PHP behaviour for Core's first settings projection, `settings/dns`, as the parity fixture
 * tests/core/fixtures/settings_dns_parity.json; go/pfb_core/settings passes the same file. A `stored` case is a config.xml
 * value: PHP never refuses it, and the value Core holds is what pfb_unbound.ini carries for it. A `posted` case is the
 * DNSBL page's input: its save validation decides `valid`, and an accepted value, stored as posted, gives the ini value.
 *
 * Issue #4036: the noAAAA and Group Policy fields. The ini has no key for either switch: it writes the [noAAAA] and
 * [GP_Bypass_List] sections exactly while its switch is on, so a switch is the ini writer's own gate, and a list is what the
 * section holds with its switch turned on, as pfB-DNS reads it (decider/pfb_unbound.go): a noAAAA row is `domain,flag`, one
 * flag per domain (the last row's), the wildcard flag held as a leading dot; a bypass row is an address or CIDR, each once.
 * Not held, as documented in docs/misc/core-api-protocol.md: a noAAAA row with a '%' (pfB-DNS refuses the whole ini) or a
 * name with white space (it matches no query), and the netmask and zone forms of a bypass entry the DNSBL page never saves.
 * A `refused` row is a value of these fields the adapter's write refuses, naming the field; Core refuses it too.
 */
#[CoversFunction('pfb_unbound_python_ini')]
#[CoversFunction('pfb_dnsbl_ini_inputs')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsDnsParityTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_dns_parity.json';

	/** The native field => its pfb_unbound.ini [MAIN] key. */
	private const INI_KEY = [
		'replyLogging'          => 'python_reply',
		'tldWildcard'           => 'python_tld_wildcard',
		'pslIncludePrivate'     => 'psl_include_private',
		'pslAllowPrivate'       => 'psl_allow_private',
		'pslFeedPrivatePolicy'  => 'psl_feed_private_policy',
		'pslFeedIcannPolicy'    => 'psl_feed_icann_policy',
		'idnMode'               => 'idn_mode',
		'idnBlockMalicious'     => 'python_idn_block_malicious',
		'idnEscalateSuspicious' => 'python_idn_escalate_suspicious',
		'decisionCacheMax'      => 'decisiondb_max',
		'cnameValidation'       => 'python_cname',
		'control'               => 'python_control',
		'controlLegacy'         => 'python_control_legacy',
		'regexCap'              => 'regex_cap',
		'metricsClientIp'       => 'metrics_client_ip',
	];

	/** The native switch => its list and the pfb_unbound.ini section that carries the list while the switch is on (issue #4036). */
	private const SECTIONS = [
		'noAaaa'      => ['noAaaaList', 'noAAAA'],
		'groupPolicy' => ['groupPolicyBypassList', 'GP_Bypass_List'],
	];

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private array $priorPost;
	private string $root;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->priorPost = $_POST;
		$this->root = sys_get_temp_dir() . '/pfb_core_parity_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root, 0700));
		$GLOBALS['config'] = [];
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
		$GLOBALS['g']['unbound_chroot_path'] = $this->root;
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		$_POST = $this->priorPost;
		rmdir_recursive($this->root);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function cases(): array
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$cases = [];
		foreach ($doc['cases'] as $case) {
			$cases[$case['id']] = [$case];
		}
		return $cases;
	}

	public function testTheFixtureIsTheDnsProjectionAndCoversEveryField(): void
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('dns', $doc['projection']);
		$defaults = array_values(array_filter($doc['cases'], static fn(array $c): bool => $c['id'] === 'defaults'));
		$this->assertCount(1, $defaults, 'one defaults case');
		$this->assertSame([...array_keys(self::INI_KEY), 'noAaaa', 'noAaaaList', 'groupPolicy', 'groupPolicyBypassList'], array_keys($defaults[0]['native']),
			'the defaults case names every field');
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function refused(): array
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$rows = [];
		foreach ($doc['refused'] as $row) {
			$rows[$row['id']] = [$row];
		}
		return $rows;
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesTheFixturesHostileValueNamingTheField(array $row): void
	{
		$interfaces = static fn(): array => [];
		$settings = pfb_core_settings($interfaces);
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => 1, 'settings' => $settings], $interfaces),
			'the adapter takes back what it read');
		$settings['dns'] = array_replace($settings['dns'], $row['input']);

		$reply = pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => 1, 'settings' => $settings], $interfaces);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$faults = array_filter($reply['error']['fieldErrors'] ?? [], static fn(array $f): bool => !in_array($f['message'], ['no such field', 'required'], TRUE));
		$this->assertContains("dns.{$row['field']}", array_column($faults, 'field'), "{$row['id']}: {$row['description']} " . json_encode($reply));
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesVerdictAndNativeValue(array $case): void
	{
		$values = $case['values'];
		if ($case['source'] === 'posted') {
			$this->assertSame($case['valid'], $this->pageAccepts($values), "{$case['id']}: the DNSBL page's verdict on " . json_encode($values));
		} else {
			$this->assertSame('stored', $case['source']);
			$this->assertTrue($case['valid'], "{$case['id']}: PHP refuses no stored value");
		}
		if (!$case['valid']) {
			$this->assertArrayNotHasKey('native', $case);
			return;
		}
		foreach ($values as $key => $value) {
			[$alias, $leaf] = explode('/', $key, 2);
			if ($value !== NULL) {
				config_set_path(PFB_SECTIONS[$alias] . '/' . $leaf, $value);
			}
		}
		pfb_global();
		pfb_dnsbl_ini_inputs();
		$switches = ['noAaaa' => $GLOBALS['pfb']['dnsbl_noaaaa'] === PfbToggle::On, 'groupPolicy' => $GLOBALS['pfb']['dnsbl_gp'] === PfbToggle::On];
		$ini = pfb_unbound_python_ini('enabled');
		$GLOBALS['pfb']['dnsbl_noaaaa'] = $GLOBALS['pfb']['dnsbl_gp'] = PfbToggle::On;
		$on = pfb_unbound_python_ini('enabled');
		$lists = [];
		foreach (self::SECTIONS as $switch => [$list, $section]) {
			$rows = self::sectionRows($on, $section);
			$this->assertSame($switches[$switch] ? $rows : [], self::sectionRows($ini, $section), "{$case['id']}: [{$section}] is in the ini exactly while {$switch} is on");
			$lists[$switch] = $switches[$switch];
			$lists[$list] = $switch === 'noAaaa' ? self::noAaaaEntries($rows) : self::bypassEntries($rows);
		}
		foreach ($case['native'] as $field => $expected) {
			if (array_key_exists($field, $lists)) {
				$this->assertSame($expected, $lists[$field], "{$case['id']}: {$field} from the ini\n{$on}");
				continue;
			}
			$this->assertArrayHasKey($field, self::INI_KEY, "{$case['id']}: {$field} is a projection field");
			$key = self::INI_KEY[$field];
			$this->assertSame(1, preg_match('/^' . $key . '\t= (.*)$/m', $ini, $m), "{$case['id']}: the ini has {$key}:\n{$ini}");
			$this->assertSame($expected, $this->native($field, $m[1]), "{$case['id']}: {$field} from ini {$key} = '{$m[1]}'");
			if ($field === 'idnMode') {
				$legacy = $expected === 'on' ? 'on' : 'off';
				$this->assertStringContainsString("\npython_idn\t= {$legacy}\n", $ini, "{$case['id']}: python_idn is on exactly for IDN mode on");
			}
		}
	}

	/** @return list<string> the values of the rows of the ini's $section, configparser's white space stripped; none when there is no section */
	private static function sectionRows(string $ini, string $section): array
	{
		if (preg_match('/\n\[' . $section . '\]\n((?:[^\[\n][^\n]*\n|\n)*)/', $ini, $m) !== 1) {
			return [];
		}
		$rows = [];
		foreach (array_filter(explode("\n", $m[1]), 'strlen') as $line) {
			[, $value] = explode('=', $line, 2);
			$rows[] = trim($value);
		}
		return $rows;
	}

	/**
	 * pfB-DNS's noAAAA table from the rows: `domain,flag` (any other count of fields skipped), the last row's flag per domain,
	 * listed in the order of those last rows with the wildcard flag as a leading dot. A row with a '%' (pfB-DNS refuses the whole
	 * ini) and a name with white space (it matches no query) are not held.
	 *
	 * @param list<string> $rows
	 * @return list<array{domain: string}>
	 */
	private static function noAaaaEntries(array $rows): array
	{
		$table = [];
		foreach ($rows as $row) {
			$data = explode(',', $row);
			if (count($data) !== 2 || str_contains($row, '%') || preg_match('/[\s\p{Z}\p{C}]/u', $data[0]) === 1) {
				continue;
			}
			unset($table[$data[0]]);
			$table[$data[0]] = $data[1] === '1';
		}
		return array_map(static fn(string $domain, bool $wildcard): array => ['domain' => ($wildcard ? '.' : '') . $domain], array_keys($table), $table);
	}

	/**
	 * The bypass entries pfB-DNS takes from the rows and Core holds, each once at its first place: an IP address, or one with a
	 * prefix length of digits within its family. pfB-DNS also takes a netmask prefix and an IPv6 zone; Core does not hold them.
	 *
	 * @param list<string> $rows
	 * @return list<array{cidr: string}>
	 */
	private static function bypassEntries(array $rows): array
	{
		$held = array_filter($rows, static function (string $row): bool {
			[$address, $bits] = [...explode('/', $row, 2), NULL];
			$packed = filter_var($address, FILTER_VALIDATE_IP) === FALSE ? FALSE : inet_pton($address);
			return $packed !== FALSE && ($bits === NULL || (ctype_digit($bits) && (int) $bits <= strlen($packed) * 8));
		});
		return array_map(static fn(string $entry): array => ['cidr' => $entry], array_values(array_unique($held)));
	}

	/** The ini token as the native value: on/off is bool, the cap an int, idn_mode '' is off, a policy its token. */
	private function native(string $field, string $token): bool|int|string
	{
		return match ($field) {
			'decisionCacheMax'                            => (int) $token,
			'idnMode'                                     => $token === '' ? 'off' : $token,
			'pslFeedPrivatePolicy', 'pslFeedIcannPolicy'  => $token,
			default                                       => match ($token) {
				'on'  => TRUE,
				'off' => FALSE,
			},
		};
	}

	/**
	 * The DNSBL page's own validation of the projection's fields, run as shipped: the statements from the decision-cache
	 * check to the IDN check (the only ones that refuse a projection field), over a POST of the page's untouched defaults.
	 *
	 * @param array<string, ?string> $values registry key => posted value
	 */
	private function pageAccepts(array $values): bool
	{
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		$from = strpos($source, "if (isset(\$_POST['pfb_py_cache_max'])");
		$to = strpos($source, '// ADR-59: top1m_token');
		$this->assertNotFalse($from, 'the DNSBL page still checks pfb_py_cache_max');
		$this->assertNotFalse($to, 'the DNSBL page still has its top1m_token anchor');
		$this->assertGreaterThan($from, $to);
		$_POST = ['pfb_idn' => 'off', 'pfb_regex_list' => ''];
		foreach ($values as $key => $value) {
			if ($value !== NULL) {
				$_POST[explode('/', $key, 2)[1]] = $value;
			}
		}
		$input_errors = [];
		eval(substr($source, $from, $to - $from));
		return $input_errors === [];
	}
}
