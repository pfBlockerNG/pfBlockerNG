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
 */
#[CoversFunction('pfb_unbound_python_ini')]
#[CoversFunction('pfb_dnsbl_ini_inputs')]
final class CoreSettingsDnsParityTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_dns_parity.json';

	/** The native field => its pfb_unbound.ini [MAIN] key. */
	private const INI_KEY = [
		'replyLogging'          => 'python_reply',
		'hstsNullBlocking'      => 'python_hsts',
		'tldWildcard'           => 'python_tld_wildcard',
		'pslIncludePrivate'     => 'psl_include_private',
		'pslAllowPrivate'       => 'psl_allow_private',
		'pslFeedPrivatePolicy'  => 'psl_feed_private_policy',
		'pslFeedIcannPolicy'    => 'psl_feed_icann_policy',
		'idnMode'               => 'idn_mode',
		'idnBlockMalicious'     => 'python_idn_block_malicious',
		'idnEscalateSuspicious' => 'python_idn_escalate_suspicious',
		'decisionCacheMax'      => 'decisiondb_max',
		'logViaWebserver'       => 'python_nolog',
		'cnameValidation'       => 'python_cname',
		'control'               => 'python_control',
		'controlLegacy'         => 'python_control_legacy',
		'regexCap'              => 'regex_cap',
		'metricsClientIp'       => 'metrics_client_ip',
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
		$this->assertSame(array_keys(self::INI_KEY), array_keys($defaults[0]['native']), 'the defaults case names every field');
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
		$ini = pfb_unbound_python_ini('enabled');
		foreach ($case['native'] as $field => $expected) {
			$this->assertArrayHasKey($field, self::INI_KEY, "{$case['id']}: {$field} is a projection field");
			$key = self::INI_KEY[$field];
			$this->assertSame(1, preg_match('/^' . $key . '\t= (.*)$/m', $ini, $m), "{$case['id']}: the ini has {$key}:\n{$ini}");
			$this->assertSame($expected, $this->native($field, $m[1]), "{$case['id']}: {$field} from ini {$key} = '{$m[1]}'");
		}
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
