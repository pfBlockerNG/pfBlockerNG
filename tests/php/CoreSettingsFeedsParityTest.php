<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3937: freezes today's PHP behaviour for Core's feed projections `feeds/ipv4`, `feeds/ipv6` and `feeds/dnsbl` as the parity
 * fixture tests/core/fixtures/settings_feeds_parity.json; go/pfb_core/settings passes the same file.
 *   - A `stored` case is one group as config.xml holds it: the settings adapter's read answers `native` for it (NULL: the group does
 *     not project), and the adapter's own write validation accepts what the read answered.
 *   - A `posted` case is a Groups editor save: the page's own validation, run as shipped, decides `valid`, and the adapter's write
 *     validation gives the same verdict on the case's `input` filled with the native defaults.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsFeedsParityTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_feeds_parity.json';
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
	private const PROJECTIONS = ['feeds/ipv4', 'feeds/ipv6', 'feeds/dnsbl'];

	/** The projection => its config.xml section, the Groups editor's $gtype and $type. */
	private const SECTION = [
		'feeds/ipv4'  => ['pfblockernglistsv4', 'ipv4', 'IPv4'],
		'feeds/ipv6'  => ['pfblockernglistsv6', 'ipv6', 'IPv6'],
		'feeds/dnsbl' => ['pfblockerngdnsbl', 'dnsbl', 'DNSBL'],
	];

	private array $priorConfig;
	private array $priorPfb;
	private array $priorPost;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->priorPost = $_POST;
		$this->dir = sys_get_temp_dir() . '/pfb_core_feeds_parity_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_lock_events'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		$_POST = $this->priorPost;
		unset($GLOBALS['pfb_test_lock_events'], $GLOBALS['pfb_test_write_config_calls']);
		rmdir_recursive($this->dir);
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

	public function testTheFixtureIsTheThreeFeedProjectionsWithStoredAndPostedCasesForEach(): void
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $doc['schema']);
		$this->assertSame(self::PROJECTIONS, $doc['projections']);
		$seen = [];
		foreach ($doc['cases'] as $case) {
			$this->assertContains($case['projection'], self::PROJECTIONS, "{$case['id']}: a known projection");
			$this->assertContains($case['source'], ['stored', 'posted'], "{$case['id']}: a known source");
			$seen[$case['projection']][$case['source']] = TRUE;
		}
		foreach (self::PROJECTIONS as $projection) {
			$this->assertArrayHasKey('stored', $seen[$projection] ?? [], "{$projection} has a stored case");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesVerdictAndNativeValue(array $case): void
	{
		$projection = $case['projection'];
		[$section, $gtype, $type] = self::SECTION[$projection];
		if ($case['source'] === 'posted') {
			$this->assertSame($case['valid'], $this->pageAccepts($case['posted'], $gtype, $type), "{$case['id']}: the Groups editor's verdict on " . json_encode($case['posted']));
			$this->assertAdapterVerdict($case['valid'], $projection, self::filled($case['input'], $projection), $case['id']);
			return;
		}
		$this->assertSame('stored', $case['source']);
		$this->assertTrue($case['valid'], "{$case['id']}: PHP refuses no stored value");
		config_set_path("installedpackages/{$section}/config/0", $case['stored']);

		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'read']);

		$this->assertArrayHasKey('settings', $reply, "{$case['id']}: the read answered " . json_encode($reply));
		$this->assertArrayHasKey($projection, $reply['settings'], "{$case['id']}: the read answers {$projection}");
		$expected = $case['native'] === NULL ? [] : [$case['native']];
		$this->assertSame(['groups' => $expected], $reply['settings'][$projection], "{$case['id']}: the projection of the stored group");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		// What the read answers, the write takes back: Core never holds a value its own backend refuses
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']]),
			"{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	/**
	 * The adapter's verdict on one group of $projection: valid is no refusal; invalid is invalid_argument naming a field of that group.
	 *
	 * @param array<string, mixed> $group
	 */
	private function assertAdapterVerdict(bool $valid, string $projection, array $group, string $id): void
	{
		$settings = ['dns' => pfb_core_dns_settings()];
		foreach (self::PROJECTIONS as $other) {
			$settings[$other] = ['groups' => []];
		}
		$settings[$projection]['groups'] = [$group];

		$refusal = pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => 1, 'settings' => $settings]);

		if ($valid) {
			$this->assertNull($refusal, "{$id}: the adapter refused " . json_encode($group) . ': ' . json_encode($refusal));
			return;
		}
		$this->assertSame('invalid_argument', $refusal['error']['code'] ?? NULL, "{$id}: " . json_encode($refusal));
		$fields = array_column($refusal['error']['fieldErrors'] ?? [], 'field');
		$named = array_filter($fields, static fn(string $field): bool => str_starts_with($field, "{$projection}.groups[0]."));
		$this->assertNotSame([], $named, "{$id}: the refusal names a field of the group: " . json_encode($fields));
	}

	/**
	 * A fixture `input` with every field it leaves out at its native default: action Disabled, updateFrequency Never, bindAddress,
	 * preScript, postScript and customList '', suppressionCidr 0 (IPv4), whoisConvert false (IP); a feed enabled, auto, url and
	 * credentials '', action deny (DNSBL).
	 *
	 * @param array<string, mixed> $input
	 * @return array<string, mixed>
	 */
	private static function filled(array $input, string $projection): array
	{
		$group = ['action' => 'Disabled', 'updateFrequency' => 'Never', 'bindAddress' => '', 'preScript' => '', 'postScript' => '', 'customList' => ''];
		if ($projection === 'feeds/ipv4') {
			$group['suppressionCidr'] = 0;
		}
		if ($projection !== 'feeds/dnsbl') {
			$group['whoisConvert'] = FALSE;
		}
		$feed = ['state' => 'enabled', 'format' => 'auto', 'url' => '', 'credentials' => ''] + ($projection === 'feeds/dnsbl' ? ['action' => 'deny'] : []);
		$group = array_merge($group, $input);
		$group['feeds'] = array_map(static fn(array $posted): array => array_merge($feed, $posted), $input['feeds'] ?? []);
		return $group;
	}

	/**
	 * The Groups editor's own validation of the projection's fields, run as shipped: the statements from the name check to the
	 * end of the source-row checks, over the posted fields. A local source path is a file under an allowed directory on the
	 * box: the sandbox's $pfb['dbdir'] stands in for /var/db/pfblockerng (PFB_FILTER_URL resolves it with realpath()).
	 *
	 * @param array<string, string> $posted
	 */
	private function pageAccepts(array $posted, string $gtype, string $type): bool
	{
		$source = (string) file_get_contents(self::PAGE);
		$from = strpos($source, "if (empty(\$_POST['aliasname'])) {");
		$to = strpos($source, '// Validate Adv. firewall rule settings');
		$this->assertNotFalse($from, 'the Groups editor still checks aliasname');
		$this->assertNotFalse($to, 'the Groups editor still has its advanced-settings anchor');
		$this->assertGreaterThan($from, $to);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		foreach ($posted as $key => $value) {
			if (str_starts_with($key, 'url-') && str_starts_with($value, '/var/db/pfblockerng/')) {
				$posted[$key] = "{$this->dir}/" . basename($value);
				$this->assertNotFalse(file_put_contents($posted[$key], "192.0.2.1\n"));
			}
		}
		$_POST = $posted;
		$pfb = $GLOBALS['pfb'];
		$pfb['maxmind_key'] = 'key';	// MaxMind configured: a GeoIP row is judged on its source alone
		$pfb['maxmind_account'] = '1';
		$line = 1;
		$input_errors = [];
		eval(substr($source, $from, $to - $from));
		return $input_errors === [];
	}
}
