<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #2851 — issue #2016's nested-pass budget becomes ONE operator-configurable
 * setting (General -> Advanced, "Nested pass timeout") that can be raised for slow
 * links and low-powered appliances WITHOUT ever becoming weakenable.
 *
 * The contract this pins:
 *   - whole seconds from 60 through 7200 INCLUSIVE are honoured;
 *   - absent / empty / non-numeric / decimal / negative / zero / overflow / below-60 /
 *     above-7200 / non-scalar all resolve to the finite 1800-second default, never to
 *     "no timeout" (the issue #2488 degradation class);
 *   - ONE global budget serves every re-entry verb (GeoIP, blacklist, TOP1M, ASN) —
 *     it reaches the PHP seam through pfb_reentry_budget()/pfb_reentry_cmd();
 *   - the shell seam normalizes against the SAME window and the SAME default, so a
 *     single stored value means the same number of seconds in both languages.
 *
 * Companion coverage: the shell rows live in
 * tests/shell/pfblockerng_reentry_bounds_spec.sh (pfb_reentry_timeout() executed under
 * dash), the gateway round-trip in CfgGatewayTest, the page wiring in
 * GeneralAdvancedTimeoutUiTest.
 */
#[CoversFunction('pfb_reentry_timeout')]
#[CoversFunction('pfb_reentry_budget')]
#[CoversFunction('pfb_reentry_cmd')]
final class ReentryTimeoutSettingTest extends TestCase
{
	private const SHELL = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.sh';

	/** The stored key the one global budget lives under (gen section). */
	private const KEY = 'pfb_reentry_timeout';

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_reentry_cfg_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		// A pristine mirror: no stored setting at all, which is the upgrade/new-install case.
		$GLOBALS['pfb'] = [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
			'config' => [],
		];
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		foreach (glob("{$this->tmp}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->tmp);
	}

	/** Seed the gen-section mirror pfb_global() populates, exactly as a stored value would. */
	private function store(mixed $raw): void
	{
		$GLOBALS['pfb']['config'][self::KEY] = $raw;
	}

	/**
	 * The `<secs>` word the composed command hands timeout(1), read off the `-k 5 `
	 * anchor so an EMPTY duration is captured as '' rather than matching something else.
	 */
	private function durationToken(string $cmd): string
	{
		$this->assertSame(1, preg_match('/ -k 5 ([^ ]*) /', $cmd, $m),
			"the built command carries no '-s TERM -k 5 <secs>' bound at all: {$cmd}");
		return $m[1];
	}

	// ── The window itself ───────────────────────────────────────────────────────

	public function testTheWindowAndTheDefaultAreNamedConstants(): void
	{
		$this->assertTrue(function_exists('pfb_reentry_timeout'),
			'pfblockerng.inc must define pfb_reentry_timeout() -- the one place a stored/submitted budget is normalized');
		$this->assertTrue(defined('PFB_REENTRY_TIMEOUT_MIN'),
			'PFB_REENTRY_TIMEOUT_MIN (the smallest configurable nested-pass budget) must be defined');
		$this->assertTrue(defined('PFB_REENTRY_TIMEOUT_MAX'),
			'PFB_REENTRY_TIMEOUT_MAX (the largest configurable nested-pass budget) must be defined');
		$this->assertSame(60, PFB_REENTRY_TIMEOUT_MIN, 'the owner ruling fixes the minimum at 60 whole seconds');
		$this->assertSame(7200, PFB_REENTRY_TIMEOUT_MAX, 'the owner ruling fixes the maximum at 7200 whole seconds');
		$this->assertSame(1800, PFB_REENTRY_TIMEOUT,
			'the owner ruling preserves 1800 as the absent/invalid/default budget');
	}

	/** @return array<string, array{0: mixed, 1: int}> */
	public static function acceptedValues(): array
	{
		return [
			'minimum as int'          => [60, 60],
			'minimum as stored digits' => ['60', 60],
			'one above the minimum'   => ['61', 61],
			'mid-range'               => ['900', 900],
			'the default itself'      => ['1800', 1800],
			'one below the maximum'   => ['7199', 7199],
			'maximum as stored digits' => ['7200', 7200],
			'maximum as int'          => [7200, 7200],
			// POSIX test(1) and PHP both read a digit run as DECIMAL, so a hand-edited
			// '0060' means sixty seconds in both seams -- never octal forty-eight.
			'leading zeros stay decimal' => ['0060', 60],
		];
	}

	#[DataProvider('acceptedValues')]
	public function testAcceptedWholeSecondsResolveToThemselves(mixed $raw, int $expected): void
	{
		$this->assertSame($expected, pfb_reentry_timeout($raw),
			'a whole second count inside [60, 7200] must be honoured verbatim');
	}

	/** @return array<string, array{0: mixed}> */
	public static function rejectedValues(): array
	{
		return [
			'absent (upgrade / new install)' => [NULL],
			'empty string (field cleared)'   => [''],
			'non-numeric'                    => ['abc'],
			'decimal string'                 => ['1.5'],
			'decimal seconds'                => ['60.5'],
			'negative'                       => ['-5'],
			'negative int'                   => [-1800],
			'zero string'                    => ['0'],
			'zero int'                       => [0],
			'one below the minimum'          => ['59'],
			'one above the maximum'          => ['7201'],
			'far above the maximum'          => ['99999999'],
			'64-bit overflow'                => ['99999999999999999999'],
			'PHP_INT_MAX'                    => [PHP_INT_MAX],
			'PHP_INT_MIN'                    => [PHP_INT_MIN],
			'leading space'                  => [' 900'],
			'trailing space'                 => ['900 '],
			'trailing newline'               => ["900\n"],
			'signed'                         => ['+900'],
			'exponent notation'              => ['1e3'],
			'hexadecimal'                    => ['0x384'],
			'thousands separator'            => ['1,800'],
			'array (crafted POST / config)'  => [['900']],
			'boolean true'                   => [TRUE],
			'boolean false'                  => [FALSE],
			'float'                          => [900.0],
			'object'                         => [new stdClass()],
		];
	}

	#[DataProvider('rejectedValues')]
	public function testEveryDegradedValueResolvesToTheFiniteDefault(mixed $raw): void
	{
		$secs = pfb_reentry_timeout($raw);

		$this->assertSame(PFB_REENTRY_TIMEOUT, $secs,
			'a value outside the accepted window must resolve to the finite default, never to no timeout');
		$this->assertGreaterThanOrEqual(PFB_REENTRY_TIMEOUT_MIN, $secs, 'the resolved budget must stay inside the window');
		$this->assertLessThanOrEqual(PFB_REENTRY_TIMEOUT_MAX, $secs, 'the resolved budget must stay inside the window');
	}

	// ── One global budget, reaching the PHP seam ────────────────────────────────

	public function testTheStoredMinimumReachesTheSeamAsTheDuration(): void
	{
		$this->store('60');

		$this->assertSame(60, pfb_reentry_budget(NULL), 'the stored minimum must become the resolved budget');
		$this->assertSame('60', $this->durationToken(pfb_reentry_cmd('dc', ['scheduled'], "{$this->tmp}/out")),
			'the stored minimum must be the duration timeout(1) gets');
	}

	public function testTheStoredMaximumReachesTheSeamAsTheDuration(): void
	{
		$this->store('7200');

		$this->assertSame(7200, pfb_reentry_budget(NULL), 'the stored maximum must become the resolved budget');
		$this->assertSame('7200', $this->durationToken(pfb_reentry_cmd('dc', ['scheduled'], "{$this->tmp}/out")),
			'the stored maximum must be the duration timeout(1) gets');
	}

	public function testAnAbsentSettingKeepsTheFiniteDefaultOnTheSeam(): void
	{
		// Before: nothing stored -- the upgrade case the issue names first.
		$this->assertArrayNotHasKey(self::KEY, $GLOBALS['pfb']['config']);

		$this->assertSame(1800, pfb_reentry_budget(NULL), 'an absent setting must resolve to the finite default');
		$this->assertSame('1800', $this->durationToken(pfb_reentry_cmd('al', ['scheduled'], "{$this->tmp}/out")),
			'an absent setting must leave the seam on its 1800s default');
	}

	/** @return array<string, array{0: mixed}> */
	public static function hostileStoredValues(): array
	{
		return [
			'empty'      => [''],
			'zero'       => ['0'],
			'below the minimum' => ['5'],
			'above the maximum' => ['7201'],
			'non-numeric' => ['forever'],
			'negative'   => ['-1'],
			'overflow'   => ['99999999999999999999'],
			'array'      => [['5']],
		];
	}

	#[DataProvider('hostileStoredValues')]
	public function testAHostileStoredValueCannotWeakenTheSeamsBound(mixed $raw): void
	{
		$this->store($raw);

		$secs = $this->durationToken(pfb_reentry_cmd('bls', ['scheduled', 'x'], "{$this->tmp}/out"));

		$this->assertSame((string) PFB_REENTRY_TIMEOUT, $secs,
			"a hostile stored budget must fall back to the finite default; got [{$secs}]");
		$this->assertMatchesRegularExpression('/^[0-9]+$/', $secs,
			"issue #2488: no stored value may leave timeout(1) an empty or non-numeric duration; got [{$secs}]");
	}

	public function testOneGlobalBudgetServesEveryReentryVerb(): void
	{
		// The owner ruling: ONE global nested-pass budget, no per-subsystem override.
		$this->store('600');

		$durations = [];
		foreach (['al', 'bls', 'dc', 'asn', 'asn_shell', 'bu', 'dnsbl-control'] as $verb) {
			$durations[$verb] = $this->durationToken(pfb_reentry_cmd($verb, [], "{$this->tmp}/out"));
		}

		$this->assertSame(array_fill_keys(array_keys($durations), '600'), $durations,
			'every re-entry verb must read the SAME global budget -- no per-subsystem window');
	}

	public function testAnExplicitCallerBudgetStillWinsOverTheStoredSetting(): void
	{
		// The off-appliance injection point issue #2016 shipped: the executed expiry rows
		// need a 2s budget, and a caller that names one is not the config path.
		$this->store('7200');

		$this->assertSame(2, pfb_reentry_budget(2), 'an explicit positive caller budget must stay authoritative');
	}

	public function testADegradedCallerBudgetFallsThroughToTheStoredSetting(): void
	{
		// Before: the stored setting is what the fallback must land on -- not the constant.
		$this->store('900');

		$this->assertSame(900, pfb_reentry_budget(''), 'a degraded caller budget must fall through to the stored setting');
		$this->assertSame(900, pfb_reentry_budget(0), 'a zero caller budget must fall through to the stored setting');
		$this->assertSame(900, pfb_reentry_budget(-1), 'a negative caller budget must fall through to the stored setting');
	}

	public function testTheReaperModeAndTheFileCaptureSurviveAConfiguredBudget(): void
	{
		// issue #2016's semantics are preserved, not traded for configurability.
		$this->store('7200');
		$out = "{$this->tmp}/capture.out";

		$cmd = pfb_reentry_cmd('dc', ['scheduled'], $out);

		$this->assertStringNotContainsString('--foreground', $cmd,
			"a configured budget must not move the seam out of default (reaper) mode: {$cmd}");
		$this->assertStringEndsWith('> ' . escapeshellarg($out) . ' 2>&1 < /dev/null', $cmd,
			"a configured budget must not disturb the file capture or the /dev/null stdin: {$cmd}");
	}

	// ── Both seams, one window ──────────────────────────────────────────────────

	public function testTheShellSeamNormalizesAgainstTheSameWindowAndDefault(): void
	{
		$src  = (string) file_get_contents(self::SHELL);
		$this->assertSame(1, preg_match('/^pfb_reentry_timeout\(\)\s*\{\n(.*?)^\}$/ms', $src, $m),
			'pfblockerng.sh must define pfb_reentry_timeout() -- the shell seam\'s normalization boundary');
		$body = $m[1];

		$this->assertSame(1, preg_match('/^\t_pfbrt=([0-9]+)$/m', $body, $d),
			"the shell resolver must START at a literal default budget: {$body}");
		$this->assertSame(1, preg_match('/-ge ([0-9]+) \]/', $body, $lo),
			"the shell resolver must carry a minimum bound: {$body}");
		$this->assertSame(1, preg_match('/-le ([0-9]+) \]/', $body, $hi),
			"the shell resolver must carry a maximum bound: {$body}");

		$this->assertSame((string) PFB_REENTRY_TIMEOUT, $d[1],
			'the two seams must fall back to the SAME default budget');
		$this->assertSame((string) PFB_REENTRY_TIMEOUT_MIN, $lo[1],
			'the two seams must accept the SAME minimum budget');
		$this->assertSame((string) PFB_REENTRY_TIMEOUT_MAX, $hi[1],
			'the two seams must accept the SAME maximum budget');
	}

	public function testTheShellSeamReadsTheOneStoredSettingBeforeItsInitBlockRuns(): void
	{
		$src = (string) file_get_contents(self::SHELL);

		$resolver = strpos($src, "\npfb_reentry_timeout() {");
		$init     = strpos($src, 'if [ -z "${PFB_SOURCED:-}" ]; then');
		$this->assertNotFalse($resolver, 'pfblockerng.sh must define pfb_reentry_timeout()');
		$this->assertNotFalse($init, 'pfblockerng.sh must keep its PFB_SOURCED init guard');
		$this->assertLessThan($init, $resolver,
			'sh executes top to bottom: the resolver must be DEFINED before the init block that calls it');

		$this->assertSame(1, preg_match('/^\tpfbreentrytimeout=(.*)$/m', $src, $m),
			'the init block must seed pfbreentrytimeout');
		$this->assertStringContainsString('pfb_reentry_timeout_from_reader ', $m[1],
			"the stored setting must reach the shell seam through the newline-preserving resolver boundary: {$m[1]}");
		$this->assertStringContainsString(
			'installedpackages/pfblockerng/config/' . self::KEY, $m[1],
			"the shell seam must read the ONE registered gen-section key: {$m[1]}");
	}
}
