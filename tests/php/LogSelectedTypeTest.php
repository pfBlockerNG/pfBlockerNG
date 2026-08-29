<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_log.php selected-logtype behavior and retained scalar defaults.
 *
 * The page carries top-level execution and cannot be require()d off-appliance,
 * so the retained regions below are eval-extracted verbatim from the source.
 */
final class LogSelectedTypeTest extends TestCase
{
	private array $savedPost = [];
	private static string $pconfigRegion;
	private static string $selectedRegion;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/LogPageLoader.php';
		pfb_test_load_log_page_functions();

		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_log.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_log.php');
		}

		// Region 1: $_POST ingress -> $pconfig['logtype']/'logFile' defaults.
		if (!function_exists('pfb_log_oracle_pconfig')) {
			if (!preg_match('/\$pconfig = array\(\);\n(.*?\$pconfig\[[\'\"]logFile[\'\"]\] = \'\';\n\})/s', $src, $m)) {
				throw new RuntimeException('test bootstrap: pconfig ingress region not found');
			}
			self::$pconfigRegion = $m[1];
			eval('function pfb_log_oracle_pconfig(): array { $pconfig = array(); ' . $m[1] . ' return $pconfig; }');
		}

		// Region 5: 'logtype' -> $selected -> $pfb_logtypes[$selected] offset,
		// through $logs/getlogs()/$clearable/$downloadable (issues #1198/#1207).
		if (!function_exists('pfb_log_oracle_selected_logtype')) {
			$start = strpos($src, '$logs = array();');
			$selected = strpos($src, '$selected =', $start === false ? 0 : $start);
			$downloadable = strpos($src, '$downloadable', $selected === false ? 0 : $selected);
			$end = $downloadable === false ? false : strpos($src, ";\n", $downloadable);
			if ($start === false || $selected === false || $downloadable === false || $end === false || $end <= $start) {
				throw new RuntimeException('test bootstrap: selected-logtype region not found');
			}
			self::$selectedRegion = substr($src, $start, $end + 2 - $start);
			eval(
				'function pfb_log_oracle_selected_logtype(array $pconfig, array $pfb_logtypes): array { '
				. self::$selectedRegion
				. ' return compact(\'pfb_sel\', \'logs\', \'clearable\', \'downloadable\'); }'
			);
		}
	}

	public function testExtractionUsesExecutableBoundariesNotProductionComments(): void
	{
		$this->assertStringStartsWith('if ($_POST)', self::$pconfigRegion);
		$this->assertStringNotContainsString('Send logfile to screen', self::$pconfigRegion);
		$this->assertStringStartsWith('$logs = array();', self::$selectedRegion);
		$this->assertStringNotContainsString('Collect selected logs', self::$selectedRegion);
	}

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
		$_POST = [];
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
	}

	/**
	 * A $pfb_logtypes fixture shaped like the real page's entries, including
	 * both inline log lists and extension-based discovery through getlogs().
	 */
	private function logtypes(): array
	{
		return [
			'defaultlogs' => ['logdir' => '/var/log/pfblockerng/', 'logs' => ['pfblockerng.log', 'error.log'], 'clear' => TRUE, 'download' => TRUE],
			'originallogs' => ['logdir' => '/var/db/pfblockerng/original/', 'ext' => ['orig', 'raw'], 'clear' => TRUE, 'download' => TRUE],
			'python'      => ['logdir' => '/var/unbound/', 'logs' => ['py_error.log'], 'clear' => TRUE, 'download' => TRUE],
			// mixed-case static key (real page has 'GeoIP') -- pins case-sensitivity.
			'GeoIP'       => ['logdir' => '/var/db/pfblockerng/GeoIP/', 'logs' => ['GeoLite2-Country.mmdb'], 'clear' => FALSE, 'download' => TRUE],
			// dynamic blacklist-title key shape (`<Title>logs`, merged in at :189).
			'MyFeedlogs'  => ['logdir' => '/var/db/pfblockerng/myfeed/', 'logs' => ['myfeed.log'], 'clear' => TRUE, 'download' => FALSE],
		];
	}

	/**
	 * Runs Region 5 capturing E_WARNING/E_DEPRECATED and fails loudly on a
	 * TypeError at the selected-logtype offset.
	 */
	private function runSelectedLogtypeExpectingNoWarnings(array $pconfig, array $pfb_logtypes): array
	{
		$warnings = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return TRUE;
		}, E_WARNING | E_DEPRECATED);
		try {
			$result = pfb_log_oracle_selected_logtype($pconfig, $pfb_logtypes);
		} catch (\TypeError $e) {
			$this->fail('an unknown scalar logtype must not TypeError the $pfb_logtypes[] offset: ' . $e->getMessage());
		} finally {
			// finally, not the happy path: any other throwable would otherwise leak the
			// handler into sibling tests (self-encapsulation).
			restore_error_handler();
		}
		$this->assertSame([], $warnings, 'an unknown scalar logtype must emit zero warnings, got: ' . implode('; ', $warnings));
		return $result;
	}

	public function testPconfigScalarValuesRemainUnmodified(): void
	{
		$_POST['logtype'] = 'defaultlogs';
		$_POST['logFile'] = '/var/log/pfblockerng/ok.log';
		$pconfig = pfb_log_oracle_pconfig();
		$this->assertSame('defaultlogs', $pconfig['logtype'], 'a scalar logtype value must remain unmodified');
		$this->assertSame(
			'/var/log/pfblockerng/ok.log',
			$pconfig['logFile'],
			'a scalar logFile value must remain unmodified'
		);
	}

	public function testPconfigMissingKeysStillDefaultToEmptyString(): void
	{
		// The pre-existing !isset() defaults remain empty for missing fields.
		$pconfig = pfb_log_oracle_pconfig();
		$this->assertSame('', $pconfig['logtype']);
		$this->assertSame('', $pconfig['logFile']);
	}

	// --- issue #1198: unknown-scalar coverage matrix -------------------------

	public function testSelectedLogtypeAbsentLogtypeFallsBackToDefaultNoWarnings(): void
	{
		// No $_POST at all -- ingress leaves $pconfig['logtype'] === ''.
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['defaultlogs'], $result['pfb_sel']);
	}

	public function testSelectedLogtypeEmptyStringFallsBackToDefaultNoWarnings(): void
	{
		$_POST['logtype'] = '';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['defaultlogs'], $result['pfb_sel']);
	}

	public function testSelectedLogtypeDefaultLogsKeyResolvesItsOwnEntryNoWarnings(): void
	{
		$_POST['logtype'] = 'defaultlogs';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['defaultlogs'], $result['pfb_sel']);
	}

	public function testSelectedLogtypeDynamicKeyResolvesItsOwnEntryNoWarnings(): void
	{
		$_POST['logtype'] = 'MyFeedlogs';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame(
			$this->logtypes()['MyFeedlogs'],
			$result['pfb_sel'],
			'a valid dynamic-title logtype key must resolve its own entry, not be clobbered to defaultlogs'
		);
		// issue #1207: own-entry resolution -- $logs/$clearable/$downloadable must come
		// from MyFeedlogs, not leak a defaultlogs fallback.
		$this->assertSame($this->logtypes()['MyFeedlogs']['logs'], $result['logs']);
		$this->assertSame($this->logtypes()['MyFeedlogs']['clear'], $result['clearable']);
		$this->assertSame($this->logtypes()['MyFeedlogs']['download'], $result['downloadable']);
	}

	public function testSelectedLogtypeWithoutInlineLogsUsesGetlogs(): void
	{
		$_POST['logtype'] = 'originallogs';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['originallogs'], $result['pfb_sel']);
		$this->assertSame(['a.log'], $result['logs']);
		$this->assertSame($this->logtypes()['originallogs']['clear'], $result['clearable']);
		$this->assertSame($this->logtypes()['originallogs']['download'], $result['downloadable']);
	}

	public function testSelectedLogtypeUnknownScalarFallsBackToDefaultNoWarnings(): void
	{
		// issue #1198: the reported defect -- a scalar but unknown logtype.
		$_POST['logtype'] = 'zzz';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['defaultlogs'], $result['pfb_sel']);
		// issue #1207: the fallback must carry defaultlogs' own $logs/$clearable/$downloadable.
		$this->assertSame($this->logtypes()['defaultlogs']['logs'], $result['logs']);
		$this->assertSame($this->logtypes()['defaultlogs']['clear'], $result['clearable']);
		$this->assertSame($this->logtypes()['defaultlogs']['download'], $result['downloadable']);
	}

	public function testSelectedLogtypeNumericZeroStringDoesNotDivergeFromOldGuard(): void
	{
		// '0' is the one value where !empty() and array_key_exists() could
		// have disagreed (empty('0') === TRUE); pins that neither matches.
		$_POST['logtype'] = '0';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['defaultlogs'], $result['pfb_sel']);
	}

	public function testSelectedLogtypeLowercaseCaseVariantFallsBackToDefaultNoWarnings(): void
	{
		// keys are case-sensitive; a real key is mixed-case ('GeoIP').
		$_POST['logtype'] = 'geoip';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['defaultlogs'], $result['pfb_sel']);
	}

	public function testSelectedLogtypeTrailingSpaceNearMissFallsBackToDefaultNoWarnings(): void
	{
		$_POST['logtype'] = 'defaultlogs ';
		$pconfig = pfb_log_oracle_pconfig();
		$result = $this->runSelectedLogtypeExpectingNoWarnings($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['defaultlogs'], $result['pfb_sel']);
	}

}
