<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_log.php array-valued request-field guard (issue #1183).
 *
 * A crafted request submitting an array-valued 'file' (ajax GET), 'logFile',
 * or 'logtype' field reached strictly-typed string sinks (htmlspecialchars(),
 * an array-offset access) before any type check, TypeError-ing the page
 * (HTTP 500). The fix normalizes 'logtype'/'logFile' to '' right after the
 * $pconfig = $_POST; ingress (one guard covers every downstream sink) and
 * guards $_REQUEST['file'] at its own ajax sink, mirroring the is_string
 * idiom landed for #1106/#1125/#1128.
 *
 * The page carries top-level execution and cannot be require()d
 * off-appliance, so each region below is eval-extracted verbatim from the
 * REAL source, anchored on text stable across both the pre-fix and post-fix
 * code so the same test file proves red on the old code and green on the new.
 */
final class LogArrayRequestGuardTest extends TestCase
{
	private array $savedPost = [];
	private array $savedGet = [];
	private array $savedRequest = [];

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
			if (!preg_match('/\$pconfig = array\(\);\n(.*?)\n\n\/\/ Send logfile to screen/s', $src, $m)) {
				throw new RuntimeException('test bootstrap: pconfig ingress region not found');
			}
			eval('function pfb_log_oracle_pconfig(): array { $pconfig = array(); ' . $m[1] . ' return $pconfig; }');
		}

		// Region 2: ajax 'file' -> $pfb_logfilename (site :234).
		if (!function_exists('pfb_log_oracle_ajax_filename')) {
			if (!preg_match(
				'/\/\/ Send logfile to screen\nif \(isset\(\$_REQUEST\) && isset\(\$_REQUEST\[\'ajax\'\]\)\) \{\n\n'
				. '(.*?)\n\tif \(!pfb_validate_filepath\(\$pfb_logfilename, \$pfb_logtypes\)\)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: ajax filename region not found');
			}
			eval('function pfb_log_oracle_ajax_filename(): string { ' . $m[1] . ' return $pfb_logfilename; }');
		}

		// Region 3: ajax 'action' == 'load' loose compare -- array-safe, no guard needed.
		if (!function_exists('pfb_log_oracle_action_is_load')) {
			if (!preg_match('/\t\/\/ Load log\n(\tif \(\$_REQUEST\[\'action\'\] == \'load\'\) \{)/', $src, $m)) {
				throw new RuntimeException('test bootstrap: action-is-load region not found');
			}
			eval('function pfb_log_oracle_action_is_load(): bool { ' . $m[1] . ' return TRUE; } return FALSE; }');
		}

		// Region 4: 'logFile' download/clear gate + htmlspecialchars() sink (site :303/:435).
		if (!function_exists('pfb_log_oracle_logfile_sink')) {
			if (!preg_match(
				'/\/\/ Download\/Clear logfile\n(if \(isset\(\$pconfig\[\'logFile\'\]\) && !empty\(\$pconfig\[\'logFile\'\]\) && '
				. '\(isset\(\$pconfig\[\'download\'\]\) \|\| isset\(\$pconfig\[\'clear\'\]\)\)\) \{\n\t\n\t\$s_logfile = '
				. 'htmlspecialchars\(\$pconfig\[\'logFile\'\]\);)\n\tif \(!pfb_validate_filepath/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: logFile sink region not found');
			}
			eval(
				'function pfb_log_oracle_logfile_sink(array $pconfig): string { '
				. $m[1]
				. ' return $s_logfile; } $s_logfile = \'\'; return $s_logfile; }'
			);
		}

		// Region 5: 'logtype' -> $selected -> $pfb_logtypes[$selected] offset (site :406-407).
		if (!function_exists('pfb_log_oracle_selected_logtype')) {
			if (!preg_match(
				'/\/\/ Collect selected logs\n\$logs = array\(\);\n\$clearable = \$downloadable = FALSE;\n'
				. '(\$selected = !empty\(\$pconfig\[\'logtype\'\]\) \? \$pconfig\[\'logtype\'\] : \'defaultlogs\';\n'
				. '\$pfb_sel = \$pfb_logtypes\[\$selected\];)/',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: selected-logtype region not found');
			}
			eval(
				'function pfb_log_oracle_selected_logtype(array $pconfig, array $pfb_logtypes): array { '
				. $m[1]
				. ' return $pfb_sel; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost    = $_POST;
		$this->savedGet     = $_GET;
		$this->savedRequest = $_REQUEST;
		$_POST = $_GET = $_REQUEST = [];
	}

	protected function tearDown(): void
	{
		$_POST    = $this->savedPost;
		$_GET     = $this->savedGet;
		$_REQUEST = $this->savedRequest;
	}

	/** A $pfb_logtypes fixture shaped like the real page's (LogValidateFilepathNulByteTest sibling shape). */
	private function logtypes(): array
	{
		return [
			'defaultlogs' => ['logdir' => '/var/log/pfblockerng/'],
			'python'      => ['logdir' => '/var/unbound/'],
		];
	}

	// --- site :234 -- ajax 'file' -> htmlspecialchars() ---------------------

	public function testAjaxFileArrayValueDoesNotThrowAndFailsValidation(): void
	{
		$_REQUEST['file'] = ['x'];
		try {
			$filename = pfb_log_oracle_ajax_filename();
		} catch (\TypeError $e) {
			$this->fail('an array file value must not TypeError htmlspecialchars(): ' . $e->getMessage());
		}
		$this->assertSame('', $filename, 'an array file value must be blanked to the empty string');
		$this->assertFalse(
			pfb_validate_filepath($filename, $this->logtypes()),
			'the blanked file value must fail validation, riding the existing reject path'
		);
	}

	public function testAjaxFileNestedArrayValueDoesNotThrowAndFailsValidation(): void
	{
		parse_str('file[a][b]=x', $parsed);
		$_REQUEST['file'] = $parsed['file'];
		try {
			$filename = pfb_log_oracle_ajax_filename();
		} catch (\TypeError $e) {
			$this->fail('a nested array file value must not TypeError htmlspecialchars(): ' . $e->getMessage());
		}
		$this->assertSame('', $filename, 'a nested array file value must be blanked to the empty string');
		$this->assertFalse(pfb_validate_filepath($filename, $this->logtypes()));
	}

	public function testAjaxFileAbsentKeyDoesNotThrowOrEmitDeprecation(): void
	{
		unset($_REQUEST['file']);
		$warnings = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return TRUE;
		}, E_DEPRECATED | E_WARNING);
		try {
			$filename = pfb_log_oracle_ajax_filename();
		} catch (\TypeError $e) {
			restore_error_handler();
			$this->fail('a missing file key must not TypeError: ' . $e->getMessage());
		}
		restore_error_handler();
		$this->assertSame('', $filename, 'a missing file key must yield the blank filename');
		$this->assertSame(
			[],
			$warnings,
			'a missing file key must not emit a deprecation/warning from htmlspecialchars(null)'
		);
		$this->assertFalse(pfb_validate_filepath($filename, $this->logtypes()));
	}

	public function testAjaxFileScalarValueIsUnaffectedByTheGuard(): void
	{
		$_REQUEST['file'] = '/var/log/pfblockerng/ok.log';
		$filename = pfb_log_oracle_ajax_filename();
		$this->assertSame(
			'/var/log/pfblockerng/ok.log',
			$filename,
			'a scalar file value must survive the guard unmodified'
		);
		$this->assertTrue(pfb_validate_filepath($filename, $this->logtypes()));
	}

	// --- site :241 -- 'action' loose compare, array-safe, no guard needed ---

	public function testActionArrayValueIsNotLoadWithoutThrowing(): void
	{
		$_REQUEST['action'] = ['load'];
		try {
			$isLoad = pfb_log_oracle_action_is_load();
		} catch (\TypeError $e) {
			$this->fail('an array action value must not TypeError the loose == compare: ' . $e->getMessage());
		}
		$this->assertFalse($isLoad, 'an array action value must not be treated as the load action');
	}

	public function testActionScalarLoadValueEntersLoadBranch(): void
	{
		$_REQUEST['action'] = 'load';
		$this->assertTrue(pfb_log_oracle_action_is_load(), 'a scalar "load" action must still enter the load branch');
	}

	public function testActionScalarOtherValueDoesNotEnterLoadBranch(): void
	{
		$_REQUEST['action'] = 'other';
		$this->assertFalse(
			pfb_log_oracle_action_is_load(),
			'a non-"load" scalar action must not enter the load branch'
		);
	}

	// --- ingress -- $_POST -> $pconfig['logtype']/'logFile' normalization ---

	public function testPconfigLogFileArrayValueIsNormalizedToEmptyString(): void
	{
		$_POST['logFile'] = ['x'];
		$pconfig = pfb_log_oracle_pconfig();
		$this->assertSame('', $pconfig['logFile'], 'an array logFile POST value must be normalized to the empty string');
	}

	public function testPconfigLogtypeArrayValueIsNormalizedToEmptyString(): void
	{
		$_POST['logtype'] = ['y'];
		$pconfig = pfb_log_oracle_pconfig();
		$this->assertSame('', $pconfig['logtype'], 'an array logtype POST value must be normalized to the empty string');
	}

	public function testPconfigBothLogtypeAndLogFileArrayValuesAreNormalized(): void
	{
		$_POST['logtype'] = ['y'];
		$_POST['logFile'] = ['x'];
		$pconfig = pfb_log_oracle_pconfig();
		$this->assertSame('', $pconfig['logtype']);
		$this->assertSame('', $pconfig['logFile']);
	}

	public function testPconfigScalarValuesSurviveNormalizationUnmodified(): void
	{
		$_POST['logtype'] = 'defaultlogs';
		$_POST['logFile'] = '/var/log/pfblockerng/ok.log';
		$pconfig = pfb_log_oracle_pconfig();
		$this->assertSame('defaultlogs', $pconfig['logtype'], 'a scalar logtype value must survive the guard unmodified');
		$this->assertSame(
			'/var/log/pfblockerng/ok.log',
			$pconfig['logFile'],
			'a scalar logFile value must survive the guard unmodified'
		);
	}

	public function testPconfigMissingKeysStillDefaultToEmptyString(): void
	{
		// Before-state control: the pre-existing !isset() defaults must survive the fix untouched.
		$pconfig = pfb_log_oracle_pconfig();
		$this->assertSame('', $pconfig['logtype']);
		$this->assertSame('', $pconfig['logFile']);
	}

	// --- site :303/:435 -- download/clear gate + htmlspecialchars() sink ----

	public function testLogfileArrayValueWithClearSetDoesNotThrowAndSkipsGate(): void
	{
		$_POST['logFile'] = ['x'];
		$_POST['clear'] = '1';
		$pconfig = pfb_log_oracle_pconfig();
		try {
			$s_logfile = pfb_log_oracle_logfile_sink($pconfig);
		} catch (\TypeError $e) {
			$this->fail('an array logFile value (clear) must not TypeError htmlspecialchars(): ' . $e->getMessage());
		}
		$this->assertSame('', $s_logfile, 'the normalized empty logFile must skip the download/clear gate entirely');
	}

	public function testLogfileArrayValueWithDownloadSetDoesNotThrowAndSkipsGate(): void
	{
		$_POST['logFile'] = ['x'];
		$_POST['download'] = '1';
		$pconfig = pfb_log_oracle_pconfig();
		try {
			$s_logfile = pfb_log_oracle_logfile_sink($pconfig);
		} catch (\TypeError $e) {
			$this->fail('an array logFile value (download) must not TypeError htmlspecialchars(): ' . $e->getMessage());
		}
		$this->assertSame('', $s_logfile, 'the normalized empty logFile must skip the download/clear gate entirely');
	}

	public function testLogfileScalarValueWithClearSetStillReachesTheSink(): void
	{
		// Behaviour-preserving control: a genuine scalar logFile must still enter
		// the gate and reach htmlspecialchars(), unaffected by the ingress guard.
		$_POST['logFile'] = '/var/log/pfblockerng/ok.log';
		$_POST['clear'] = '1';
		$pconfig = pfb_log_oracle_pconfig();
		$s_logfile = pfb_log_oracle_logfile_sink($pconfig);
		$this->assertSame(
			'/var/log/pfblockerng/ok.log',
			$s_logfile,
			'a scalar logFile value must still reach the sink unmodified'
		);
	}

	// --- site :406-407 -- $pfb_logtypes[$selected] array-offset access ------

	public function testSelectedLogtypeArrayValueDoesNotThrowAndFallsBackToDefault(): void
	{
		$_POST['logtype'] = ['y'];
		$pconfig = pfb_log_oracle_pconfig();
		try {
			$pfb_sel = pfb_log_oracle_selected_logtype($pconfig, $this->logtypes());
		} catch (\TypeError $e) {
			$this->fail('an array logtype value must not TypeError the $pfb_logtypes[] offset: ' . $e->getMessage());
		}
		$this->assertSame(
			$this->logtypes()['defaultlogs'],
			$pfb_sel,
			'an array logtype value must fall back to defaultlogs'
		);
	}

	public function testSelectedLogtypeScalarValueStillResolvesItsOwnEntry(): void
	{
		$_POST['logtype'] = 'python';
		$pconfig = pfb_log_oracle_pconfig();
		$pfb_sel = pfb_log_oracle_selected_logtype($pconfig, $this->logtypes());
		$this->assertSame($this->logtypes()['python'], $pfb_sel, 'a scalar logtype value must still resolve its own entry');
	}
}
