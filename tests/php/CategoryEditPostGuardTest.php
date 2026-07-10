<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Category-edit page array-POST guard (issue #1106).
 *
 * A crafted request submitting an array-valued field ('aliasname[]=x',
 * 'atype[]=x', 'savemsg[]=x', a rowhelper 'url-0[]=x', ...) reached a
 * strictly-typed string sink (preg_match/strlen/strpos/explode/
 * str_starts_with) before the input-errors gate, TypeError-ing the page
 * (HTTP 500). The fix rejects a non-scalar $_POST field with an input error
 * and blanks it to '' right after the select-option normalisation loop, so
 * every later read in the save block stays scalar; 'atype' (GET+POST) and
 * '$_REQUEST[savemsg]' get their own is_string() guard since they run
 * outside the save block. 'Lmove' (row-move checkboxes) is the page's one
 * legitimate array field and is exempt -- a user who checks a row then
 * clicks Save posts Lmove[] alongside save=Save.
 *
 * Like SyncRowhelperGuardTest, the page carries top-level execution and
 * cannot be require()d off-appliance, so each region below is eval-extracted
 * verbatim from the REAL source, anchored on text stable across both the
 * pre-fix and post-fix code so the same test file proves red on the old
 * code and green on the new.
 */
final class CategoryEditPostGuardTest extends TestCase
{
	private array $savedPost = [];
	private array $savedGet = [];
	private array $savedRequest = [];
	private mixed $savedPfb = null;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('print_info_box')) {
			// Not doubled in pfsense_doubles.php (out of scope for this issue) -- a
			// no-op is enough since the guard tests only assert on $savemsg/errors.
			function print_info_box($msg): void
			{
			}
		}

		// Region 1: select_options-normalisation close through the ingress guard,
		// the aliasname checks and the CIDR checks -- up to the state-loop foreach.
		if (!function_exists('pfb_category_oracle_aliasname_region')) {
			if (!preg_match(
				'/\$_POST\[\$s_option\] = \$s_default;\n\t\t\}\n\t\}\n(.*?)(?=\n\tforeach \(\$_POST as \$key => \$value\) \{)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: aliasname/CIDR region not found');
			}
			eval(
				'function pfb_category_oracle_aliasname_region(string $gtype): array {'
				. ' $input_errors = array();'
				. $m[1]
				. ' return $input_errors; }'
			);
		}

		// Region 2: the rowhelper state-loop (URL/header/format validation).
		if (!function_exists('pfb_category_oracle_state_loop')) {
			if (!preg_match(
				'/(\tforeach \(\$_POST as \$key => \$value\) \{\n.*?\n\t\})\n\n\n\t\/\/ Validate Adv\. firewall rule settings/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: state validation loop not found');
			}
			eval(
				'function pfb_category_oracle_state_loop(string $type): array {'
				. ' global $pfb; $input_errors = array(); $line = 1;'
				. $m[1]
				. ' return $input_errors; }'
			);
		}

		// Region 3: the custom-list block.
		if (!function_exists('pfb_category_oracle_custom_block')) {
			if (!preg_match(
				'/(\t\/\/ Validate Custom List\n\tif \(!empty\(\$_POST\[\'custom\'\]\)\) \{\n.*?\n\t\})\n\n\tif \(!\$input_errors\) \{/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: custom-list block not found');
			}
			eval(
				'function pfb_category_oracle_custom_block(string $gtype): array {'
				. ' $input_errors = array();'
				. $m[1]
				. ' return $input_errors; }'
			);
		}

		// Region 4: the GET 'atype' ingress block.
		if (!function_exists('pfb_category_oracle_get_atype')) {
			if (!preg_match(
				'/(\tif \(isset\(\$_GET\[\'atype\'\]\).*?\n\t\})\n\}\n\nif \(isset\(\$_POST\)\) \{/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: GET atype block not found');
			}
			eval(
				'function pfb_category_oracle_get_atype(): string {'
				. ' $atype = \'\';'
				. $m[1]
				. ' return $atype; }'
			);
		}

		// Region 5: the POST 'atype' ingress block.
		if (!function_exists('pfb_category_oracle_post_atype')) {
			if (!preg_match(
				'/(\tif \(isset\(\$_POST\[\'atype\'\]\).*?\n\t\})\n\tif \(isset\(\$_POST\[\'chgstate\'\]\)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: POST atype block not found');
			}
			eval(
				'function pfb_category_oracle_post_atype(): string {'
				. ' $atype = \'\';'
				. $m[1]
				. ' return $atype; }'
			);
		}

		// Region 6: the '$_REQUEST[savemsg]' render-time block.
		if (!function_exists('pfb_category_oracle_savemsg')) {
			if (!preg_match(
				'/if \(isset\(\$savemsg\)\) \{\n\tprint_info_box\(\$savemsg\);\n\}\n\n(if \(isset\(\$_REQUEST\[\'savemsg\'\]\).*?\n\})\n\n\$form = new Form\(/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: savemsg block not found');
			}
			eval(
				'function pfb_category_oracle_savemsg(): ?string {'
				. ' ' . $m[1]
				. ' return $savemsg ?? null; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost    = $_POST;
		$this->savedGet     = $_GET;
		$this->savedRequest = $_REQUEST;
		$this->savedPfb     = $GLOBALS['pfb'] ?? null;
		$_POST = $_GET = $_REQUEST = [];
		// Satisfied MaxMind credentials so the state-loop's geoip-format row
		// doesn't also trip the (unrelated) credential-notice input error.
		$GLOBALS['pfb']['maxmind_key']     = 'test-key';
		$GLOBALS['pfb']['maxmind_account'] = 'test-account';
	}

	protected function tearDown(): void
	{
		$_POST    = $this->savedPost;
		$_GET     = $this->savedGet;
		$_REQUEST = $this->savedRequest;
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	// --- R1/R2: atype (POST/GET) ------------------------------------------------

	public function testPostAtypeArrayValueIsIgnoredWithoutThrowing(): void
	{
		$_POST['atype'] = ['x'];
		try {
			$atype = pfb_category_oracle_post_atype();
		} catch (\TypeError $e) {
			$this->fail('an array atype POST value must not TypeError: ' . $e->getMessage());
		}
		$this->assertSame('', $atype, 'an array atype must be silently ignored (stays unset/blank)');
	}

	public function testPostAtypeScalarValueStillResolves(): void
	{
		// Branch coverage: the new is_string() clause's TRUE side still resolves.
		$_POST['atype'] = 'Whitelist|1.2.3.4|test';
		$atype = pfb_category_oracle_post_atype();
		$this->assertStringStartsWith('Whitelist|', $atype, 'a scalar Whitelist atype must still resolve');
	}

	public function testGetAtypeArrayValueIsIgnoredWithoutThrowing(): void
	{
		$_GET['atype'] = ['x'];
		try {
			$atype = pfb_category_oracle_get_atype();
		} catch (\TypeError $e) {
			$this->fail('an array atype GET value must not TypeError: ' . $e->getMessage());
		}
		$this->assertSame('', $atype, 'an array atype must be silently ignored (stays unset/blank)');
	}

	// --- R3/R4: aliasname ---------------------------------------------------

	public function testAliasnameArrayValueDoesNotThrowForDnsbl(): void
	{
		$_POST = ['aliasname' => ['x']];
		try {
			$errors = pfb_category_oracle_aliasname_region('dnsbl');
		} catch (\TypeError $e) {
			$this->fail('an array aliasname must not TypeError (dnsbl): ' . $e->getMessage());
		}
		$this->assertNotEmpty($errors, 'an array aliasname must be rejected as an input error');
		$this->assertSame('', $_POST['aliasname'], 'the guard must blank the array value to an empty string');
	}

	public function testAliasnameArrayValueDoesNotThrowForIpv4(): void
	{
		// gtype=ipv4 additionally exercises the strlen() 24-char limit check (line ~525).
		$_POST = ['aliasname' => ['x'], 'suppression_cidr' => '24'];
		try {
			$errors = pfb_category_oracle_aliasname_region('ipv4');
		} catch (\TypeError $e) {
			$this->fail('an array aliasname must not TypeError (ipv4/strlen): ' . $e->getMessage());
		}
		$this->assertNotEmpty($errors);
		$this->assertSame('', $_POST['aliasname']);
	}

	// --- R15: Lmove exemption + no false positive ---------------------------

	public function testLmoveArrayFieldIsExemptFromGuard(): void
	{
		// Given: a valid Save submission where the user also checked a row-move
		// checkbox (Lmove posts as an array alongside save=Save in real usage).
		$_POST = ['aliasname' => 'validname', 'Lmove' => [0 => '0']];

		// When: the ingress guard runs.
		$errors = pfb_category_oracle_aliasname_region('dnsbl');

		// Then: no error is raised for Lmove and its array value survives untouched.
		$this->assertSame([], $errors, 'Lmove must not be flagged as an invalid field');
		$this->assertSame([0 => '0'], $_POST['Lmove'], 'Lmove must survive the guard unmodified');
	}

	public function testFullyScalarValidPostAddsNoGuardErrors(): void
	{
		$_POST = ['aliasname' => 'validname', 'description' => 'd', 'action' => 'Disabled'];
		$errors = pfb_category_oracle_aliasname_region('dnsbl');
		$this->assertSame([], $errors, 'an all-scalar POST must add zero guard errors');
	}

	public static function hostileArrayShapeProvider(): array
	{
		return [
			'single element' => [['x']],
			'multi element'  => [['a', 'b']],
			'nested'         => [[['x']]],
			'empty array'    => [[]],
		];
	}

	#[DataProvider('hostileArrayShapeProvider')]
	public function testHostileArrayShapeUnderRowhelperKeyIsRejectedWithoutThrowing(array $shape): void
	{
		$_POST = ['aliasname' => 'validname', 'url-0' => $shape];
		try {
			$errors = pfb_category_oracle_aliasname_region('dnsbl');
		} catch (\TypeError $e) {
			$this->fail("shape " . var_export($shape, true) . " under 'url-0' must not TypeError: " . $e->getMessage());
		}
		$this->assertNotEmpty($errors);
		$this->assertSame('', $_POST['url-0']);
	}

	#[DataProvider('hostileArrayShapeProvider')]
	public function testHostileArrayShapeUnderUnknownKeyIsRejectedWithoutThrowing(array $shape): void
	{
		$_POST = ['aliasname' => 'validname', 'zzz' => $shape];
		try {
			$errors = pfb_category_oracle_aliasname_region('dnsbl');
		} catch (\TypeError $e) {
			$this->fail("shape " . var_export($shape, true) . " under an unknown key must not TypeError: " . $e->getMessage());
		}
		$this->assertNotEmpty($errors);
		$this->assertSame('', $_POST['zzz']);
	}

	// --- R5-R8: rowhelper state-loop (run AFTER the ingress guard, mirroring
	// the real script's execution order: guard mutates $_POST, then the state
	// loop reads it) ----------------------------------------------------------

	public function testStateLoopHeaderArrayValueDoesNotThrow(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => ['x'],
			'url-0'     => 'http://192.0.2.1/feed',	// RFC 5737 literal -- avoids DNS resolution
			'format-0'  => 'auto',
		];
		pfb_category_oracle_aliasname_region('dnsbl');	// runs the ingress guard
		try {
			pfb_category_oracle_state_loop('DNSBL');
		} catch (\TypeError $e) {
			$this->fail('an array header-0 must not TypeError the state loop: ' . $e->getMessage());
		}
		$this->assertSame('', $_POST['header-0'], 'the guard must blank the array header value');
	}

	public function testStateLoopUrlArrayValueDoesNotThrow(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => ['x'],
			'format-0'  => 'auto',
		];
		$guardErrors = pfb_category_oracle_aliasname_region('dnsbl');
		try {
			pfb_category_oracle_state_loop('DNSBL');
		} catch (\TypeError $e) {
			$this->fail('an array url-0 must not TypeError the state loop: ' . $e->getMessage());
		}
		// R11: the guard itself produced an input error for the array url-0 field.
		$this->assertNotEmpty(
			array_filter($guardErrors, static fn (string $e): bool => str_contains($e, 'url-0')),
			'the guard must report the array url-0 field as invalid'
		);
		// R12: url-0 is blanked to a scalar, never left as an array to reach config_set_path().
		$this->assertSame('', $_POST['url-0'], 'the guard must blank the array url value');
	}

	public function testStateLoopGeoipFormatUrlArrayDoesNotThrow(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => ['x'],
			'format-0'  => 'geoip',
		];
		pfb_category_oracle_aliasname_region('dnsbl');
		try {
			pfb_category_oracle_state_loop('DNSBL');
		} catch (\TypeError $e) {
			$this->fail('format=geoip with an array url-0 must not TypeError: ' . $e->getMessage());
		}
		$this->assertSame('', $_POST['url-0']);
	}

	public function testStateLoopAsnFormatUrlArrayDoesNotThrow(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => ['x'],
			'format-0'  => 'asn',
		];
		pfb_category_oracle_aliasname_region('dnsbl');
		try {
			pfb_category_oracle_state_loop('DNSBL');
		} catch (\TypeError $e) {
			$this->fail('format=asn with an array url-0 must not TypeError: ' . $e->getMessage());
		}
		$this->assertSame('', $_POST['url-0']);
	}

	// --- R9/R10: custom list --------------------------------------------------

	public function testCustomArrayValueDoesNotThrow(): void
	{
		$_POST = ['aliasname' => 'validname', 'custom' => ['x']];
		pfb_category_oracle_aliasname_region('dnsbl');	// guard blanks 'custom' to ''
		try {
			$errors = pfb_category_oracle_custom_block('dnsbl');
		} catch (\TypeError $e) {
			$this->fail('an array custom value must not TypeError explode(): ' . $e->getMessage());
		}
		// R10/R11: both save-success sinks -- base64_encode('custom') and the
		// asn-format htmlentities(url-N) -- are unreachable once the guard raises
		// input errors (the save block requires empty $input_errors); not separately tested.
		$this->assertSame([], $errors, 'a blanked custom value adds no further validation errors');
		$this->assertSame('', $_POST['custom']);
	}

	public function testCustomBlockStillValidatesInvalidIpv4Entry(): void
	{
		// Behaviour-preserving: the extraction still runs the REAL validation,
		// not a stub that always returns clean.
		$_POST = ['custom' => 'not-an-ip', 'whois_convert' => ''];
		$errors = pfb_category_oracle_custom_block('ipv4');
		$this->assertNotEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'Invalid IPv4 entry')),
			'a bad IPv4 custom-list entry must still be rejected'
		);
	}

	// --- R13: savemsg ---------------------------------------------------------

	public function testSavemsgArrayValueIsIgnoredWithoutThrowing(): void
	{
		$_REQUEST['savemsg'] = ['x'];
		try {
			$savemsg = pfb_category_oracle_savemsg();
		} catch (\TypeError $e) {
			$this->fail('an array savemsg must not TypeError htmlspecialchars(): ' . $e->getMessage());
		}
		$this->assertNull($savemsg, 'an array savemsg must be ignored -- $savemsg stays unset');
	}

	public function testSavemsgScalarValueIsEscaped(): void
	{
		$_REQUEST['savemsg'] = 'ok <b>';
		$savemsg = pfb_category_oracle_savemsg();
		$this->assertSame(htmlspecialchars('ok <b>'), $savemsg, 'a scalar savemsg is still HTML-escaped and rendered');
	}
}
