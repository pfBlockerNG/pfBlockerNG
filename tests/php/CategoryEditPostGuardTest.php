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
 * outside the save block. ADR-63 P4 retired the Lmove/Xmove row-move POST
 * mechanism (replaced by a staged client-side reorder that never posts a new
 * array field), so no field is exempt any more -- every array-valued field,
 * Lmove included, is rejected the same way.
 *
 * The page carries top-level execution and cannot be require()d off-appliance,
 * so each region below is eval-extracted from the REAL source using executable
 * boundaries; comments are stripped before extraction.
 */
final class CategoryEditPostGuardTest extends TestCase
{
	private array $savedPost = [];
	private array $savedGet = [];
	private array $savedRequest = [];
	private mixed $savedPfb = null;
	private bool $hadConfig = FALSE;
	private mixed $savedConfig = null;

	public static function setUpBeforeClass(): void
	{
		$src = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('print_info_box')) {
			// Not doubled in pfsense_doubles.php (out of scope for this issue) -- a
			// no-op is enough since the guard tests only assert on $savemsg/errors.
			function print_info_box($msg): void
			{
			}
		}

		// Region 1: the #1106 ingress guard + #1723 sanitize prologue through the
		// select-options loop's executable close, then the aliasname/CIDR checks
		// up to the state-loop foreach.
		if (!function_exists('pfb_category_oracle_aliasname_region')) {
			if (!preg_match(
				'/(foreach \(\$_POST as \$pfb_post_key => \$pfb_post_value\) \{.*?)(?=\$select_options = array\()/s',
				$src,
				$guard
			)) {
				throw new RuntimeException('test bootstrap: #1106/#1723 executable guard region not found');
			}
			if (!preg_match(
				'/\$_POST\[\$s_option\] = \$s_default;\s*\}\s*\}\s*(.*?)(?=foreach \(\$_POST as \$key => \$value\) \{)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: aliasname/CIDR executable region not found');
			}
			if (strpos($guard[1], 'pfb_sanitize_text_area') === FALSE ||
			    strpos($m[1], 'suppression_cidr_v6') === FALSE) {
				throw new RuntimeException('test bootstrap: aliasname ingress executable region incomplete');
			}
			eval(
				'function pfb_category_oracle_aliasname_region(string $gtype): array {'
				. ' $input_errors = array();'
				. $guard[1]
				. $m[1]
				. ' return $input_errors; }'
			);
		}

		// Region 2: the rowhelper state-loop (URL/header/format validation).
		if (!function_exists('pfb_category_oracle_state_loop')) {
			if (!preg_match(
				'/(foreach \(\$_POST as \$key => \$value\) \{.*?\})'
				. '\s*foreach \(pfb_adv_alias_field_errors\(\$_POST\) as \$pfb_alias_error\)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: state validation executable region not found');
			}
			if (strpos($m[1], 'pfb_header_reserved_error') === FALSE) {
				throw new RuntimeException('test bootstrap: state validation executable region incomplete');
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
				'/(if \(!empty\(\$_POST\[\x27custom\x27\]\)\) \{.*?\})'
				. '\s*if \(!\$input_errors\) \{/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: custom-list executable region not found');
			}
			if (strpos($m[1], 'pfb_idn_to_ascii_wildcard') === FALSE) {
				throw new RuntimeException('test bootstrap: custom-list executable region incomplete');
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
				'/(if \(isset\(\$_GET\[\x27atype\x27\]\).*?\})'
				. '\s*\}\s*if \(isset\(\$_POST\)\) \{/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: GET atype executable region not found');
			}
			if (strpos($m[1], 'pfb_filter_whitelist_atype') === FALSE) {
				throw new RuntimeException('test bootstrap: GET atype executable region incomplete');
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
				'/(if \(isset\(\$_POST\[\x27atype\x27\]\).*?\})'
				. '\s*if \(isset\(\$_POST\[\x27chgstate\x27\]\)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: POST atype executable region not found');
			}
			if (strpos($m[1], 'pfb_filter_whitelist_atype') === FALSE) {
				throw new RuntimeException('test bootstrap: POST atype executable region incomplete');
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
				'/if \(isset\(\$savemsg\)\) \{\s*print_info_box\(\$savemsg\);\s*\}'
				. '\s*(if \(isset\(\$_REQUEST\[\x27savemsg\x27\]\).*?\})'
				. '\s*\$form = new Form\(/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: savemsg executable region not found');
			}
			if (strpos($m[1], 'is_string($_REQUEST[\'savemsg\'])') === FALSE) {
				throw new RuntimeException('test bootstrap: savemsg executable region incomplete');
			}
			eval(
				'function pfb_category_oracle_savemsg(): ?string {'
				. ' ' . $m[1]
				. ' return $savemsg ?? null; }'
			);
		}

		// Region 7: the persist rowhelper loop (issue #1737 persist-parity
		// coverage), bounded by its executable config-write loop and cleanup loop.
		if (!function_exists('pfb_category_oracle_persist_rowhelper_loop')) {
			if (!preg_match(
				'/(\$rowhelper_exist = array\(\);\s*foreach \(\$_POST as \$key => \$value\) \{.*?\})'
				. '\s*foreach \(config_get_path\("installedpackages\/\{\$conf_type\}\/config\/\{\$rowid\}\/row", \[\]\) as \$r_key => \$row\)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: persist rowhelper executable region not found');
			}
			if (strpos($m[1], 'config_set_path("installedpackages/{$conf_type}/config/{$rowid}/row') === FALSE) {
				throw new RuntimeException('test bootstrap: persist rowhelper executable region incomplete');
			}
			eval(
				'function pfb_category_oracle_persist_rowhelper_loop(string $conf_type, $rowid): void {'
				. $m[1]
				. ' }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost    = $_POST;
		$this->savedGet     = $_GET;
		$this->savedRequest = $_REQUEST;
		$this->savedPfb     = $GLOBALS['pfb'] ?? null;
		// The persist oracle writes config through the doubled config_set_path(),
		// so $GLOBALS['config'] is test-mutated state like the superglobals above:
		// restore it (absent stays absent) or it leaks into every later test in
		// this process.
		$this->hadConfig    = array_key_exists('config', $GLOBALS);
		$this->savedConfig  = $GLOBALS['config'] ?? null;
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
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
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

	// --- R15: Lmove is retired -- no longer exempt, rejected like any array field ---

	public function testLmoveArrayFieldIsNoLongerExemptFromGuard(): void
	{
		// Given: a crafted POST carrying an array 'Lmove' -- the retired row-move
		// mechanism's checkbox field. With the mechanism gone, no legitimate array
		// field remains under this key.
		$_POST = ['aliasname' => 'validname', 'Lmove' => [0 => '0']];

		// When: the ingress guard runs.
		$errors = pfb_category_oracle_aliasname_region('dnsbl');

		// Then: Lmove is rejected like any other array field and blanked to ''.
		$this->assertNotEmpty($errors, 'an array Lmove must now be flagged as an invalid field');
		$this->assertNotEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'Lmove')),
			'the guard must report the array Lmove field as invalid'
		);
		$this->assertSame('', $_POST['Lmove'], 'the guard must blank the array Lmove value to an empty string');
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
			$this->fail("shape " . var_export($shape, TRUE) . " under 'url-0' must not TypeError: " . $e->getMessage());
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
			$this->fail("shape " . var_export($shape, TRUE) . " under an unknown key must not TypeError: " . $e->getMessage());
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

	// --- url-N save-time character guard (issue #1104): the state loop must
	// REJECT control chars + HTML-breakout <>" in url-N for EVERY format,
	// never transform the stored value. Distinguishing substring for the
	// guard's own message: 'disallowed character'. --------------------------

	private function assertGuardRejects(array $post, string $type = 'DNSBL', string $gtype = 'dnsbl'): array
	{
		$_POST = $post;
		pfb_category_oracle_aliasname_region($gtype);
		$errors = pfb_category_oracle_state_loop($type);
		$this->assertNotEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'disallowed character')),
			'expected the url-N character guard to reject: ' . var_export($post['url-0'] ?? null, TRUE)
		);
		$this->assertNotEmpty($errors, 'a rejected row must leave $input_errors non-empty (blocks the atomic save)');
		return $errors;
	}

	private function assertGuardAccepts(array $post, string $type = 'DNSBL', string $gtype = 'dnsbl'): array
	{
		$_POST = $post;
		pfb_category_oracle_aliasname_region($gtype);
		$errors = pfb_category_oracle_state_loop($type);
		$this->assertEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'disallowed character')),
			'expected the url-N character guard to accept: ' . var_export($post['url-0'] ?? null, TRUE)
		);
		return $errors;
	}

	// -- coverage matrix: one REJECT + one ACCEPT per format's current gate --

	public function testUrlSaveGuardAutoFormatRejectsScriptInQuery(): void
	{
		// RFC 5737 literal host -- is_ipaddr() short-circuits pfb_filter()'s
		// PFB_FILTER_URL host check before any DNS resolution is attempted.
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'http://192.0.2.1/?x=<script>alert(1)</script>',
			'format-0'  => 'auto',
		]);
	}

	public function testUrlSaveGuardAutoFormatAcceptsUrlWithUserinfoPortQueryEncoding(): void
	{
		$value = 'http://user:pass@192.0.2.1:8443/path?a=1&b=2%20c';
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'auto',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0'], 'the guard must never transform the persisted value');
	}

	public function testUrlSaveGuardGeoipFormatRejectsScriptSuffix(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'US <script>alert(document.cookie)</script>',
			'format-0'  => 'geoip',
		]);
	}

	public function testUrlSaveGuardGeoipFormatAcceptsMultiCountryList(): void
	{
		$value = 'US CA MX GB';
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'geoip',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0']);
	}

	public function testUrlSaveGuardAsnFormatRejectsScriptSuffix(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => '12345 <script>',
			'format-0'  => 'asn',
		]);
	}

	public function testUrlSaveGuardAsnFormatAcceptsApiKeyPlaceholderValue(): void
	{
		// '_API_KEY_' trips the PRE-EXISTING, unrelated API-key-placeholder
		// check (line ~552) regardless of our guard -- assert only that OUR
		// guard adds no error, not that $errors is empty overall.
		$value = '12345 _API_KEY_';
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'asn',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0']);
	}

	public function testUrlSaveGuardWhoisFormatAcceptsPlainDomain(): void
	{
		$value = 'example.com';
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'whois',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0']);
	}

	// -- issue #1104: the remaining format-N axis rows (regex/rsync/whois-reject) --

	public function testUrlSaveGuardRegexFormatRejectsScriptInQuery(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'http://192.0.2.1/?x=<script>alert(1)</script>',
			'format-0'  => 'regex',
		]);
	}

	public function testUrlSaveGuardRegexFormatAcceptsValidQuery(): void
	{
		$value = 'http://192.0.2.1/list?a=1&b=2%20c';
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'regex',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0'], 'the guard must never transform the persisted value');
	}

	public function testUrlSaveGuardRsyncFormatRejectsScriptTag(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'rsync://192.0.2.1/mod/<script>',
			'format-0'  => 'rsync',
		]);
	}

	public function testUrlSaveGuardRsyncFormatAcceptsValidPath(): void
	{
		$value = 'rsync://192.0.2.1/module/path';
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'rsync',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0'], 'the guard must never transform the persisted value');
	}

	public function testUrlSaveGuardWhoisFormatRejectsQuoteBreakout(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'example.com/x"onerror=',
			'format-0'  => 'whois',
		]);
	}

	// -- hostile-input rows -----------------------------------------------

	// issue #1737/#1795 contract update: these rows used to assert the
	// state-loop's [\p{C}<>"] guard REJECTS an embedded Cc/Cf byte / tab.
	// That shape is now stale -- pfb_sanitize_text() strips the full \p{C}
	// set (Cc AND Cf, issue #1795) at ingestion (before the state loop ever
	// runs), the same #1723 standard already shipped for the Hooks tab
	// (commit 66da925d) and for header-N/url-N whitespace elsewhere on this
	// page. An embedded Cc/Cf byte is now silently cleaned, not rejected --
	// pinned below as sanitize-then-accept. The `<`/`"` rows further down
	// prove the guard is still LIVE for what sanitize does NOT strip.

	public function testUrlEmbeddedControlCharSanitizedAtIngestion(): void
	{
		$value = "US\x01CA";
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'geoip',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame('USCA', $_POST['url-0'], 'the embedded Cc byte must be stripped at ingestion, not merely tolerated');
	}

	public function testUrlEmbeddedTabCharacterMergedAtIngestion(): void
	{
		// The tab (Cc, 0x09) is stripped with no replacement, so 'US<TAB>CA'
		// merges to 'USCA' -- a knowing consequence of the single-line Cc-strip
		// contract, not a special case for tab. Crafted-POST territory only: a
		// browser text input cannot submit a literal tab character.
		$value = "US\tCA";
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'geoip',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame('USCA', $_POST['url-0'], 'the embedded tab must be stripped (merged, no replacement) at ingestion');
	}

	public function testUrlEmbeddedCfCharacterSanitizedAtIngestion(): void
	{
		// issue #1795: pfb_sanitize_text() widened from \p{Cc}+BOM to the
		// full \p{C} set -- U+200D ZERO WIDTH JOINER (Cf) is now stripped at
		// ingestion too, so the state-loop's [\p{C}<>"] guard never sees it.
		$value = "http://192.0.2.1/x\u{200D}y";
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'auto',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame('http://192.0.2.1/xy', $_POST['url-0'], 'the zero-width joiner must be stripped at ingestion, not merely tolerated');
	}

	// issue #1795 vacuity guard: pfb_sanitize_text() strips the full \p{C}
	// set now, but never `<` or `"` (ordinary printable text) -- so the
	// state-loop's [\p{C}<>"] character guard must still be provably live
	// post-sanitize for those.

	public function testUrlSaveGuardStillRejectsRawLessThanAfterSanitize(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'http://192.0.2.1/x<y',
			'format-0'  => 'auto',
		]);
	}

	public function testUrlSaveGuardRejectsRawDoubleQuoteAttributeBreakout(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'http://192.0.2.1/x"onerror=alert(1)',
			'format-0'  => 'auto',
		]);
	}

	public function testUrlSaveGuardRejectsGeoipBareSuffixWithNoInternalSpaces(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'US <script>alert(1)</script>',
			'format-0'  => 'geoip',
		]);
	}

	public function testUrlInvalidUtf8ScrubbedToValidUtf8AtIngestion(): void
	{
		// issue #1737/#1797 (A6) contract update: pfb_sanitize_text() scrubs
		// invalid UTF-8 deterministically at ingestion (no ISO-8859-1
		// guessing), before the state loop's /u guard ever runs -- the raw
		// bytes never reach the guard as invalid UTF-8. Downstream format
		// validators (PFB_FILTER_URL, here) still run on the scrubbed bytes --
		// an unrelated "Invalid URL" error from that check is not this guard's
		// concern (assertGuardAccepts filters for the character guard's own
		// message only).
		$value = "\xFF\xFE";
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'auto',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame('??', $_POST['url-0'], 'invalid UTF-8 must be scrubbed to valid UTF-8 at ingestion, never guessed into mojibake');
		$this->assertTrue(mb_check_encoding((string) $_POST['url-0'], 'UTF-8'));
	}

	public function testUrlSaveGuardAcceptsSingleQuoteSubDelim(): void
	{
		// Deliberate: ' is a valid RFC-3986 sub-delim and cannot break the
		// double-quoted href attribute (the display sink already runs
		// htmlspecialchars(ENT_QUOTES)) -- documents the conscious exclusion.
		$value = "http://192.0.2.1/?q='onmouseover='foo";
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'auto',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0']);
	}

	public function testUrlSaveGuardSkipsDisabledRowWithEmptyUrl(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Disabled',
			'header-0'  => '',
			'url-0'     => '',
			'format-0'  => 'auto',
		];
		pfb_category_oracle_aliasname_region('dnsbl');
		$errors = pfb_category_oracle_state_loop('DNSBL');
		$this->assertEmpty($errors, 'a Disabled row must skip every url-N check, including the new guard');
	}

	public function testUrlSaveGuardAcceptsIdnPunycodeHost(): void
	{
		// whois format (PFB_FILTER_DOMAIN, pure regex, no DNS) exercises the
		// guard on a punycode domain string without touching resolve_host_addresses.
		$value = 'xn--e1aybc.tld';
		$post = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => $value,
			'format-0'  => 'whois',
		];
		$this->assertGuardAccepts($post);
		$this->assertSame($value, $_POST['url-0']);
	}

	public function testUrlSaveGuardArrayValuedUrlDoesNotThrowAndAddsNoNewError(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => ['x'],
			'format-0'  => 'auto',
		];
		pfb_category_oracle_aliasname_region('dnsbl');	// blanks url-0 to ''
		try {
			$errors = pfb_category_oracle_state_loop('DNSBL');
		} catch (\TypeError $e) {
			$this->fail('an array url-0 must not TypeError the new character guard: ' . $e->getMessage());
		}
		$this->assertEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'disallowed character')),
			'a blanked (empty-string) url-0 must not trip the new character guard'
		);
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

	// --- issue #1737: rowhelper header-N/url-N sanitize at ingestion, not
	// only at persist -- the validation loop must see the SAME bytes the
	// persist loop later stores. -------------------------------------------

	public function testIngestionSanitizesHeaderBomAndNbspBeforeValidation(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Disabled',	// issue #1270: header/url checks are non-empty-, not state-, gated
			'header-0'  => "\u{00A0}hdr\u{FEFF}",
			'url-0'     => '',
			'format-0'  => 'auto',
		];
		pfb_category_oracle_aliasname_region('dnsbl');	// ingestion prologue
		$errors = pfb_category_oracle_state_loop('DNSBL');
		$this->assertEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'Header field cannot contain spaces')),
			'a header sanitized to plain word chars at ingestion must not trip the validation \W check'
		);
		$this->assertSame('hdr', $_POST['header-0'], 'the ingestion prologue must sanitize header-N (NBSP/BOM stripped)');
	}

	public function testIngestionSanitizesUrlControlCharAndWhitespaceBeforeValidation(): void
	{
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Disabled',	// issue #1270: the control-char guard is non-empty-, not state-, gated
			'header-0'  => 'validheader',
			'url-0'     => " https://example.com/x\x01 ",
			'format-0'  => 'auto',
		];
		pfb_category_oracle_aliasname_region('dnsbl');
		$errors = pfb_category_oracle_state_loop('DNSBL');
		$this->assertEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, 'disallowed character')),
			'a url-N sanitized (Cc stripped, trimmed) at ingestion must not trip the control-char guard'
		);
		$this->assertSame(
			'https://example.com/x',
			$_POST['url-0'],
			'the ingestion prologue must sanitize url-N (Cc stripped + leading/trailing whitespace trimmed)'
		);
	}

	public function testIngestionPrologueLeavesStateAndFormatSelectValuesUntouched(): void
	{
		// Scope pin: the header/url prologue targets ONLY header-N/url-N keys --
		// a select value under state-N/format-N must survive byte-identical.
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => "  Enabled\u{00A0}",
			'header-0'  => 'validheader',
			'url-0'     => 'http://192.0.2.1/feed',
			'format-0'  => " auto\u{00A0}",
		];
		pfb_category_oracle_aliasname_region('dnsbl');
		$this->assertSame(
			"  Enabled\u{00A0}",
			$_POST['state-0'],
			'state-N is a select value, not free text -- must not be sanitized by the header/url prologue'
		);
		$this->assertSame(
			" auto\u{00A0}",
			$_POST['format-0'],
			'format-N is a select value, not free text -- must not be sanitized by the header/url prologue'
		);
	}

	public function testPersistRowhelperLoopStoresIngestionSanitizedHeaderOnce(): void
	{
		// Regression pin (passes unchanged pre- and post-fix): the persist loop's
		// stored value must equal the sanitized+PFB_FILTER_HTML'd form whether
		// sanitize runs once (ingestion, post-fix) or twice idempotently
		// (ingestion is a no-op pre-fix, so persist's own #1723 sanitize is the
		// only pass) -- proves removing the persist-loop sanitize is safe.
		$GLOBALS['config'] = [];
		$_POST = [
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => "\u{00A0}hdr\u{FEFF}",
			'url-0'     => 'http://192.0.2.1/feed',
			'format-0'  => 'auto',
		];
		pfb_category_oracle_aliasname_region('dnsbl');	// ingestion prologue (no-op pre-fix)
		pfb_category_oracle_persist_rowhelper_loop('pfblockerngdnsbl', 0);

		$this->assertSame(
			'hdr',
			config_get_path('installedpackages/pfblockerngdnsbl/config/0/row/0/header'),
			'the stored header must equal the sanitized+PFB_FILTER_HTML value regardless of which loop sanitized it'
		);
	}
}
