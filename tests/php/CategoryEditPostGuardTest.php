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
			'expected the url-N character guard to reject: ' . var_export($post['url-0'] ?? null, true)
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
			'expected the url-N character guard to accept: ' . var_export($post['url-0'] ?? null, true)
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

	public function testUrlSaveGuardDnsblGtypeAutoFormatRejectsScriptInQuery(): void
	{
		// Same code path as ipv4/ipv6 auto (single file; gtype only changes
		// the format dropdown) -- prove the guard fires on the dnsbl tab too.
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => 'http://192.0.2.1/?x=<script>alert(1)</script>',
			'format-0'  => 'auto',
		], 'DNSBL', 'dnsbl');
	}

	// -- hostile-input rows -----------------------------------------------

	public function testUrlSaveGuardRejectsEmbeddedControlCharacter(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => "US\x01CA",
			'format-0'  => 'geoip',
		]);
	}

	public function testUrlSaveGuardRejectsEmbeddedTabCharacter(): void
	{
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => "US\tCA",
			'format-0'  => 'geoip',
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

	public function testUrlSaveGuardRejectsInvalidUtf8FailClosed(): void
	{
		// preg_match() with /u returns FALSE (not 0) on invalid UTF-8; the
		// guard's `!== 0` compare must treat FALSE as a reject (fail closed).
		$this->assertGuardRejects([
			'aliasname' => 'validname',
			'state-0'   => 'Enabled',
			'header-0'  => 'validheader',
			'url-0'     => "\xFF\xFE",
			'format-0'  => 'auto',
		]);
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
}
