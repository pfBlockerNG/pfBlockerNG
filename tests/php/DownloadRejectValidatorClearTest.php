<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';
require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * Issue #2820 — a content-rejected feed must not be able to hide behind the rejected
 * body's own ADR-42 validators.
 *
 * The scheduled detector promotes a 200 response's ETag / Last-Modified BEFORE the ingest
 * it schedules has run (pfblockerng_cron.inc, the '( content changed )' branch), because
 * the ingest re-uses the probe's '.md5.raw' body and therefore has no response headers of
 * its own to promote from. So when the ingest then REFUSES that body — any ADR-49
 * stage=plaintext verdict, or the mime / inner / structural / size refusals beside it —
 * the rejected body's validators are what the next conditional GET sends, the origin
 * answers 304, and pfb_conditional_get_decision() reports "unchanged": the bad body is
 * never re-fetched and never re-judged.
 *
 * Three properties are pinned here, and they are a set — none of them is safe alone:
 *
 *   1. After a rejection no validator survives, so the next pass asks unconditionally,
 *      gets the body, and judges it again. Proven end to end over real cURL against a
 *      loopback origin that DOES answer 304 to the validator it issued, for the ETag axis
 *      and the Last-Modified axis, on the wire body and on an extracted payload.
 *   2. The previously served '.orig' stays byte-identical through every rejection — the
 *      issue #2660 / #2668 contract — and so does its '.orig.xxhash128' source-hash
 *      baseline, which still describes the LAST GOOD body and so still answers the
 *      spurious-200 compare correctly. Only the validators the detector promoted go.
 *   3. A healthy ingest is untouched: its validators survive and a later 304 still
 *      short-circuits the re-ingest. Clearing on success would turn every conditional
 *      GET back into a full download.
 *
 * The feed host is a name the resolve double maps to loopback PLUS a public address, the
 * way DownloadSizeRefusalTest and DownloadRetryBodyResetTest already do it: a literal
 * 127.0.0.1 URL is classified pfSense-local by PFB_FILTER_URL and fetched with the
 * file_get_contents() stream wrapper, which has no response headers at all — the ADR-42
 * conditional-GET path only exists on the cURL branch.
 */
#[CoversFunction('pfb_download')]
final class DownloadRejectValidatorClearTest extends TestCase
{
	/** An HTML error page: text to libmagic, no blocklist-shaped line anywhere. */
	private const HTML_ERROR = "<!doctype html>\n<html><body><h1>403 Forbidden</h1>\n"
		. "<p>Access denied by the origin</p></body></html>\n";

	private const NUL_BEARING = "1.2.3.4\n\x00garbage\n";

	private const HEALTHY = "192.0.2.10/32\n198.51.100.20\n";

	/** Bytes already in service: a refused refresh must leave them untouched. */
	private const SERVED = "203.0.113.7/32\n";

	/** The validator the origin issues WITH the body the ingest is going to refuse. */
	private const BAD_ETAG = '"bad-v1"';

	private const BAD_LASTMOD = 1700000000;

	/** The validator a previous, accepted pass left behind. */
	private const SEED_ETAG = '"good-v0"';

	private const SEED_LASTMOD = 1600000000;

	private const FEED_HOST = 'reject-validators.example';

	private const HEADER = 'pfB_Rej2820_v4';

	private string $dir = '';

	private int $port = 0;

	/** @var resource|null */
	private $server = NULL;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] entries; absent key = was unset */
	private array $savedPfb = [];

	/** @var array<string,mixed> saved fixture globals; absent key = was unset */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		if (!extension_loaded('curl')) {
			$this->markTestSkipped('curl extension not available');
		}
		$this->dir = sys_get_temp_dir() . '/pfb_reject_validators_' . getmypid() . '_' . uniqid('', TRUE);
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));

		foreach (['config', 'pfb_test_resolve_map', 'pfb_test_configured_ips'] as $g) {
			if (array_key_exists($g, $GLOBALS)) {
				$this->savedGlobals[$g] = $GLOBALS[$g];
			}
		}
		foreach (['log', 'errlog', 'pnow', 'dbdir', 'mime_types', 'skipfeed', 'failed',
			'runlog', 'runlog_active'] as $k) {
			if (array_key_exists($k, $GLOBALS['pfb'] ?? [])) {
				$this->savedPfb[$k] = $GLOBALS['pfb'][$k];
			}
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		// Loopback FIRST — pfb_feed_host_allowed() pins the first vetted candidate, and the
		// self-IP carve-out admits it — plus a public address so the host is not classified
		// self-hosted (which would route the fetch through the stream wrapper instead).
		$GLOBALS['pfb_test_resolve_map'] = [
			self::FEED_HOST . '.' => [
				['type' => 'A', 'data' => '127.0.0.1'],
				['type' => 'A', 'data' => '203.0.113.5'],
			],
		];
		// The orig dir IS dbdir: pfb_download() re-uses the detector's '.md5.raw' body by
		// swapping the URL for that local path, and PFB_FILTER_URL only accepts a local feed
		// path sitting directly in an allowed directory (/var/db/pfblockerng/* on the box).
		$GLOBALS['pfb']['dbdir']      = $this->dir;
		$GLOBALS['pfb']['log']        = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']     = "{$this->dir}/error.log";
		$GLOBALS['pfb']['pnow']       = 'now';
		$GLOBALS['pfb']['skipfeed']   = 0;
		$GLOBALS['pfb']['failed']     = [];
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? $GLOBALS['pfb']['mime_types'] ?? [];
		PfbConfig::write('gen/pfb_feed_sanity', PfbToggle::On);

		$this->startOrigin();
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
			$this->server = NULL;
		}
		foreach (['log', 'errlog', 'pnow', 'dbdir', 'mime_types', 'skipfeed', 'failed',
			'runlog', 'runlog_active'] as $k) {
			if (array_key_exists($k, $this->savedPfb)) {
				$GLOBALS['pfb'][$k] = $this->savedPfb[$k];
			} else {
				unset($GLOBALS['pfb'][$k]);
			}
		}
		foreach (['config', 'pfb_test_resolve_map', 'pfb_test_configured_ips'] as $g) {
			if (array_key_exists($g, $this->savedGlobals)) {
				$GLOBALS[$g] = $this->savedGlobals[$g];
			} else {
				unset($GLOBALS[$g]);
			}
		}
		if ($this->dir !== '' && is_dir($this->dir)) {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator($this->dir, FilesystemIterator::SKIP_DOTS),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ($it as $entry) {
				$entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
			}
			rmdir($this->dir);
		}
	}

	// ------------------------------------------------------------------
	// 1. The issue's case, end to end: ETag axis, wire body
	// ------------------------------------------------------------------

	/**
	 * Scenario: the detector promoted the rejected body's ETag.
	 *   Given a '.orig' in service, and an origin serving a body the plain-text scan
	 *         refuses, tagged ETag "bad-v1", that DOES answer 304 to If-None-Match: "bad-v1";
	 *   And   a first detector pass that promotes that ETag (asserted, before-state)
	 *         and an ingest that refuses the body at stage=plaintext;
	 *   When  the next detector pass runs;
	 *   Then  it asks the origin UNCONDITIONALLY, is handed the body, and reports the feed
	 *         changed — so the ingest re-judges it — instead of reporting "not modified";
	 *   And   the served '.orig' is byte-identical throughout.
	 */
	public function test_a_rejected_wire_body_cannot_hide_behind_its_own_etag(): void
	{
		$base = $this->seedPublication();
		$this->serve($this->fixturePlain(self::HTML_ERROR), self::BAD_ETAG, 0);

		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the first detector pass must complete');
		$this->assertTrue((bool) $GLOBALS['pfb']['cron_update'],
			'the first pass must find the changed body');
		// Before-state: the promotion this issue is about really happened.
		$this->assertSame(self::BAD_ETAG, file_get_contents("{$base}.orig.etag"),
			'premise: the detector promotes the response ETag before the ingest has run');

		$this->assertFalse($this->ingest()->success, 'the refused body must fail the ingest');
		$this->assertStringContainsString(
			'stage=plaintext reason=html_error_page',
			$this->log(),
			'the ingest must refuse the body through the ADR-49 plain-text gate'
		);
		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'a refused refresh must leave the previously served payload byte-identical');

		$this->truncateRequests();
		$GLOBALS['pfb']['cron_update'] = NULL;
		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the second detector pass must complete');

		$asked = $this->requests();
		$this->assertCount(1, $asked, 'the second pass must make exactly one request');
		$this->assertSame('', $asked[0]['inm'],
			'the rejected body\'s ETag must not be offered back — that is what lets the origin 304');
		$this->assertTrue((bool) $GLOBALS['pfb']['cron_update'],
			'the second pass must re-fetch and re-judge, not report the feed unchanged');
		$this->assertStringNotContainsString('( 304 not modified )', $this->log(),
			'a rejected body must never be able to answer the next pass with 304');
		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'the served payload must still be byte-identical after the second pass');
	}

	// ------------------------------------------------------------------
	// 2. The Last-Modified axis — an origin with no ETag at all
	// ------------------------------------------------------------------

	/**
	 * Same scenario against an origin that issues only Last-Modified, so the conditional
	 * GET rides CURLOPT_TIMECONDITION / If-Modified-Since. Clearing the ETag alone would
	 * leave this axis hiding the rejected body exactly as before.
	 */
	public function test_a_rejected_wire_body_cannot_hide_behind_its_own_last_modified(): void
	{
		$base = $this->seedPublication();
		$this->serve($this->fixturePlain(self::HTML_ERROR), '', self::BAD_LASTMOD);

		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the first detector pass must complete');
		$this->assertSame((string) self::BAD_LASTMOD, file_get_contents("{$base}.orig.lastmod"),
			'premise: the detector promotes the response Last-Modified before the ingest has run');
		$this->assertFileDoesNotExist("{$base}.orig.etag",
			'premise: this origin issues no ETag, so only the Last-Modified axis is live');

		$this->assertFalse($this->ingest()->success, 'the refused body must fail the ingest');
		$this->assertStringContainsString('stage=plaintext reason=html_error_page', $this->log(),
			'the ingest must refuse the body through the ADR-49 plain-text gate');

		$this->truncateRequests();
		$GLOBALS['pfb']['cron_update'] = NULL;
		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the second detector pass must complete');

		$asked = $this->requests();
		$this->assertCount(1, $asked, 'the second pass must make exactly one request');
		$this->assertSame('', $asked[0]['ims'],
			'the rejected body\'s Last-Modified must not be offered back as If-Modified-Since');
		$this->assertTrue((bool) $GLOBALS['pfb']['cron_update'],
			'the second pass must re-fetch and re-judge, not report the feed unchanged');
		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'the served payload must stay byte-identical');
	}

	// ------------------------------------------------------------------
	// 3. The extracted-payload gate (#2660), end to end
	// ------------------------------------------------------------------

	/**
	 * The same end-to-end property for the gate that judges an archive feed's EXTRACTED
	 * payload: the wire body is a well-formed gzip libmagic accepts, and only what comes
	 * out of it is refused.
	 */
	public function test_a_rejected_extracted_payload_cannot_hide_behind_its_own_etag(): void
	{
		$base = $this->seedPublication();
		$this->serve($this->fixtureGz(self::HTML_ERROR), self::BAD_ETAG, 0);

		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the first detector pass must complete');
		$this->assertSame(self::BAD_ETAG, file_get_contents("{$base}.orig.etag"),
			'premise: the detector promotes the response ETag before the ingest has run');

		$this->assertFalse($this->ingest()->success, 'the refused payload must fail the ingest');
		$this->assertStringContainsString(
			'stage=plaintext reason=html_error_page detected=' . self::HEADER . '.orig',
			$this->log(),
			'the refusal must come from the extracted-payload gate, naming the staged .orig'
		);
		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'a refused refresh must leave the previously served payload byte-identical');

		$this->truncateRequests();
		$GLOBALS['pfb']['cron_update'] = NULL;
		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the second detector pass must complete');
		$asked = $this->requests();
		$this->assertCount(1, $asked, 'the second pass must make exactly one request');
		$this->assertSame('', $asked[0]['inm'],
			'the rejected payload\'s ETag must not be offered back');
		$this->assertTrue((bool) $GLOBALS['pfb']['cron_update'],
			'the second pass must re-fetch and re-judge the archive');
	}

	// ------------------------------------------------------------------
	// 4. Every reject stage reachable on the standard list-feed lane
	// ------------------------------------------------------------------

	/**
	 * Every ADR-48 reject stage a standard list feed ($type == '') can reach, enumerated
	 * from pfb_download()'s own pfb_validate_log() call sites — one row per (archive kind,
	 * refusing gate) pair, so a stage that stopped clearing is visible per stage rather
	 * than hidden behind a sibling.
	 *
	 * stage=member is deliberately absent and that is not an omission: all five of its
	 * call sites sit inside `$type == 'blacklist'`, `'geoip'` or `'top1m'` branches, so no
	 * standard list feed can reach it. Those lanes promote their validators only AFTER a
	 * successful publication (pfblockerng.php's TOP1M detector), so no rejected body's
	 * validator can survive there — Top1mSemanticMatrixTest pins that retention.
	 * stage=size is covered by its own test below (it needs the transfer ceiling).
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: string}>
	 */
	public static function rejectStageMatrix(): array
	{
		return [
			'wire body MIME is not allowed'      => ['binary', 'ok',    'mime',       'mime_not_allowed'],
			'wire body is an HTML error page'    => ['plain',  'html',  'plaintext',  'html_error_page'],
			'gzip payload is an HTML error page' => ['gz',     'html',  'plaintext',  'html_error_page'],
			'gzip payload MIME is not allowed'   => ['gz',     'nul',   'inner',      'compressed_mime_not_allowed'],
			'gzip archive fails its probe'       => ['gz-bad', 'ok',    'structural', 'probe_failed'],
			'bzip2 payload is an HTML error page' => ['bz2',    'html',  'plaintext',  'html_error_page'],
			'bzip2 payload MIME is not allowed'  => ['bz2',    'nul',   'inner',      'compressed_mime_not_allowed'],
			'bzip2 archive fails its probe'      => ['bz2-bad', 'ok',   'structural', 'probe_failed'],
			'zip payload is an HTML error page'  => ['zip',    'html',  'plaintext',  'html_error_page'],
			'zip payload MIME is not allowed'    => ['zip',    'nul',   'inner',      'inner_mime_not_allowed'],
			'zip archive fails its probe'        => ['zip-bad', 'ok',   'structural', 'probe_failed'],
			'tar payload is an HTML error page'  => ['tar',    'html',  'plaintext',  'html_error_page'],
			'tar archive fails its probe'        => ['tar-bad', 'ok',   'structural', 'probe_failed'],
		];
	}

	/**
	 * Scenario: a refusal at any stage discards the validators the detector promoted.
	 *   Given a '.orig' in service, its '.orig.xxhash128' source baseline, and the
	 *         validators a detector pass promoted for the body about to be refused;
	 *   When  the ingest refuses that body at $stage;
	 *   Then  no validator remains for the next conditional GET to offer,
	 *   And   the served '.orig' and its source-hash baseline are byte-identical.
	 */
	#[DataProvider('rejectStageMatrix')]
	public function test_every_reject_stage_clears_the_promoted_validators(
		string $kind,
		string $payload,
		string $stage,
		string $reason
	): void {
		$base = $this->seedPublication();
		$baseline = (string) file_get_contents("{$base}.orig.xxhash128");
		$this->promoteValidators($base);
		$this->serve($this->fixture($kind, $payload), self::BAD_ETAG, self::BAD_LASTMOD);

		$this->assertFalse($this->ingest()->success, 'the row must fail the ingest');
		$this->assertStringContainsString("stage={$stage} reason={$reason}", $this->log(),
			'the row must be refused by the gate it claims');

		$validators = pfb_validator_read("{$base}.orig");
		$this->assertFalse($validators['etag'],
			'the refused body\'s ETag must not survive to 304 the next pass');
		$this->assertFalse($validators['lastmod'],
			'the refused body\'s Last-Modified must not survive to 304 the next pass');
		$this->assertFileDoesNotExist("{$base}.orig.etag", 'the .etag sidecar must be gone');
		$this->assertFileDoesNotExist("{$base}.orig.lastmod", 'the .lastmod sidecar must be gone');

		$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
			'a refused refresh must leave the previously served payload byte-identical');
		$this->assertSame($baseline, file_get_contents("{$base}.orig.xxhash128"),
			'the source-hash baseline still describes the last GOOD body, so it must survive');
	}

	// ------------------------------------------------------------------
	// 5. stage=size — the transfer ceiling
	// ------------------------------------------------------------------

	/**
	 * The size refusal (issue #2658) happens inside the cURL write callback, before any
	 * content gate, and returns from a different place in pfb_download(). It must discard
	 * the promoted validators exactly like every content refusal does.
	 */
	public function test_an_over_large_body_clears_the_promoted_validators(): void
	{
		$hadCeiling = array_key_exists(CURLOPT_MAXFILESIZE_LARGE, $GLOBALS['pfb']['curl_defaults'] ?? []);
		$savedCeiling = $hadCeiling ? $GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE] : NULL;
		$GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE] = 16;
		try {
			$base = $this->seedPublication();
			$baseline = (string) file_get_contents("{$base}.orig.xxhash128");
			$this->assertNotSame('', $baseline, 'fixture: the source-hash baseline must be on disk');
			$this->promoteValidators($base);
			$this->serve($this->fixturePlain(str_repeat("192.0.2.10/32\n", 64)), self::BAD_ETAG, self::BAD_LASTMOD);

			$this->assertFalse($this->ingest()->success, 'an over-large body must fail the ingest');
			$this->assertStringContainsString('stage=size reason=download_too_large', $this->log(),
				'the row must be refused by the transfer ceiling');
			$this->assertFileDoesNotExist("{$base}.orig.etag",
				'the refused body\'s ETag must not survive the size refusal');
			$this->assertFileDoesNotExist("{$base}.orig.lastmod",
				'the refused body\'s Last-Modified must not survive the size refusal');
			$this->assertSame(self::SERVED, file_get_contents("{$base}.orig"),
				'a refused refresh must leave the previously served payload byte-identical');
			$this->assertSame($baseline, file_get_contents("{$base}.orig.xxhash128"),
				'the source-hash baseline still describes the last GOOD body, so it must survive');
		} finally {
			if ($hadCeiling) {
				$GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE] = $savedCeiling;
			} else {
				unset($GLOBALS['pfb']['curl_defaults'][CURLOPT_MAXFILESIZE_LARGE]);
			}
		}
	}

	// ------------------------------------------------------------------
	// 6. The success path is untouched
	// ------------------------------------------------------------------

	/**
	 * Scenario: the other side of the branch — a healthy ingest.
	 *   Given an origin serving a healthy list tagged ETag "bad-v1" that answers 304 to it;
	 *   When  the detector promotes the ETag and the ingest ACCEPTS the body;
	 *   Then  the validator survives, and the next pass offers it and is told 304, so the
	 *         re-ingest is correctly short-circuited.
	 * Clearing on the success path too would turn every conditional GET back into a full
	 * body download.
	 */
	public function test_a_healthy_ingest_keeps_its_validators_and_a_later_304_short_circuits(): void
	{
		$base = $this->seedPublication();
		$this->serve($this->fixturePlain(self::HEALTHY), self::BAD_ETAG, 0);

		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the first detector pass must complete');
		$this->assertSame(self::BAD_ETAG, file_get_contents("{$base}.orig.etag"),
			'premise: the detector promotes the response ETag');

		$this->assertTrue($this->ingest()->success, 'a healthy body must still ingest');
		$this->assertSame(self::HEALTHY, file_get_contents("{$base}.orig"),
			'the healthy body must be published');
		$this->assertSame(self::BAD_ETAG, file_get_contents("{$base}.orig.etag"),
			'an accepted body\'s validator must survive the ingest');

		$this->truncateRequests();
		$GLOBALS['pfb']['cron_update'] = NULL;
		$this->assertSame(PfbScheduleTerminalResult::Success, $this->detect(),
			'the second detector pass must complete');
		$asked = $this->requests();
		$this->assertCount(1, $asked, 'the second pass must make exactly one request');
		$this->assertSame(self::BAD_ETAG, $asked[0]['inm'],
			'the accepted body\'s validator must be offered back as If-None-Match');
		$this->assertFalse((bool) $GLOBALS['pfb']['cron_update'],
			'a 304 on an accepted body must still short-circuit the re-ingest');
		$this->assertStringContainsString('( 304 not modified )', $this->log(),
			'the short-circuit must be the ADR-42 304 path');
	}

	// ------------------------------------------------------------------
	// 7. The behaviour cannot diverge per stage
	// ------------------------------------------------------------------

	/**
	 * pfb_download() has 80-odd failure returns spread over the archive branches. The
	 * uniformity the issue asks for is structural, not per-site discipline: every outcome
	 * leaves through ONE wrapper, so no stage can be given (or forget) its own clear.
	 * Pinned on code, not comments, because a comment cannot hold this invariant.
	 */
	public function test_every_download_outcome_leaves_through_the_single_clear_point(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		$this->assertNotSame('', $source, 'could not read a comment-free pfblockerng.inc');

		$wrapper = strpos($source, 'function pfb_download(PfbDownloadRequest $request): PfbDownloadResult {');
		$impl    = strpos($source, 'function pfb_download_fetch(PfbDownloadRequest $request): PfbDownloadResult {');
		$this->assertNotFalse($wrapper, 'pfb_download() must stay the callers\' entry point');
		$this->assertNotFalse($impl, 'the fetch/ingest pipeline must live in pfb_download_fetch()');
		$this->assertLessThan($impl, $wrapper, 'the wrapper must precede the implementation');

		$wrapperBody = substr($source, $wrapper, $impl - $wrapper);
		$this->assertSame(1, substr_count($wrapperBody, 'pfb_download_fetch($request)'),
			'the wrapper must call the pipeline exactly once');
		$this->assertStringNotContainsString('PfbDownloadResult::', $wrapperBody,
			'the wrapper must not build its own results — every outcome comes from the pipeline');
		$this->assertSame(['src/usr/local/pkg/pfblockerng/pfblockerng.inc' => 1], $this->pipelineCallers(),
			'pfb_download_fetch() must have exactly one caller: nothing may bypass the wrapper');

		$implEnd = strpos($source, 'function pfb_download_failure(', $impl);
		$this->assertNotFalse($implEnd);
		$implBody = substr($source, $impl, $implEnd - $impl);
		$this->assertGreaterThan(50, substr_count($implBody, 'PfbDownloadResult::failure()'),
			'premise: the pipeline really does refuse from dozens of places');
		$this->assertStringNotContainsString('.orig.etag', $implBody,
			'no reject site may grow its own validator clear beside the wrapper\'s');
	}

	/**
	 * Every mention of the pipeline's name in shipped PHP, as repo-relative path => count,
	 * with only its own declaration discounted. Keyed on the full path and counted per file,
	 * so a second caller cannot hide behind a duplicate basename; read from PHP TOKENS, so
	 * it cannot hide behind whitespace before the parenthesis, a leading namespace
	 * separator, or a string literal handed to a dynamic call. Any of those would be exactly
	 * the bypass this pins against. A bare mention counts too: for a guardrail, naming the
	 * pipeline anywhere outside its own declaration is the thing worth looking at.
	 *
	 * @return array<string, int>
	 */
	private function pipelineCallers(): array
	{
		$root = dirname(__DIR__, 2);
		$callers = [];
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator("{$root}/src", FilesystemIterator::SKIP_DOTS)
		);
		foreach ($it as $entry) {
			if (!$entry->isFile() || !in_array($entry->getExtension(), ['inc', 'php'], TRUE)) {
				continue;
			}
			$uses = 0;
			$previous = NULL;
			foreach (token_get_all((string) file_get_contents($entry->getPathname())) as $token) {
				if (is_array($token)
				    && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], TRUE)) {
					continue;
				}
				$named = NULL;
				if (is_array($token)) {
					if ($token[0] === T_STRING || $token[0] === T_NAME_FULLY_QUALIFIED) {
						$named = ltrim($token[1], '\\');
					} elseif ($token[0] === T_CONSTANT_ENCAPSED_STRING) {
						$named = ltrim(trim($token[1], '\'"'), '\\');
					}
				}
				if ($named === 'pfb_download_fetch'
				    && !(is_array($previous) && $previous[0] === T_FUNCTION)) {
					$uses++;
				}
				$previous = $token;
			}
			if ($uses > 0) {
				$callers[ltrim(str_replace($root, '', $entry->getPathname()), '/')] = $uses;
			}
		}
		ksort($callers, SORT_STRING);
		return $callers;
	}

	// ------------------------------------------------------------------
	// fixtures and plumbing
	// ------------------------------------------------------------------

	/** Put a healthy list in service, with the source-hash baseline a real pass leaves. */
	private function seedPublication(): string
	{
		$base = "{$this->dir}/" . self::HEADER;
		$this->assertNotFalse(file_put_contents("{$base}.orig", self::SERVED));
		$this->assertTrue(pfb_hash_write("{$base}.orig", "{$base}.orig"));
		$this->assertNotFalse(file_put_contents("{$this->dir}/" . self::HEADER . '.txt', self::SERVED));
		return $base;
	}

	/**
	 * Stand in for the detector pass the matrix rows do not run: the validators the
	 * '( content changed )' branch promotes for the body that is about to be refused.
	 */
	private function promoteValidators(string $base): void
	{
		pfb_validator_write("{$base}.orig", self::BAD_ETAG, self::BAD_LASTMOD);
		$this->assertFileExists("{$base}.orig.etag", 'fixture: the promoted ETag must be on disk');
		$this->assertFileExists("{$base}.orig.lastmod", 'fixture: the promoted Last-Modified must be on disk');
	}

	private function payload(string $name): string
	{
		switch ($name) {
			case 'html':
				return self::HTML_ERROR;
			case 'nul':
				return self::NUL_BEARING;
			case 'ok':
				return self::HEALTHY;
		}
		throw new InvalidArgumentException("unknown payload fixture [{$name}]");
	}

	private function fixture(string $kind, string $payload): string
	{
		if (str_starts_with($kind, 'zip')) {
			$this->requirePipefailShell();
			$this->requireTarReadsZip();
		}
		$bytes = $this->payload($payload);
		switch ($kind) {
			case 'plain':
				return $this->fixturePlain($bytes);
			case 'binary':
				// A body no allow-listed MIME covers, with no control characters in the
				// first bytes, so the wire-body MIME gate is what refuses it.
				return $this->write('wire.bin', "\x89PNG\r\n\x1a\n" . str_repeat("\x7f\x21\x40", 128));
			case 'gz':
				return $this->fixtureGz($bytes);
			case 'gz-bad':
				// libmagic still reads the gzip header; the structural probe must not.
				return $this->write('corrupt.gz', substr((string) gzencode($bytes), 0, 10) . str_repeat("\xff", 64));
			case 'bz2':
				return $this->fixtureBz2($bytes);
			case 'bz2-bad':
				return $this->write('corrupt.bz2',
					substr((string) file_get_contents($this->fixtureBz2($bytes)), 0, 8) . str_repeat("\x55", 64));
			case 'zip':
				return $this->fixtureZip($bytes);
			case 'zip-bad':
				return $this->write('corrupt.zip',
					substr((string) file_get_contents($this->fixtureZip($bytes)), 0, 40) . str_repeat("\x00", 80));
			case 'tar':
				return $this->fixtureTar($bytes);
			case 'tar-bad':
				// Keep the 512-byte member header libmagic classifies on; shred the data.
				return $this->write('corrupt.tar',
					substr((string) file_get_contents($this->fixtureTar($bytes)), 0, 512) . str_repeat("\xee", 900));
		}
		throw new InvalidArgumentException("unknown archive kind [{$kind}]");
	}

	private function write(string $name, string $bytes): string
	{
		$path = "{$this->dir}/{$name}";
		$this->assertNotFalse(file_put_contents($path, $bytes));
		return $path;
	}

	private function fixturePlain(string $bytes): string
	{
		return $this->write('body.txt', $bytes);
	}

	private function fixtureGz(string $bytes): string
	{
		return $this->write('body.gz', (string) gzencode($bytes));
	}

	/** Built with the same absolute binaries pfb_download() extracts with. */
	private function fixtureBz2(string $bytes): string
	{
		$member = $this->write('payload.txt', $bytes);
		$path = "{$this->dir}/body.bz2";
		exec('/usr/bin/bzip2 -zc ' . escapeshellarg($member) . ' > ' . escapeshellarg($path), $out, $rc);
		$this->assertSame(0, $rc, '/usr/bin/bzip2 could not build the fixture');
		return $path;
	}

	private function fixtureZip(string $bytes): string
	{
		$path = "{$this->dir}/body.zip";
		$zip = new ZipArchive();
		$this->assertTrue($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE));
		$this->assertTrue($zip->addFromString('payload.txt', $bytes));
		$this->assertTrue($zip->close());
		return $path;
	}

	private function fixtureTar(string $bytes): string
	{
		$this->write('payload.txt', $bytes);
		$path = "{$this->dir}/body.tar";
		exec(escapeshellarg(pfb_test_tar()) . ' -cf ' . escapeshellarg($path) . ' -C ' . escapeshellarg($this->dir)
			. ' payload.txt', $out, $rc);
		$this->assertSame(0, $rc, 'the archive tool could not build the fixture');
		return $path;
	}

	/**
	 * The ZIP arm extracts through a `set -o pipefail` pipeline (issue #819) and PHP's
	 * exec() runs /bin/sh, so a /bin/sh without pipefail cannot exercise that arm at all:
	 * Debian's dash — the Linux CI runner's /bin/sh — exits on the option error before tar
	 * runs. Skip loudly rather than report a host property as a product defect; FreeBSD's
	 * sh has pipefail, so the appliance path is covered live by tests/smoke.
	 */
	private function requirePipefailShell(): void
	{
		$out = [];
		$rc = 1;
		// `set -e` is what makes the probe loud: without it $rc is the ECHO's status, so a
		// shell that only WARNS on an unsupported option reports a capability it lacks.
		exec('{ set -e; set -o pipefail; /bin/echo pfbpipefail; } 2>/dev/null', $out, $rc);
		if ($rc !== 0 || ($out[0] ?? '') !== 'pfbpipefail') {
			$this->markTestSkipped(
				"/bin/sh cannot 'set -o pipefail' (exit {$rc}); the ZIP arm's extraction pipeline "
				. 'never runs on this host'
			);
		}
	}

	/** GNU tar cannot read a ZIP at all; the appliance and macOS ship bsdtar. */
	private function requireTarReadsZip(): void
	{
		$probe = "{$this->dir}/tarprobe.zip";
		$zip = new ZipArchive();
		$this->assertTrue($zip->open($probe, ZipArchive::CREATE | ZipArchive::OVERWRITE));
		$this->assertTrue($zip->addFromString('probe.txt', "192.0.2.1\n"));
		$this->assertTrue($zip->close());
		exec(escapeshellarg(pfb_test_tar()) . ' -tf ' . escapeshellarg($probe) . ' >/dev/null 2>&1', $out, $rc);
		unlink($probe);
		if ($rc !== 0) {
			$this->markTestSkipped('the archive tool cannot read ZIP on this host; the appliance uses bsdtar');
		}
	}

	// ---- the loopback origin -------------------------------------------------

	/**
	 * One origin per test, its body and validators swapped per pass through a control
	 * file, so a multi-pass scenario keeps the same port (and the same connection reuse)
	 * the appliance sees. It records every request's conditional headers, which is how
	 * "the next pass asked unconditionally" is asserted rather than inferred.
	 */
	private function startOrigin(): void
	{
		$router = "{$this->dir}/router.php";
		$this->assertNotFalse(file_put_contents($router, <<<'ROUTER'
			<?php
			$uri = $_SERVER['REQUEST_URI'] ?? '';
			if ($uri === '/__pfb_ready' || str_starts_with($uri, '/__pfb_ready/')) {
				if ($uri === '/__pfb_ready') {
					echo getenv('READY_TOKEN');
				}
				return;
			}
			$dir = __DIR__;
			$ctl = json_decode((string) file_get_contents("{$dir}/control.json"), TRUE) ?: [];
			file_put_contents("{$dir}/requests.log", json_encode([
				'inm' => trim($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''),
				'ims' => trim($_SERVER['HTTP_IF_MODIFIED_SINCE'] ?? ''),
			]) . "\n", FILE_APPEND | LOCK_EX);
			$etag = (string) ($ctl['etag'] ?? '');
			$lastmod = (int) ($ctl['lastmod'] ?? 0);
			if ($etag !== '') {
				header("ETag: {$etag}");
			}
			if ($lastmod > 0) {
				header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $lastmod) . ' GMT');
			}
			$conditional = ($etag !== '' && trim($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $etag)
				|| ($lastmod > 0 && trim($_SERVER['HTTP_IF_MODIFIED_SINCE'] ?? '') !== '');
			if ($conditional) {
				http_response_code(304);
				return;
			}
			readfile("{$dir}/body.bin");
			ROUTER));
		$this->serveControl('', 0);
		$this->assertNotFalse(file_put_contents("{$this->dir}/body.bin", ''));

		$failures = [];
		for ($try = 0; $try < 20 && $this->port === 0; $try++) {
			$candidate = random_int(20000, 60000);
			$nonce = bin2hex(random_bytes(16));
			$stderr = "{$this->dir}/server-{$candidate}-{$try}.stderr";
			$proc = proc_open(
				['php', '-S', "127.0.0.1:{$candidate}", $router],
				[1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']],
				$pipes,
				$this->dir,
				['READY_TOKEN' => $nonce, 'PATH' => (string) getenv('PATH')]
			);
			if (!is_resource($proc)) {
				$failures[] = "port {$candidate}: process=proc_open failed stderr=(unavailable)";
				continue;
			}
			for ($poll = 0; $poll < 40; $poll++) {
				if (pfb_test_http_fixture_event_received($candidate, $nonce)) {
					$this->server = $proc;
					$this->port = $candidate;
					break;
				}
				usleep(50000);
			}
			if ($this->port === 0) {
				$status = proc_get_status($proc);
				if ($status['running']) {
					proc_terminate($proc);
				}
				$closeExit = proc_close($proc);
				$stderrText = trim((string) @file_get_contents($stderr));
				$failures[] = sprintf(
					'port %d: process[running=%s exit=%d close=%d] stderr=%s',
					$candidate,
					$status['running'] ? 'true' : 'false',
					$status['exitcode'],
					$closeExit,
					$stderrText === '' ? '(empty)' : $stderrText
				);
			}
		}
		$this->assertGreaterThan(
			0,
			$this->port,
			'loopback HTTP fixture unavailable; ' . implode(' | ', $failures)
		);
	}

	private function serveControl(string $etag, int $lastmod): void
	{
		$this->assertNotFalse(file_put_contents(
			"{$this->dir}/control.json",
			(string) json_encode(['etag' => $etag, 'lastmod' => $lastmod]),
			LOCK_EX
		));
	}

	/** Point the origin at $bodyPath and give it the validators it issues with that body. */
	private function serve(string $bodyPath, string $etag, int $lastmod): void
	{
		$this->assertTrue(copy($bodyPath, "{$this->dir}/body.bin"));
		$this->serveControl($etag, $lastmod);
		$this->truncateRequests();
	}

	private function truncateRequests(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->dir}/requests.log", ''));
	}

	/** @return array<int, array{inm: string, ims: string}> */
	private function requests(): array
	{
		$raw = (string) @file_get_contents("{$this->dir}/requests.log");
		$out = [];
		foreach (explode("\n", $raw) as $line) {
			if (trim($line) === '') {
				continue;
			}
			$decoded = json_decode($line, TRUE);
			$out[] = ['inm' => (string) ($decoded['inm'] ?? ''), 'ims' => (string) ($decoded['ims'] ?? '')];
		}
		return $out;
	}

	private function url(): string
	{
		return 'http://' . self::FEED_HOST . ":{$this->port}/feed";
	}

	private function detect(): ?PfbScheduleTerminalResult
	{
		return pfb_update_check(self::HEADER, $this->url(), $this->dir, $this->dir, FALSE, '', '');
	}

	private function ingest(): PfbDownloadResult
	{
		return pfb_download(new PfbDownloadRequest(
			listUrl: $this->url(),
			downloadPath: "{$this->dir}/" . self::HEADER,
			flex: FALSE,
			header: self::HEADER,
			format: '',
			logType: 1,
			timeout: 30,
			type: '',
		));
	}

	private function log(): string
	{
		return is_file($GLOBALS['pfb']['log']) ? (string) file_get_contents($GLOBALS['pfb']['log']) : '';
	}
}
