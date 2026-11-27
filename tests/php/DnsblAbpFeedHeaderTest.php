<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4272: a DNSBL feed whose first non-blank line is an Adblock-family header is parsed as
 * Adblock. Its lines take the ABP path, are kept as a hostname, hosts line or hostname mask, or are
 * dropped, so a path rule such as EasyPrivacy's '.imgur.com/lumbar.gif' never blocks the whole domain.
 */
final class DnsblAbpFeedHeaderTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_abp_header_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function feed(string $content): string
	{
		$path = $this->dir . '/feed.norm';
		file_put_contents($path, $content);
		return $path;
	}

	/** @return array<string, array{string}> */
	public static function adblockFeedProvider(): array
	{
		return [
			'EasyList'                 => ["[Adblock Plus 2.0]\n! Title: EasyList\n||ads.example^\n"],
			'EasyPrivacy'              => ["[Adblock Plus 1.1]\n.imgur.com/lumbar.gif\n"],
			'bare Adblock'             => ["[Adblock]\nexample.com\n"],
			'one word'                 => ["[AdblockPlus 2.0]\n"],
			'uBlock'                   => ["[uBlock Origin]\n"],
			'AdGuard'                  => ["[AdGuard]\n"],
			'other case'               => ["[ADBLOCK PLUS 2.0]\n"],
			'UTF-8 BOM'                => ["\xEF\xBB\xBF[Adblock Plus 2.0]\n"],
			'CRLF'                     => ["[Adblock Plus 2.0]\r\n! x\r\n"],
			'blank lines before'       => ["\n\n[Adblock Plus 2.0]\n"],
			'indented'                 => ["  [Adblock Plus 2.0]\t\n"],
		];
	}

	#[DataProvider('adblockFeedProvider')]
	public function testAnAdblockHeaderOnTheFirstLineMarksTheFeedAsAdblock(string $content): void
	{
		$this->assertTrue(pfb_dnsbl_feed_has_abp_header($this->feed($content)));
	}

	/** @return array<string, array{string}> */
	public static function otherFeedProvider(): array
	{
		return [
			'hosts feed'               => ["# Title: hosts\n0.0.0.0 example.com\n"],
			'plain domains'            => ["example.com\n[Adblock Plus 2.0]\n"],
			'ABP comment first'        => ["! Title: list\n[Adblock Plus 2.0]\n"],
			'ABP rules, no header'     => ["||ads.example^\n"],
			'unclosed header'          => ["[Adblock Plus 2.0\n"],
			'bracketed IP'             => ["[1.2.3.4]\n"],
			'other bracket word'       => ["[Adblocker list]x\n"],
			'empty feed'               => [''],
		];
	}

	#[DataProvider('otherFeedProvider')]
	public function testAFeedWithoutAnAdblockHeaderKeepsPerLineRouting(string $content): void
	{
		$this->assertFalse(pfb_dnsbl_feed_has_abp_header($this->feed($content)));
	}

	public function testAMissingFeedFileIsNotAdblock(): void
	{
		$this->assertFalse(pfb_dnsbl_feed_has_abp_header($this->dir . '/absent.norm'));
	}

	/**
	 * The DNSBL download loop has no off-appliance driver, so this pins its wiring: the feed's
	 * header is read once before the line loop, and an Adblock feed's lines stop right after the
	 * ABP capture, before CSV extraction and host extraction can see them.
	 */
	public function testTheParseLoopStopsAnAdblockFeedsLinesAfterTheAbpCapture(): void
	{
		$code = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertIsString($code);

		// issue #4272 owner decision: a header or, failing it, any Adblock rule makes the feed Adblock.
		// A custom list is the user's own: only an explicit Adblock header makes it an Adblock feed.
		$detect  = strpos($code, '$abp_feed = $custom ? pfb_dnsbl_feed_has_abp_header($pfb_parse_path) : pfb_dnsbl_feed_is_abp($pfb_parse_path);');
		$loop    = strpos($code, 'while (($line = @fgets($fhandle)) !== FALSE)', (int) $detect);
		$capture = strpos($code, 'if (pfb_dnsbl_is_abp_rule_line($line)) {', (int) $loop);
		// issue #4272 owner decision: only a hostname, a hosts line or a hostname mask of an Adblock feed goes on.
		$stop    = strpos($code, 'if ($abp_feed) { $abp_kept = pfb_dnsbl_abp_feed_line($line); if ($abp_kept === NULL) { continue; }', (int) $capture);
		$csv     = strpos($code, 'pfb_dnsbl_csv_extract(', (int) $capture);
		$host    = strpos($code, 'pfb_dnsbl_extract_host(', (int) $capture);

		$this->assertIsInt($detect, 'the feed header must be read before the line loop');
		$this->assertIsInt($loop, 'the line loop must follow the header read');
		$this->assertIsInt($capture, 'the ABP capture must be inside the line loop');
		$this->assertIsInt($stop, 'an Adblock feed must stop its lines after the ABP capture');
		$this->assertLessThan((int) $csv, (int) $stop, 'the stop must come before CSV extraction');
		$this->assertLessThan((int) $host, (int) $stop, 'the stop must come before host extraction');
	}
}
