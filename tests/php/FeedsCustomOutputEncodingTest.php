<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Render pins for legacy custom-feed text containing invalid UTF-8 (#1819).
 * The page cannot be required off-appliance, so this extracts its custom-row
 * template and evaluates it with the same page-scope inputs.
 */
final class FeedsCustomOutputEncodingTest extends TestCase
{
	private function renderCustomRow(string $url, string $header): string
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.php'
		);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_feeds.php');
		}

		$table = strpos($src, "\n\t\t\t<tbody>\n");
		$start = strpos($src, "\t\t\t\t\$p_type = '';", $table === false ? 0 : $table);
		$end   = strpos($src, "\n\t\t\t<tbody>\n\t\t\t</table>", $start === false ? 0 : $start);
		if ($start === false || $end === false || $end <= $start) {
			throw new RuntimeException('could not locate the custom-feed row template');
		}
		$this->assertStringNotContainsString('issue #1496', substr($src, $start, $end - $start));

		$ex_feeds = ['ipv4' => [[
			'aliasname' => 'InvalidUtf8Feed',
			'url'       => $url,
			'header'    => $header,
			'rowid'     => 17,
		]]];
		$gtype      = 'ipv4';
		$type_label = ['ipv4' => 'IPv4'];

		ob_start();
		eval('?>' . "<?php\n" . substr($src, $start, $end - $start));
		return (string) ob_get_clean();
	}

	public function testInvalidUtf8ByteInUrlRendersSubstitutedNotBlanked(): void
	{
		$html     = $this->renderCustomRow("https://before\xFFafter.invalid-url.example/list.txt", 'SafeHeader');
		$expected = "https://before\u{FFFD}after.invalid-url.example/list.txt";

		$this->assertStringContainsString($expected, $html, 'the custom-feed URL must survive with only its invalid byte substituted');
		$this->assertStringNotContainsString("\xFF", $html, 'the rendered row must not retain the invalid byte');
		$this->assertTrue(mb_check_encoding($html, 'UTF-8'), 'the rendered row must be valid UTF-8');
	}

	public function testInvalidUtf8ByteInHeaderRendersSubstitutedNotBlanked(): void
	{
		$html     = $this->renderCustomRow('https://safe.invalid-header.example/list.txt', "before\xFFafter-header");
		$expected = "before\u{FFFD}after-header";

		$this->assertStringContainsString($expected, $html, 'the custom-feed header must survive with only its invalid byte substituted');
		$this->assertStringNotContainsString("\xFF", $html, 'the rendered row must not retain the invalid byte');
		$this->assertTrue(mb_check_encoding($html, 'UTF-8'), 'the rendered row must be valid UTF-8');
	}
}
