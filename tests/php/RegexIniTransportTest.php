<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #1718: regex textarea stays opaque base64 through the PHP INI writer. */
final class RegexIniTransportTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private function functionBody(string $name): string
	{
		$source = file_get_contents(self::SRC);
		$this->assertNotFalse($source, 'failed to read pfblockerng.inc');
		$start = strpos($source, "\nfunction {$name}(");
		$this->assertNotFalse($start, "function {$name}() not found");
		$start++;
		$open = strpos($source, '{', $start);
		$this->assertNotFalse($open, "opening brace missing for {$name}()");
		$depth = 0;
		for ($i = $open, $len = strlen($source); $i < $len; $i++) {
			if ($source[$i] === '{') {
				$depth++;
			} elseif ($source[$i] === '}') {
				$depth--;
				if ($depth === 0) {
					return substr($source, $start, $i - $start + 1);
				}
			}
		}
		$this->fail("closing brace missing for {$name}()");
	}

	public function testWriterEmitsStoredRegexBlobUnderMainWithoutDecode(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertMatchesRegularExpression(
			'/regex_list\s*=\s*\{\$pfb\[\'dnsbl_regex_list\'\]\}/',
			$body,
			'PHP must emit the stored base64 blob as MAIN.regex_list'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/pfb_text_area_decode\(\$pfb\[\'dnsbl_regex_list\'\]/',
			$body,
			'PHP must not decode or re-encode the regex blob'
		);
	}

	public function testWriterDoesNotGenerateLegacyRegexSection(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertDoesNotMatchRegularExpression(
			'/\[REGEX\]/',
			$body,
			'new writer must not emit plaintext legacy REGEX entries'
		);
	}
}
