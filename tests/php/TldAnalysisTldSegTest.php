<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1168 — tld_analysis() computed a per-TLD running max of label
 * segments into a function-LOCAL $tld_segments, then discarded it: nothing
 * reads the value, it feeds no output file, log line, or global (the
 * blacklist branch's real outputs — the synthetic DNSBL_TLD row, $tld_cnt,
 * $tlds pruning — are byte-pinned by DnsblNdjsonFlipTest). Dead-code
 * sibling of issue #1155; this pins that the computation is gone.
 */
#[CoversFunction('tld_analysis')]
final class TldAnalysisTldSegTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	/**
	 * Brace-counts from `function {$name}(` to its matching closing brace,
	 * so the assertion below inspects ONLY tld_analysis()'s body — never a
	 * neighbour's same-named local.
	 */
	private function functionBody(string $name): string
	{
		$source = file_get_contents(self::SRC);
		$this->assertNotFalse($source, 'failed to read pfblockerng.inc');

		$needle = "\nfunction {$name}(";
		$start = strpos($source, $needle);
		$this->assertNotFalse($start, "function {$name}() not found in source");
		$start++; // step past the leading \n onto 'function'

		$braceOpen = strpos($source, '{', $start);
		$this->assertNotFalse($braceOpen, "no opening brace found for {$name}()");

		$depth = 0;
		for ($i = $braceOpen, $len = strlen($source); $i < $len; $i++) {
			if ($source[$i] === '{') {
				$depth++;
			} elseif ($source[$i] === '}') {
				$depth--;
				if ($depth === 0) {
					$body = substr($source, $start, $i - $start + 1);
					$this->assertNotSame('', trim($body), "empty body extracted for {$name}() -- vacuous extraction");
					return $body;
				}
			}
		}
		$this->fail("no matching closing brace found for {$name}()");
	}

	public function testTldAnalysisHasNoTldSegmentsToken(): void
	{
		$body = $this->functionBody('tld_analysis');
		$this->assertStringNotContainsString('tld_segments', $body,
			'issue #1168: the write-only $tld_segments max must be deleted, not just unused');
	}
}
