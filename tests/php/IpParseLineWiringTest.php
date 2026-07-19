<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The feed loop must delegate each raw line to the pure parser seam.  This
 * source pin keeps the extraction honest: the old family/parser branches must
 * not remain inline where they can silently diverge from the helper.
 */
final class IpParseLineWiringTest extends TestCase
{
	private static string $source;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
		self::$source = (string) file_get_contents($path);
	}

	public function testSyncLoopDelegatesRawLineToPureParser(): void
	{
		$ipPass = strpos(self::$source, '$ip_lineno = 0');
		$this->assertNotFalse($ipPass, 'IP feed parser setup not found');
		$loopStart = strpos(self::$source, 'while (($line = @fgets($fhandle)) !== FALSE)', (int) $ipPass);
		$this->assertNotFalse($loopStart, 'sync feed loop not found');
		$loopEnd = strpos(self::$source, 'if ($fhandle)', (int) $loopStart);
		$this->assertNotFalse($loopEnd, 'sync feed loop end not found');
		$loop = substr(self::$source, (int) $loopStart, (int) $loopEnd - (int) $loopStart);

		$this->assertStringContainsString('pfb_ip_parse_line(', $loop);
		$this->assertStringContainsString('$raw_line', $loop);
		$this->assertStringNotContainsString("if (\$list['vtype'] == '_v4'", $loop);
		$this->assertStringNotContainsString("if (\$list['vtype'] == '_v6'", $loop);
		$this->assertStringNotContainsString('preg_match_all($pfb[\'ipv4\']', $loop);
		$this->assertStringNotContainsString('preg_match_all($pfb[\'ipv6\']', $loop);

		$replayContract = [
			'normalized line'       => '$line = $parsed_line[\'line\'];',
			'ordered messages'      => 'foreach ($parsed_line[\'messages\'] as $message)',
			'message logging'       => 'pfb_logger($message, 1);',
			'ordered entries'       => 'foreach ($parsed_line[\'entries\'] as $entry)',
			'newline-delimited data' => '$ip_data .= $entry . "\\n";',
			'suppression state'     => '$ip_suppressed = $ip_suppressed || $parsed_line[\'suppressed\'];',
			'parse-failure count'   => '$parse_fail += $parsed_line[\'parse_fail_delta\'];',
			'detailed-failure gate' => 'if ($parsed_line[\'detailed_parse_fail\'])',
			'detailed-failure data' => 'pfb_parse_fail_log($header, $line, $raw_line, $pfb[\'ip_parse_err\'], $ip_lineno, TRUE);',
		];
		foreach ($replayContract as $effect => $needle) {
			$this->assertStringContainsString($needle, $loop, "missing parser replay effect: {$effect}");
		}
		$this->assertStringContainsString('$ip_lineno++;', $loop);
		$this->assertStringContainsString('pfb_ip_parse_fail_warn($parse_fail, $header);', self::$source);
		$this->assertStringContainsString(
			"if (empty(\$ip_data) && \$ip_suppressed && \$list['vtype'] == '_v6')",
			self::$source
		);
	}
}
