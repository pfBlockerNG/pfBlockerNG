<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Source pin: the query responder's salvage expiry must be loud and parent-observed. */
final class DnsblLogEventQueryAttributionSalvageDiagnosticTest extends TestCase
{
	public function testResponderExpiryIsTypedTrackedAndNotDetached(): void
	{
		$source = file_get_contents(__DIR__ . '/DnsblLogEventQueryAttributionTest.php');
		$this->assertNotFalse($source, 'DnsblLogEventQueryAttributionTest.php must be readable');

		$signature = "\tprivate function spawnResponder(string \$replyTemplateJson): void";
		$start = strpos($source, $signature);
		$this->assertNotFalse($start, 'spawnResponder() must exist');
		$end = strpos($source, "\n\tprivate function ", $start + strlen($signature));
		$this->assertNotFalse($end, 'spawnResponder() must have a following private method boundary');
		$spawnResponder = substr($source, $start, $end - $start);

		$this->assertSame(
			1,
			preg_match('/^[ \t]*\$this->forkChild\(function \(\) use \(\$replyTemplateJson\): void \{$/m', $spawnResponder),
			'the responder must fork on an executable line'
		);
		$this->assertSame(
			1,
			preg_match('/^[ \t]*\$deadline = microtime\(true\) \+ self::SALVAGE_CAP_S;[ \t]*$/m', $spawnResponder),
			'the responder deadline must use the salvage cap on an executable line'
		);
		$this->assertSame(
			1,
			preg_match('/^[ \t]*\$written = file_put_contents\([^;]+, \$reply\);[ \t]*$/m', $spawnResponder),
			'the reply write count must be captured on an executable line'
		);
		$this->assertSame(
			1,
			preg_match('/^[ \t]*if \(\$written !== strlen\(\$reply\)\) \{$/m', $spawnResponder),
			'the reply write count must be checked on an executable line'
		);
		$this->assertSame(
			1,
			preg_match('/^[ \t]*throw new RuntimeException\(\'query responder reply write failed\'\);[ \t]*$/m', $spawnResponder),
			'the reply-write failure must throw on an executable line'
		);
		$this->assertStringNotContainsString('> /dev/null 2>&1 &', $spawnResponder, 'the responder must not use the old detached shell');
		foreach (['exec(', 'proc_open(', 'shell_exec(', 'system(', 'passthru('] as $sink) {
			$this->assertStringNotContainsString($sink, $spawnResponder, "responder must not invoke process sink {$sink}");
		}

		$this->assertSame(
			1,
			preg_match(
				'/^[ \t]*throw new RuntimeException\((?:"|\')[^"\']*salvage cap expired \/ stuck or environment[^"\']*query-channel request marker[^"\']*(?:"|\')\);[ \t]*$/m',
				$spawnResponder
			),
			'query-channel request-marker salvage expiry must be typed on an executable line'
		);
		$this->assertSame(1, preg_match('/^[ \t]*private const SALVAGE_CAP_S = 30\.0;[ \t]*$/m', $source));

		foreach ([
			'testBlockedVerdictAttributesLiveGroupAndBumpsLiveCounter',
			'testCleanVerdictAttributesUnknownNoCounterMove',
			'testBlockedEmptyAttributionFallsBackToUnknownPerField',
			'testHostileGroupIsHtmlEncodedNeverRaw',
		] as $caller) {
			$callerStart = strpos($source, "\tpublic function {$caller}(): void");
			$this->assertNotFalse($callerStart, "{$caller}() must exist");
			$callerEnd = strpos($source, "\n\tpublic function ", $callerStart + 1);
			$callerEnd = $callerEnd === false ? strlen($source) : $callerEnd;
			$callerSource = substr($source, $callerStart, $callerEnd - $callerStart);
			$reapMatch = [];
			$assertMatch = [];
			$this->assertSame(
				1,
				preg_match('/^[ \t]*\$this->reapResponders\(\);[ \t]*$/m', $callerSource, $reapMatch, PREG_OFFSET_CAPTURE),
				"{$caller}() must reap its responder on an executable line"
			);
			$this->assertSame(
				1,
				preg_match('/^[ \t]*\$this->assert[A-Za-z]+\(/m', $callerSource, $assertMatch, PREG_OFFSET_CAPTURE),
				"{$caller}() must retain product assertions on executable lines"
			);
			$this->assertLessThan($assertMatch[0][1], $reapMatch[0][1], "{$caller}() must reap before product assertions");
		}
	}
}
