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

		$this->assertStringContainsString('$written = file_put_contents(', $spawnResponder);
		$this->assertStringContainsString('if ($written !== strlen($reply))', $spawnResponder);
		$this->assertStringContainsString("throw new RuntimeException('query responder reply write failed');", $spawnResponder);
		$this->assertStringContainsString('$this->forkChild(', $spawnResponder, 'the responder must be a tracked child');
		foreach (['exec(', 'proc_open(', 'shell_exec(', 'system(', 'passthru('] as $sink) {
			$this->assertStringNotContainsString($sink, $spawnResponder, "responder must not invoke process sink {$sink}");
		}

		$this->assertStringContainsString(
			'salvage cap expired / stuck or environment',
			$spawnResponder,
			'query-channel request-marker salvage expiry must be distinguishable from a behavioural failure'
		);
		$this->assertStringContainsString('query-channel request marker', $spawnResponder);
		$this->assertStringContainsString("\tprivate const SALVAGE_CAP_S = 30.0;", $source);
		$this->assertStringContainsString('self::SALVAGE_CAP_S', $spawnResponder, 'the responder poll must use the salvage cap');

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
			$reap = strpos($callerSource, '$this->reapResponders();');
			$assert = strpos($callerSource, '$this->assert');
			$this->assertNotFalse($reap, "{$caller}() must reap its responder");
			$this->assertNotFalse($assert, "{$caller}() must retain product assertions");
			$this->assertLessThan($assert, $reap, "{$caller}() must reap before product assertions");
		}
	}
}
