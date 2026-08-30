<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/DownloadRedirectCredentialScopeTest.php';
require_once __DIR__ . '/HttpFixtureReadinessTest.php';

/** Issue #2065: fixture diagnostics and readiness traffic stay distinct from credential hops. */
final class DownloadRedirectFixtureReadinessHygieneTest extends TestCase
{
	public function testForeignReadinessSecretDoesNotPolluteFixtureLogs(): void
	{
		$this->withFixture(function (DownloadRedirectCredentialScopeTest $suite, ReflectionClass $ref): void {
			$port = (int) $ref->getProperty('originPort')->getValue($suite);
			$workdir = (string) $ref->getProperty('workdir')->getValue($suite);
			$eventLog = "{$workdir}/events.log";
			$eventsBefore = @file($eventLog, FILE_IGNORE_NEW_LINES) ?: [];

			$this->assertFalse(
				pfb_test_http_fixture_event_received($port, bin2hex(random_bytes(16))),
				'a secret for another fixture must not satisfy this router readiness event'
			);
			$this->assertSame(
				$eventsBefore,
				@file($eventLog, FILE_IGNORE_NEW_LINES) ?: [],
				'a foreign readiness secret must not appear as a normal redirect event'
			);
			$this->assertSame(
				[],
				@file("{$workdir}/auth.log", FILE_IGNORE_NEW_LINES) ?: [],
				'a foreign readiness secret must not appear as a credential-bearing redirect hop'
			);
		});
	}

	public function testLegacyReadinessSubpathDoesNotReachCredentialEffects(): void
	{
		$this->withFixture(function (DownloadRedirectCredentialScopeTest $suite, ReflectionClass $ref): void {
			$port = (int) $ref->getProperty('originPort')->getValue($suite);
			$workdir = (string) $ref->getProperty('workdir')->getValue($suite);
			$eventLog = "{$workdir}/events.log";
			$eventsBefore = @file($eventLog, FILE_IGNORE_NEW_LINES) ?: [];
			$context = stream_context_create(['http' => ['timeout' => 0.05, 'ignore_errors' => TRUE]]);
			$body = @file_get_contents(
				"http://127.0.0.1:{$port}/__pfb_ready/legacy-probe",
				FALSE,
				$context
			);

			$this->assertSame('', $body, 'legacy readiness subpaths must be reserved without a response');
			$this->assertSame(
				$eventsBefore,
				@file($eventLog, FILE_IGNORE_NEW_LINES) ?: [],
				'legacy readiness subpaths must not appear as normal redirect events'
			);
			$this->assertSame(
				[],
				@file("{$workdir}/auth.log", FILE_IGNORE_NEW_LINES) ?: [],
				'legacy readiness subpaths must not reach credential-bearing router effects'
			);
		});
	}

	public function testNormalRequestStillReachesEventLog(): void
	{
		$this->withFixture(function (DownloadRedirectCredentialScopeTest $suite, ReflectionClass $ref): void {
			$port = (int) $ref->getProperty('originPort')->getValue($suite);
			$workdir = (string) $ref->getProperty('workdir')->getValue($suite);
			$eventLog = "{$workdir}/events.log";
			$eventsBefore = @file($eventLog, FILE_IGNORE_NEW_LINES) ?: [];
			$context = stream_context_create(['http' => ['timeout' => 0.05, 'ignore_errors' => TRUE]]);

			$this->assertSame(
				'BODY',
				@file_get_contents("http://127.0.0.1:{$port}/final", FALSE, $context)
			);
			$eventsAfter = @file($eventLog, FILE_IGNORE_NEW_LINES) ?: [];
			$this->assertCount(count($eventsBefore) + 1, $eventsAfter);
			$event = json_decode((string) end($eventsAfter), TRUE);
			$this->assertIsArray($event);
			$this->assertSame('/final', $event[1] ?? NULL);
		});
	}

	public function testFailureDiagnosticsNameResponseHopsPortsAndProcesses(): void
	{
		$this->withFixture(function (DownloadRedirectCredentialScopeTest $suite, ReflectionClass $ref): void {
			$message = $ref->getMethod('redirectFailureMessage')->invoke(
				$suite,
				PfbDownloadResult::failure(['status' => '599'])
			);
			$origin = $ref->getProperty('originPort')->getValue($suite);
			$target = $ref->getProperty('targetPort')->getValue($suite);
			$alt = $ref->getProperty('altPort')->getValue($suite);

			$this->assertStringContainsString('response status=599', $message);
			$this->assertStringContainsString('events=', $message);
			$this->assertStringNotContainsString('__pfb_ready', $message);
			$this->assertStringContainsString(
				"ports=origin:{$origin} target:{$target} alt:{$alt}",
				$message
			);
			$this->assertStringContainsString('processes=port ', $message);
			$this->assertStringContainsString('pfBlockerNG log=', $message);
		});
	}

	public function testReadinessTearDownGuardsWorkdirBeforeGlob(): void
	{
		$root = tempnam(sys_get_temp_dir(), 'pfbreadyguard');
		$this->assertNotFalse($root);
		$this->assertTrue(unlink($root) && mkdir($root, 0700) && mkdir("{$root}/match", 0700));
		$sentinel = "{$root}/match/sentinel";
		$this->assertNotFalse(file_put_contents($sentinel, 'keep'));

		$suite = new HttpFixtureReadinessTest('testProbeRejectsReflectiveForeignListener');
		$ref = new ReflectionClass($suite);
		$ref->getProperty('workdir')->setValue($suite, "{$root}/*");

		try {
			$ref->getMethod('tearDown')->invoke($suite);
			$this->assertFileExists(
				$sentinel,
				'tearDown must validate workdir before expanding its cleanup glob'
			);
		} finally {
			@unlink($sentinel);
			@rmdir("{$root}/match");
			@rmdir($root);
		}
	}

	private function withFixture(callable $test): void
	{
		$savedGlobals = [];
		foreach (['config', 'pfb_test_resolve_map', 'pfb_test_configured_ips'] as $name) {
			$savedGlobals[$name] = [
				'had' => array_key_exists($name, $GLOBALS),
				'value' => $GLOBALS[$name] ?? NULL,
			];
		}

		$suite = new DownloadRedirectCredentialScopeTest('testCrossHostRedirectKeepsNonCredentialExtraHeaders');
		$ref   = new ReflectionClass($suite);
		$setUp = $ref->getMethod('setUp');
		$tear  = $ref->getMethod('tearDown');

		try {
			$setUp->invoke($suite);
			$test($suite, $ref);
		} finally {
			$tear->invoke($suite);
			foreach ($savedGlobals as $name => $saved) {
				if ($saved['had']) {
					$GLOBALS[$name] = $saved['value'];
				} else {
					unset($GLOBALS[$name]);
				}
			}
		}
	}
}
