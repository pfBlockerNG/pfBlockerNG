<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/OctetStreamRecoveryWiringTest.php';
require_once __DIR__ . '/PfbFileMimeNormaliseWiringTest.php';
require_once __DIR__ . '/PfbFileMimeSinkEscapeTest.php';
require_once __DIR__ . '/PfbMimeAllowlistTest.php';

/** Issue #2906: MIME fixture producers must restore the bootstrap allow-list. */
final class PfbMimeTypesProducerHygieneTest extends TestCase
{
	public static function producer(): array
	{
		return [
			'OctetStreamRecoveryWiringTest' => [
				OctetStreamRecoveryWiringTest::class,
				'test_octet_stream_archive_recovered_to_zip',
			],
			'PfbFileMimeNormaliseWiringTest' => [
				PfbFileMimeNormaliseWiringTest::class,
				'test_epub_zip_passes_via_normalise_wiring',
			],
			'PfbFileMimeSinkEscapeTest' => [
				PfbFileMimeSinkEscapeTest::class,
				'testBenignPathProbesMimeUnchanged',
			],
			'PfbMimeAllowlistTest' => [
				PfbMimeAllowlistTest::class,
				'test_pfb_mime_allowlist_accepts_canonical_zip',
			],
		];
	}

	#[DataProvider('producer')]
	public function testProducerLifecycleRestoresBootstrapMimeTypes(string $class, string $method): void
	{
		$hadMimeTypes = array_key_exists('mime_types', $GLOBALS['pfb']);
		$previous = $GLOBALS['pfb']['mime_types'] ?? null;
		$bootstrap = ['application/x-pfb-bootstrap-sentinel' => 2906];
		$GLOBALS['pfb']['mime_types'] = $bootstrap;

		try {
			$suite = new $class($method);
			$ref = new ReflectionClass($suite);
			$setUp = $ref->getMethod('setUp');
			$tearDown = $ref->getMethod('tearDown');
			$setUpComplete = false;

			try {
				$setUp->invoke($suite);
				$setUpComplete = true;
			} finally {
				if ($setUpComplete) {
					$tearDown->invoke($suite);
				}
			}

			$this->assertArrayHasKey(
				'mime_types',
				$GLOBALS['pfb'],
				"{$class} teardown must not remove the bootstrap MIME allow-list"
			);
			$this->assertSame(
				$bootstrap,
				$GLOBALS['pfb']['mime_types'],
				"{$class} teardown must restore the exact bootstrap MIME allow-list"
			);
		} finally {
			if ($hadMimeTypes) {
				$GLOBALS['pfb']['mime_types'] = $previous;
			} else {
				unset($GLOBALS['pfb']['mime_types']);
			}
		}
	}
}
