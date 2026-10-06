<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Fresh Sync-page render must not warn when the sync section has never been
 * saved (issue #3447). Absent keys keep the page defaults: mode '', timeout
 * 150, and the empty replication-target placeholder. A stored 0 or '' timeout
 * still becomes 150; a stored non-empty mode and a stored row pass through.
 *
 * The page cannot be require()d off-appliance, so the GET render assignments
 * are eval-extracted from the real source. Anchors match the bare reads and
 * the later `??` guards.
 */
final class SyncPageAbsentSectionRenderTest extends TestCase
{
	/** Hand-checked empty-row placeholder from the GET render block. */
	private const EMPTY_ROW_PLACEHOLDER = [[
		'varsyncdestinenable' => '',
		'varsyncprotocol' => 'https',
		'varsyncipaddress' => '',
		'varsyncport' => '443',
		'varsyncusername' => 'admin',
		'varsyncpassword' => '',
	]];

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_sync.php'
		);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_sync.php');
		}
		if (function_exists('pfb_sync_page_fresh_section_reads')) {
			return;
		}

		if (!preg_match(
			'/^(\$pconfig\[\'varsynconchanges\'\]\s*=\s*[^\n]*;\n'
			. '\$pconfig\[\'varsynctimeout\'\]\s*=\s*[^\n]*;)/m',
			$src,
			$assigns
		)) {
			throw new RuntimeException('test bootstrap: sync-page mode/timeout assignments not found');
		}
		if (!preg_match(
			'/^(\$rowdata = \$pfb\[\'sconfig\'\]\[\'row\'\][^\n]*;\n'
			. '\n'
			. '\/\/ Add empty row placeholder if no rows defined\n'
			. 'if \(empty\(\$rowdata\)\) \{\n'
			. '(?:.*\n)*?'
			. '\})/m',
			$src,
			$row
		)) {
			throw new RuntimeException('test bootstrap: sync-page row placeholder block not found');
		}

		$snippet = $assigns[1] . "\n" . $row[1];
		foreach (['varsynconchanges', 'varsynctimeout', "['row']"] as $needle) {
			if (!str_contains($snippet, $needle)) {
				throw new RuntimeException("test bootstrap: extract missing {$needle}");
			}
		}
		if (str_contains($snippet, 'syncinterfaces') || str_contains($snippet, '$_POST')) {
			throw new RuntimeException('test bootstrap: extract left the GET render reads');
		}

		eval(
			'function pfb_sync_page_fresh_section_reads(array $sconfig): array {'
			. ' $pfb = ["sconfig" => $sconfig];'
			. ' $pconfig = [];'
			. "\n" . $snippet . "\n"
			. ' return ['
			. ' "varsynconchanges" => $pconfig["varsynconchanges"],'
			. ' "varsynctimeout" => $pconfig["varsynctimeout"],'
			. ' "rowdata" => $rowdata,'
			. ' ]; }'
		);
	}

	/**
	 * @param array<string, mixed> $sconfig
	 * @return array{varsynconchanges: mixed, varsynctimeout: mixed, rowdata: mixed}
	 */
	private function render(array $sconfig): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$result = pfb_sync_page_fresh_section_reads($sconfig);
		} finally {
			restore_error_handler();
		}

		$undefined = array_values(array_filter(
			$diagnostics,
			static fn (string $errstr): bool => str_contains($errstr, 'Undefined array key')
		));
		$this->assertSame(
			[],
			$undefined,
			"Sync-page render must not emit Undefined array key diagnostics:\n" . implode("\n", $undefined)
		);
		$this->assertSame(
			[],
			$diagnostics,
			"Sync-page render must emit zero diagnostics, got:\n" . implode("\n", $diagnostics)
		);

		return $result;
	}

	public function testAbsentSectionRendersDefaultsWithoutUndefinedKeys(): void
	{
		$rendered = $this->render([]);

		$this->assertSame('', $rendered['varsynconchanges']);
		$this->assertSame(150, $rendered['varsynctimeout']);
		$this->assertSame(self::EMPTY_ROW_PLACEHOLDER, $rendered['rowdata']);
	}

	public function testStoredZeroAndEmptyTimeoutStillBecome150(): void
	{
		$present = [
			'varsynconchanges' => 'disabled',
			'row' => self::EMPTY_ROW_PLACEHOLDER,
		];

		$this->assertSame(150, $this->render($present + ['varsynctimeout' => 0])['varsynctimeout']);
		$this->assertSame(150, $this->render($present + ['varsynctimeout' => ''])['varsynctimeout']);
		$this->assertSame(200, $this->render($present + ['varsynctimeout' => 200])['varsynctimeout']);
	}

	public function testStoredNonEmptyModeAndRowPassThrough(): void
	{
		$stored_row = [[
			'varsyncdestinenable' => 'on',
			'varsyncprotocol' => 'http',
			'varsyncipaddress' => '10.1.2.3',
			'varsyncport' => '8443',
			'varsyncusername' => 'syncer',
			'varsyncpassword' => 'secret',
		]];

		$rendered = $this->render([
			'varsynconchanges' => 'manual',
			'varsynctimeout' => 150,
			'row' => $stored_row,
		]);
		$this->assertSame('manual', $rendered['varsynconchanges']);
		$this->assertSame($stored_row, $rendered['rowdata']);

		$empty_mode = $this->render([
			'varsynconchanges' => '',
			'varsynctimeout' => 150,
			'row' => $stored_row,
		]);
		$this->assertSame('', $empty_mode['varsynconchanges']);
	}
}
