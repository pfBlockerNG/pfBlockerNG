<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Support logo must not overflow a narrow viewport, must not clip the shield,
 * and must keep a light color-scheme so force-dark cannot wash the fills.
 * Both shipped copies are held to this one contract (issue #2863).
 */
final class SupportLogoUiTest extends TestCase
{
	/** @return array<string, array{0: string}> */
	public static function logoPages(): array
	{
		return [
			'general page' => ['src/usr/local/www/pfblockerng/pfblockerng_general.php'],
			'setup wizard' => ['src/usr/local/www/wizards/pfblockerng_wizard.xml'],
		];
	}

	#[DataProvider('logoPages')]
	public function testSupportLogoUsesAFluidColumnAndAShieldViewBox(string $page): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/' . $page);
		$this->assertNotFalse($source, "{$page} must be readable");

		$this->assertStringContainsString('class="row"', $source,
			"{$page}: col-sm-* needs a row parent, or it carries Bootstrap's negative gutters uncancelled");
		$this->assertStringContainsString('class="col-sm-9"', $source, "{$page}: fluid text column");
		$this->assertStringContainsString('class="col-sm-3"', $source, "{$page}: fluid logo column");
		$this->assertStringContainsString('viewBox="0 0 256 256"', $source,
			"{$page}: the viewBox must frame the shield (the full square artwork, nothing cropped)");
		$this->assertStringContainsString('color-scheme: only light', $source, "{$page}: force-dark guard");
		$this->assertStringContainsString('max-width:140pt', $source, "{$page}: bounded intrinsic width");
		$this->assertStringContainsString('margin-left:auto;margin-right:auto', $source, "{$page}: centred");

		// The Support block drifts as a whole, not just its logo: the reorganisation that
		// centred the logo also reworded these two links, and only one copy was updated.
		foreach (['Follow on X formerly Twitter', 'Contact Us'] as $label) {
			$this->assertStringContainsString($label, $source, "{$page}: Support link copy drifted: {$label}");
		}

		foreach ([
			'enable-background',
			'width="180.0pt"',
			'height="180.0pt"',
			'width: 75%; height: 180px; float: left;',
			'width: 25%; height: 170px; float: right;',
			'width: 75%; height: 170px; float: left;',
			'viewBox="120 225 560 470"',
			'viewBox="128 172 384 384"',
			'max-width:180pt',
		] as $retired) {
			$this->assertStringNotContainsString($retired, $source,
				"{$page}: retired construction is back: {$retired}");
		}
	}

	/** Each inline copy draws the approved shield asset, not a lookalike or the old circle. */
	#[DataProvider('logoPages')]
	public function testSupportLogoDrawsTheApprovedShieldAsset(string $page): void
	{
		$root = dirname(__DIR__, 2);
		$source = file_get_contents($root . '/' . $page);
		$asset = file_get_contents($root . '/docs/assets/logo.svg');
		$this->assertNotFalse($source, "{$page} must be readable");
		$this->assertNotFalse($asset, 'docs/assets/logo.svg must be readable');

		$this->assertSame(5, preg_match_all('/<path fill="[^"]*" d="[^"]*"/', $asset, $paths),
			'the approved shield asset changed shape; re-sync both inline copies');
		foreach ($paths[0] as $path) {
			$this->assertStringContainsString($path, $source, "{$page}: shield path drifted from the asset: {$path}");
		}
		$this->assertStringContainsString('<rect width="256" height="256" rx="46" fill="#2b2b2b"/>', $source,
			"{$page}: shield background tile");
		$this->assertStringContainsString('aria-label="pfBlockerNG"', $source, "{$page}: logo accessible name");

		foreach (['<circle', 'XMLID_', '.st0{'] as $retired) {
			$this->assertStringNotContainsString($retired, $source, "{$page}: old circle logo is back: {$retired}");
		}
	}

	/** Every SVG viewBox under src/, not just the two known logo copies. */
	public function testEverySvgViewBoxInTheTreeIsTheContractValue(): void
	{
		$root = dirname(__DIR__, 2) . '/src';
		$found = [];
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
		foreach ($files as $file) {
			if (!$file->isFile() || str_contains($file->getPathname(), '/vendor/')) {
				continue;
			}
			$body = file_get_contents($file->getPathname());
			if ($body === FALSE) {
				continue;
			}
			foreach (['/viewBox="([^"]*)"/'] as $pattern) {
				if (preg_match_all($pattern, $body, $matches) > 0) {
					foreach ($matches[1] as $box) {
						$found[] = substr($file->getPathname(), strlen($root) + 1) . ': ' . $box;
					}
				}
			}
		}
		sort($found);
		$offenders = array_values(array_filter($found,
			static fn (string $hit): bool => !str_ends_with($hit, ': 0 0 256 256')));

		$this->assertNotSame([], $found, 'the scan found no viewBox at all -- it is not looking where it should');
		$this->assertSame([], $offenders,
			'every shipped SVG viewBox must be the contract value that frames the shield; found: '
			. implode(' | ', $offenders));
	}
}
