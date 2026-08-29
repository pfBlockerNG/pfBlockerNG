<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Enable DNSBL infoblock: v4 evaluation order from evaluate_domain().
 *
 * The v3 text lived on pfb_py_block and must not be pasted: null-blocking is
 * not a stage property, and CNAME Validation / no-AAAA are not pipeline stages.
 */
final class DnsblEvalOrderHelpTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read DNSBL page');
		}
		return $source;
	}

	private static function pfbDnsblHelp(string $source): string
	{
		self::assertSame(
			1,
			preg_match(
				"/new Form_Checkbox\(\s*'pfb_dnsbl'.*?->setHelp\((.*?)\);\s*\n/s",
				$source,
				$m
			),
			'pfb_dnsbl Form_Checkbox setHelp() must exist'
		);
		return $m[1];
	}

	private static function evalOrderBlock(string $source): string
	{
		self::assertSame(
			1,
			preg_match(
				'/<div id="dnsbl_eval_order">(.*?)<\/div>/s',
				$source,
				$m
			),
			'Enable DNSBL must carry #dnsbl_eval_order infoblock'
		);
		return $m[1];
	}

	public function testEvalOrderInfoblockLivesOnEnableDnsblHelp(): void
	{
		$source = self::source();
		$help = self::pfbDnsblHelp($source);
		$this->assertStringContainsString('{$dnsbl_text}', $help);
		$this->assertStringNotContainsString(
			'class="infoblock"',
			$help,
			'Enable DNSBL setHelp must not stack a second infoblock beside {$dnsbl_text}'
		);
		$this->assertStringContainsString('id="dnsbl_eval_order"', $source);
	}

	public function testEvalOrderListsFiveDiscoveryStagesInEvaluateDomainOrder(): void
	{
		$block = self::evalOrderBlock(self::source());
		$stages = [
			'Feed lists, exact name',
			'Feed lists, wildcard/zone',
			'TLD Allow',
			'IDN Blocking',
			'Regex Blocking',
		];
		$last = -1;
		foreach ($stages as $stage) {
			$pos = strpos($block, $stage);
			$this->assertNotFalse($pos, "evaluation-order infoblock must name stage '{$stage}'");
			$this->assertGreaterThan($last, $pos, "'{$stage}' must follow the previous evaluate_domain() stage");
			$last = $pos;
		}
		$this->assertStringContainsString('<ol>', $block);
		$this->assertStringContainsString('first match wins', $block);
	}

	public function testEvalOrderDoesNotPasteV3NullBlockOrPythonTitle(): void
	{
		$block = self::evalOrderBlock(self::source());
		$this->assertStringNotContainsStringIgnoringCase('python blocking order', $block);
		$this->assertStringNotContainsString('Blocked events (#2-4)', $block);
		$this->assertStringNotContainsString('will be Null Blocked', $block);
		$this->assertStringContainsString('not a property of which stage matched', $block);
	}

	public function testCnameAndNoAaaaAreNamedAsSeparateFeaturesNotOlStages(): void
	{
		$block = self::evalOrderBlock(self::source());
		$this->assertSame(
			1,
			preg_match('/<ol>(.*?)<\/ol>/s', $block, $ol),
			'evaluation-order infoblock must use an <ol> for discovery stages'
		);
		$this->assertStringNotContainsString('CNAME Validation', $ol[1]);
		$this->assertStringNotContainsString('no-AAAA', $ol[1]);
		$this->assertStringContainsString('CNAME Validation', $block);
		$this->assertStringContainsString('no-AAAA', $block);
		$this->assertStringContainsString('separate features', $block);
	}

	public function testOverrideSentenceNamesImportantPriority(): void
	{
		$block = self::evalOrderBlock(self::source());
		$this->assertStringContainsString('ABP allow rule (@@)', $block);
		$this->assertStringContainsString('loads $important rules', $block);
		$this->assertStringContainsString('resolved by priority rather than allow-always-wins', $block);
		$source = self::source();
		$this->assertMatchesRegularExpression(
			"/'[^'\\n]*loads \\\$important rules/",
			$source,
			'$important must stay in a single-quoted PHP string'
		);
	}

	public function testVipParagraphIsModeAware(): void
	{
		$source = self::source();
		$this->assertStringNotContainsString(
			'the request is redirected to the Virtual IP address',
			$source
		);
		$this->assertStringContainsString('How a blocked name is answered depends on the', $source);
		$this->assertStringContainsString('Null Blocking', $source);
		$this->assertStringContainsString('No Virtual IP, no web server and no block page are involved', $source);
		$this->assertStringContainsString('in VIP mode', $source);
	}

	public function testTcpdumpExampleUsesAutoVipPattern(): void
	{
		$source = self::source();
		$this->assertStringNotContainsString("A 10.10.10.1", $source);
		$this->assertStringContainsString("A 10.10.0.53", $source);
		$this->assertStringContainsString('10.10.x.53', $source);
		$this->assertStringContainsString('DNSBL Webserver Configuration', $source);
	}
}
