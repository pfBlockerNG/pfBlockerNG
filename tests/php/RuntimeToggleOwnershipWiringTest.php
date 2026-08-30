<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class RuntimeToggleOwnershipWiringTest extends TestCase
{
	public function testStaticAndDynamicAdvancedTogglesKeepTheirOwners(): void
	{
		$reflection = new ReflectionFunction('pfb_determine_list_detail');
		$lines = file($reflection->getFileName());
		if (!is_array($lines)) {
			throw new RuntimeException('test bootstrap: failed to read pfb_determine_list_detail source');
		}
		$source = implode('', array_slice(
			$lines,
			$reflection->getStartLine() - 1,
			$reflection->getEndLine() - $reflection->getStartLine() + 1
		));

		// The behavioral matrix cannot distinguish these owners because both adapters
		// intentionally share the same vocabulary and Off default.
		$this->assertStringContainsString(
			'$registered=$confconfig===\'pfblockerngdnsblsettings\'&&(string)$key===\'0\';'
			. '$toggle_enabled=staticfunction(string$field)use($conf_config,$registered):bool{'
			. 'if($registered){returnPfbConfig::read("dnsbl/{$field}")===PfbToggle::On;}'
			. 'returnpfb_dnsbl_toggle_enabled($conf_config[$field]??\'\');};',
			self::tokensWithoutTrivia($source),
			'registered settings must use PfbConfig while dynamic row/continent namesakes use the foreign-key adapter'
		);
	}

	private static function tokensWithoutTrivia(string $source): string
	{
		$result = '';
		foreach (token_get_all("<?php\n{$source}") as $token) {
			if (is_array($token) && in_array($token[0], [T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], TRUE)) {
				continue;
			}
			$result .= is_array($token) ? $token[1] : $token;
		}
		return $result;
	}
}
