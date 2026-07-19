<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #1346 — every independent persisted group-action read must fail closed. */
final class GroupActionWiringTest extends TestCase
{
	private static string $inc;
	private static string $cron;
	private static string $category;
	private static string $alerts;
	private static string $categoryEdit;
	private static string $www;

	public static function setUpBeforeClass(): void
	{
		$root = dirname(__DIR__, 2);
		self::$inc = (string) file_get_contents("{$root}/src/usr/local/pkg/pfblockerng/pfblockerng.inc")
			. "\n" . (string) file_get_contents("{$root}/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc")
			. "\n" . (string) file_get_contents("{$root}/src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc");
		self::$category = (string) file_get_contents("{$root}/src/usr/local/www/pfblockerng/pfblockerng_category.php");
		self::$alerts = (string) file_get_contents("{$root}/src/usr/local/www/pfblockerng/pfblockerng_alerts.php");
		self::$categoryEdit = (string) file_get_contents("{$root}/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php");
		self::$www = (string) file_get_contents("{$root}/src/usr/local/www/pfblockerng/pfblockerng.php");
		self::$cron = (string) file_get_contents("{$root}/src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc");
	}

	private function assertGuardBeforeActionUse(
		string $source,
		string $start,
		string $end,
		string $guard,
		string $actionUse
	): void {
		$startPos = strpos($source, $start);
		$this->assertNotFalse($startPos, "start anchor not found: {$start}");
		$endPos = strpos($source, $end, $startPos + strlen($start));
		$this->assertNotFalse($endPos, "end anchor not found: {$end}");
		$block = substr($source, $startPos, $endPos - $startPos);
		$guardPos = strpos($block, $guard);
		$this->assertNotFalse($guardPos, "guard not found between anchors: {$guard}");
		$usePos = strpos($block, $actionUse);
		$this->assertNotFalse($usePos, "action use not found between anchors: {$actionUse}");
		$this->assertTrue($guardPos < $usePos, "guard must precede action use: {$actionUse}");
	}

	public function testSummaryAjaxUsesSharedGroupValidator(): void
	{
		$this->assertStringContainsString('pfb_group_action_valid($value, $gtype)', self::$category);
		$this->assertStringNotContainsString('in_array($value, $action_values)', self::$category);
	}

	public function testSummaryRenderNormalizesStoredActionBeforeFormSelect(): void
	{
		$this->assertStringContainsString(<<<'PHP'
						if (!pfb_group_action_valid($rowdata[$r_id]['action'] ?? NULL, $gtype)) {
							$rowdata[$r_id]['action'] = 'Disabled';
						}
PHP, self::$category);
		$this->assertGuardBeforeActionUse(
			self::$category,
			"if (\$gtype == 'ipv4' || \$gtype == 'ipv6' || \$gtype == 'geoip') {\n\t\t\t\t\t\t\t\$list_array",
			"\$selectadd->setWidth(8)->setAttribute('style', 'width: auto');",
			"pfb_group_action_valid(\$rowdata[\$r_id]['action'] ?? NULL, \$gtype)",
			"\$rowdata[\$r_id]['action'],"
		);
	}

	public function testGeneratedGeoipPageNormalizesStoredActionBeforeFormSelect(): void
	{
		$this->assertStringContainsString(
			"\$pconfig['action'] = pfb_group_action_valid(\$pfb['geoipconfig']['action'] ?? NULL, 'geoip') ? \$pfb['geoipconfig']['action'] : 'Disabled';",
			self::$www
		);
		$this->assertGuardBeforeActionUse(
			self::$www,
			"\$pfb['geoipconfig'] = config_get_path",
			"\$section->addInput(new Form_Select(\n\t'aliaslog'",
			"pfb_group_action_valid(\$pfb['geoipconfig']['action'] ?? NULL, 'geoip')",
			"\t\$pconfig['action'],\n\t\$options_action"
		);
	}

	public function testSummaryMutationRequiresExactPostTypeBeforeConfigSelection(): void
	{
		$this->assertStringContainsString(
			"is_string(\$_POST['type']) && in_array(\$_POST['type'], array('ipv4', 'ipv6', 'geoip', 'dnsbl'), TRUE)",
			self::$category
		);
		$this->assertGuardBeforeActionUse(
			self::$category,
			'if (isset($_POST))',
			'// Collect rowdata',
			'if (!empty($action) && !$post_type_valid)',
			'switch ($gtype)'
		);
	}

	public function testMatchdirIpListActionIsValidatedBeforeClassification(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'function pfb_matchdir_config_headers',
			'$pfb_dnsbl_action =',
			"pfb_group_action_valid(\$pfb_action, 'ipv4')",
			"strpos(\$pfb_action, 'Deny')"
		);
	}

	public function testMatchdirDnsblIpActionIsNormalizedBeforeClassification(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'$pfb_dnsbl_action =',
			'foreach ($continent_configs',
			'pfb_dnsblip_action_value(',
			"strpos(\$pfb_dnsbl_action, 'Deny')"
		);
	}

	public function testMatchdirGeoipActionIsValidatedBeforeClassification(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'foreach ($continent_configs',
			"return array('deny' => \$deny",
			"pfb_group_action_valid(\$pfb_cont_action, 'geoip')",
			"strpos(\$pfb_cont_action, 'Deny')"
		);
	}

	public function testAlertsStoredActionIsValidatedBeforePermitClassification(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$alerts,
			"foreach (\$c_config['config'] as \$row => \$data)",
			'// Add Default pfBlockerNG IP Whitelist',
			'pfb_group_action_valid($group_action, $group_type)',
			"strpos(\$group_action, 'Permit')"
		);
	}

	public function testCategoryEditStoredActionIsValidatedBeforeFolderClassification(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$categoryEdit,
			"\$pconfig['custom']",
			'// Indicate any failed downloads',
			"pfb_group_action_valid(\$pconfig['action'] ?? NULL, \$gtype)",
			"strpos(\$pconfig['action'], 'Deny_')"
		);
	}

	public function testNormalizeLoopGuardsStoredAction(): void
	{
		$this->assertStringContainsString(<<<'PHP'
				foreach ($type_config as $list) {
					if (!pfb_group_action_valid($list['action'] ?? NULL, $ltype === 'pfblockerngdnsbl' ? 'dnsbl' : 'ipv4')) {
						continue;
					}
PHP, self::$inc);
	}

	public function testDnsblProcessingLoopGuardsStoredAction(): void
	{
		$this->assertStringContainsString(<<<'PHP'
			foreach (config_get_path('installedpackages/pfblockerngdnsbl/config', []) as $list) {
				if (!pfb_group_action_valid($list['action'] ?? NULL, 'dnsbl')) {
					continue;
				}
PHP, self::$inc);
	}

	public function testCronPrepassGuardsStoredAction(): void
	{
		$this->assertStringContainsString(<<<'PHP'
		foreach (config_get_path("installedpackages/{$ltype}/config", []) as $list) {
			if (!pfb_group_action_valid($list['action'] ?? NULL, $is_dnsbl ? 'dnsbl' : 'ipv4')) {
				continue;
			}
PHP, self::$cron);
	}

	public function testCronGeoipFallbackGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$cron,
			'// If no lists require updates, check if Continents are configured',
			"if (\$pfb['update_cron']) {",
			"pfb_group_action_valid(\$continent_config['action'] ?? NULL, 'geoip')",
			"\$continent_config['action'] != 'Disabled'"
		);
	}

	public function testCustomPermitSuppressionGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			"// Collect any 'Permit' Customlist IPs to suppress",
			'$custom_supp = array_unique',
			"pfb_group_action_valid(\$list['action'] ?? NULL, 'ipv4')",
			"strpos(\$list['action'], 'Permit_')"
		);
	}

	public function testAutoruleGeoipDiscoveryGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'// Discover if any rules are autorules',
			"if (!\$pfb['autorules']) {",
			"pfb_group_action_valid(\$continent_config['action'] ?? NULL, 'geoip')",
			"\$continent_config['action'] != 'Disabled'"
		);
	}

	public function testAutoruleIpDiscoveryGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			"if (!\$pfb['autorules']) {",
			'// Check if DNSBL auto permit rule',
			"pfb_group_action_valid(\$list['action'] ?? NULL, 'ipv4')",
			"\$list['action'] != 'Disabled'"
		);
	}

	public function testDnsblIpGlobalActionIsNormalizedAtReadBoundary(): void
	{
		$this->assertStringContainsString(
			"\$pfb['dnsbl_ip']\t= pfb_dnsblip_action_value(\$pfb['dnsblconfig']['action'] ?? NULL);",
			self::$inc
		);
	}

	public function testDnsblIpAutoruleUsesNormalizedAction(): void
	{
		$start = strpos(self::$inc, '// Check if DNSBL auto permit rule');
		$this->assertNotFalse($start);
		$end = strpos(self::$inc, '// Configure auto rule suffix', $start);
		$this->assertNotFalse($end);
		$block = substr(self::$inc, $start, $end - $start);

		$this->assertStringContainsString("strpos(\$pfb['dnsbl_ip'], 'Deny_')", $block);
		$this->assertStringNotContainsString("\$pfb['dnsblconfig']['action']", $block);
	}

	public function testDnsblIpActionFolderGuardsBeforeRouting(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'function pfb_dnsblip_action_folder',
			'// Write the DNSBLIP',
			"pfb_group_action_valid(\$action, 'ipv4')",
			'pfb_determine_list_detail($action'
		);
	}

	public function testMasterDnsblIpSyntheticActionGuardsBeforeInterpolation(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'// ADD DNSBL IP',
			'if (!empty($lists))',
			"pfb_group_action_valid(\$pfb['dnsbl_ip'] ?? NULL, 'ipv4')",
			'"{$pfb[\'dnsbl_ip\']}"'
		);
	}

	public function testDownloadDnsblIpSyntheticActionGuardsBeforeInterpolation(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'// Add DNSBLIP, if configured (IPv4 + IPv6)',
			'$maxmind_run_once',
			"pfb_group_action_valid(\$pfb['dnsbl_ip'] ?? NULL, 'ipv4')",
			'"{$pfb[\'dnsbl_ip\']}"'
		);
	}

	public function testAliasDnsblIpSyntheticActionGuardsBeforeInterpolation(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'CONFIGURE ALIASES AND FIREWALL RULES',
			'// Clear variables',
			"pfb_group_action_valid(\$pfb['dnsbl_ip'] ?? NULL, 'ipv4')",
			'"{$pfb[\'dnsbl_ip\']}"'
		);
	}

	public function testMasterGeoipDiscoveryGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'// Find all enabled Continents lists',
			'// Find all enabled IPv4/IPv6 lists and DNSBL lists',
			"pfb_group_action_valid(\$continent_config['action'] ?? NULL, 'geoip')",
			"\$continent_config['action'] != 'Disabled'"
		);
	}

	public function testGeoipProcessingGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'// Download MaxMind Databases if not found',
			'// Remove temp file',
			"pfb_group_action_valid(\$continent_config['action'] ?? NULL, 'geoip')",
			"pfb_determine_list_detail(\$continent_config['action']"
		);
	}

	public function testIpDownloadCollectionGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'// Collect lists and custom list configuration and format into one array',
			'// Add DNSBLIP, if configured',
			"pfb_group_action_valid(\$list['action'] ?? NULL, 'ipv4')",
			'$lists[] = $list'
		);
	}

	public function testIpAliasRuleLoopGuardsStoredAction(): void
	{
		$this->assertGuardBeforeActionUse(
			self::$inc,
			'CONFIGURE ALIASES AND FIREWALL RULES',
			'// Clear variables',
			"pfb_group_action_valid(\$list['action'] ?? NULL, 'ipv4')",
			"pfb_determine_list_detail(\$list['action']"
		);
	}
}
