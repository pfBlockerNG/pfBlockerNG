<?php

declare(strict_types=1);

/**
 * Child process for CrowdsecRulesTest: asks the rule hook for one or more rule types the way pfSense's discover_pkg_rules() does
 * during a filter reload, then ends, so the shutdown functions the hook registered run as they do on the appliance. Every command
 * mwexec() runs is printed as `exec <command>` the moment it runs, and `returned` is printed once the hook calls are done: what
 * the shutdown sends comes after it.
 * argv: scenario JSON: `types` (the rule types asked for, in order), `running` (the bouncer should run), `alive` (isvalidpid()'s
 * answer for the bouncer's pidfile).
 */

$scenario = json_decode((string) $argv[1], TRUE, 4, JSON_THROW_ON_ERROR);

require_once dirname(__DIR__) . '/bootstrap.php';

$GLOBALS['config'] = [];
// pfSense's filter reload never runs pfb_global(): the master enable is only what config.xml stores
unset($GLOBALS['pfb']['enable']);
config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');
config_set_path('installedpackages/pfblockerngcrowdsec/config/0', ['enable' => $scenario['running'] ? 'on' : '', 'api_key' => 'k3y',
	'lapi_url' => 'https://lapi.example.net/', 'rules_all_interfaces' => 'on', 'rule_v4' => 'on', 'rule_v6' => 'on']);
$GLOBALS['pfb_test_valid_pids'] = ['/var/run/pfb_crowdsec.pid' => $scenario['alive'], '/var/run/pfb_crowdsec_daemon.pid' => TRUE];
$GLOBALS['pfb_test_mwexec_hook'] = static function (string $command): int {
	echo "exec {$command}\n";
	return 0;
};

foreach ($scenario['types'] as $type) {
	echo 'rules ' . $type . ' ' . (pfb_crowdsec_rules($type) === '' ? 'none' : 'some') . "\n";
}
echo "returned\n";
