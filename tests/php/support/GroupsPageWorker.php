<?php

declare(strict_types=1);

/**
 * Child process for GroupsPageConfigLockTest (issue #3945): runs the Groups pages' real POST/GET code over the PHPUnit doubles,
 * with another request's write (pfBlockerNG Core's settings adapter, shaped like pfb_core_feed_merge()) interleaved at the instant the
 * page reads config.xml afresh. The pages cannot be included whole: they render, and end in exit(). The code is cut out of the shipped
 * source by its anchors: the list page from `pfb_global();` to the render (its empty-row cleanup and the del/update actions), the editor
 * from its custom-list validation (the last check before the writes) to the end of the `save` branch.
 *
 * argv: page (`list` | `edit`), scenario, result file, case (JSON, optional): `type` the group type (`dnsbl` | `ipv4` | `geoip`),
 * `post`/`get` the request over the worker's defaults, `emptyFirstRow` the stored list starts with an empty `<config></config>`,
 * `ledger` an open download entry for DNSBL_Bravo in the sync-status ledger, `core.socket` the Core API socket the notice talks to
 * (default: none listens), `timeline` a file every lock/read/write event is appended to as {"event": ...} (a Core stand-in given the
 * same file as its record puts the notice on the same line of events).
 *
 * Scenarios: `plain` (nothing else wrote), `interleave` (Core patched another group and appended a group after this request read
 * config.xml), `row_deleted` (the group this request addresses was removed on disk), `cleaned_elsewhere` (the empty row was already
 * removed on disk), `lock_taken` (another process holds the config lock), `read_fails` (the fresh read fails), `write_refused`
 * (write_config answers FALSE), `write_failed` (answers -1), `write_throws` (exception).
 * The result holds the disk config after and before the request, the config the request read, lock/read/write events, the lock state after, the write_config()
 * descriptions, the input errors, `$savemsg`, what the page printed, whether control returned to render instead of exiting, the
 * pending-changes marker, the ledger's open entries before and after, and the record of a failed notice to Core.
 */

$workerArgv = $argv;
$page = (string) $workerArgv[1];
$scenario = (string) $workerArgv[2];
$resultFile = (string) $workerArgv[3];
$case = json_decode((string) ($workerArgv[4] ?? '{}'), TRUE, 512, JSON_THROW_ON_ERROR);
$repo = dirname(__DIR__, 3);
$disk = NULL;
$before = NULL;
$diskBefore = NULL;
$ledgerBefore = [];
$returned = FALSE;

register_shutdown_function(static function () use ($resultFile, &$disk, &$before, &$diskBefore, &$ledgerBefore, &$returned): void {
	$timeline = $GLOBALS['pfb_test_lock_events'] ?? [];
	$pfb = $GLOBALS['pfb'] ?? [];
	file_put_contents($resultFile, json_encode([
		'disk'          => $disk,
		'before'        => $before,
		'diskBefore'    => $diskBefore,
		'events'        => $timeline instanceof ArrayObject ? $timeline->getArrayCopy() : $timeline,
		'lockHeld'      => !empty($GLOBALS['pfb_test_lock_held']),
		'writes'        => $GLOBALS['pfb_test_write_config_calls'] ?? [],
		'inputErrors'   => $GLOBALS['input_errors'] ?? [],
		'savemsg'       => $GLOBALS['savemsg'] ?? NULL,
		'output'        => ob_get_level() > 0 ? (string) ob_get_contents() : '',
		'returned'      => $returned,
		'pendingMarked' => is_file($pfb['pending_marker'] ?? ''),
		'ledgerBefore'  => $ledgerBefore,
		'ledger'        => array_map(static fn (array $entry): string => "{$entry['item']}/{$entry['stage']}", pfb_sync_status_list_open($pfb['dbdir'] ?? '')),
		'settingsFailed' => ($failed = @file_get_contents($pfb['core_settings_failed'] ?? '')) === FALSE ? NULL : $failed,
	], JSON_THROW_ON_ERROR));
});

require_once $repo . '/tests/php/bootstrap.php';
require_once $repo . '/tests/php/SyncPrereqSeedTrait.php';

final class GroupsWorkerSeeder
{
	use SyncPrereqSeedTrait;

	public function seed(): void
	{
		$this->seedSyncPrereqs();
	}
}

/** Every lock, read and write event, in order; appended to the case's timeline file as it happens, so a Core stand-in's record interleaves with them. */
final class GroupsWorkerTimeline extends ArrayObject
{
	public function __construct(private readonly ?string $file)
	{
		parent::__construct();
	}

	public function offsetSet(mixed $key, mixed $value): void
	{
		parent::offsetSet($key, $value);
		if ($this->file !== NULL) {
			file_put_contents($this->file, json_encode(['event' => $value[0]]) . "\n", FILE_APPEND | LOCK_EX);
		}
	}
}

/** The shipped page's source between two anchors (start exclusive, end exclusive; the end may be NULL for the end of the file). */
function groups_worker_between(string $source, string $start, string $end): string
{
	$from = strpos($source, $start);
	$to = strpos($source, $end, $from === FALSE ? 0 : $from);
	if ($from === FALSE || $to === FALSE) {
		throw new RuntimeException("worker: the page no longer has its anchors {$start} .. {$end}");
	}
	return substr($source, $from + strlen($start), $to - $from - strlen($start));
}

/** The editor's save: from its custom-list validation to the end of `if ($_POST && isset($_POST['save']))`. */
function groups_worker_edit_block(string $source): string
{
	$anchor = '// Validate Custom List';
	$from = strpos($source, $anchor);
	if ($from === FALSE) {
		throw new RuntimeException('worker: the editor no longer has its custom-list anchor');
	}
	$code = '';
	$depth = 0;
	foreach (token_get_all('<?php ' . substr($source, $from)) as $token) {
		$text = is_array($token) ? $token[1] : $token;
		if ($text === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], TRUE))) {
			$depth++;
		} elseif ($text === '}' && --$depth < 0) {
			return substr($code, strlen('<?php '));
		}
		$code .= $text;
	}
	throw new RuntimeException('worker: the editor save branch has no end');
}

$type = (string) ($case['type'] ?? 'dnsbl');
$conf = ['dnsbl' => 'pfblockerngdnsbl', 'ipv4' => 'pfblockernglistsv4'][$type] ?? '';
$section = "installedpackages/{$conf}/config";

/** One group as the two sections store it: the feed row is what Core's projection reads. */
$group = static fn (string $name, array $more = []): array => $more + [
	'aliasname'   => $name,
	'description' => "{$name} group",
	'action'      => $type === 'dnsbl' ? 'unbound' : 'Deny_Inbound',
	'cron'        => 'Never',
	'row'         => [['state' => 'Enabled', 'url' => "https://example.invalid/{$name}.txt", 'header' => "{$name}Feed", 'format' => 'auto']],
];

$GLOBALS['config'] = [];
(new GroupsWorkerSeeder())->seed();
global $pfb;
pfb_global();
config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/global_log_mode', 'default');	// a migrated policy: the upgrade facade writes nothing
$tmp = $GLOBALS['pfb_test_tmp'];
$pfb['pending_marker'] = "{$tmp}/pending";
$pfb['dbdir'] = $tmp;
$pfb['schedule_state_dir'] = $tmp;
$pfb['core_socket'] = $case['core']['socket'] ?? "{$tmp}/core.sock";
$pfb['core_settings_failed'] = "{$tmp}/core_settings_failed";
$pfb['log'] = "{$tmp}/pfblockerng.log";
$pfb['errlog'] = "{$tmp}/error.log";
$pfb['runlog'] = '';

if ($type === 'geoip') {
	// GeoIP groups are the continents' own sections: Top Spammers is row 0, Africa row 1, Europe row 4
	$continents = ['topspammers', 'africa', 'europe'];
	foreach ($continents as $continent) {
		config_set_path("installedpackages/pfblockerng{$continent}/config", [['action' => 'Disabled', 'cron' => 'Never', 'aliaslog' => 'enabled']]);
	}
	$before = $GLOBALS['config'];
	$other = $before;
	$other['installedpackages']['pfblockerngeurope']['config'][0]['cron'] = 'Weekly';	// the adapter patched another continent
} else {
	$groups = [$group('Alpha'), $group('Bravo')];
	if (!empty($case['emptyFirstRow'])) {
		array_unshift($groups, []);
	}
	config_set_path($section, $groups);
	$before = $GLOBALS['config'];
	// What the settings adapter wrote after this request read config.xml: another group patched, a new group appended
	$patched = $groups;
	$alpha = array_key_last(array_filter($patched, static fn (mixed $g): bool => ($g['aliasname'] ?? '') === 'Alpha'));
	$patched[$alpha]['cron'] = '06hours';
	$patched[$alpha]['description'] = 'patched by Core';
	$other = $before;
	if ($scenario === 'interleave') {
		$other['installedpackages'][$conf]['config'] = [...$patched, $group('Charlie')];
	} elseif ($scenario === 'row_deleted') {
		$other['installedpackages'][$conf]['config'] = array_values(array_filter($patched, static fn (mixed $g): bool => ($g['aliasname'] ?? '') !== 'Bravo'));
	} elseif ($scenario === 'cleaned_elsewhere') {
		$other['installedpackages'][$conf]['config'] = array_values(array_filter($patched, static fn (mixed $g): bool => $g !== []));
	}
}
if (!empty($case['ledger'])) {
	pfb_sync_status_open('dnsbl', 'DNSBL_Bravo', 'download', 'seeded', $tmp);
}
$ledgerBefore = array_map(static fn (array $entry): string => "{$entry['item']}/{$entry['stage']}", pfb_sync_status_list_open($tmp));

$disk = $before;
$GLOBALS['pfb_test_lock_events'] = new GroupsWorkerTimeline($case['timeline'] ?? NULL);
if (in_array($scenario, ['interleave', 'row_deleted', 'cleaned_elsewhere', 'lock_taken', 'read_fails'], TRUE)) {
	$disk = $other;
}
$diskBefore = $disk;
$GLOBALS['pfb_test_config_read_hook'] = static function () use (&$disk): void {
	$GLOBALS['pfb_test_lock_events'][] = ['read'];
	$GLOBALS['config'] = $disk;
};
if ($scenario === 'lock_taken') {
	$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
} elseif ($scenario === 'read_fails') {
	$GLOBALS['pfb_test_config_read_fails'] = TRUE;
} elseif ($scenario === 'write_refused') {
	$GLOBALS['pfb_test_write_config_result'] = FALSE;
} elseif ($scenario === 'write_failed') {
	$GLOBALS['pfb_test_write_config_result'] = -1;
}
$GLOBALS['pfb_test_write_config_hook'] = static function (string $description) use (&$disk, $scenario): void {
	$GLOBALS['pfb_test_lock_events'][] = ['write'];
	if ($scenario === 'write_throws') {
		throw new RuntimeException("config.xml could not be written: {$description}");
	}
	if (!in_array($scenario, ['write_refused', 'write_failed'], TRUE)) {
		$disk = $GLOBALS['config'];
	}
};

$input_errors = [];
ini_set('open_basedir', "{$tmp}:" . dirname($resultFile) . ":{$repo}:/usr/share/php:/dev/null:/dev/urandom");
ob_start();

if ($page === 'list') {
	$_GET = $case['get'] ?? [];
	$_POST = $case['post'] ?? [];
	eval(groups_worker_between((string) file_get_contents($repo . '/src/usr/local/www/pfblockerng/pfblockerng_category.php'), "pfb_global();\n", "\$pgtype = 'IP';"));
	$returned = TRUE;
	return;
}

// The editor: the request's variables as the page leaves them for the save, the group addressed (Bravo, row 1) posted with edits
$gtype = $type;
$type = ['dnsbl' => 'DNSBL', 'ipv4' => 'IPv4'][$gtype];
$conf_type = $conf;
$suffix = ['dnsbl' => '', 'ipv4' => '_v4'][$gtype];
$rowid = $case['rowid'] ?? 1;
$action = '';
$rowdata = [];
$pfb_logging_default = 'default';
$block = groups_worker_edit_block((string) file_get_contents($repo . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'));
$_POST = ['save' => 'save'];
preg_match_all("~\\\$_POST\\['([a-z0-9_]+)'\\]~", $block, $posted);
foreach (array_unique($posted[1]) as $key) {
	$_POST[$key] = '';
}
$_POST = array_replace($_POST, [
	'aliasname' => 'Bravo', 'description' => 'edited on the page', 'action' => $gtype === 'dnsbl' ? 'Disabled' : 'Deny_Both', 'cron' => 'Weekly',
	'schedule_override' => '', 'schedule_weekday' => '7', 'schedule_hour' => '0', 'schedule_minute' => '0', 'sort' => 'sort',
	'logging' => 'default', 'order' => 'default', 'aliaslog' => 'enabled', 'stateremoval' => 'enabled', 'autoproto_in' => 'any',
	'autoproto_out' => 'any', 'agateway_in' => 'default', 'agateway_out' => 'default', 'suppression_cidr' => 'Disabled',
	'state-0' => 'Enabled', 'header-0' => 'BravoFeed', 'url-0' => 'https://example.invalid/bravo-edited.txt', 'format-0' => 'auto',
], $case['post'] ?? []);
$pconfig = $_POST;
eval($block);
$returned = TRUE;
