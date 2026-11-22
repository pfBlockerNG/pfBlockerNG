<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/FeedParseCorpusFile.php';

/**
 * The whole-feed corpus of the Core Updater's feed stage (issue #4038, tests/updateloop/fixtures/feedstage/scenarios.json):
 * one feed through reuse, transfer, custom list, normalize, pre-script, parse, post-script, the empty check and publication.
 * sync_package_pfblockerng() keeps its per-feed blocks inline in a loop of several thousand lines, so this runner cuts each
 * block verbatim out of pfblockerng_apply.inc (from its reuse decision to the end of its if/else) and evaluates it with the
 * loop's variables set for one row: it drives today's code, not a copy. The Go runner (go/pfb_core/update/feedstage)
 * replays the same file; where Core differs on purpose the case holds today's answer in old_expect, which this runner
 * asserts.
 *
 * Each case runs two passes in one sandbox: a baseline pass with the baseline source and no script, then the case's pass.
 * The change detection that runs before the pass today (pfb_update_check) is not part of the block: a changed source is
 * given to the block as the '.update' marker that check leaves.
 */
#[CoversFunction('pfb_feed_normalize')]
#[CoversFunction('pfb_list_pre_script_run')]
#[CoversFunction('pfb_list_post_script_stage')]
#[CoversFunction('pfb_list_script_exec')]
#[CoversFunction('pfb_ip_parse_feed')]
#[CoversFunction('pfb_dnsbl_parse_feed')]
final class UpdateLoopFeedStageCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../updateloop/fixtures/feedstage/scenarios.json';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const CASE_KEYS = ['id', 'description', 'kind', 'custom', 'baseline', 'source', 'pre', 'post', 'expect'];
	private const EXPECT = ['outcome', 'stage', 'postFailed', 'entries', 'placeholder', 'orig'];
	/** Where each block starts (the first variable it needs from the loop is set before it) and the if that ends it. */
	private const BLOCKS = [
		'ipv4' => ['$pfb_ip_verbatim_reuse = file_exists(', "if (\$pfb_ip_reuse_decision['verbatim']) {"],
		'dnsbl' => ["\$reuse_unset\t= \$pfbreuse == '';", "if (\$pfb_dnsbl_reuse_decision['verbatim']) {"],
	];

	private string $root;
	/** The main log of the last pass, for the failure message. */
	private string $lastLog = '';
	private mixed $savedPfb = NULL;

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_feedstage_' . getmypid() . '_' . bin2hex(random_bytes(4));
		foreach (['orig', 'list', 'db', 'scripts', 'log', 'dnsbl'] as $d) {
			mkdir("{$this->root}/{$d}", 0700, TRUE);
		}
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->root));
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	/** @return array<string, mixed> */
	private static function corpus(): array
	{
		$doc = json_decode((string) file_get_contents(self::CORPUS), TRUE, 64, JSON_THROW_ON_ERROR);
		FeedParseCorpusFile::keys($doc, ['schema', 'placeholder', 'cases'], 'scenarios.json');
		if ($doc['schema'] !== 1 || !is_string($doc['placeholder']) || !is_array($doc['cases']) || $doc['cases'] === []) {
			throw new RuntimeException('scenarios.json: schema 1, a placeholder string and a non-empty case list');
		}
		return $doc;
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function cases(): array
	{
		$out = [];
		foreach (self::corpus()['cases'] as $case) {
			$w = 'case ' . ($case['id'] ?? '?');
			FeedParseCorpusFile::keys($case, array_key_exists('old_expect', $case) ? [...self::CASE_KEYS, 'old_expect', 'departure'] : self::CASE_KEYS, $w);
			FeedParseCorpusFile::keys($case['expect'], self::EXPECT, "{$w} expect");
			if (!in_array($case['kind'], ['ipv4', 'dnsbl'], TRUE) || !is_bool($case['custom']) || isset($out[$case['id']])) {
				throw new RuntimeException("{$w}: kind ipv4 or dnsbl, custom a bool, a unique id");
			}
			if (array_key_exists('old_expect', $case) && (array_diff(array_keys($case['old_expect']), self::EXPECT) !== []
			    || !is_string($case['departure']) || $case['departure'] === '')) {
				throw new RuntimeException("{$w}: old_expect holds expect keys, and departure says why");
			}
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/**
	 * The code from $start to the end of the if/else chain $if opens, verbatim: braces are counted on PHP tokens, so the
	 * "{$var}" of a string is no block.
	 */
	private static function block(string $source, string $start, string $if): string
	{
		foreach ([$start, $if] as $anchor) {
			if (substr_count($source, $anchor) !== 1) {
				throw new RuntimeException("the block moved: '{$anchor}' must occur once in pfblockerng_apply.inc");
			}
		}
		$from = strpos($source, $start);
		$at = strpos($source, $if);
		if ($at < $from) {
			throw new RuntimeException("'{$if}' must follow '{$start}'");
		}
		$tail = substr($source, $at);
		$offset = -6;
		$depth = 0;
		$closed = FALSE;
		foreach (token_get_all('<?php ' . $tail) as $token) {
			$text = is_array($token) ? $token[1] : $token;
			$offset += strlen($text);
			if ($offset <= 0 || (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], TRUE))) {
				continue;
			}
			if ($closed) {
				if (is_array($token) && in_array($token[0], [T_ELSE, T_ELSEIF], TRUE)) {
					$closed = FALSE;
					continue;
				}
				return substr($source, $from, $at - $from) . substr($tail, 0, $offset - strlen($text));
			}
			if ($token === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], TRUE))) {
				$depth++;
			} elseif ($token === '}' && --$depth === 0) {
				$closed = TRUE;
			}
		}
		throw new RuntimeException("no end after '{$if}'");
	}

	/**
	 * One pass of the block for the case's feed: the loop's variables as sync_package_pfblockerng() sets them for one row,
	 * then the block, inside a one-iteration loop for its continue statements.
	 *
	 * @param array<string, mixed> $case
	 * @return array<string, mixed> what the pass decided, from the block's own variables
	 */
	private function pass(array $case, string $placeholder, ?string $pre, ?string $post, bool $changed): array
	{
		global $pfb;
		$ip = $case['kind'] === 'ipv4';
		$pfb = array_merge(is_array($this->savedPfb) ? $this->savedPfb : [], [
			'log' => "{$this->root}/log/main.log", 'errlog' => "{$this->root}/log/error.log", 'runlog' => "{$this->root}/log/run.log",
			'runlog_active' => TRUE, 'run_stdout_override' => FALSE, 'dbdir' => "{$this->root}/db", 'dnsbldir' => "{$this->root}/dnsbl",
			'ip_ph' => $placeholder, 'grep' => '/usr/bin/grep', 'agg' => PfbToggle::Off, 'dup' => PfbToggle::Off,
			'rep' => PfbToggle::Off, 'supp' => PfbToggle::Off, 'scheduled_runtime_cron' => '', 'dnsbl_ip' => 'Disabled',
			'dnsbl_lenient' => PfbToggle::Off, 'dnsbl_parse_err' => FALSE, 'ip_parse_err' => FALSE, 'updateip' => FALSE, 'skipfeed' => 0,
		]);
		$regex = pfb_ip_regex_config();
		[$pfb['range'], $pfb['ipv4'], $pfb['ipv6']] = [$regex['range'], $regex['ipv4'], $regex['ipv6']];
		$header = $ip ? 'Feed_v4' : 'Feed';
		$alias = $ip ? 'pfB_Test_v4' : 'DNSBL_Test';
		$pfbfolder = "{$this->root}/list";
		$pfborig = "{$this->root}/orig";
		if ($changed) {
			touch("{$pfbfolder}/{$header}.update");
		}
		$source = "{$this->root}/db/feed.txt";
		$custom = $case['custom'] ? 'on' : '';
		$encoded = base64_encode((string) $case['source']);
		$row = ['header' => $header, 'state' => 'Enabled', 'format' => 'auto', 'url' => $source, 'custom' => $encoded];
		$list = ['vtype' => $ip ? '_v4' : '', 'script_pre' => $pre === NULL ? '' : 'pre.sh', 'script_post' => $post === NULL ? '' : 'post.sh',
			'custom' => $encoded, 'whois_convert' => ''];
		$dirs = ["{$this->root}/scripts"];
		$resolve = static fn(?string $s, string $name) => $s === NULL ? FALSE : pfb_resolve_list_script($name, $dirs);
		$pfbreuse = '';
		$scheduled_selected = TRUE;
		$srcint = '';
		$logtab = '';
		$pfb_script_state = ['failed' => FALSE];
		$pfb_dl_failed = FALSE;
		$header_esc = escapeshellarg($header);
		$elog = '';
		if ($ip) {
			$pfb_script_pre = $resolve($pre, 'pre.sh');
			$pfb_script_post = $resolve($post, 'post.sh');
			$pfbarr = ['aaddrnot_in' => '', 'aaddrnot_out' => ''];
			$pfbadv = FALSE;
			$pfbcidr = $pfbcidr_v6 = 'Disabled';
			$scheduled_family = 'ipv4';
			$pfb_alias_lists = [];
		} else {
			$pfb_row_script_pre = $resolve($pre, 'pre.sh');
			$pfb_row_script_post = $resolve($post, 'post.sh');
			$txt_exists = file_exists("{$pfbfolder}/{$header}.txt");
			$mode = 'deny';
			$logging_type = 'enabled';
			$filter_top1m = FALSE;
			$lists_dnsbl_all = $pfb_py_feeds = [];
			$alias_cnt = 0;
		}

		$seen = eval('foreach ([0] as $pfb_test_once) {' . self::block((string) file_get_contents(self::APPLY), ...self::BLOCKS[$case['kind']])
		    . '} return get_defined_vars();');

		$log = (string) @file_get_contents($pfb['log']);
		$decision = $seen[$ip ? 'pfb_ip_reuse_decision' : 'pfb_dnsbl_reuse_decision'];
		$outcome = match (TRUE) {
			$seen['pfb_dl_failed'] => ['failed', 'transfer'],
			($seen['pfb_pre']['ok'] ?? TRUE) === FALSE => ['failed', 'pre-script'],
			$decision['verbatim'] || str_contains($log, 'unchanged after normalization') => ['unchanged', ''],
			str_contains($log, $ip ? 'No IPs found!' : 'No Domains Found!') => ['empty', ''],
			default => ['updated', ''],
		};
		$this->lastLog = $log;
		file_put_contents($pfb['log'], '');
		return ['outcome' => $outcome[0], 'stage' => $outcome[1], 'postFailed' => ($seen['pfb_post_status'] ?? 0) !== 0];
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testCaseMatchesTodaysFeedBlock(array $case): void
	{
		$doc = self::corpus();
		foreach (['pre' => $case['pre'], 'post' => $case['post']] as $name => $body) {
			if ($body !== NULL) {
				file_put_contents("{$this->root}/scripts/{$name}.sh", "#!/bin/sh\n{$body}\n");
				chmod("{$this->root}/scripts/{$name}.sh", 0755);
			}
		}
		$source = "{$this->root}/db/feed.txt";
		if ($case['baseline'] !== NULL) {
			file_put_contents($source, $case['baseline']);
			$this->assertSame('updated', $this->pass($case, $doc['placeholder'], NULL, NULL, FALSE)['outcome'], "the baseline pass publishes; its log:\n{$this->lastLog}");
		}
		@unlink($source);
		if ($case['source'] !== NULL && !$case['custom']) {
			file_put_contents($source, $case['source']);
		}
		$got = $this->pass($case, $doc['placeholder'], $case['pre'], $case['post'], $case['source'] !== $case['baseline']);

		$header = $case['kind'] === 'ipv4' ? 'Feed_v4' : 'Feed';
		$orig = "{$this->root}/orig/{$header}.orig";
		$this->assertFalse(is_link($orig), "{$case['id']}: the download is never left a link");
		$lines = array_values(array_filter(explode("\n", (string) @file_get_contents("{$this->root}/list/{$header}.txt")),
		    static fn(string $l): bool => $l !== ''));
		$placeholder = '';
		if ($case['kind'] === 'ipv4' && $lines === [$doc['placeholder']]) {
			[$lines, $placeholder] = [[], 'empty'];
		}
		if ($case['kind'] === 'dnsbl') {
			$lines = array_map(static fn(string $l): string => (string) json_decode($l, TRUE, 4, JSON_THROW_ON_ERROR)[1], $lines);
		}
		$got += ['entries' => $lines, 'placeholder' => $placeholder, 'orig' => @file_get_contents($orig)];
		$want = array_merge($case['expect'], $case['old_expect'] ?? []);
		ksort($got);
		ksort($want);
		$this->assertSame($want, $got, "{$case['id']}: {$case['description']}; the pass's log:\n{$this->lastLog}");
	}
}
