<?php

declare(strict_types=1);

/*
 * issue #3647: Reports > Alerts. The whitelist icon on a row blocked by a TLD Blacklist entry asked to add
 * the domain "to the TLD Whitelist", a different list; the dialog adds it to the DNSBL Whitelist.
 *
 * Standalone runner: release/3.3 ships no PHPUnit and no UI tier, so it eval()s the PRODUCTION
 * dnsbl_whitelist_type() straight out of pfblockerng_alerts.php.
 *   A  TLD-blocked row  -> prompt names the DNSBL Whitelist and not a "TLD Whitelist"
 *   B  Whole-TLD icon still routes to the DNSBL whitelist dialog (id type 'tld')
 *
 * NOT covered: the browser dialog the icon opens (tests/test_alerts_tld_whitelist_dialog_3_3.py runs that JS).
 */

$root = dirname(__DIR__, 2);
$alerts = (string) file_get_contents($root . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
$failures = 0;

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

function row(string $name, callable $test): void
{
	global $failures;
	try {
		$test();
		echo "PASS {$name}\n";
	} catch (Throwable $error) {
		$failures++;
		echo "FAIL {$name}: {$error->getMessage()}\n";
	}
}

function function_source(string $source, string $name): string
{
	$start = strpos($source, "function {$name}(");
	check($start !== false, "missing function {$name}");
	$open = strpos($source, '{', $start);
	check($open !== false, "missing body of {$name}");
	$depth = 0;
	$length = strlen($source);
	for ($i = $open; $i < $length; $i++) {
		if ($source[$i] === '{') {
			$depth++;
		} elseif ($source[$i] === '}' && --$depth === 0) {
			return substr($source, $start, $i - $start + 1);
		}
	}
	throw new RuntimeException("unterminated {$name}");
}

eval(function_source($alerts, 'dnsbl_whitelist_type'));

/** dnsbl.log row fields as the Alerts page builds them; index 5 is the block type, 7 the evaluated domain. */
function tld_blocked_row_icon(): array
{
	$GLOBALS['pfb'] = ['dnsbl_py_blacklist' => false];
	$fields = [2 => 'bad.example', 5 => 'DNSBL_TLD', 6 => 'TLD', 7 => 'example', 8 => 'TLD'];
	[$icon] = dnsbl_whitelist_type($fields, [], false, false, 'bad.example');
	check(preg_match('/id="([^"]*)" title="([^"]*)"/', (string) $icon, $m) === 1, 'no icon id/title in: ' . $icon);
	return ['id' => $m[1], 'title' => html_entity_decode($m[2])];
}

row('A TLD-blocked row prompt names the DNSBL Whitelist, not a TLD Whitelist', static function (): void {
	$icon = tld_blocked_row_icon();
	check(!str_contains($icon['title'], 'TLD Whitelist'), 'prompt names the wrong whitelist: ' . $icon['title']);
	check(str_contains($icon['title'], 'DNSBL Whitelist'), 'prompt does not name the DNSBL Whitelist: ' . $icon['title']);
});

row('B Whole-TLD icon still opens the whitelist dialog for the blocked domain', static function (): void {
	$icon = tld_blocked_row_icon();
	check($icon['id'] === 'DNSBLWT|tld|bad.example|example', 'unexpected icon id: ' . $icon['id']);
});

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURE(S)\n";
exit($failures === 0 ? 0 : 1);
