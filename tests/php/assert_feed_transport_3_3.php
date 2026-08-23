<?php

declare(strict_types=1);

/*
 * Feed transport assertions backported from the development line.
 *
 * Two contracts, both reported from the field (a UT1 archive that downloaded but
 * never unpacked):
 *
 *  1. The download must not request a transfer encoding. An origin that labels an
 *     archive "Content-Encoding: gzip" -- the Apache AddEncoding misconfiguration --
 *     otherwise has libcurl decode it in flight, so what lands on disk is the inner
 *     tar. On this line application/x-tar is allow-listed, so the decoded body passes
 *     MIME validation and the Blacklist branch reports a successful update having
 *     extracted nothing.
 *  2. The shipped UT1 provider must fetch over an authenticated transport, and the
 *     patch that names its download must key on the provider id rather than a feed
 *     URL literal -- the download name decides every category filename, so a
 *     URL-literal match renames the whole category set the day the URL moves.
 *
 * Source-level assertions: this line ships no PHPUnit, no composer and no live-VM
 * suite, and pfb_download() has no off-appliance double for its curl/exec surface.
 */

$root = dirname(__DIR__, 2);
$inc = $root . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
$php = $root . '/src/usr/local/www/pfblockerng/pfblockerng.php';
$provider = $root . '/src/usr/local/pkg/pfblockerng/ut1_global_usage';

$failures = 0;
function check(bool $cond, string $label): void
{
	global $failures;
	if ($cond) {
		echo "PASS {$label}\n";
		return;
	}
	$failures++;
	echo "FAIL {$label}\n";
}

foreach (array($inc, $php, $provider) as $path) {
	if (!is_file($path)) {
		echo "FAIL missing source: {$path}\n";
		exit(1);
	}
}

$inc_src = (string) file_get_contents($inc);
$php_src = (string) file_get_contents($php);

check(
	strpos($inc_src, 'CURLOPT_ENCODING') === FALSE,
	'the download requests no transfer encoding'
);

/* Read FEED exactly as the shipped discovery loop does (pfblockerng_blacklist.php):
   skip comments and blanks, split once on ':', trim, first match wins -- a later
   duplicate is ignored there, so this must not invent a uniqueness rule. */
$feed = '';
foreach ((array) file($provider, FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES) as $line) {
	$line = trim($line);
	if ($line === '' || strpos($line, '#') === 0) {
		continue;
	}
	if (strpos($line, 'FEED:') !== FALSE) {
		$feed = trim(explode(':', $line, 2)[1]);
		break;
	}
}

check($feed !== '', 'ut1_global_usage declares a FEED');
check(
	strpos($feed, 'https://') === 0,
	"the shipped UT1 feed is fetched over HTTPS (found: {$feed})"
);

check(
	preg_match("/if\s*\(\s*\\\$item\['xml'\]\s*==\s*'ut1'\s*\)/", $php_src) === 1,
	'the ut1.tar.gz filename patch keys on the provider id'
);
check(
	strpos($php_src, 'ftp://ftp.ut-capitole.fr') === FALSE,
	'the filename patch does not key on a feed URL literal'
);

if ($failures > 0) {
	echo "{$failures} FAILURE(S)\n";
	exit(1);
}

echo "ALL PASS\n";
