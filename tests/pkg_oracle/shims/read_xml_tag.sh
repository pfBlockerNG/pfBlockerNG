#!/bin/sh
# Stand-in for /usr/local/sbin/read_xml_tag.sh: reads a config path from the probe's file-backed config (first element of list nodes).
exec php -r '
$c = json_decode((string) @file_get_contents(getenv("RACE_DIR") . "/config.json"), true);
foreach (explode("/", $argv[3]) as $k) { if (is_array($c) && array_key_exists($k, $c)) { $c = $c[$k]; } elseif (is_array($c) && isset($c[0]) && is_array($c[0]) && array_key_exists($k, $c[0])) { $c = $c[0][$k]; } else { $c = ""; break; } }
echo is_scalar($c) ? $c : "";' x "$@"
