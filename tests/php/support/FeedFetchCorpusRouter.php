<?php

// php -S router of FeedFetchParityCorpusTest: serves one corpus server (env CORPUS_SERVER) from the route table in
// CORPUS_ROUTES ({server: {path: route}}, placeholders already expanded) and appends every request to CORPUS_REQUESTS.
// Route semantics are the corpus's (tests/feedfetch/fixtures/parity), mirrored by go/pfb_core/feedfetch/corpus_test.go.

$uri = $_SERVER['REQUEST_URI'] ?? '';
if ($uri === '/__pfb_ready') {
	echo getenv('READY_TOKEN');
	return;
}
$server = (string) getenv('CORPUS_SERVER');
$path = (string) parse_url($uri, PHP_URL_PATH);

$record = ['server' => $server, 'path' => $path];
foreach ([
	'authorization'     => 'HTTP_AUTHORIZATION',
	'if_none_match'     => 'HTTP_IF_NONE_MATCH',
	'if_modified_since' => 'HTTP_IF_MODIFIED_SINCE',
	'x_feed_probe'      => 'HTTP_X_FEED_PROBE',
	'accept_encoding'   => 'HTTP_ACCEPT_ENCODING',
] as $key => $var) {
	if (isset($_SERVER[$var])) {
		$record[$key] = $_SERVER[$var];
	}
}
file_put_contents((string) getenv('CORPUS_REQUESTS'), json_encode($record, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);

$routes = json_decode((string) file_get_contents((string) getenv('CORPUS_ROUTES')), TRUE);
$route = $routes[$server][$path] ?? NULL;
if ($route === NULL) {
	http_response_code(404);
	header('Content-Length: 8');
	echo "missing\n";
	return;
}

$body = (string) ($route['body'] ?? '');
if (isset($route['etag'])) {
	header("ETag: {$route['etag']}");
}
if (isset($route['last_modified'])) {
	header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $route['last_modified']) . ' GMT');
}
$not_modified = isset($route['etag'])
	? ($_SERVER['HTTP_IF_NONE_MATCH'] ?? NULL) === $route['etag']
	: isset($route['last_modified'], $_SERVER['HTTP_IF_MODIFIED_SINCE'])
		&& strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= $route['last_modified'];
if ($not_modified) {
	http_response_code(304);
	return;
}
http_response_code((int) ($route['status'] ?? 200));
if (isset($route['location'])) {
	header("Location: {$route['location']}");
}
header('Content-Length: ' . (string) ($route['declared_length'] ?? strlen($body)));
echo $body;
