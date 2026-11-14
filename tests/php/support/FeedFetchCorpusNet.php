<?php

declare(strict_types=1);

// Network stand-ins of FeedFetchParityCorpusTest beyond plain `php -S`: the test certificates and the shared Python
// fixture (tests/feedfetch/fixtures/net_fixture.py) that serves TLS in front of a `php -S` server and acts as the
// forward proxy. The Go runner starts the same script (go/pfb_core/feedfetch/corpus_net_test.go).

/**
 * Generates the corpus's test PKI into $dir: a CA, a leaf signed by it ("trusted") and a self-signed leaf the CA did not
 * sign ("untrusted"). Both leaves name feed.example and rdr.example only, never an IP address. Keys are made here, at test time, and
 * die with the case's temp directory; nothing is committed.
 *
 * @return array{ca:string, trusted:array{cert:string,key:string}, untrusted:array{cert:string,key:string}}
 */
function pfb_test_corpus_pki(string $dir): array
{
	if (!is_dir($dir) && !mkdir($dir, 0700, TRUE)) {
		throw new RuntimeException("cannot create {$dir}");
	}
	$cnf = "{$dir}/openssl.cnf";
	file_put_contents($cnf, <<<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = corpus
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:feed.example,DNS:rdr.example
CNF);
	$cfg = ['config' => $cnf, 'digest_alg' => 'sha256'];
	$newKey = static fn () => openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
	$save = static function ($key, $cert, string $name) use ($dir): array {
		if (!openssl_x509_export($cert, $pem) || !openssl_pkey_export($key, $keyPem)) {
			throw new RuntimeException("cannot export {$name}");
		}
		file_put_contents("{$dir}/{$name}.pem", $pem);
		file_put_contents("{$dir}/{$name}.key", $keyPem);
		chmod("{$dir}/{$name}.key", 0600);
		return ['cert' => "{$dir}/{$name}.pem", 'key' => "{$dir}/{$name}.key"];
	};
	$leaf = static function (string $name, $issuerCert, $issuerKey, int $serial) use ($cfg, $newKey, $save): array {
		$key = $newKey();
		$csr = openssl_csr_new(['commonName' => 'feed.example'], $key, $cfg);
		$cert = openssl_csr_sign($csr, $issuerCert, $issuerKey ?? $key, 2, $cfg + ['x509_extensions' => 'v3_leaf'], $serial);
		return $save($key, $cert, $name);
	};

	$caKey = $newKey();
	$caCsr = openssl_csr_new(['commonName' => 'pfb corpus test CA'], $caKey, $cfg);
	$ca = openssl_csr_sign($caCsr, null, $caKey, 2, $cfg + ['x509_extensions' => 'v3_ca'], 1);
	$caFiles = $save($caKey, $ca, 'ca');

	return [
		'ca' => $caFiles['cert'],
		'trusted' => $leaf('trusted', $ca, $caKey, 2),
		'untrusted' => $leaf('untrusted', NULL, NULL, 3),
	];
}

/**
 * Starts net_fixture.py with $args and returns [process, port] once it prints its "ready <port>" line, or NULL when it
 * exits without one. The 10 s cap is a watchdog for a hung start, never the readiness signal.
 *
 * @param list<string> $args
 * @return array{0:resource,1:int}|null
 */
function pfb_test_corpus_net_fixture(array $args, string $stderrPath): ?array
{
	$proc = proc_open(
		array_merge(['python3', __DIR__ . '/../../feedfetch/fixtures/net_fixture.py'], $args),
		[1 => ['pipe', 'w'], 2 => ['file', $stderrPath, 'w']],
		$pipes,
		NULL,
		['PATH' => (string) getenv('PATH')]
	);
	if (!is_resource($proc)) {
		return NULL;
	}
	$read = [$pipes[1]];
	$write = $except = NULL;
	$line = stream_select($read, $write, $except, 10) === 1 ? (string) fgets($pipes[1]) : '';
	fclose($pipes[1]);
	if (preg_match('/^ready (\d+)$/', trim($line), $m) === 1) {
		return [$proc, (int) $m[1]];
	}
	proc_terminate($proc);
	proc_close($proc);
	return NULL;
}
