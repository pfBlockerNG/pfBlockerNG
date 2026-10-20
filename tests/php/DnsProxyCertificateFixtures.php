<?php

declare(strict_types=1);

/**
 * Real certificates and keys for the DNS proxy's certificate tests (issue #3515): EC P-256, issued by PHP's own openssl
 * functions, so the key-matches-certificate check runs against what OpenSSL would say and not against a stub.
 */
final class DnsProxyCertificateFixtures
{
	/** @var array{cert:string,key:string}|null */
	private static ?array $shared = NULL;

	/**
	 * One certificate for every test of the process: issuing one is the slow part.
	 *
	 * @return array{cert:string,key:string}
	 */
	public static function shared(): array
	{
		return self::$shared ??= self::issue('localhost');
	}

	/**
	 * Give a test a usable Resolver certificate, so that DoT (or DoH, DoQ) on means what it does on a box: the apply writes
	 * it to $dir/etc/pfb_dns/tls.pem for the gateway, and no notice says it could not. Seeds config.xml and $pfb (the certificate
	 * file, the control socket's path and the Unbound chroot copy an earlier build left, all under $dir).
	 */
	public static function seedResolver(string $dir, string $refid = 'cert123'): void
	{
		$GLOBALS['config']['unbound']['sslcertref'] = $refid;
		$GLOBALS['config']['cert'] = [self::certEntry($refid, self::shared())];
		$GLOBALS['pfb']['dns_proxy_cert'] = "{$dir}/etc/pfb_dns/tls.pem";
		$GLOBALS['pfb']['dns_proxy_cert_legacy'] = "{$dir}/chroot/pfb_dns_cert.pem";
		$GLOBALS['pfb']['dns_proxy_ctl'] = "{$dir}/ctl.sock";
	}

	/**
	 * A certificate for $cn and its key as PEM, signed by $parent (self-signed when NULL).
	 *
	 * @param array{cert:string,key:string}|null $parent
	 * @return array{cert:string,key:string}
	 */
	public static function issue(string $cn, ?array $parent = NULL): array
	{
		$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
		if ($key === FALSE) {
			throw new RuntimeException('openssl_pkey_new() failed: ' . self::drain());
		}
		$csr = openssl_csr_new(['commonName' => $cn], $key, ['digest_alg' => 'sha256']);
		$signed = ($csr === FALSE) ? FALSE : openssl_csr_sign($csr, $parent['cert'] ?? NULL, $parent['key'] ?? $key, 2);
		if ($signed === FALSE || !openssl_x509_export($signed, $cert) || !openssl_pkey_export($key, $pem)) {
			throw new RuntimeException('could not issue a test certificate: ' . self::drain());
		}
		self::drain();
		return ['cert' => $cert, 'key' => $pem];
	}

	/** config.xml <cert> entry (base64 crt and prv) for the certificate. */
	public static function certEntry(string $refid, array $pair, string $caref = ''): array
	{
		return ['refid' => $refid, 'caref' => $caref, 'crt' => base64_encode($pair['cert']), 'prv' => base64_encode($pair['key'])];
	}

	/** config.xml <ca> entry (base64 crt) for the authority. */
	public static function caEntry(string $refid, array $pair, string $caref = ''): array
	{
		return ['refid' => $refid, 'caref' => $caref, 'crt' => base64_encode($pair['cert'])];
	}

	private static function drain(): string
	{
		$errors = [];
		while (($error = openssl_error_string()) !== FALSE) {
			$errors[] = $error;
		}
		return implode('; ', $errors);
	}
}
