rule EcPrivateKey {
	meta:
		description = "EC private key (SEC1 / RFC 5915, PEM)"
	strings:
		$start_string = /-----BEGIN EC PRIVATE KEY-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END EC PRIVATE KEY-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule EcPrivateKeyDer {
	meta:
		description = "EC private key (SEC1 / RFC 5915, DER)"
	strings:
		// SEQUENCE { version INTEGER(1), privateKey OCTET STRING ... }
		// handles short-form and long-form (1 or 2 byte) SEQUENCE lengths
		$a = { 30 (?? | 81 ?? | 82 ?? ??) 02 01 01 04 }
	condition:
		any of them
}
