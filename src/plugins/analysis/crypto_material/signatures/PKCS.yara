rule Pkcs8PrivateKey {
	meta:
		description = "PKCS8 unencrypted private key"
	strings:
		// version INTEGER(0) immediately followed by the algorithmIdentifier SEQUENCE
		$a = { 30 (82 ?? ?? | 81 ??) 02 01 00 30 }
	condition:
		$a
}

rule EncryptedPrivateKey {
	meta:
		description = "Encrypted PKCS8 private key (PEM)"
	strings:
		$start_string = /-----BEGIN ENCRYPTED PRIVATE KEY-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END ENCRYPTED PRIVATE KEY-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule Pkcs1RsaPrivateKey {
	meta:
		description = "PKCS1 RSA private key"
	strings:
		// version INTEGER(0) followed by the modulus INTEGER, handling
		// short-form and long-form (1 or 2 byte) SEQUENCE/INTEGER lengths
		$a = { 30 (82 ?? ?? | 81 ??) 02 01 00 02 (82 ?? ?? | 81 ??) }
	condition:
		$a
}

rule EncryptedPrivateKeyDer {
	meta:
		description = "Encrypted PKCS8 private key (DER, PBES1/PBES2)"
	strings:
		// encryptionAlgorithm SEQUENCE containing PBES1 OIDs 1.2.840.113549.1.5.{1,3,10,12,13}
		$a = { 30 (?? | 81 ??) 06 09 2a 86 48 86 f7 0d 01 05 (01 | 03 | 0a | 0c | 0d) }
	condition:
		$a
}

rule Pkcs12Certificate {
   	meta:
		description = "PKCS12 certificate"
	strings:
		$a = { 30 82 ?? ?? 02 01 03 }
	condition: 
		$a
}

rule Pkcs7SignedData {
	meta:
		description = "PKCS7/CMS SignedData (DER)"
	strings:
		// ContentInfo SEQUENCE, contentType = 1.2.840.113549.1.7.2 (signedData)
		$a = { 30 82 ?? ?? 06 09 2a 86 48 86 f7 0d 01 07 02 }
	condition:
		any of them
}

rule Pkcs7Pem {
	meta:
		description = "PKCS7/CMS (PEM)"
	strings:
		$start_string = /-----BEGIN PKCS7-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END PKCS7-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule CertificateRequest {
	meta:
		description = "PKCS10 Certificate Signing Request (PEM)"
	strings:
		$start_string = /-----BEGIN (NEW )?CERTIFICATE REQUEST-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END CERTIFICATE REQUEST-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}
