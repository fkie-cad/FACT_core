rule Tss2PrivateKey {
	meta:
		description = "TSS2 (TPM 2.0) private key (PEM)"
	strings:
		$start_string = /-----BEGIN TSS2 PRIVATE KEY-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END TSS2 PRIVATE KEY-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule Tss2KeyBlob {
	meta:
		description = "TSS2 (TPM 2.0) key blob (PEM)"
	strings:
		$start_string = /-----BEGIN TSS2 KEY BLOB-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END TSS2 KEY BLOB-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}
