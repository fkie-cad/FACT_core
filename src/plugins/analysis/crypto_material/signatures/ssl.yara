rule SSLPrivateKey {
	meta:
		author = "Peter Weidenbach"
		description = "SSL Private Key"
		date = "2017-03-16"
		version = "2"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string = /-----BEGIN PRIVATE KEY-----[0-9a-zA-Z\/+\n\r=]{32}/
		$end_string = "-----END PRIVATE KEY-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule SSLCertificate {
	meta:
		author = "Joerg Stucke"
		description = "PEM encoded SSL certificate (CERTIFICATE, CA CERTIFICATE, TRUSTED CERTIFICATE, X509 CERTIFICATE)"
		date = "2017-03-16"
		version = "3"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string = /-----BEGIN (CA |TRUSTED |X509 )?CERTIFICATE-----[0-9a-zA-Z\/+\n\r=]{32}/
		$end_string = /-----END (CA |TRUSTED |X509 )?CERTIFICATE-----/
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule OpenVpnStaticKey {
	meta:
		description = "OpenVPN static key V1 (PEM)"
	strings:
		$start_string = /-----BEGIN OpenVPN Static key V1-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END OpenVPN Static key V1-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}
