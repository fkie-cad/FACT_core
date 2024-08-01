rule SSLPrivateKey
{
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

rule SSLCertificate
{
	meta:
		author = "Joerg Stucke"
		description = "PEM encoded SSL certificate"
		date = "2017-03-16"
		version = "2"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string = /-----BEGIN CERTIFICATE-----[0-9a-zA-Z\/+\n\r=]{32}/
		$end_string = "-----END CERTIFICATE-----"

	condition:
		$start_string and $end_string in (@start_string..filesize)
}
