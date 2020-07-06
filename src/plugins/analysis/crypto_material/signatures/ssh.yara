rule SshRsaPublicKeyBlock
{
	meta:
		author = "Joerg Stucke"
		description = "Find ssh public key"
		date = "2017-03-16"
		version = "2"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string = /ssh-rsa AAAA\S+ \S+/
	condition:
		$start_string
}

rule SshRsaPrivateKeyBlock
{
	meta:
		author = "Joerg Stucke"
		description = "Find SSH Secret key"
		date = "2017-03-16"
		version = "2"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string = /-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END RSA PRIVATE KEY-----"

	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule SshEncryptedRsaPrivateKeyBlock
{
	meta:
		author = "Joerg Stucke"
		description = "Find encrypted SSH Secret key"
		date = "2020-07-06"
		version = "1"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string = /-----BEGIN RSA PRIVATE KEY-----/
		$end_string = /-----END RSA PRIVATE KEY-----/
		$proc_type = "Proc-Type:"
		$dek_info = "DEK-Info:"

	condition:
		for all of ($proc_type,$dek_info) : ( @ > @start_string and @ < @end_string )
}
