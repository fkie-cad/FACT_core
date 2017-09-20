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
