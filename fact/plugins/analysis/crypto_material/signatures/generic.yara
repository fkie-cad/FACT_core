rule genericPublicKey
{
	meta:
		author = "Joerg Stucke"
		description = "Generic Public Key Block"
		date = "2017-03-16"
		version = "2"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string="-----BEGIN PUBLIC KEY-----"
		$end_string="-----END PUBLIC KEY-----"

	condition:
		$start_string and $end_string in (@start_string..filesize)
}