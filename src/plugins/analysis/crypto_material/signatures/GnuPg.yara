rule PgpPublicKeyBlock
{
	meta:
		author = "Raphael Ernst"
		description = "Find PGP Public key"
		date = "2015-11-27"
		version = "1"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string="-----BEGIN PGP PUBLIC KEY BLOCK-----"
		$end_string="-----END PGP PUBLIC KEY BLOCK-----"

	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule PgpPrivateKeyBlock
{
	meta:
		author = "Johannes vom Dorp"
		description = "Find PGP Private key"
		date = "2015-01-28"
		version = "1"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string="-----BEGIN PGP PRIVATE KEY BLOCK-----"
		$end_string="-----END PGP PRIVATE KEY BLOCK-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule PgpPublicKeyBlock_GnuPG
{
	meta:
		author = "Raphael Ernst"
		description = "Find PGP Public key from GnuPG"
		date = "2015-11-27"
		version = "1"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string="-----BEGIN PGP PUBLIC KEY BLOCK-----"
		$end_string="-----END PGP PUBLIC KEY BLOCK-----"
		$gnupg_version_string="Version: GnuPG"

	condition:
		$start_string and $gnupg_version_string in (@start_string..@end_string) and $end_string in (@start_string..filesize)
}
