rule SshRsaPrivateKeyBlock {
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

rule SshEncryptedRsaPrivateKeyBlock {
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

rule SshDsaPrivateKeyBlock {
	meta:
		author = "Joerg Stucke"
		description = "Find DSA private key (PEM)"
		date = "2026-09-17"
		version = "1"
		version_schema_information = "Version number is increased whenever something changes."
	strings:
		$start_string = /-----BEGIN DSA PRIVATE KEY-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END DSA PRIVATE KEY-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule OpenSshPrivateKey {
	meta:
		description = "OpenSSH new-format private key (ed25519/ecdsa/rsa)"
	strings:
		$start_string = /-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9+\/\n\r=]{32}/
		$end_string = "-----END OPENSSH PRIVATE KEY-----"
	condition:
		$start_string and $end_string in (@start_string..filesize)
}

rule SshPublicKey {
	meta:
		description = "SSH public key (rsa/dss/ed25519/ecdsa/sk-*)"
	strings:
		// covers ssh-rsa, ssh-dss, ssh-ed25519, ecdsa-sha2-nistp256/384/521
		// and FIDO/U2F sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com
		$start_string = /((sk-)?(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521))(@openssh.com)?) AAAA\S+( \S+)?/
	condition:
		$start_string
}
