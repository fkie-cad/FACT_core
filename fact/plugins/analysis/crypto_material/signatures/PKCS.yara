rule Pkcs8PrivateKey
{
	meta:
		description = "PKCS8 private key"

	strings: 
		$version = {30 82 ?? ?? 02 01 00}
	condition: 
		$version
}

rule Pkcs12Certificate
{
   	meta:
		description = "PKCS12 certificate"

	strings: 
		$version3 = {30 82 ?? ?? 02 01 03}
	condition: 
		$version3
}
