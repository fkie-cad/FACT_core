rule OpenSSL
{
	meta:
		software_name = "OpenSSL"
		open_source = true
		website = "https://www.openssl.org"
		description ="SSL library"
		version_regex = "\\d\\.\\d\\.\\d[a-z]{0,2}"
		no_text_file = true
    strings:
        $a = /OpenSSL( \d+\.\d+\.\d+[a-z]?)?/ nocase ascii wide
    condition:
        $a
}

rule SSLeay
{
	meta:
		software_name = "SSLeay"
		open_source = true
		website = "https://en.wikipedia.org/wiki/SSLeay"
		description ="SSL library"
		no_text_file = true
    strings:
        $a = /SSLeay \d+\.\d+\.\d+[a-z]?/ nocase ascii wide
    condition:
        $a
}
