rule OpenSSL
{
	meta:
		software_name = "OpenSSL"
		open_source = true
		website = "https://www.openssl.org"
		description ="SSL library"
		version_regex = "\\d\\.\\d\\.\\d[a-z]{0,2}"
    strings:
        $a = /OpenSSL( \d+\.\d+\.\d+[a-z]?)?/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule SSLeay
{
	meta:
		software_name = "SSLeay"
		open_source = true
		website = "https://en.wikipedia.org/wiki/SSLeay"
		description ="SSL library"
    strings:
        $a = /SSLeay \d+\.\d+\.\d+[a-z]?/ nocase ascii wide
    condition:
        $a and no_text_file
}

