rule mbed_TLS {
	meta:
		software_name = "mbed TLS"
		open_source = true
		website = "https://github.com/Mbed-TLS/mbedtls"
		description = "embedded library for cryptography, X.509 certificate manipulation and the SSL/TLS and DTLS protocols"
    strings:
        // see https://github.com/Mbed-TLS/mbedtls/blob/b6860cf7f9f4be0cc60f36909f6a5887008fb408/include/mbedtls/build_info.h#L38
        $a = /mbed TLS \d+\.\d+\.\d+/ ascii
    condition:
        $a and no_text_file
}

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
