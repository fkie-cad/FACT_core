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
        $a
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
        $a
}

rule GnuPG
{
	meta:
		software_name = "GnuPG"
		open_source = true
		website = "https://gnupg.org"
		description = "OpenPGP implementation (gpg)"
		version_regex = "\\d+\\.\\d+\\.\\d+"
    strings:
        // name of the versioned config file (1.3.3 - 2.2)
        $a = /gpg\.conf-\d+\.\d+\.\d+/ ascii
        // --server greeting (2.x)
        $b = /GNU Privacy Guard's OpenPGP server \d+\.\d+\.\d+/ ascii
        // ASCII armor header with the full version (older 1.4 and 2.0 releases, also gpgv)
        $c = /Version: GnuPG v\d+\.\d+\.\d+/ ascii
        // program name of --version in the releases whose armor header has the full version
        $d = /gpgv? \(GnuPG\)/ ascii
    condition:
        // keys, signatures, and signed files exported by GnuPG carry the armor header too, also embedded in programs
        $a or $b or ($c and $d and uint32(0) == 0x464c457f)
}
