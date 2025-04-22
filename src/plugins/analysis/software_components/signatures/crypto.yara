rule CryptoPP {
    meta:
        software_name = "Crypto++"
        open_source = true
        website = "https://www.cryptopp.com/"
        description ="Free C++ library for cryptographic schemes library"
    strings:
        $a = "this object doesn't support resynchronization"
        $b = "Clone() is not implemented yet."
        $c = "CryptoMaterial: this object does not support precomputation"
        $d = "BufferedTransformation: this object doesn't allow input"
        $e = "StreamTransformation: this object doesn't support random access"
        $f = "BaseN_Encoder: Log2Base must be between 1 and 7 inclusive"
        $g = "RandomNumberGenerator: IncorporateEntropy not implemented"
        $h = "block size of underlying block cipher is not 16"
        $i = "DigestSize must be 4, 6, 8, 10, 12, 14, or 16"
    condition:
        3 of them
}

rule LibreSSL {
    meta:
        software_name = "LibreSSL"
        open_source = true
        website = "https://www.libressl.org/"
        description ="LibreSSL is a version of the TLS/crypto stack forked from OpenSSL in 2014"
    strings:
        $a = /LibreSSL \d\.\d{1,2}\.\d{1,2}/
    condition:
        $a and no_text_file
}

rule Mbed_TLS {
    meta:
        software_name = "Mbed TLS"
        open_source = true
        website = "https://www.trustedfirmware.org/projects/mbed-tls/"
        description ="C library implementing cryptographic primitives and protocols (formerly known as PolarSSL)"
    strings:
        // fixme: it is possible to build a smaller variant of the library without this string
        $a = /([Mm]bed TLS|PolarSSL) \d\.\d{1,2}\.\d{1,2}/
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
        description = "SSL library"
    strings:
        $a = /SSLeay \d+\.\d+\.\d+[a-z]?/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule wolfSSL {
    meta:
        software_name = "wolfSSL"
        open_source = true
        website = "https://www.wolfssl.com/"
        description ="Embedded SSL/TLS Library (formerly CyaSSL)"
        _version_function = "wolfSSL_lib_version"
    strings:
        // the function which yields the version as string (available since version 3.6.0)
        $a = "wolfSSL_lib_version"
        // error strings (should be in all versions)
        $b = "handshake layer not ready yet, complete first"
        $c = "non-blocking socket wants data to be read"
        $d = "error during rsa priv op"
    condition:
        $a or ($b and $c and $d) and no_text_file
}
