rule secp256r1 {
    meta:
        description = "NIST P-256 elliptic curve parameter set (RFC 5903)"
    strings:
        // numerical form
        $p = {FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF}
        $b = {5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B}
        $n = {FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551}
        $gx = {6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296}
        $gy = {4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5}
        // hex form
        $p_hex = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
        $b_hex = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
        $n_hex = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
        $gx_hex = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
        $gy_hex = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
    condition:
        any of them
}

rule AES_Constants {
    meta:
        description = "AES cipher lookup tables"
    strings:
        // AES encryption substitution table
        $enc_st = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 }
        // AES decryption substitution table
        $dec_st = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb }
        // precalculated AES encryption lookup table
        $enc_lt = { c6 63 63 a5 f8 7c 7c 84 ee 77 77 99 f6 7b 7b 8d ff f2 f2 0d d6 6b 6b bd de 6f 6f b1 91 c5 c5 54 }
        // precalculated AES decryption lookup table
        $dec_lt = { 51 f4 a7 50 7e 41 65 53 1a 17 a4 c3 3a 27 5e 96 3b ab 6b cb 1f 9d 45 f1 ac fa 58 ab 4b e3 03 93 }
    condition:
        any of them
}

rule SMIME_IDs {
    meta:
        description = "Cipher S/MIME object identifiers (RFCs 3447 & 5754)"
    strings:
        $md2 = { 2a 86 48 86 f7 0d 02 02 05 }
        $md5 = { 2a 86 48 86 f7 0d 02 05 05 }
        $sha1 = { 2b 0e 03 02 1a 05 00 04 14 }
        $sha256 = { 60 86 48 01 65 03 04 02 01 }
        $sha384 = { 60 86 48 01 65 03 04 02 02 }
        $sha512 = { 60 86 48 01 65 03 04 02 03 }
        $sha224 = { 60 86 48 01 65 03 04 02 04 }

        $dsa_sha224 = { 60 86 48 01 65 03 04 03 01 }
        $dsa_sha256 = { 60 86 48 01 65 03 04 03 02 }

        $rsa_sha224 = { 06 09 2a 86 48 86 f7 0d 01 01 0e 05 00 }
        $rsa_sha256 = { 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 }
        $rsa_sha384 = { 06 09 2a 86 48 86 f7 0d 01 01 0c 05 00 }
        $rsa_sha512 = { 06 09 2a 86 48 86 f7 0d 01 01 0d 05 00 }

        $ecdsa_sha224 = { 06 08 2a 86 48 ce 3d 04 03 01 }
        $ecdsa_sha256 = { 06 08 2a 86 48 ce 3d 04 03 02 }
        $ecdsa_sha384 = { 06 08 2a 86 48 ce 3d 04 03 03 }
        $ecdsa_sha512 = { 06 08 2a 86 48 ce 3d 04 03 04 }
    condition:
        any of them
}

rule Tiger_Hash_Constants {
    meta:
        description = "Tiger hash substitution box constants"
    strings:
        $c1 = { 5E 0C E9 F7 7C B1 AA 02 }
        $c2 = { EC A8 43 E2 03 4B 42 AC }
        $c3 = { D3 FC D5 0D E3 5B CD 72 }
        $c4 = { 3A 7F F9 F6 93 9B 01 6D }
        $c5 = { 93 91 1F D2 FF 78 99 CD }
        $c6 = { E2 29 80 70 C9 A1 73 75 }
        $c7 = { C3 83 2A 92 6B 32 64 B1 }
        $c8 = { 70 58 91 04 EE 3E 88 46 }
        $c9 = { 38 21 A1 05 5A BE A6 E6 }
        $c10 = { 98 7C F8 B4 A5 22 A1 B5 }
        $c11 = { 90 69 0B 14 89 60 3C 56 }
        $c12 = { D5 5D 1F 39 2E CB 46 4C }
        $c13 = { 34 94 B7 C9 DB AD 32 D9 }
        $c14 = { F5 AF 15 20 E4 70 EA 08 }
        $c15 = { F1 8C 47 3E 67 A6 65 D7 }
        $c16 = { 99 8D 27 AB 7E 75 FB C4 }
    condition:
        4 of them
}

rule camellia_constants {
    meta:
        description = "Camellia cipher substitution table constants"
    strings:
        $c1 = { 70 82 2C EC B3 27 C0 E5 E4 85 57 35 EA 0C AE 41 }
        $c2 = { E0 05 58 D9 67 4E 81 CB C9 0B AE 6A D5 18 5D 82 }
        $c3 = { 38 41 16 76 D9 93 60 F2 72 C2 AB 9A 75 06 57 A0 }
        $c4 = { 70 2C B3 C0 E4 57 EA AE 23 6B 45 A5 ED 4F 1D 92 }
    condition:
        all of them
}

rule present_cipher {
    meta:
        description = "PRESENT block cipher substitution table constants"
    strings:
        // substitution box
        $sb = { 0C 05 06 0B 09 00 0A 0D 03 0E 0F 08 04 07 01 02 }
        // inverse substitution box
        $isb = { 05 0E 0F 08 0C 01 02 0D 0B 04 06 03 00 07 09 0A }
    condition:
        all of them
}
