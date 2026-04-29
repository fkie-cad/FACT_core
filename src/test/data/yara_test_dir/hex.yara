rule test_hex_rule {
    strings:
        $c = { 01 23 45 67 }
    condition:
        $c
}
