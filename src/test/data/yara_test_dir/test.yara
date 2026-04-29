rule test_string_rule {
    strings:
        $a = "Testblubblah"
    condition:
        $a
}
