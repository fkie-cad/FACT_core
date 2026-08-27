rule test_ascii_string {
    strings:
        $b = "hello world"
    condition:
        $b
}
