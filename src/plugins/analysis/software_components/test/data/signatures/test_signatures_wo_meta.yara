rule missing_meta_1
{
	meta:
		software_name = "missing meta"
		open_source = false
    strings:
        $a = "a"
    condition:
        $a
}

rule missing_meta_2
{
    strings:
        $a = "a"
    condition:
        $a
}
