rule OS1
{
	meta:
		software_name = "OS1"
		open_source = false
		website = ""
		description = ""
		no_text_file = true
    strings:
        $b = "OS1"
    condition:
        $b
}

rule OS2
{
	meta:
		software_name = "OS2"
		open_source = false
		website = ""
		description = ""
		no_text_file = true
    strings:
        $b = "OS2"
    condition:
        $b
}
