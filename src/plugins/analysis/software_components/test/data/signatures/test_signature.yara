rule OS1
{
	meta:
		software_name = "OS1"
		open_source = false
		website = ""
		description = ""
    strings:
        $b = ""
    condition:
        $b and no_text_file
}

rule OS2
{
	meta:
		software_name = "OS2"
		open_source = false
		website = ""
		description = ""
    strings:
        $b = ""
    condition:
        $b and no_text_file
}