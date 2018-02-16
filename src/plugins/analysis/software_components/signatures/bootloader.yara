rule UBoot
{
	meta:
		software_name = "U-Boot"
		open_source = true
		website = "http://www.denx.de/wiki/U-Boot"
		description = "The Universal Boot Loader"
    strings:
        $a = /U-Boot \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}
