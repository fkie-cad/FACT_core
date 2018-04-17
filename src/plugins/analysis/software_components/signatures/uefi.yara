rule EFIshell
{
	meta:
		software_name = "EFI Shell"
		open_source = true
		website = "https://www.tianocore.org/"
		description = "UEFI Shell"
    strings:
        $a = /EFI Shell Version \d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule BootAgent
{
	meta:
		software_name = "Intel Boot Agent"
		open_source = true
		website = "http://www.intel.com"
		description = "Intel Boot Agent"
    strings:
        $a = /Boot Agent CL v\d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $a and no_text_file
}
