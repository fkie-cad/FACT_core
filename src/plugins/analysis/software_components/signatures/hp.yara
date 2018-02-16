rule ChaiVM
{
	meta:
		software_name = "HP ChaiVM"
		open_source = false
		website = "https://www.hp.com"
		description ="Embedded virutal machine for java applications."
    strings:
        $a = /ChaiVM \d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $a and no_text_file
}