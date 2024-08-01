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

rule HP_FTP_print_server
{
	meta:
		software_name = "HP FTP Print Server"
		open_source = false
		website = "https://www.hp.com"
		description ="HP Print Server"
    strings:
        $a = /Hewlett-Packard FTP Print Server Version \d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}
