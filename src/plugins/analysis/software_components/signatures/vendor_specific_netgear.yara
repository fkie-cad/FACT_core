rule smart_wizzard
{
	meta:
		software_name = "Netgear Smart Wizzard"
		open_source = false
		website = "https://www.netgear.com/"
		description = "Setup assistent"
		no_text_file = true
	strings:
		$a = /Netgear Smart Wizard \d+\.\d+/ nocase ascii wide
	condition:
		$a
}
