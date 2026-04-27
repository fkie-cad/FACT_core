rule siproxd
{
	meta:
		software_name = "Siproxd"
		open_source = true
		website = "http://siproxd.sourceforge.net/"
		description = "Masquerading SIP Proxy Server"
		no_text_file = true
	strings:
		$a = /siproxd-\d+\.\d+\.\d+/ nocase ascii wide
	condition:
		$a
}
