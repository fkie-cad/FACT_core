rule siproxd
{
	meta:
		software_name = "Siproxd"
		open_source = true
		website = "http://siproxd.sourceforge.net/"
		description = "Masquerading SIP Proxy Server"
	strings:
		$a = /siproxd-\d+\.\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}