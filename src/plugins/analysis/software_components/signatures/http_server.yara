rule lighttpd
{
	meta:
		software_name = "lighttpd"
		open_source = true
		website = "https://www.lighttpd.net/"
		description = "Lighttpd is a web-server optimized for low memory and cpu usage."
	strings:
		$a = /lighttpd-\d+\.\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule GoAhead
{
	meta:
		software_name = "GoAhead"
		open_source = true
		website = "http://embedthis.com/goahead/"
		description = "Web-Server"
	strings:
		$a = /GoAhead-Webs/ nocase ascii wide
	condition:
		$a and no_text_file
}
