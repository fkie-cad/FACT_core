rule lighttpd {
	meta:
		software_name = "lighttpd"
		open_source = true
		website = "https://www.lighttpd.net/"
		description = "Lighttpd is a web-server optimized for low memory and cpu usage."
	strings:
		$a = /lighttpd[-\/]\d+\.\d+\.\d+/ ascii
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

rule mini_httpd
{
	meta:
		software_name = "mini_httpd"
		open_source = true
		website = "https://acme.com"
		description = "small HTTP server"
	strings:
		$a = /mini_httpd\/\d\.\d+ \d{2}[a-z]{3}\d{4}/ ascii wide
	condition:
		$a and no_text_file
}

rule nginx
{
	meta:
		software_name = "nginx"
		open_source = true
		website = "https://www.nginx.com/"
		description = "Web-Server"
	strings:
		$a = /nginx version: nginx\/\d+\.\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule eCosWebServer
{
	meta:
		software_name = "eCos Embedded Web Server"
		open_source = true
		website = "https://www.ecoscentric.com"
		description = "Web-Server"
		format_string = true
	strings:
		$a = "eCos Embedded Web Server" nocase ascii wide
		$b = "Server: %s" nocase ascii wide
	condition:
		$a and $b and no_text_file
}
