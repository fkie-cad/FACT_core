/* this a template for software component rules 

rule SHORT_NAME_OF_SOFTWARE
{
	meta:
		software_name = "NAME OF SOFTWARE"
		open_source = true / false
		website = "URL OF SOFTWARE'S WEBSITE OR GIT"
		description = "SHORT DESCRIPTION OF SOFTWARE"
    strings:
        $a = /REGULAR_EXPRESSION/ nocase ascii wide
    condition:
        $a
}

*/

rule Bash
{
	meta:
		software_name = "Bash"
		open_source = true
		website = "https://www.gnu.org/software/bash/"
		description = "Linux Shell"
	strings:
		$a = /Bash version \d+\.\d+(.\d+)?/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule BusyBox
{
	meta:
		software_name = "BusyBox"
		open_source = true
		website = "http://www.busybox.net/"
		description = "BusyBox combines tiny versions of many common UNIX utilities into a single small executable."
	strings:
		$a = /BusyBox v\d+\.\d+(.\d+)?/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule jQuery
{
	meta:
		software_name = "jQuery"
		open_source = true
		website = "http://www.jquery.com"
		description = "java script library"
	strings:
		$a =  /jQuery v\d+\.\d+/ nocase ascii wide
	condition:
		$a
}

