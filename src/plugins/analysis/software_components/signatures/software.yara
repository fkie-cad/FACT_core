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

rule file_libmagic {
	meta:
		software_name = "file"
		open_source = true
		website = "https://www.darwinsys.com/file/"
		description = "file type guesser"
		// versions are stored as decimal int with three digits
		// (first digit: major version, remaining two digits: minor version)
		version_regex = "\\d{3}"
		_version_function = "magic_version"
		// sub XYY -> X.YY
		_sub_regex = "[\"(\\\\d)(\\\\d{2})\", \"\\\\1.\\\\2\"]"
	strings:
	    // see https://github.com/file/file/blob/f7d05cade99ff4819b4de70445511037000f6b14/src/magic.c#L607
		$a =  "magic_version" nocase ascii
	condition:
		$a and no_text_file
}

rule OPKG {
	meta:
		software_name = "OPKG"
		open_source = true
		website = "https://openwrt.org/docs/guide-user/additional-software/opkg"
		description = "Opkg lightweight embedded package manager"
		// the version is not stored as a number; instead a git commit hash and a date is used: [hash] ([YYYY-MM-DD])
		version_regex = "[0-9a-z]{40} \\(\\d{4}-\\d{2}-\\d{2}\\)"
	strings:
	    // see https://github.com/openwrt/opkg-lede/blob/38eccbb1fd694d4798ac1baf88f9ba83d1eac616/src/opkg-cl.c#L158
		$a =  "opkg version %s\n" nocase ascii
		$b =  /[0-9a-z]{40} \(\d{4}-\d{2}-\d{2}\)/ ascii
	condition:
		$a and $b and no_text_file
}

rule Perl
{
	meta:
		software_name = "Perl"
		open_source = true
		website = "https://www.perl.org/"
		description = "Perl scripting language interpreter"
	strings:
		$a = "This is perl"
		$b = /perl\d?\/\d\.\d+\.\d+/ ascii
	condition:
		$a and $b and no_text_file
}

rule PHP
{
	meta:
		software_name = "PHP"
		open_source = true
		website = "https://www.php.net/"
		description = "PHP scripting language interpreter"
	strings:
		$a = "PHP %s (%s) (built: %s %s)"
		$b = /X-Powered-By: PHP\/\d+\.\d+\.\d+/ ascii
	condition:
		($a or $b) and no_text_file
}

rule Realtek_SDK
{
	meta:
		software_name = "Realtek SDK"
		open_source = false
		website = "http://www.realtek.com.tw"
		description = "Realtek IoT Software Development Kit"
	strings:
		$a = "MiniIGD %s (%s)."
	condition:
		$a and no_text_file
}

rule redis
{
    meta:
        software_name = "redis"
		open_source = true
		website = "https://redis.io/"
		description = "Redis is an open source in-memory data structure store"
		format_string = true
    strings:
        $a = "redis_version:%s"
        $b = "Redis version=%s"
        $c = "Redis needs to enable the AOF"
    condition:
        ($a or $b) and $c and no_text_file
}

