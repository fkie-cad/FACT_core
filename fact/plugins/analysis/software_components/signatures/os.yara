rule VxWorks
{
	meta:
		software_name = "VxWorks"
		open_source = false
		website = "http://www.windriver.com/products/vxworks/"
		description = "Real Time Operating System by WindRiver"
    strings:
        $b = /VxWorks[ -]?\d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $b and no_text_file
}

rule WindRiverLinux
{
	meta:
		software_name = "Wind River Linux"
		open_source = false
		website = "http://windriver.com/products/linux/"
		description = "Operating system for embedded devices based on Linux"
    strings:
        $b = /wrlinux-\d+\.\d+/ nocase ascii wide
    condition:
        $b and no_text_file
}

rule LynxOS
{
	meta:
		software_name = "LynxOS"
		open_source = false
		website = "http://www.lynx.com/products/real-time-operating-systems/lynxos-rtos/"
		description = "Operating system for embedded devices"
    strings:
        $b = /LynxOS \d+\.\d+/ nocase ascii wide
    condition:
        $b and no_text_file
}

rule OpenWrt
{
	meta:
		software_name = "OpenWrt"
		open_source = true
		website = "https://openwrt.org/"
		description = "Linux based operating system for home routers"
    strings:
        $b = /([a-zA-Z]+ )?OpenWrt Linux-\d+.\d+\.\d+/ nocase ascii wide
    condition:
        $b and no_text_file
}

rule FireOS
{
	meta:
		software_name = "Fire OS"
		open_source = true
		website = "https://developer.amazon.com/android-fireos"
		description = "Linux (Android) based operating system used on Amazon devices"
	strings:
		$a = /ro.build.version.name=Fire OS \d+\.\d+(\.\d+)?(\.\d+)?/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule LinuxKernel
{
	meta:
		software_name = "Linux Kernel"
		open_source = true
		website = "http://www.kernel.org"
		description = "The Linux Kernel"
    strings:
		$safe_condition = /Linux version \d\.\d{1,2}\.\d{1,3}(-[\d\w.-]+)?/ nocase ascii wide

	condition:
		$safe_condition and no_text_file

/* tmporarly removed due to too many false positives */
/*
        $a = /[2-4]\.\d\d?\.\d\d?-[a-z_][a-z\-_]+/ nocase ascii wide
        $b = /gcc-[2-4]\.\d\d?\.\d\d?-[a-z_][a-z\-_]+/ nocase ascii wide

    condition:
        $a and not $b
*/
}

rule CiscoIOS
{
	meta:
		software_name = "Cisco IOS"
		open_source = false
		website = "https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-technologies/index.html"
		description = "Cisco Internetwork Operating System"
	strings:
		$a = "CW_SYSDESCR$Cisco IOS Software"
		$b = /Cisco IOS Software,[A-Za-z0-9 .()-]+, Version [^,]+,/ ascii
	condition:
		($a or $b) and no_text_file
}

rule ThreadX
{
	meta:
		software_name = "ThreadX"
		open_source = false
		website = "https://rtos.com/solutions/threadx/real-time-operating-system/"
		description = "Real Time Operating System"
	strings:
		$a = /ThreadX [a-z\/ 1-9_]+ [a-z]?\d+\.\d+(\.\d+)?(\.\d+)?/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule MicroC_OS {
	meta:
		software_name = "MicroC/OS"
		open_source = false
		website = "https://www.micrium.com/rtos/"
		description = "Real Time Operating System by Micrium"

    strings:
        $a = /Micrium ?OS/ nocase
        $b = /(\xc2\xb5|u|micro)c\/os-?[i]{0,3}/ nocase

    condition:
        ($a or $b) and no_text_file
}

rule Contiki
{
	meta:
		software_name = "Contiki-OS"
		open_source = true
		website = "http://www.contiki-os.org/"
		description = "Real Time Operating System"
	strings:
		$a = /Contiki\/\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule eCos
{
	meta:
		software_name = "eCos"
		open_source = false
		website = "https://www.ecoscentric.com"
		description = "Real Time Operating System"
		format_string = true
	strings:
		$a = "eCos Release: %d.%d.%d" nocase ascii wide
	condition:
		$a and no_text_file
}
