rule VxWorks
{
	meta:
		software_name = "VxWorks"
		open_source = false
		website = "http://www.windriver.com/products/vxworks/"
		description = "Real Time Operating System by WindRiver"
		no_text_file = true
    strings:
        $b = /VxWorks[ -]?\d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $b
}

rule WindRiverLinux
{
	meta:
		software_name = "Wind River Linux"
		open_source = false
		website = "http://windriver.com/products/linux/"
		description = "Operating system for embedded devices based on Linux"
		no_text_file = true
    strings:
        $b = /wrlinux-\d+\.\d+/ nocase ascii wide
    condition:
        $b
}

rule LynxOS
{
	meta:
		software_name = "LynxOS"
		open_source = false
		website = "http://www.lynx.com/products/real-time-operating-systems/lynxos-rtos/"
		description = "Operating system for embedded devices"
		no_text_file = true
    strings:
        $b = /LynxOS \d+\.\d+/ nocase ascii wide
    condition:
        $b
}

rule OpenWrt
{
	meta:
		software_name = "OpenWrt"
		open_source = true
		website = "https://openwrt.org/"
		description = "Linux based operating system for home routers"
		no_text_file = true
    strings:
        $b = /([a-zA-Z]+ )?OpenWrt Linux-\d+.\d+\.\d+/ nocase ascii wide
    condition:
        $b
}

rule FireOS
{
	meta:
		software_name = "Fire OS"
		open_source = true
		website = "https://developer.amazon.com/android-fireos"
		description = "Linux (Android) based operating system used on Amazon devices"
		no_text_file = true
	strings:
		$a = /ro.build.version.name=Fire OS \d+\.\d+(\.\d+)?(\.\d+)?/ nocase ascii wide
	condition:
		$a
}

rule LinuxKernel
{
	meta:
		software_name = "Linux Kernel"
		open_source = true
		website = "http://www.kernel.org"
		description = "The Linux Kernel"
		no_text_file = true
    strings:
		$safe_condition = /Linux version \d\.\d{1,2}\.\d{1,3}(-[\d\w.-]+)?/ nocase ascii wide

	condition:
		$safe_condition

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
		no_text_file = true
	strings:
		$a = "CW_SYSDESCR$Cisco IOS Software"
		$b = /Cisco IOS Software,[A-Za-z0-9 .()-]+, Version [^,]+,/ ascii
	condition:
		$a or $b
}

rule ThreadX
{
	meta:
		software_name = "ThreadX"
		open_source = false
		website = "https://rtos.com/solutions/threadx/real-time-operating-system/"
		description = "Real Time Operating System"
		no_text_file = true
	strings:
		$a = /ThreadX [a-z\/ 1-9_]+ [a-z]?\d+\.\d+(\.\d+)?(\.\d+)?/ nocase ascii wide
	condition:
		$a
}

rule MicroC_OS {
	meta:
		software_name = "MicroC/OS"
		open_source = false
		website = "https://www.micrium.com/rtos/"
		description = "Real Time Operating System by Micrium"
		no_text_file = true

    strings:
        $a = /Micrium ?OS/ nocase
        $b = /(\xc2\xb5|u|micro)c\/os-?[i]{0,3}/ nocase

    condition:
        $a or $b
}

rule Contiki
{
	meta:
		software_name = "Contiki-OS"
		open_source = true
		website = "http://www.contiki-os.org/"
		description = "Real Time Operating System"
		no_text_file = true
	strings:
		$a = /Contiki\/\d+\.\d+/ nocase ascii wide
	condition:
		$a
}

rule eCos
{
	meta:
		software_name = "eCos"
		open_source = false
		website = "https://www.ecoscentric.com"
		description = "Real Time Operating System"
		format_string = true
		no_text_file = true
	strings:
		$a = "eCos Release: %d.%d.%d" nocase ascii wide
	condition:
		$a
}
