rule VxWorks
{
	meta:
		software_name = "VxWorks"
		open_source = false
		website = "http://www.windriver.com/products/vxworks/"
		description = "Operating system for embedded devices"
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
		$a
}

rule LinuxKernel
{
	meta:
		software_name = "Linux Kernel"
		open_source = true
		website = "http://www.kernel.org"
		description = "The Linux Kernel"
    strings:
		$safe_condition = /Linux version [2-4]\.\d\d?\.\d\d?/ nocase ascii wide
		
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
	condition:
		$a
}

rule ThreadX
{
	meta:
		software_name = "ThreadX"
		open_source = false
		website = "https://rtos.com/solutions/threadx/real-time-operating-system/"
		description = "Real Time Operating System"
	strings:
		$a = /ThreadX [a-z\/ 1-9]+ [a-z]?\d+\.\d+(\.\d+)?(\.\d+)?/ nocase ascii wide
	condition:
		$a
}
