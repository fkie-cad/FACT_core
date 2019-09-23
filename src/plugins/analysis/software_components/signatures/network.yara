rule avahi
{
	meta:
		software_name = "Avahi"
		open_source = true
		website = "http://www.avahi.org/"
		description = "Avahi is a system which facilitates service discovery on a local network via the mDNS/DNS-SD protocol suite."
    strings:
        $a = /avahi-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule Bftpd
{
	meta:
		software_name = "Bftpd"
		open_source = true
		website = "http://bftpd.sourceforge.net/"
		description = "FTP Server"
    strings:
        $a = /bftpd-V\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule cadaver
{
	meta:
		software_name = "cadaver"
		open_source = true
		website = "http://www.webdav.org/cadaver/"
		description = "WebDAV client"
    strings:
        $a = /cadaver \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule CUPS
{
	meta:
		software_name = "CUPS"
		open_source = true
		website = "http://www.cups.org/"
		description = "Print server"
    strings:
        $a = /CUPS v\d+\.\d+\.\d+/ nocase ascii wide
        $b = /cups-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        any of them and no_text_file
}

rule curl
{
	meta:
		software_name = "curl"
		open_source = true
		website = "https://curl.haxx.se/"
		description = "command line network client"
    strings:
        $a = /curl\/\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule dhcp6c
{
	meta:
		software_name = "dhcp6c"
		open_source = true
		website = "https://fedorahosted.org/dhcpv6/"
		description = "DHCP Client Daemon for IPv6"
    strings:
        $a = /dhcp6c-V\d+\.\d+/ nocase ascii wide
    condition:
    	$a and no_text_file
}


rule dhcp6s
{
	meta:
		software_name = "dhcp6s"
		open_source = true
		website = "https://fedorahosted.org/dhcpv6/"
		description = "DHCP Server Daemon for IPv6"
    strings:
        $a = /dhcp6s-V\d+\.\d+/ nocase ascii wide
    condition:
    	$a and no_text_file
}

rule dnsmasq
{
	meta:
		software_name = "Dnsmasq"
		open_source = true
		website = "http://www.thekelleys.org.uk/dnsmasq/doc.html"
		description = "DNS and DHCP Server"
	strings:
		$a = /dnsmasq-\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule Dropbear
{
	meta:
		software_name = "Dropbear SSH"
		open_source = true
		website = "https://matt.ucc.asn.au/dropbear/dropbear.html"
		description = "SSH Server and Client"
    strings:
        $a = /dropbear_\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule hostapd
{
	meta:
		software_name = "hostapd"
		open_source = true
		website = "https://w1.fi/hostapd/"
		description = "hostapd is a user space daemon for access point and authentication servers."
    strings:
        $a = /hostapd v\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule iptables
{
	meta:
		software_name = "iptables"
		open_source = true
		website = "http://www.netfilter.org/projects/iptables/index.html"
		description = "iptables is the userspace command line program used to configure the Linux 2.4.x and later packet filtering ruleset."
    strings:
        $a = /iptables-\d+\.\d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule libpcap
{
	meta:
		software_name = "libpcap"
		open_source = true
		website = "http://www.tcpdump.org/"
		description = "Library for network traffic capturing"
	strings:
		$a = /libpcap version \d+\.\d+.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule libupnp
{
	meta:
		software_name = "libupnp"
		open_source = true
		website = "http://pupnp.sourceforge.net"
		description = "Portable upnp library"
	strings:
		$a = /libupnp-\d+\.\d+.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule MiniUPnP
{
	meta:
		software_name = "MiniUPnP"
		open_source = true
		website = "http://miniupnp.free.fr/"
		description = "UPnP Software"
	strings:
		$a = /MiniUPNP \d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule netatalk
{
	meta:
		software_name = "Netatalk"
		open_source = true
		website = "http://netatalk.sourceforge.net/"
		description = "AFP fileserver"
	strings:
		$a =  /netatalk-\d+.\d+.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule NicheStack
{
	meta:
		software_name = "NicheStack"
		open_source = false
		website = "http://www.iniche.com/source-code/networking-stack/nichestack.php"
		description = "embedded TCP/IP stack from InterNiche"
    strings:
        $a = /InterNiche Portable TCP\/IP[a-zA-Z ]{,30}, v\d(\.\d)?/
    condition:
        $a and no_text_file
}

rule OpenSSH
{
	meta:
		software_name = "OpenSSH"
		open_source = true
		website = "http://www.openssh.com"
		description = "SSH library"
    strings:
        $a = /OpenSSH(_\d+\.\d+(\.\d)?\x00)?/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule pptpClient
{
	meta:
		software_name = "pptp-client"
		open_source = true
		website = "http://pptpclient.sourceforge.net/"
		description = "PPTP Client is a Linux, FreeBSD, NetBSD and OpenBSD client for the proprietary Microsoft Point-to-Point Tunneling Protocol, PPTP."
    strings:
        $a = /pptp version \d+\.\d+\.\d/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule ProFTPD
{
	meta:
		software_name = "ProFTPD"
		open_source = true
		website = "http://www.proftpd.org/"
		description = "Highly configurable FTP Server"
    strings:
        $a = /ProFTPD \d+\.\d+\.\d/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule radvd
{
	meta:
		software_name = "radvd"
		open_source = true
		website = "http://www.litech.org/radvd/"
		description = "IPv6 Router Advertisement Daemon"
	strings:
		$a = /radvd-\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule readymedia
{
	meta:
		software_name = "ReadyMedia (minidlna)"
		open_source = true
		website = "http://sourceforge.net/projects/minidlna/"
		description = "ReadyMedia is a simple media server software"
	strings:
		$a = /ReadyDLNA \d+\.\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule samba
{
	meta:
		software_name = "Samba"
		open_source = true
		website = "https://www.samba.org/"
		description = "Samba is the standard Windows interoperability suite of programs for Linux and Unix."
	strings:
		$a =  /samba-\d+.\d+.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule telnetd
{
	meta:
		software_name = "telnetd"
		open_source = true
		website = "https://www.gnu.org/software/inetutils/"
		description = "DARPA TELNET protocol server (part of GNU network utilities)"
	strings:
		$a = /telnetd-V\d+\.\d+/ nocase ascii wide
	condition:
		$a and no_text_file
}

rule udhcp
{
	meta:
		software_name = "udhcp"
		open_source = true
		website = "https://busybox.net/"
		description = "udhcp is a lightweight dhcp server/client. It is part of Busybox by now."
    strings:
        $a = /udhcp \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule wpa_supplicant
{
	meta:
		software_name = "wpa_supplicant"
		open_source = true
		website = "https://w1.fi/wpa_supplicant/"
		description = "wpa_supplicant is a WPA Supplicant for Linux and other OSes with support for WPA and WPA2."
    strings:
        $a = /wpa_supplicant v\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule xl2tpd
{
	meta:
		software_name = "xl2tpd"
		open_source = false
		website = "https://www.xelerance.com/services/software/xl2tpd/"
		description = "Layer 2 Tunneling Protocol (L2TP) daemon"
    strings:
        $a = /xl2tpd-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}
