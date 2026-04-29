rule avahi
{
	meta:
		software_name = "Avahi"
		open_source = true
		website = "http://www.avahi.org/"
		description = "Avahi is a system which facilitates service discovery on a local network via the mDNS/DNS-SD protocol suite."
		no_text_file = true
    strings:
        $a = /avahi-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule Bftpd
{
	meta:
		software_name = "Bftpd"
		open_source = true
		website = "http://bftpd.sourceforge.net/"
		description = "FTP Server"
		no_text_file = true
    strings:
        $a = /bftpd-V\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule cadaver
{
	meta:
		software_name = "cadaver"
		open_source = true
		website = "http://www.webdav.org/cadaver/"
		description = "WebDAV client"
		no_text_file = true
    strings:
        $a = /cadaver \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule CUPS
{
	meta:
		software_name = "CUPS"
		open_source = true
		website = "http://www.cups.org/"
		description = "Print server"
		no_text_file = true
    strings:
        $a = /CUPS v\d+\.\d+\.\d+/ nocase ascii wide
        $b = /cups-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        any of them
}

rule curl
{
	meta:
		software_name = "curl"
		open_source = true
		website = "https://curl.haxx.se/"
		description = "command line network client"
		no_text_file = true
    strings:
        $a = /curl\/\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule dhcp6c
{
	meta:
		software_name = "dhcp6c"
		open_source = true
		website = "https://fedorahosted.org/dhcpv6/"
		description = "DHCP Client Daemon for IPv6"
		no_text_file = true
    strings:
        $a = /dhcp6c-V\d+\.\d+/ nocase ascii wide
    condition:
    	$a
}


rule dhcp6s
{
	meta:
		software_name = "dhcp6s"
		open_source = true
		website = "https://fedorahosted.org/dhcpv6/"
		description = "DHCP Server Daemon for IPv6"
		no_text_file = true
    strings:
        $a = /dhcp6s-V\d+\.\d+/ nocase ascii wide
    condition:
    	$a
}

rule dnsmasq
{
	meta:
		software_name = "Dnsmasq"
		open_source = true
		website = "http://www.thekelleys.org.uk/dnsmasq/doc.html"
		description = "DNS and DHCP Server"
		format_string = true
		no_text_file = true
	strings:
		$a = /dnsmasq-\d+\.\d+/ nocase ascii wide
		$b = "dnsmasq-%s"
		$c = "dnsmasq version %s"
	condition:
		$a or $b or $c
}

rule Dropbear {
	meta:
		software_name = "Dropbear SSH"
		open_source = true
		website = "https://matt.ucc.asn.au/dropbear/dropbear.html"
		description = "SSH Server and Client"
		format_string = true
		no_text_file = true
    strings:
        $a = /dropbear_\d+\.\d+/ nocase ascii
        $b = "Dropbear SSH client v%s" ascii
        $c = "Dropbear SSH multi-purpose v%s" ascii
        $d = "Dropbear v%s" ascii
        $e = "Dropbear server v%s" ascii
    condition:
        any of them
}

rule FRRouting
{
	meta:
		software_name = "FRRouting"
		open_source = true
		website = "https://frrouting.org/"
		description = "A free and open source Internet routing protocol suite"
		no_text_file = true
    strings:
        $a = /FRRouting \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule hostapd
{
	meta:
		software_name = "hostapd"
		open_source = true
		website = "https://w1.fi/hostapd/"
		description = "hostapd is a user space daemon for access point and authentication servers."
		no_text_file = true
    strings:
        $a = /hostapd v\d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $a
}

rule iptables
{
	meta:
		software_name = "iptables"
		open_source = true
		website = "http://www.netfilter.org/projects/iptables/index.html"
		description = "iptables is the userspace command line program used to configure the Linux 2.4.x and later packet filtering ruleset."
		no_text_file = true
    strings:
        $a = /iptables-\d+\.\d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $a
}

rule l2tpd
{
	meta:
		software_name = "l2tpd"
		open_source = true
		website = "http://l2tpd.sourceforge.net/"
		description = "the original Layer 2 Tunnelling Protocol Daemon"
		no_text_file = true
    strings:
        $a = /l2tpd version 0.\d+/ ascii
    condition:
        $a
}

rule libpcap
{
	meta:
		software_name = "libpcap"
		open_source = true
		website = "http://www.tcpdump.org/"
		description = "Library for network traffic capturing"
		no_text_file = true
	strings:
		$a = /libpcap version \d+\.\d+.\d+/ nocase ascii wide
	condition:
		$a
}

rule libupnp
{
	meta:
		software_name = "libupnp"
		open_source = true
		website = "http://pupnp.sourceforge.net"
		description = "Portable upnp library"
		no_text_file = true
	strings:
		$a = /libupnp-\d+\.\d+.\d+/ nocase ascii wide
	condition:
		$a
}

rule MiniUPnP
{
	meta:
		software_name = "MiniUPnP"
		open_source = true
		website = "http://miniupnp.free.fr/"
		description = "UPnP Software"
		no_text_file = true
	strings:
		$a = /MiniUPNP \d+\.\d+/ nocase ascii wide
	condition:
		$a
}

rule netatalk
{
	meta:
		software_name = "Netatalk"
		open_source = true
		website = "http://netatalk.sourceforge.net/"
		description = "AFP fileserver"
		no_text_file = true
	strings:
		$a =  /netatalk-\d+.\d+.\d+/ nocase ascii wide
	condition:
		$a
}

rule NicheStack
{
	meta:
		software_name = "NicheStack"
		open_source = false
		website = "http://www.iniche.com/source-code/networking-stack/nichestack.php"
		description = "embedded TCP/IP stack from InterNiche"
		no_text_file = true
    strings:
        $a = /InterNiche Portable TCP\/IP[a-zA-Z ]{,30}, v\d(\.\d)?/
    condition:
        $a
}

rule netcat_traditional
{
	meta:
		software_name = "netcat-traditional"
		open_source = true
		website = "https://nc110.sourceforge.io/"
		description = "TCP/IP swiss army knife"
		no_text_file = true
    strings:
        $a = "nc -h for help"
        $b = /\[v1.\d+-?\d*\.?\d*]/
    condition:
        $a and $b
}

rule NTP
{
	meta:
		software_name = "NTP"
		open_source = true
		website = "http://www.ntp.org/"
		description = "NTP is a protocol designed to synchronize the clocks of computers over a network"
		no_text_file = true
    strings:
        $a = /NTP daemon program - Ver. \d+\.\d+\.\d+p?\d*/
        $b = /ntpd \d+.\d+.\d+p?\d*/
    condition:
        $a or $b
}

rule OpenSSH
{
	meta:
		software_name = "OpenSSH"
		open_source = true
		website = "http://www.openssh.com"
		description = "SSH library"
		no_text_file = true
    strings:
        $a = /OpenSSH(_\d+\.\d+(\.\d)?(p\d)?[ \x00])?/ nocase ascii wide
    condition:
        $a
}

rule OpenVPN
{
	meta:
		software_name = "OpenVPN"
		open_source = true
		website = "https://pupnp.sourceforge.io"
		description = "open source virtual private network (VPN) system"
	strings:
		$a = /OpenVPN \d\.\d+(\.\d+) .{0,100}built on/
	condition:
		$a
}

rule pppd_format_string
{
    meta:
        software_name = "Point-to-Point Protocol daemon"
		open_source = true
		website = "https://ppp.samba.org/"
		description = "ppp (Paul's PPP Package) is an open source package which implements the Point-to-Point Protocol (PPP) on Linux and Solaris systems."
		format_string = true
		no_text_file = true
    strings:
        $a = "pppd %s started by %s, uid %d"
        $b = "pppd version %s"
        $c = "pppd: %s %d"
        $d = "See pppd(8) for more options."
    condition:
        ($a or $b or $c) and $d
}

rule pptpClient
{
	meta:
		software_name = "pptp-client"
		open_source = true
		website = "http://pptpclient.sourceforge.net/"
		description = "PPTP Client is a Linux, FreeBSD, NetBSD and OpenBSD client for the proprietary Microsoft Point-to-Point Tunneling Protocol, PPTP."
		no_text_file = true
    strings:
        $a = /pptp version \d+\.\d+\.\d/ nocase ascii wide
    condition:
        $a
}

rule ProFTPD
{
	meta:
		software_name = "ProFTPD"
		open_source = true
		website = "http://www.proftpd.org/"
		description = "Highly configurable FTP Server"
		no_text_file = true
    strings:
        $a = /ProFTPD \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule Pure_FTPd
{
	meta:
		software_name = "Pure-FTPd"
		open_source = true
		website = "https://www.pureftpd.org/"
		description = "free (BSD), secure, production-quality and standard-conformant FTP server"
		no_text_file = true
    strings:
        $a = /pure-ftpd v\d\.\d+\.\d+(\-\d)?/ ascii
    condition:
        $a
}

rule Quagga
{
	meta:
		software_name = "Quagga"
		open_source = true
		website = "https://www.quagga.net/"
		description = "network routing software suite (fork of Zebra)"
		no_text_file = true
    strings:
        $a = /Hello, this is Quagga \(version .+\)./ nocase ascii wide
    condition:
        $a
}

rule radvd
{
	meta:
		software_name = "radvd"
		open_source = true
		website = "http://www.litech.org/radvd/"
		description = "IPv6 Router Advertisement Daemon"
		no_text_file = true
	strings:
		$a = /radvd-\d+\.\d+/ nocase ascii wide
	condition:
		$a
}

rule radvd_format_string
{
	meta:
		software_name = "radvd"
		open_source = true
		website = "http://www.litech.org/radvd/"
		description = "IPv6 Router Advertisement Daemon"
		format_string = true
		no_text_file = true
	strings:
	    $a = "radvd already running, terminating."
        $b = "version %s started"
        $c = "Version: %s"
	condition:
        $a and ($b or $c)
}

rule readymedia
{
	meta:
		software_name = "ReadyMedia (minidlna)"
		open_source = true
		website = "http://sourceforge.net/projects/minidlna/"
		description = "ReadyMedia is a simple media server software"
		no_text_file = true
	strings:
		$a = /ReadyDLNA \d+\.\d+\.\d+/ nocase ascii wide
	condition:
		$a
}

rule RP_L2TP
{
	meta:
		software_name = "RP-L2TP"
		open_source = true
		website = "https://sourceforge.net/projects/rp-l2tp/"
		description = "user-space implementation of L2TP for Linux and other UNIX systems"
		format_string = true
		version_regex = "0\\.\\d"
		no_text_file = true
    strings:
        $a = /l2tpd Version %s Copyright \d+ Roaring Penguin/ ascii
    condition:
        $a
}

rule samba
{
	meta:
		software_name = "Samba"
		open_source = true
		website = "https://www.samba.org/"
		description = "Samba is the standard Windows interoperability suite of programs for Linux and Unix."
		no_text_file = true
	strings:
		$a =  /samba-\d+.\d+.\d+/ nocase ascii wide
	condition:
		$a
}

rule squid
{
	meta:
		software_name = "Squid"
		open_source = true
		website = "http://www.squid-cache.org/"
		description = "Squid is a full-featured HTTP proxy cache"
		no_text_file = true
	strings:
		$a =  /squid\/\d+.\d+.\d+/ nocase ascii wide
	condition:
		$a
}

rule strongSwan
{
	meta:
		software_name = "strongSwan"
		open_source = true
		website = "https://www.strongswan.org/"
		description = "OpenSource IPsec-based VPN Solution"
		no_text_file = true
	strings:
		$a =  /strongSwan \d+.\d+.\d+/ nocase ascii wide
	condition:
		$a
}

rule telnetd
{
	meta:
		software_name = "telnetd"
		open_source = true
		website = "https://www.gnu.org/software/inetutils/"
		description = "DARPA TELNET protocol server (part of GNU network utilities)"
		no_text_file = true
	strings:
		$a = /telnetd-V\d+\.\d+/ nocase ascii wide
	condition:
		$a
}

rule tinyproxy
{
	meta:
		software_name = "tinyproxy"
		open_source = true
		website = "http://tinyproxy.github.io/"
		description = "lightweight http(s) proxy daemon"
		no_text_file = true
	strings:
		$a = /(Proxy-agent|Server): tinyproxy\/\d\.\d+\.\d+(pre\d|rc\d|-rc\d)?/ ascii
	condition:
		$a
}

rule udhcp
{
	meta:
		software_name = "udhcp"
		open_source = true
		website = "https://busybox.net/"
		description = "udhcp is a lightweight dhcp server/client. It is part of Busybox by now."
		no_text_file = true
    strings:
        $a = /udhcp \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule upnp_portable_sdk
{
	meta:
		software_name = "portable SDK for UPnP"
		open_source = true
		website = "https://pupnp.sourceforge.io"
		description = "Portable UPnP library"
		version_regex = "\\d\\.\\d\\.\\d+"
		no_text_file = true
	strings:
		$a = /UPnP\/1.0, Portable SDK for UPnP devices\/\d\.\d\.\d+/
	condition:
		$a
}

rule vsftpd
{
	meta:
		software_name = "vsftpd"
		open_source = true
		website = "https://security.appspot.com/vsftpd.html"
		description = "very secure FTP server for UNIX systems"
		no_text_file = true
    strings:
        $a = /vsftpd: version \d\.\d+(\.\d+)?/ nocase ascii
    condition:
        $a
}

rule wpa_supplicant
{
	meta:
		software_name = "wpa_supplicant"
		open_source = true
		website = "https://w1.fi/wpa_supplicant/"
		description = "wpa_supplicant is a WPA Supplicant for Linux and other OSes with support for WPA and WPA2."
		no_text_file = true
    strings:
        $a = /wpa_supplicant v\d+\.\d+(\.\d+)?/ nocase ascii wide
    condition:
        $a
}

rule xl2tpd
{
	meta:
		software_name = "xl2tpd"
		open_source = false
		website = "https://www.xelerance.com/services/software/xl2tpd/"
		description = "Layer 2 Tunneling Protocol (L2TP) daemon"
		no_text_file = true
    strings:
        $a = /xl2tpd-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule zebra
{
	meta:
		software_name = "GNU Zebra"
		open_source = true
		website = "https://www.gnu.org/software/zebra/"
		description = "multi-server routing software which provides TCP/IP based routing protocols"
		no_text_file = true
    strings:
        $a = /Hello, this is zebra \(version 0.\d+.{0,10}\)./ nocase ascii wide
    condition:
        $a
}
