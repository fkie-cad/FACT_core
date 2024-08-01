/* this a template for software component rules 

rule NAME_OF_RULE
{
	meta:
        description = "short description"
        reliability = "range(0, 101)"
        score = "low / medium / high"
        link = "http://link.to.vulnerability.description/ or empty string"
    strings:
        $a = /REGULAR_EXPRESSION/ nocase ascii wide
    condition:
        $a
}

*/

rule DLink_Bug {
    meta:
        description = "D-Link authentication backdoor"
        reliability = "100"
        score = "high"
        link = "http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/"
    strings:
        $a = "xmlset_roodkcableoj28840ybtide"
    condition: $a
}

rule BackDoor_String {
	meta:
        description = "Contains a string similar to backdoor"
        reliability = "90"
        score = "medium"
        link = ""
    strings:
        $normaldoor = /b[a4]ckd[o0]{2}r/ nocase ascii wide
        $reversedoor = /r[o0]{2}dkc[a4]b/ nocase ascii wide
        $basedoor = "YmFja2Rvb3I"
        $hexdoor = { 62 61 63 6b 64 6f 6f 72 }
    condition:
        any of them
}

rule WPA_Key_Hardcoded {
    meta:
        description = "WiFi Access Point with hardcoded WPA key"
        reliability = "80"
        score = "high"
        link = ""
    strings:
        $a = /\swpa_passphrase=\S+/ nocase ascii wide
    condition: $a
} 
