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
