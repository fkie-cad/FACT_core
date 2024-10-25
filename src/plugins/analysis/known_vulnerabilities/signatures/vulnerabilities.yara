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

rule xz_backdoor {
    meta:
        description = "CVE-2024-3094: a malicious backdoor was planted into the xz compression library"
        reliability = "80"
        score = "high"
        link = "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
    strings:
        $a = {f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410}
        $b = {488d7c2408f3ab488d4424084889d14c89c74889c2e8????????89c2}
        $c = {4d8b6c2408458b3c244c8b6310898578f1ffff31c083bd78f1ffff00f3ab7907}
        $d = {31c04989ffb9160000004d89c5488d7c24484d89cef3ab488d442448}
        $e = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj"
    condition:
        any of them
}
