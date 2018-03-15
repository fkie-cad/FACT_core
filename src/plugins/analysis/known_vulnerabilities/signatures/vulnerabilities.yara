/* this a template for software component rules 

rule NAME_OF_RULE
{
	meta:
        description = "short description"
        reliability = "range(0, 101)"
        score = "low / medium / high"
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
    strings:
        $a = "xmlset_roodkcableoj28840ybtide"
    condition: $a
}
