rule smart_wizzard
{
    meta:
        software_name = "Netgear Smart Wizzard"
        open_source = false
        website = "https://www.netgear.com/"
        description = "Setup assistent"
    strings:
        $a = /Netgear Smart Wizard \d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}
