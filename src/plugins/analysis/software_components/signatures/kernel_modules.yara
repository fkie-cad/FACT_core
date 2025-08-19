rule NetUSB
{
    meta:
        software_name = "KCodes NetUSB"
        open_source = false
        website = "https://www.kcodes.com"
        description = "Kernel module for USB over IP"
    strings:
        $a = "KC NetUSB General Driver"
        $b = "NetUSB module for Linux"
        $c = /\x001\.\d+\.\d+\x00/
    condition:
        2 of them and no_text_file
}
