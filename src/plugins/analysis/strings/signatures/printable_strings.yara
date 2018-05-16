rule PrintableString
{
    strings:
        $re = /[0-9a-zA-Z!"#$%&'()*+,-.\/:;<=>?@[\\\]^_`{|}~ \t\n\r]{8,}/ ascii wide fullword
    condition:
        $re
}