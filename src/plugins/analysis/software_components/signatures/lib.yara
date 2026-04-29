rule libFLAC
{
	meta:
		software_name = "libFLAC"
		open_source = true
		website = "https://xiph.org/flac/"
		description = "Free Lossless Audio Codec multimedia library."
		no_text_file = true
    strings:
        $a = /libFLAC \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule liblzma {
	meta:
		software_name = "xz"
		open_source = true
		website = "https://tukaani.org/xz/"
		description = "XZ-format compression library"
		_version_function = "lzma_version_string"
		no_text_file = true
    strings:
        $a = "lzma_version_number"
        $b = "lzma_version_string"
    condition:
        $a and $b
}

rule libogg
{
	meta:
		software_name = "libogg"
		open_source = true
		website = "https://xiph.org/ogg/"
		description = "ogg multimedia file parsing library."
		no_text_file = true
    strings:
        $a = /libogg-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule libVorbis
{
	meta:
		software_name = "libVorbis"
		open_source = true
		website = "https://xiph.org/vorbis/"
		description = "ogg vorbis compressed audio format library."
		no_text_file = true
    strings:
        $a = /libVorbis \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule PH7
{
	meta:
		software_name = "PH7"
		open_source = true
		website = "http://ph7.symisc.net/"
		description = "Byte code compiler and virtual machine for PHP"
		no_text_file = true
    strings:
        $a = /PH7\/\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a
}

rule FileX
{
	meta:
		software_name = "FileX"
		open_source = false
		website = "https://rtos.com/solutions/threadx/real-time-operating-system/"
		description = "FAT filesystem implementation for ThreadX RTOS"
		no_text_file = true
	strings:
		$a = /FileX [a-z\/ 1-9_]+ [a-z]?\d+\.\d+(\.\d+)?(\.\d+)?/ nocase ascii wide
	condition:
		$a
}

rule liblua
{
	meta:
		software_name = "Lua"
		open_source = true
		website = "https://www.lua.org/"
		description = "Shared library for the Lua interpreter"
		no_text_file = true
	strings:
		$a = /Lua: Lua \d\.\d+(\.\d+)? Copyright \(C\) 1994-\d+/ nocase ascii wide
	condition:
		$a
}
