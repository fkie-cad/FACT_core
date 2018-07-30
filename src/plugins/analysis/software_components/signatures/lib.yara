rule libFLAC
{
	meta:
		software_name = "libFLAC"
		open_source = true
		website = "https://xiph.org/flac/"
		description = "Free Lossless Audio Codec multimedia library."
    strings:
        $a = /libFLAC \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule libogg
{
	meta:
		software_name = "libogg"
		open_source = true
		website = "https://xiph.org/ogg/"
		description = "ogg multimedia file parsing library."
    strings:
        $a = /libogg-\d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}

rule libVorbis
{
	meta:
		software_name = "libVorbis"
		open_source = true
		website = "https://xiph.org/vorbis/"
		description = "ogg vorbis compressed audio format library."
    strings:
        $a = /libVorbis \d+\.\d+\.\d+/ nocase ascii wide
    condition:
        $a and no_text_file
}