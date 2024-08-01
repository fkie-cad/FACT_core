rule testRule
{
	meta:
		software_name = "Test Software"
		open_source = false
		website = "http://www.fkie.fraunhofer.de"
		description = "Generic Software"
    strings:
        $a = /test(\d+\.\d+\.\d+)?/ nocase ascii wide
    condition:
        $a
}

