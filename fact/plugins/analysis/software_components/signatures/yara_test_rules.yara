rule MyTestRule
{
	meta:
		software_name = "Test Software"
		open_source = true
		website = "http://www.fkie.fraunhofer.de"
		description = "This is a test rule"
    strings:
        $a = /MyTestRule [\d]+.[\d]+[.\d]*/
    condition:
        $a
}
