import "magic"

private rule no_text_file
{
    meta:
        software_name = "magic"
        open_source = true
        website = "https://www.fkie.fraunhofer.de/"
        description = "no text_file_rule"
    condition:
        (magic.mime_type() != "text/plain" and magic.mime_type() != "text/html") or test_flag
}
