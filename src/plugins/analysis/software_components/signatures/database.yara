 rule sqlite3
{
	meta:
		software_name = "SQLite"
		open_source = true
		website = "https://sqlite.org/index.html"
		description = "a small fast SQL database engine"
		format_string = true
		version_regex = "\\d\\.\\d+\\.\\d+\\.?\\d?"
	strings:
		$a = "SQLite version %s" ascii
		$b = /SQLite version \d\.\d+\.\d+(\.\d)?/ ascii
		$c = /libsqlite3\-\d\.\d+\.\d+(\.\d)?\.so/ ascii
	condition:
		($a or $b or $c) and no_text_file
}
