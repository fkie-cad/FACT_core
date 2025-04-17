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

rule postgres {
    meta:
        software_name = "PostgreSQL"
        open_source = true
        website = "https://www.postgresql.org/"
        description = "a powerful object-relational database system"
    strings:
        $a = /\(PostgreSQL\) \d{1,2}\.\d{1,2}\.?\d{0,2}[a-z]{0,5}/
        $b = /PostgreSQL \d{1,2}\.\d{1,2}\.?\d{0,2}[a-z]{0,5} on [^ ,]+/
    condition:
        ($a or $b) and no_text_file
}
