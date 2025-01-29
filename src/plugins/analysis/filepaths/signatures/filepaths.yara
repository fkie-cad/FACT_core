rule filepath {
	meta:
		description ="find POSIX file paths"
    strings:
        $a = /(\.|\.\.|~)?(\/[a-zA-Z0-9_.-]{2,32}){1,16}/
        $b = /'(\.|\.\.|~)?(\/[a-zA-Z0-9 _.-]{2,32}){1,16}'/
        $c = /"(\.|\.\.|~)?(\/[a-zA-Z0-9 _.-]{2,32}){1,16}"/
    condition:
        any of them
}
