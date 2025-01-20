import "magic"

/*
The sole purpose of this rule file is to test if yara-python is installed correctly.
To be more specific, it is tested whether yara is installed with the magic module enabled (which is needed for some
plugins (for more info see https://yara.readthedocs.io/en/stable/modules/magic.html).
If you get an error like e.g. `invalid field name "mime_type"` when compiling these rules, then the module is missing.
*/

rule test_magic_module_is_enabled {
	condition:
		magic.mime_type() == "text/plain"
}
