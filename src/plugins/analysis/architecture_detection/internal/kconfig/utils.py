def kconfig_contains(kconfig: str, options):
    for line in kconfig.splitlines():
        if line[-2:] != '=y':
            continue

        if str.strip(line)[len('CONFIG_') : -len('=y')] in options:
            return True

    return False
