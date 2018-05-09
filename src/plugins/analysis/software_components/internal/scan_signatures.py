def get_scanned_software(yara_signature_file):
    with open(yara_signature_file, 'r') as file:
        scanned_software = []
        line = file.readline()
        while line:
            line = line.strip()
            pline = line.split("=")
            if (pline[0].strip() == "software_name"):
                software_name = str(pline[1].strip())
                software_name = software_name.replace('"','')
                scanned_software.append(software_name)
            line = file.readline()
    return scanned_software