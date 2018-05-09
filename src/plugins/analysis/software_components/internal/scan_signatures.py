def get_scanned_software(yara_signature_file):
    with open(yara_signature_file, 'r') as file:
        scanned_software = []
        line = file.readline()
        while line:
            line = line.strip()
            parts_of_line = line.split('=')
            if parts_of_line[0].strip() == 'software_name':
                software_name = parts_of_line[1].strip()
                software_name = software_name.replace('"', '')
                scanned_software.append(software_name)
            line = file.readline()
    return scanned_software
