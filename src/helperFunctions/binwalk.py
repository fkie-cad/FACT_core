import string


def get_list_of_binwalk_signatures(binwalk_output):
    matches = list()
    output_lines = binwalk_output.splitlines()
    for line in iterate_valid_signature_lines(output_lines):
        matches.append(line)
    return matches


def iterate_valid_signature_lines(output_lines):
    return (line for line in output_lines if line and line[0] in string.digits)
