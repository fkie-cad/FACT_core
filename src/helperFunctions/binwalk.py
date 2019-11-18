import string


def iterate_valid_signature_lines(output_lines):
    return (line for line in output_lines if line and line[0] in string.digits)
