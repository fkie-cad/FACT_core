import base64
import json
import os
import re
import sys

import r2pipe


def open_with_radare(path_to_elf):
    r2 = r2pipe.open(path_to_elf)
    r2.cmd('aaaa')
    return r2


def get_ins(r2, func):
    r2.cmd('s %s' % func['offset'])
    return r2.cmdj('pdfj')


def get_xrefs_to(r2, imp):
    res = []
    for xref in r2.cmdj('axtj %s' % imp):
        res.append(int(xref["from"]))
    return res


def get_filtered_strings(r2, f):
    res = []
    strings = r2.cmdj('izj')
    for s in strings:
        decoded_str = base64.b64decode(s['string']).decode()
        if re.match(f, decoded_str) is not None:
            res.append(decoded_str)
    return res


def get_possible_url_paths(r2, f):
    res = []
    strings = r2.cmdj('izj')
    for s in strings:
        decoded_str = base64.b64decode(s['string']).decode()
        if decoded_str.startswith('/') and re.search(f, decoded_str) is None:
            res.append(decoded_str)
    return res


def matches_import(imp, input_class):
    for elem in input_class:
        if re.match(re.compile(elem), imp) is not None:
            return True
    return False


def check_interrupts(r2):
    interrupts = []
    for func in r2.cmdj('aflj'):
        try:
            for ins in get_ins(r2, func)['ops']:
                if 'opcode' in ins and ins['type'] == 'swi':
                    for trap in ['syscall', 'swi', 'int 0x80']:
                        if trap in ins['opcode']:
                            interrupts.append(ins['offset'])
        except:
            # function issues
            pass
    return interrupts


def find_input_vectors(r2, config):
    input_vectors = []
    functions = r2.cmdj("aflj")
    for func in functions:
        if config['import_prefix'] in func["name"]:
            clean_import = func["name"].replace(config['import_prefix'], "")
            # print(clean_import)
            for input_class in config['input_classes']:
                if matches_import(clean_import.lower(), config['input_classes'][input_class]):
                    input_vectors.append({'class': input_class,
                                          'name': clean_import,
                                          'xrefs': get_xrefs_to(r2, func["name"])})

    interrupts = check_interrupts(r2)
    if len(interrupts) > 0:
        input_vectors.append({'class': 'kernel',
                              'count': len(interrupts),
                              'xrefs': interrupts})
    return input_vectors


def get_class_summary(input_vectors):
    classes = []
    for elem in input_vectors:
        classes.append(elem['class'])
    return list(set(classes))


def main(argv):
    if len(argv) != 2:
        print("usage: input_vectors_r2.py PATH_TO_ELF")
        sys.exit(1)
    else:
        config = json.load(open(os.path.join(os.path.split(os.path.realpath(__file__))[0], "config.json"), 'r'))

        r2 = open_with_radare(argv[1])
        input_vectors = find_input_vectors(r2, config)

        output = {'summary': get_class_summary(input_vectors),
                  'full': {
                      'inputs': input_vectors,
                      'configs': get_filtered_strings(r2, re.compile(config['config_regex'])),
                      'domains': get_filtered_strings(r2, re.compile(config['domain_regex'])),
                      'url_paths': get_possible_url_paths(r2, re.compile(config['config_regex']))
        }}

        print(json.dumps(output, indent=4))

        r2.quit()


if __name__ == "__main__":
    main(sys.argv)
