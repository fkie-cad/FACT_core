from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

import r2pipe


class RadareAPI:
    def __init__(self, path_to_elf: str, config: dict):
        self.config = config
        self.api = r2pipe.open(path_to_elf)

    def __enter__(self):
        self.api.cmd('aaaa')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.api.quit()

    def get_function_instructions(self, function):
        self.api.cmd(f"s {function['offset']}")
        return self.api.cmdj('pdfj')

    def get_xrefs_to(self, imp):
        return {int(xref['from']) for xref in self.api.cmdj(f'axtj {imp}')}

    def get_filtered_strings(self, regex):
        result = []
        string_list = self.api.cmdj('izj')
        for string in string_list:
            decoded_str = base64.b64decode(string['string']).decode()
            if re.match(regex, decoded_str) is not None:
                result.append(decoded_str)
        return result

    def get_possible_url_paths(self, regex):
        result = []
        string_list = self.api.cmdj('izj')
        for string in string_list:
            decoded_str = base64.b64decode(string['string']).decode()
            if decoded_str.startswith('/') and re.search(regex, decoded_str) is None:
                result.append(decoded_str)
        return result

    @staticmethod
    def matches_import(imp, input_class):
        for element in input_class:
            if re.match(re.compile(element), imp) is not None:
                return True
        return False

    def get_interrupts(self, function_list):
        interrupts = []
        for function in function_list:
            try:
                interrupts.extend(self._get_interrupts_of_function(function))
            except (TypeError, KeyError):  # function issues
                continue
        return interrupts

    def _get_interrupts_of_function(self, function):
        interrupts = []
        for instruction in self.get_function_instructions(function)['ops']:
            if 'opcode' in instruction and instruction['type'] == 'swi':
                for trap in ['syscall', 'swi', 'int 0x80']:
                    if trap in instruction['opcode']:
                        interrupts.append(instruction['offset'])
        return interrupts

    def find_input_vectors(self):
        input_vectors = []
        function_list = self.api.cmdj('aflj')
        if not function_list:
            return input_vectors

        for function in function_list:
            if self._is_imported_function(function):
                input_vectors.extend(self.find_input_vectors_of_function(function))

        interrupts = self.get_interrupts(function_list)
        if interrupts:
            input_vectors.append(
                {'class': 'kernel', 'name': 'interrupts', 'count': len(interrupts), 'xrefs': interrupts}
            )
        return input_vectors

    def find_input_vectors_of_function(self, function):
        input_vectors = []
        clean_import = function['name'].replace(self.config['import_prefix'], '')
        for input_class in self.config['input_classes']:
            if self.matches_import(clean_import.lower(), self.config['input_classes'][input_class]):
                input_vectors.append(
                    {
                        'class': input_class,
                        'name': clean_import,
                        'xrefs': [hex(address) for address in self.get_xrefs_to(function['name'])],
                    }
                )
        return input_vectors

    def _is_imported_function(self, function):
        return self.config['import_prefix'] in function['name']


def get_class_summary(input_vectors):
    classes = {class_ for class_ in input_vectors}
    return list(classes)


def group_input_vectors(input_vectors: list[dict]) -> dict[str, list[dict]]:
    result = {}
    for entry in input_vectors:
        result.setdefault(entry['class'], []).append({'name': entry['name'], 'xrefs': entry['xrefs']})
    return result


def get_input_vectors(elf_file):
    config_file = Path(__file__).absolute().parent / 'config.json'
    config = json.loads(config_file.read_text())

    with RadareAPI(elf_file, config) as r2_api:
        input_vectors = r2_api.find_input_vectors()
        input_vectors = group_input_vectors(input_vectors)

        output = {
            'summary': get_class_summary(input_vectors),
            'full': {
                'inputs': input_vectors,
                'configs': r2_api.get_filtered_strings(re.compile(config['config_regex'])),
                'domains': r2_api.get_filtered_strings(re.compile(config['domain_regex'])),
                'url_paths': r2_api.get_possible_url_paths(re.compile(config['config_regex'])),
            },
        }

    print(json.dumps(output, indent=4))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: input_vectors_r2.py PATH_TO_ELF')
        sys.exit(1)
    get_input_vectors(sys.argv[1])
