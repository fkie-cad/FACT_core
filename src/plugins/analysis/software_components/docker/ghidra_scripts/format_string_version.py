# pylint: disable=invalid-name,not-callable,broad-except

from __future__ import print_function

import json
import logging
import os
import sys
from string import printable

GHIDRA_OUTPUT_FILE = 'ghidra_output.json'
RELEVANT_REFERENCE_TYPES = ['PARAM', 'READ', 'DATA']
KEY_FILE = 'key_file'


if 'ghidra' not in globals():
    logging.error('this script should only run in ghidra')
    ghidra, getCurrentProgram, getMonitor = [None] * 3
    sys.exit(2)


def get_key_strings():
    try:
        with open(KEY_FILE, 'r') as fp:
            key_strings = json.loads(fp.read())
    except IOError:
        logging.error('key string file not found')
        sys.exit(3)
    logging.info('key: {}'.format(repr(key_strings)))
    return key_strings


def string_is_printable(string):
    return all(c in printable for c in string)


def save_results(output_file, result):
    with open(output_file, 'wb') as fp:
        json.dump(result, fp)
    os.chmod(output_file, 0o777)  # assure access rights to file created in docker container


class ReferencedStringFinder:

    MAX_LEN = 32

    def __init__(self):
        self.flat_api = ghidra.program.flatapi.FlatProgramAPI(getCurrentProgram(), getMonitor())
        decompiler_api = ghidra.app.decompiler.flatapi.FlatDecompilerAPI(self.flat_api)
        decompiler_api.initialize()
        self.decompiler = decompiler_api.getDecompiler()
        self.key_string_list = get_key_strings()

    def main(self):
        result = []
        for key_string in self.key_string_list:
            result.extend(self.find_other_strings_relating_to(key_string))

        result = sorted(set(result))
        save_results(GHIDRA_OUTPUT_FILE, result)

    def find_other_strings_relating_to(self, key_string):
        result = []
        address = self.flat_api.find(key_string)
        if address is None:
            logging.error('key string address not found')
            return []
        logging.info('found address of key string: {}'.format(address))
        reference_list = self.flat_api.getReferencesTo(address)
        if not reference_list:
            logging.warning('found no references to address')
            return []
        logging.info('found references to address:')
        for reference in set(reference_list):
            logging.info('\t{}'.format(reference))
            basic_block = self.find_basic_block_containing(reference)
            if not basic_block:
                logging.warning('address not in function -> skipping')
                continue
            result.extend(self.get_strings_referenced_from(basic_block, key_string))
        return result

    def find_basic_block_containing(self, reference):
        source_addr = reference.getFromAddress()
        function = self.flat_api.getFunctionBefore(source_addr)
        logging.info('\tin function: {}'.format(function))
        function_decompiler = self.decompiler.decompileFunction(function, 120, getMonitor())
        high_function = function_decompiler.getHighFunction()
        basic_block_list = high_function.getBasicBlocks()
        for basic_block in basic_block_list:
            if basic_block.contains(source_addr):
                return basic_block
        return None

    def get_strings_referenced_from(self, basic_block, key_string):
        result = []
        address_list = self.get_addresses_in_block(basic_block)
        data_reference_list = self.get_references_from_addresses(address_list)
        logging.info('found data references in basic block:')
        for data_reference in data_reference_list:
            data_address = data_reference.getToAddress()
            string = self.read_string_from_address(data_address)
            if string and key_string[: self.MAX_LEN] not in string and string_is_printable(string):
                result.append(string)
                logging.info('\t{} -> {}'.format(data_reference, repr(string)))
        return result

    @staticmethod
    def get_addresses_in_block(basic_block):
        start = basic_block.getStart()
        end = basic_block.getStop()
        result = [start]
        current_address = start.next()
        while True:
            result.append(current_address)
            if current_address.equals(end):
                break
            current_address = current_address.next()
        return result

    def get_references_from_addresses(self, address_list):
        return [
            reference
            for address in address_list
            for reference in self.flat_api.getReferencesFrom(address)
            if str(reference.getReferenceType()) in RELEVANT_REFERENCE_TYPES
        ]

    def read_string_from_address(self, data_address):
        result = b''
        current_addr = data_address
        try:
            while True:
                byte = self.flat_api.getByte(current_addr)
                if byte == 0 or byte == b'\0' or len(result) >= self.MAX_LEN or byte < 0:
                    break
                result += chr(byte)
                current_addr = current_addr.next()
        except:  # pylint: disable=bare-except  # noqa: E722
            pass
        return result


if __name__ == '__main__':
    ReferencedStringFinder().main()
    sys.exit(0)
