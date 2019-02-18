import logging
import os
import re
from binascii import a2b_base64

from analysis.PluginBase import AnalysisBasePlugin
from common_helper_files import get_dir_of_file, get_string_list_from_file
from entropy import shannon_entropy  # pylint: disable=no-name-in-module
from fact_helper_file import get_file_type_from_binary
from helperFunctions.dataConversion import remove_linebreaks_from_byte_string
from helperFunctions.fileSystem import get_parent_dir
from helperFunctions.strings import find_all_strings

LINEBREAK_LENGTH = 1


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    detect and decode base64 encoded data

    Credits:
    Original version by Konstantin Samuel created during Firmware Bootcamp WT16/17 at University of Bonn
    Refactored and improved by Fraunhofer FKIE
    '''
    NAME = 'base64_decoder'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['audio', 'image', 'video']
    DESCRIPTION = 'Detect and decode base64 sections'
    VERSION = '0.1.3'

    def __init__(self, plugin_administrator, config=None, recursive=True, timeout=300):
        self._word_list = self.load_word_list()
        super().__init__(plugin_administrator, config=config, recursive=recursive, timeout=timeout, plugin_path=__file__)

    @staticmethod
    def load_word_list():
        word_list_file = os.path.join(get_parent_dir(get_dir_of_file(__file__)), 'internal/optimized_word_list.txt')
        return get_string_list_from_file(word_list_file)

    def process_object(self, file_object):
        original_binary = file_object.binary
        my_binary, removed_linebreaks = remove_linebreaks_from_byte_string(original_binary)

        try:
            base64_sections = self.find_base64_sections(my_binary, int(self.config[self.NAME]['base64_section_min_length']))
        except ValueError as value_error:
            logging.error(str(value_error))
            return file_object

        file_object.processed_analysis[self.NAME] = self.iterate_base64_sections(base64_sections, original_binary, removed_linebreaks)
        file_object.processed_analysis[self.NAME]['summary'] = ['Base64 code detected'] if file_object.processed_analysis[self.NAME] else []
        return file_object

    def iterate_base64_sections(self, base64_sections, original_binary, removed_linebreaks):
        results = dict()
        section_id = 0
        for base64_section in base64_sections:
            base64_matches = self.generate_valid_base64_matches(base64_section.group(0))
            section_results = list()
            span_in_binary = self.find_span_in_binary(original_binary, base64_section, removed_linebreaks)

            for span_in_section, base64_expression in base64_matches:
                if span_in_binary:
                    section_results.append(self._create_expression_result(base64_expression, section_id, span_in_binary, span_in_section))
                    section_id += 1

            if section_results and max(section['size'] for section in section_results) > 64:
                smallest_id = min(item['id'] for item in section_results)
                start, end = [item['span_in_binary'] for item in section_results if item['id'] == smallest_id][0]
                results['{} - {}'.format(start, end)] = section_results
        return results

    def _create_expression_result(self, base64_expression, section_id, span_in_binary, span_in_section):
        decoded_expression = a2b_base64(base64_expression)
        expression_results = self.execute_all_measurements(decoded_expression)
        expression_results['span_in_section'] = span_in_section
        expression_results['span_in_binary'] = span_in_binary
        expression_results['size'] = len(decoded_expression)
        expression_results['id'] = section_id
        return expression_results

    def find_span_in_binary(self, original_binary, base64_section, removed_linebreaks, block_length=16):
        base64_section_content = base64_section.group(0)
        base64_section_span = base64_section.span()
        start_block = base64_section_content[:block_length]
        end_block = base64_section_content[-block_length:]

        start_index = self.index_of_start_pattern_in_section(original_binary, start_block, base64_section_span[0], block_length + removed_linebreaks)
        if not start_index:
            return None
        end_index = self.index_of_end_pattern_in_section(original_binary, end_block, start_index + len(base64_section_content), block_length + removed_linebreaks)
        if not end_index:
            return None
        return start_index, end_index + block_length

    @staticmethod
    def index_of_start_pattern_in_section(full_byte_string, start_pattern, section_offset, section_length):
        pattern_split = len(start_pattern) // 2
        index = full_byte_string.find(start_pattern[:pattern_split], section_offset, section_offset + section_length)
        if index < 0:
            index = full_byte_string.find(start_pattern[pattern_split:], section_offset, section_offset + section_length) - pattern_split - LINEBREAK_LENGTH
            if index < 0:
                return None
        return index

    @staticmethod
    def index_of_end_pattern_in_section(full_byte_string, end_pattern, section_offset, section_length):
        pattern_split = len(end_pattern) // 2
        index = full_byte_string.rfind(end_pattern[:pattern_split], section_offset, section_offset + section_length)
        if index < 0:
            index = full_byte_string.rfind(end_pattern[pattern_split:], section_offset, section_offset + section_length) - pattern_split
            if index < 0:
                return None
        return index

    # ---------- Methods for parsing ----------

    @staticmethod
    def find_base64_sections(my_bytes, min_length, special_characters='+/'):
        if min_length < 4:
            raise ValueError('Minimum length of base64 section must be larger or equal to 4')
        min_repetitions = str(min_length - 4)
        all_characters = '[A-Za-z0-9{}]'.format(re.escape(special_characters))
        # regex_pattern = bytes(all_characters + '{' + min_repititions + ',}(?:' + all_characters + '{2}==|' + all_characters + '{3}=|' + all_characters + '{4})', 'ascii')
        regex_pattern = bytes('{all_characters}{{{min_repetitions},}}(?:{all_characters}{{2}}==|{all_characters}{{3}}=|{all_characters}{{4}})'.format(
            all_characters=all_characters,
            min_repetitions=min_repetitions
        ), 'ascii')
        return re.finditer(regex_pattern, my_bytes)

    @staticmethod
    def generate_valid_base64_matches(base64_section):
        '''
        Returns iterator with 4 ((left_offset, length, right_offset), base64_expression) tuples
        '''
        length = len(base64_section)
        return (((offset, length - ((length - offset) % 4), (length - offset) % 4), base64_section[offset:length - ((length - offset) % 4)]) for offset in range(4))

    # ---------- Methods for measuring ----------

    def execute_all_measurements(self, base64_expression_decoded):
        results = dict()
        results['entropy'] = shannon_entropy(base64_expression_decoded)
        results['strings'] = self.words_in_strings(base64_expression_decoded, self._word_list, int(self.config[self.NAME]['string_min_length']))
        results['filetype'] = get_file_type_from_binary(base64_expression_decoded)
        return results

    @staticmethod
    def words_in_strings(my_bytes, word_list, min_length=10):
        total_matches = 0
        strings_containing_words = set()
        for string in find_all_strings(my_bytes, min_length=min_length):
            for word in word_list:
                if word.lower() in string.lower():
                    total_matches += 1
                    strings_containing_words.add(string)
        return total_matches, sorted(list(strings_containing_words), key=len, reverse=True)
