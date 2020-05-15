# pylint: disable=protected-access
import gc

import pytest

from helperFunctions.statistic import calculate_total_files
from statistic.update import StatisticUpdater
from storage.db_interface_statistic import StatisticDbViewer
from test.common_helper import clean_test_database, get_config_for_testing, get_database_names


@pytest.mark.usefixtures('start_db')
class TestStatistic:
    @classmethod
    def setup_class(cls):
        cls.config = get_config_for_testing()

    def setup(self):
        self.updater = StatisticUpdater(config=self.config)
        self.frontend_db_interface = StatisticDbViewer(config=self.config)

    def teardown(self):
        self.updater.shutdown()
        self.frontend_db_interface.shutdown()
        clean_test_database(self.config, get_database_names(self.config))
        gc.collect()

    def test_update_and_get_statistic(self):
        self.updater.db.update_statistic('test', {'test1': 1})
        result = self.frontend_db_interface.get_statistic('test')
        assert result['test1'] == 1, 'result not correct'
        self.updater.db.update_statistic('test', {'test1': 2})
        result = self.frontend_db_interface.get_statistic('test')
        assert result['test1'] == 2, 'result not correct'

    def test_get_general_stats(self):
        result = self.updater.get_general_stats()
        assert result['number_of_firmwares'] == 0, 'number of firmwares not correct'
        assert result['number_of_unique_files'] == 0, 'number of files not correct'
        self.updater.db.firmwares.insert_one({'test': 1})
        self.updater.db.file_objects.insert_one({'test': 1})
        result = self.updater.get_general_stats()
        assert result['number_of_firmwares'] == 1, 'number of firmwares not correct'
        assert result['number_of_unique_files'] == 1, 'number of files not correct'

    def test_find_most_frequent_architecture(self):
        test_list = ['MIPS, 32-bit, big endian (M)', 'MIPS (M)', 'MIPS, 32-bit, big endian (M)', 'MIPS, 32-bit, big endian (M)']
        result = self.updater._find_most_frequent_architecture(test_list)
        expected_result = 'MIPS, 32-bit, big endian (M)'
        assert result == expected_result
        test_list = ['A', 'B', 'B', 'B', 'C', 'C']
        result = self.updater._find_most_frequent_architecture(test_list)
        expected_result = 'B'
        assert result == expected_result

    def test_get_mitigation_data(self):
        result_list = [('PIE enabled', 3), ('Canary enabled', 9), ('RELRO partially enabled', 7),
                       ('PIE/DSO present', 565), ('PIE disabled', 702), ('NX enabled', 1696),
                       ('PIE - invalid ELF file', 633), ('Canary disabled', 1894), ('RELRO fully enabled', 40),
                       ('NX disabled', 207), ('RELRO disabled', 1856)]
        mitigation_on = StatisticUpdater.extract_mitigation_from_list('NX enabled', result_list)
        mitigation_off = StatisticUpdater.extract_mitigation_from_list('Canary disabled', result_list)
        mitigation_partial = StatisticUpdater.extract_mitigation_from_list('RELRO partially enabled', result_list)
        mitigation_invalid = StatisticUpdater.extract_mitigation_from_list('PIE - invalid ELF file', result_list)
        assert mitigation_on == [('NX enabled', 1696)]
        assert mitigation_off == [('Canary disabled', 1894)]
        assert mitigation_partial == [('RELRO partially enabled', 7)]
        assert mitigation_invalid == [('PIE - invalid ELF file', 633)]

    def test_set_single_stats(self):
        result = [('PIE - invalid ELF file', 100), ('NX disabled', 200), ('PIE/DSO present', 300),
                  ('RELRO fully enabled', 400), ('PIE enabled', 500), ('RELRO partially enabled', 600),
                  ('Canary disabled', 700), ('NX enabled', 800), ('PIE disabled', 900), ('Canary enabled', 1000),
                  ('RELRO disabled', 1100)]

        stats = {'exploit_mitigations': []}
        self.set_nx_stats_to_dict(result, stats)

        stats = {'exploit_mitigations': []}
        self.set_canary_stats_to_dict(result, stats)

        stats = {'exploit_mitigations': []}
        self.set_pie_stats_to_dict(result, stats)

        stats = {'exploit_mitigations': []}
        self.set_relro_stats_to_dict(result, stats)

    def set_nx_stats_to_dict(self, result, stats):
        nx_off, nx_on = self.updater.extract_nx_data_from_analysis(result)
        assert nx_off == [('NX disabled', 200)]
        assert nx_on == [('NX enabled', 800)]
        total_amount_of_files = calculate_total_files([nx_off, nx_on])
        assert total_amount_of_files == 1000
        self.updater.append_nx_stats_to_result_dict(nx_off, nx_on, stats, total_amount_of_files)
        assert stats == {'exploit_mitigations': [('NX enabled', 800, 0.8), ('NX disabled', 200, 0.2)]}

    def set_canary_stats_to_dict(self, result, stats):
        canary_off, canary_on = self.updater.extract_canary_data_from_analysis(result)
        assert canary_off == [('Canary disabled', 700)]
        assert canary_on == [('Canary enabled', 1000)]
        total_amount_of_files = calculate_total_files([canary_off, canary_on])
        assert total_amount_of_files == 1700
        self.updater.append_canary_stats_to_result_dict(canary_off, canary_on, stats, total_amount_of_files)
        assert stats == {'exploit_mitigations': [('Canary enabled', 1000, 0.58824), ('Canary disabled', 700, 0.41176)]}

    def set_pie_stats_to_dict(self, result, stats):
        pie_invalid, pie_off, pie_on, pie_partial = self.updater.extract_pie_data_from_analysis(result)
        assert pie_invalid == [('PIE - invalid ELF file', 100)]
        assert pie_off == [('PIE disabled', 900)]
        assert pie_partial == [('PIE/DSO present', 300)]
        assert pie_on == [('PIE enabled', 500)]
        total_amount_of_files = calculate_total_files([pie_on, pie_partial, pie_off, pie_invalid])
        assert total_amount_of_files == 1800
        self.updater.append_pie_stats_to_result_dict(pie_invalid, pie_off, pie_on, pie_partial, stats, total_amount_of_files)
        assert stats == {'exploit_mitigations': [
            ('PIE enabled', 500, 0.27778), ('PIE/DSO present', 300, 0.16667), ('PIE disabled', 900, 0.5), ('PIE - invalid ELF file', 100, 0.05556)
        ]}

    def set_relro_stats_to_dict(self, result, stats):
        relro_off, relro_on, relro_partial = self.updater.extract_relro_data_from_analysis(result)
        assert relro_off == [('RELRO disabled', 1100)]
        assert relro_on == [('RELRO fully enabled', 400)]
        assert relro_partial == [('RELRO partially enabled', 600)]
        total_amount_of_files = calculate_total_files([relro_off, relro_on, relro_partial])
        assert total_amount_of_files == 2100
        self.updater.append_relro_stats_to_result_dict(relro_off, relro_on, relro_partial, stats, total_amount_of_files)
        assert stats == {'exploit_mitigations': [
            ('RELRO fully enabled', 400, 0.19048), ('RELRO partially enabled', 600, 0.28571), ('RELRO disabled', 1100, 0.52381)
        ]}

    def test_get_all_stats(self):
        result = [
            ('PIE - invalid ELF file', 100), ('NX disabled', 200), ('PIE/DSO present', 300),
            ('RELRO fully enabled', 400), ('PIE enabled', 500), ('RELRO partially enabled', 600),
            ('Canary disabled', 700), ('NX enabled', 800), ('PIE disabled', 900), ('Canary enabled', 1000),
            ('RELRO disabled', 1100)
        ]
        stats = {'exploit_mitigations': []}
        self.updater.get_stats_nx(result, stats)
        self.updater.get_stats_canary(result, stats)
        self.updater.get_stats_relro(result, stats)
        self.updater.get_stats_pie(result, stats)
        assert stats == {'exploit_mitigations': [
            ('NX enabled', 800, 0.8), ('NX disabled', 200, 0.2), ('Canary enabled', 1000, 0.58824),
            ('Canary disabled', 700, 0.41176), ('RELRO fully enabled', 400, 0.19048),
            ('RELRO partially enabled', 600, 0.28571), ('RELRO disabled', 1100, 0.52381), ('PIE enabled', 500, 0.27778),
            ('PIE/DSO present', 300, 0.16667), ('PIE disabled', 900, 0.5), ('PIE - invalid ELF file', 100, 0.05556)
        ]}

    def test_return_none_if_no_exploit_mitigations(self):
        result = []
        stats = {'exploit_mitigations': []}
        assert self.updater.get_stats_nx(result, stats) is None

    def test_fetch_mitigations(self):
        assert self.updater.get_exploit_mitigations_stats() == {'exploit_mitigations': []}

    def test_known_vulnerabilities_works(self):
        assert self.updater.get_known_vulnerabilities_stats() == {'known_vulnerabilities': []}


def test_convert_dict_list_to_list():
    test_list = [{'count': 1, '_id': 'A'}, {'count': 2, '_id': 'B'}, {'count': 3, '_id': None}]
    result = StatisticUpdater._convert_dict_list_to_list(test_list)
    assert isinstance(result, list), 'result is not a list'
    assert ['A', 1] in result
    assert ['B', 2] in result
    assert ['not available', 3] in result
    assert len(result) == 3, 'too many keys in the result'


def test_filter_sanitized_entries():
    test_list = [['valid', 1], ['sanitized_81abfc7a79c8c1ed85f6b9fc2c5d9a3edc4456c4aecb9f95b4d7a2bf9bf652da_1', 1]]
    result = StatisticUpdater._filter_sanitized_objects(test_list)
    assert result == [['valid', 1]]


def test_count_occurrences():
    test_list = ['A', 'B', 'B', 'C', 'C', 'C']
    result = set(StatisticUpdater._count_occurrences(test_list))
    expected_result = {('A', 1), ('C', 3), ('B', 2)}
    assert result == expected_result


def test_round():
    assert StatisticUpdater._round([('NX enabled', 1696)], 1903) == 0.89122


def test_shorten_architecture_string():
    tests_string = 'MIPS, 64-bit, little endian (M)'
    result = StatisticUpdater._shorten_architecture_string(tests_string)
    assert result == 'MIPS, 64-bit'
    tests_string = 'MIPS (M)'
    result = StatisticUpdater._shorten_architecture_string(tests_string)
    assert result == 'MIPS'
