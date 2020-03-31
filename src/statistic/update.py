import itertools
import logging
import sys
from collections import Counter
from datetime import datetime
from time import time

from bson.son import SON
from common_helper_filter.time import time_format
from common_helper_mongo import get_field_average, get_field_sum, get_objects_and_count_of_occurrence

from helperFunctions.dataConversion import build_time_dict
from helperFunctions.merge_generators import avg, merge_dict, sum_up_lists, sum_up_nested_lists
from helperFunctions.mongo_task_conversion import is_sanitized_entry
from helperFunctions.statistic import calculate_total_files
from storage.db_interface_statistic import StatisticDbUpdater


class StatisticUpdater:
    '''
    This class handles statistic generation
    '''

    def __init__(self, config=None):
        self._config = config
        self.db = StatisticDbUpdater(config=self._config)
        self.start_time = None
        self.match = {}

    def shutdown(self):
        self.db.shutdown()

    def set_match(self, match):
        self.match = match if match else {}

    def update_all_stats(self):
        self.start_time = time()

        self.db.update_statistic('firmware_meta', self.get_firmware_meta_stats())
        self.db.update_statistic('file_type', self.get_file_type_stats())
        self.db.update_statistic('malware', self.get_malware_stats())
        self.db.update_statistic('crypto_material', self.get_crypto_material_stats())
        self.db.update_statistic('unpacking', self.get_unpacking_stats())
        self.db.update_statistic('architecture', self.get_architecture_stats())
        self.db.update_statistic('ips_and_uris', self.get_ip_stats())
        self.db.update_statistic('release_date', self.get_time_stats())
        self.db.update_statistic('exploit_mitigations', self.get_exploit_mitigations_stats())
        self.db.update_statistic('known_vulnerabilities', self.get_known_vulnerabilities_stats())
        self.db.update_statistic('software_components', self.get_software_components_stats())
        # should always be the last, because of the benchmark
        self.db.update_statistic('general', self.get_general_stats())

# ---- get statistic functions

    def get_general_stats(self):
        if self.start_time is None:
            self.start_time = time()
        stats = {
            'number_of_firmwares': self.db.firmwares.count_documents(self.match),
            'total_firmware_size': get_field_sum(self.db.firmwares, '$size', match=self.match),
            'average_firmware_size': get_field_average(self.db.firmwares, '$size', match=self.match)
        }
        if not self.match:
            stats['number_of_unique_files'] = self.db.file_objects.count_documents({})
            stats['total_file_size'] = get_field_sum(self.db.file_objects, '$size')
            stats['average_file_size'] = get_field_average(self.db.file_objects, '$size')
        else:
            aggregation_pipeline = self._get_file_object_filter_aggregation_pipeline(
                pipeline_group={'_id': '$_id', 'size': {'$push': '$size'}},
                additional_projection={'size': 1}
            )
            query_result = [item['size'][0] for item in self.db.file_objects.aggregate(aggregation_pipeline, allowDiskUse=True)]
            stats['number_of_unique_files'] = len(query_result)
            stats['total_file_size'] = sum(query_result)
            stats['average_file_size'] = avg(query_result)
        stats['creation_time'] = time()

        benchmark = stats['creation_time'] - self.start_time
        stats['benchmark'] = benchmark
        logging.info('time to create stats: {}'.format(time_format(benchmark)))
        return stats

    def get_malware_stats(self):
        stats = {}
        result = self._get_objects_and_count_of_occurrence('$processed_analysis.malware_scanner.scans.ClamAV.result', unwind=False, match=self.match)
        stats['malware'] = self._clean_malware_list(result)
        return stats

    def get_exploit_mitigations_stats(self):
        stats = dict()
        stats['exploit_mitigations'] = []
        aggregation_pipeline = self._get_file_object_filter_aggregation_pipeline(
            pipeline_group={'_id': '$parent_firmware_uids',
                            'exploit_mitigations': {'$push': '$processed_analysis.exploit_mitigations.summary'}},
            pipeline_match={'processed_analysis.exploit_mitigations.summary': {'$exists': True, '$not': {'$size': 0}}},
            additional_projection={'processed_analysis.exploit_mitigations.summary': 1})

        result_list_of_lists = [list(itertools.chain.from_iterable(d['exploit_mitigations']))
                                for d in self.db.file_objects.aggregate(aggregation_pipeline, allowDiskUse=True)]
        result_flattened = list(itertools.chain.from_iterable(result_list_of_lists))
        result = self._count_occurrences(result_flattened)
        self.get_stats_nx(result, stats)
        self.get_stats_canary(result, stats)
        self.get_stats_relro(result, stats)
        self.get_stats_pie(result, stats)
        self.get_stats_fortify(result, stats)
        return stats

    def get_stats_fortify(self, result, stats):
        fortify_off, fortify_on = self.extract_fortify_data_from_analysis(result)
        total_amount_of_files = calculate_total_files([fortify_off, fortify_on])
        self.append_nx_stats_to_result_dict(fortify_off, fortify_on, stats, total_amount_of_files)

    def extract_fortify_data_from_analysis(self, result):
        fortify_on = self.extract_mitigation_from_list('FORTIFY_SOURCE enabled', result)
        fortify_off = self.extract_mitigation_from_list('FORTIFY_SOURCE disabled', result)
        return fortify_off, fortify_on

    def get_stats_nx(self, result, stats):
        nx_off, nx_on = self.extract_nx_data_from_analysis(result)
        total_amount_of_files = calculate_total_files([nx_off, nx_on])
        self.append_nx_stats_to_result_dict(nx_off, nx_on, stats, total_amount_of_files)

    def extract_nx_data_from_analysis(self, result):
        nx_on = self.extract_mitigation_from_list('NX enabled', result)
        nx_off = self.extract_mitigation_from_list('NX disabled', result)
        return nx_off, nx_on

    def append_nx_stats_to_result_dict(self, nx_off, nx_on, stats, total_amount_of_files):
        self.update_result_dict(nx_on, stats, total_amount_of_files)
        self.update_result_dict(nx_off, stats, total_amount_of_files)

    def get_stats_canary(self, result, stats):
        canary_off, canary_on = self.extract_canary_data_from_analysis(result)
        total_amount_of_files = calculate_total_files([canary_off, canary_on])
        self.append_canary_stats_to_result_dict(canary_off, canary_on, stats, total_amount_of_files)

    def extract_canary_data_from_analysis(self, result):
        canary_on = self.extract_mitigation_from_list('Canary enabled', result)
        canary_off = self.extract_mitigation_from_list('Canary disabled', result)
        return canary_off, canary_on

    def append_canary_stats_to_result_dict(self, canary_off, canary_on, stats, total_amount_of_files):
        self.update_result_dict(canary_on, stats, total_amount_of_files)
        self.update_result_dict(canary_off, stats, total_amount_of_files)

    def get_stats_relro(self, result, stats):
        relro_off, relro_on, relro_partial = self.extract_relro_data_from_analysis(result)
        total_amount_of_files = calculate_total_files([relro_off, relro_on, relro_partial])
        self.append_relro_stats_to_result_dict(relro_off, relro_on, relro_partial, stats, total_amount_of_files)

    def extract_relro_data_from_analysis(self, result):
        relro_on = self.extract_mitigation_from_list('RELRO fully enabled', result)
        relro_partial = self.extract_mitigation_from_list('RELRO partially enabled', result)
        relro_off = self.extract_mitigation_from_list('RELRO disabled', result)
        return relro_off, relro_on, relro_partial

    def append_relro_stats_to_result_dict(self, relro_off, relro_on, relro_partial, stats, total_amount_of_files):
        self.update_result_dict(relro_on, stats, total_amount_of_files)
        self.update_result_dict(relro_partial, stats, total_amount_of_files)
        self.update_result_dict(relro_off, stats, total_amount_of_files)

    def get_stats_pie(self, result, stats):
        pie_invalid, pie_off, pie_on, pie_partial = self.extract_pie_data_from_analysis(result)
        total_amount_of_files = calculate_total_files([pie_off, pie_on, pie_partial, pie_invalid])
        self.append_pie_stats_to_result_dict(pie_invalid, pie_off, pie_on, pie_partial, stats, total_amount_of_files)

    def extract_pie_data_from_analysis(self, result):
        pie_on = self.extract_mitigation_from_list('PIE enabled', result)
        pie_partial = self.extract_mitigation_from_list('PIE/DSO present', result)
        pie_off = self.extract_mitigation_from_list('PIE disabled', result)
        pie_invalid = self.extract_mitigation_from_list('PIE - invalid ELF file', result)
        return pie_invalid, pie_off, pie_on, pie_partial

    def append_pie_stats_to_result_dict(self, pie_invalid, pie_off, pie_on, pie_partial, stats, total_amount_of_files):
        self.update_result_dict(pie_on, stats, total_amount_of_files)
        self.update_result_dict(pie_partial, stats, total_amount_of_files)
        self.update_result_dict(pie_off, stats, total_amount_of_files)
        self.update_result_dict(pie_invalid, stats, total_amount_of_files)

    @staticmethod
    def extract_mitigation_from_list(string, result):
        return [entry for entry in result if string in entry]

    def update_result_dict(self, exploit_mitigation, stats, total_amount_of_files):
        if len(exploit_mitigation) > 0 and total_amount_of_files > 0:
            percentage_value = self._round(exploit_mitigation, total_amount_of_files)
            stats['exploit_mitigations'].append(
                (exploit_mitigation[0][0], exploit_mitigation[0][1], percentage_value)
            )

    @staticmethod
    def _round(exploit_mitigation_stat, total_amount_of_files):
        rounded_value = round(exploit_mitigation_stat[0][1] / total_amount_of_files, 5)
        return rounded_value

    def get_known_vulnerabilities_stats(self):
        stats = {}
        result = self._get_objects_and_count_of_occurrence('$processed_analysis.known_vulnerabilities.summary', unwind=True, match=self.match)
        stats['known_vulnerabilities'] = self._clean_malware_list(result)
        return stats

    def get_crypto_material_stats(self):
        stats = {}
        result = self._get_objects_and_count_of_occurrence('$processed_analysis.crypto_material.summary', unwind=True, match=self.match)
        stats['crypto_material'] = result
        return stats

    @staticmethod
    def _clean_malware_list(input_list):
        tmp = []
        for item in input_list:
            if item[0] != 'not available' and item[0] != 'clean':
                tmp.append(item)
        return tmp

    def get_firmware_meta_stats(self):
        return {
            'vendor': self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, '$vendor', match=self.match),
            'device_class': self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, '$device_class', match=self.match)
        }

    def get_file_type_stats(self):
        stats = {}
        if not self.match:
            stats['file_types'] = self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, '$processed_analysis.file_type.mime')
        stats['firmware_container'] = self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, '$processed_analysis.file_type.mime', match=self.match)
        return stats

    def get_unpacking_stats(self):
        fo_packing_stats = dict(self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, '$processed_analysis.unpacker.summary', unwind=True))
        firmware_packing_stats = dict(self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, '$processed_analysis.unpacker.summary', unwind=True))
        return {
            'used_unpackers': self._get_objects_and_count_of_occurrence('$processed_analysis.unpacker.plugin_used'),
            'packed_file_types': self._get_objects_and_count_of_occurrence_single_db(
                self.db.file_objects, '$processed_analysis.file_type.mime', match={'processed_analysis.unpacker.summary': 'packed'}),
            'data_loss_file_types': self._get_objects_and_count_of_occurrence(
                '$processed_analysis.file_type.mime', match={'processed_analysis.unpacker.summary': 'data lost'}),
            'overall_unpack_ratio': self._get_ratio(fo_packing_stats, firmware_packing_stats, ['unpacked', 'packed']),
            'overall_data_loss_ratio': self._get_ratio(fo_packing_stats, firmware_packing_stats, ['data lost', 'no data lost']),
            'average_packed_entropy': avg(dict(self._get_objects_and_count_of_occurrence_single_db(
                self.db.file_objects, '$processed_analysis.unpacker.entropy', unwind=True, match={'processed_analysis.unpacker.summary': 'packed'})).keys()),
            'average_unpacked_entropy': avg(dict(self._get_objects_and_count_of_occurrence_single_db(
                self.db.file_objects, '$processed_analysis.unpacker.entropy', unwind=True, match={'processed_analysis.unpacker.summary': 'unpacked'})).keys())
        }

    def _get_file_object_filter_aggregation_pipeline(self, pipeline_group, pipeline_match=None, additional_projection=None, sort=False, unwind=None):
        aggregation_pipeline = [
            {'$unwind': '$parent_firmware_uids'},
            {'$lookup': {'from': 'firmwares', 'localField': 'parent_firmware_uids', 'foreignField': '_id', 'as': 'firmware'}},
            {'$unwind': '$firmware'},
            {'$project': {'_id': 1, 'parent_firmware_uids': 1, 'device_class': '$firmware.device_class', 'vendor': '$firmware.vendor'}},
            {'$group': pipeline_group}
        ]
        if additional_projection:
            aggregation_pipeline[3]['$project'].update(additional_projection)
        if self.match:
            aggregation_pipeline.insert(4, {'$match': self.match})
        if pipeline_match:
            aggregation_pipeline.insert(0, {'$match': pipeline_match})
        if unwind:
            aggregation_pipeline.insert(-1, {'$unwind': unwind})
        if sort:
            aggregation_pipeline.append({'$sort': SON([('_id', 1)])})
        return aggregation_pipeline

    def get_architecture_stats(self):
        aggregation_pipeline = self._get_file_object_filter_aggregation_pipeline(
            pipeline_group={'_id': '$parent_firmware_uids', 'architecture': {'$push': '$processed_analysis.cpu_architecture.summary'}},
            pipeline_match={'processed_analysis.cpu_architecture.summary': {'$exists': True, '$not': {'$size': 0}}},
            additional_projection={'processed_analysis.cpu_architecture.summary': 1}
        )
        query_result = self.db.file_objects.aggregate(aggregation_pipeline, allowDiskUse=True)
        result = [
            self._shorten_architecture_string(self._find_most_frequent_architecture(list(itertools.chain.from_iterable(item['architecture']))))
            for item in query_result
        ]
        return {'cpu_architecture': self._count_occurrences(result)}

    def _find_most_frequent_architecture(self, arch_list):
        try:
            arch_frequency = sorted(self._count_occurrences(arch_list), key=lambda x: x[1], reverse=True)
            return arch_frequency[0][0]
        except (AttributeError, KeyError, TypeError) as exception:
            logging.error('Could not get arch frequency: {} {}'.format(sys.exc_info()[0].__name__, exception))
            return None

    @staticmethod
    def _count_occurrences(result_list):
        return list(Counter(result_list).items())

    @staticmethod
    def _shorten_architecture_string(string):
        if string is None:
            return None
        logging.debug(string)
        string_parts = string.split(',')[:2]
        if len(string_parts) > 1:
            # long string with bitness and endianness and ' (M)' at the end
            return ','.join(string.split(',')[:2])
        # short string (without bitness and endianness but with ' (M)' at the end)
        return string[:-4]

    def get_ip_stats(self):
        return {
            'ips_v4': self._get_objects_and_count_of_occurrence(
                '$processed_analysis.ip_and_uri_finder.ips_v4', unwind=True, sumup_function=sum_up_nested_lists),
            'ips_v6': self._get_objects_and_count_of_occurrence(
                '$processed_analysis.ip_and_uri_finder.ips_v6', unwind=True, sumup_function=sum_up_nested_lists),
            'uris': self._get_objects_and_count_of_occurrence('$processed_analysis.ip_and_uri_finder.uris', unwind=True)
        }

    @staticmethod
    def _get_ratio(fo_stats, firmware_stats, values):
        for stats in [fo_stats, firmware_stats]:
            for value in values:
                stats.setdefault(value, 0)
        try:
            sum_ = fo_stats[values[0]] + fo_stats[values[1]] + firmware_stats[values[0]] + firmware_stats[values[1]]
            return (fo_stats[values[0]] + firmware_stats[values[0]]) / sum_
        except ZeroDivisionError:
            return 0

    def get_time_stats(self):
        projection = {'month': {'$month': '$release_date'}, 'year': {'$year': '$release_date'}}
        query = get_objects_and_count_of_occurrence(self.db.firmwares, projection, match=self.match)
        histogram_data = self._build_stats_entry_from_date_query(query)
        return {'date_histogram_data': histogram_data}

    @staticmethod
    def _get_month_name(month_int):
        return datetime(1900, month_int, 1).strftime('%B')

    def get_software_components_stats(self):
        query_result = self.db.file_objects.aggregate([
            {'$project': {'sc': {'$objectToArray': '$processed_analysis.software_components'}}},
            {'$match': {'sc.4': {'$exists': True}}},  # match only analyses with actual results (more keys than the 4 standard keys)
            {'$unwind': '$sc'},
            {'$group': {'_id': '$sc.k', 'count': {'$sum': 1}}}
        ], allowDiskUse=True)

        return {'software_components': [
            (entry['_id'], int(entry['count']))
            for entry in query_result
            if entry['_id'] not in ['summary', 'analysis_date', 'file_system_flag', 'plugin_version', 'tags', 'skipped', 'system_version']
        ]}

# ---- internal stuff

    def _build_stats_entry_from_date_query(self, date_query):
        time_dict = build_time_dict(date_query)
        result = []
        for year in sorted(time_dict.keys()):
            for month in sorted(time_dict[year].keys()):
                result.append(('{} {}'.format(self._get_month_name(month), year), time_dict[year][month]))
        return result

    @staticmethod
    def _convert_dict_list_to_list(input_list):
        result = []
        for item in input_list:
            if item['_id'] is None:
                item['_id'] = 'not available'
            result.append([item['_id'], item['count']])
        return result

    def _get_objects_and_count_of_occurrence_single_db(self, database, object_path, unwind=False, match=None):
        if self.match and database == self.db.file_objects:  # filtered live query on file objects
            aggregation_pipeline = self._get_file_object_filter_aggregation_pipeline(
                pipeline_group={'_id': object_path, 'count': {'$sum': 1}}, pipeline_match=match, sort=True,
                additional_projection={object_path.replace('$', ''): 1}, unwind=object_path if unwind else None)
            tmp = database.aggregate(aggregation_pipeline, allowDiskUse=True)
        else:
            tmp = get_objects_and_count_of_occurrence(database, object_path, unwind=unwind, match=merge_dict(match, self.match))
        chart_list = self._convert_dict_list_to_list(tmp)
        return self._filter_sanitized_objects(chart_list)

    def _get_objects_and_count_of_occurrence(self, object_path, unwind=False, match=None, sumup_function=sum_up_lists):
        result_firmwares = self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, object_path, unwind=unwind, match=match)
        result_files = self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, object_path, unwind=unwind, match=match)
        combined_result = sumup_function(result_firmwares, result_files)
        return combined_result

    @staticmethod
    def _filter_sanitized_objects(input_list):
        out_list = []
        for item in input_list:
            if not is_sanitized_entry(item[0]):
                out_list.append(item)
        return out_list
