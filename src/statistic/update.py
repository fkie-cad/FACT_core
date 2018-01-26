import itertools
import logging
import sys
from datetime import datetime
from time import time

from bson.son import SON
from common_helper_filter.time import time_format
from common_helper_mongo import get_field_average, get_field_sum, get_objects_and_count_of_occurrence

from helperFunctions.dataConversion import build_time_dict
from helperFunctions.merge_generators import sum_up_lists, avg, merge_dict
from helperFunctions.mongo_task_conversion import is_sanitized_entry
from storage.db_interface_statistic import StatisticDbUpdater


class StatisticUpdater(object):
    '''
    This class handles statistic generation
    '''

    def __init__(self, config=None):
        self._config = config
        self.db = StatisticDbUpdater(config=self._config)
        self.start_time = None
        self.match = dict()

    def shutdown(self):
        self.db.shutdown()

    def set_match(self, match):
        self.match = match if match else dict()

    def update_all_stats(self):
        self.start_time = time()

        self.db.update_statistic('firmware_meta', self._get_firmware_meta_stats())
        self.db.update_statistic('file_type', self._get_file_type_stats())
        self.db.update_statistic('malware', self._get_malware_stats())
        self.db.update_statistic('crypto_material', self._get_crypto_material_stats())
        self.db.update_statistic('unpacking', self._get_unpacking_stats())
        self.db.update_statistic('architecture', self._get_architecture_stats())
        self.db.update_statistic('ips_and_uris', self._get_ip_stats())
        self.db.update_statistic('release_date', self._get_time_stats())
        self.db.update_statistic('exploit_mitigations', self._get_exploit_mitigations_stats())
        # should always be the last, because of the benchmark
        self.db.update_statistic('general', self.get_general_stats())

# ---- get statistic functions

    def get_general_stats(self):
        if self.start_time is None:
            self.start_time = time()
        stats = {}
        stats['number_of_firmwares'] = self.db.firmwares.count(self.match)
        stats['total_firmware_size'] = get_field_sum(self.db.firmwares, '$size', match=self.match)
        stats['average_firmware_size'] = get_field_average(self.db.firmwares, '$size', match=self.match)
        if not self.match:
            stats['number_of_unique_files'] = self.db.file_objects.count()
            stats['total_file_size'] = get_field_sum(self.db.file_objects, '$size')
            stats['average_file_size'] = get_field_average(self.db.file_objects, '$size')
        else:
            aggregation_pipeline = self._get_file_object_filter_aggregation_pipeline(
                pipeline_group={'_id': '$_id', 'size': {'$push': '$size'}},
                additional_projection={'size': 1}
            )
            query_result = [item['size'][0] for item in self.db.file_objects.aggregate(aggregation_pipeline)]
            stats['number_of_unique_files'] = len(query_result)
            stats['total_file_size'] = sum(query_result)
            stats['average_file_size'] = avg(query_result)
        stats['creation_time'] = time()

        benchmark = stats['creation_time'] - self.start_time
        stats['benchmark'] = benchmark
        logging.info('time to create stats: {}'.format(time_format(benchmark)))
        return stats

    def _get_malware_stats(self):
        stats = {}
        result = self._get_objects_and_count_of_occurrence_firmware_and_file_db(
            '$processed_analysis.malware_scanner.scans.ClamAV.result', unwind=False, match=self.match)
        stats['malware'] = self._clean_malware_list(result)
        return stats

    def _get_exploit_mitigations_stats(self):
        stats = {}
        stats['exploit_mitigations'] = []
        aggregation_pipeline = self._get_file_object_filter_aggregation_pipeline(
            pipeline_group={'_id': '$parent_firmware_uids',
                            'exploit_mitigations': {'$push': '$processed_analysis.exploit_mitigations.summary'}},
            pipeline_match={'processed_analysis.exploit_mitigations.summary': {'$exists': True, '$not': {'$size': 0}}},
            additional_projection={'processed_analysis.exploit_mitigations.summary': 1})

        result_list_of_lists = [list(itertools.chain.from_iterable(d['exploit_mitigations']))
                                for d in self.db.file_objects.aggregate(aggregation_pipeline)]
        result_flattened = list(itertools.chain.from_iterable(result_list_of_lists))
        result = self._count_occurrences(result_flattened)

        canary_on = self.extract_mitigation_from_list("Canary enabled", result)
        canary_off = self.extract_mitigation_from_list("Canary disabled", result)
        total_amount_of_files = canary_on[0][1] + canary_off[0][1]
        self.set_stats(canary_on, stats, total_amount_of_files)
        self.set_stats(canary_off, stats, total_amount_of_files)

        nx_on = self.extract_mitigation_from_list("NX enabled", result)
        nx_off = self.extract_mitigation_from_list("NX disabled", result)
        self.set_stats(nx_on, stats, total_amount_of_files)
        self.set_stats(nx_off, stats, total_amount_of_files)

        relro_on = self.extract_mitigation_from_list("RELRO fully enabled", result)
        relro_partial = self.extract_mitigation_from_list("RELRO partially enabled", result)
        relro_off = self.extract_mitigation_from_list("RELRO disabled", result)
        self.set_stats(relro_on, stats, total_amount_of_files)
        self.set_stats(relro_partial, stats, total_amount_of_files)
        self.set_stats(relro_off, stats, total_amount_of_files)

        pie_on = self.extract_mitigation_from_list("PIE enabled", result)
        pie_partial = self.extract_mitigation_from_list("PIE/DSO present", result)
        pie_off = self.extract_mitigation_from_list("PIE disabled", result)
        pie_invalid = self.extract_mitigation_from_list("PIE - invalid ELF file", result)
        self.set_stats(pie_on, stats, total_amount_of_files)
        self.set_stats(pie_partial, stats, total_amount_of_files)
        self.set_stats(pie_off, stats, total_amount_of_files)
        self.set_stats(pie_invalid, stats, total_amount_of_files)
        return stats

    def extract_mitigation_from_list(self, string, result):
        exploit_mitigation_stat = list(filter(lambda x: x.count(string) > 0, result))
        return exploit_mitigation_stat

    def set_stats(self, exploit_mitigation, stats, total_amount_of_files):
        stats['exploit_mitigations'].append((exploit_mitigation[0][0],
                                             exploit_mitigation[0][1],
                                             self.round(exploit_mitigation, total_amount_of_files)))

    def round(self, exploit_mitigation_stat, total_amount_of_files):
        rounded_value = round(exploit_mitigation_stat[0][1] / total_amount_of_files, 5)
        return rounded_value

    def _get_crypto_material_stats(self):
        stats = {}
        result = self._get_objects_and_count_of_occurrence_firmware_and_file_db(
            '$processed_analysis.crypto_material.summary', unwind=True, match=self.match)
        stats['crypto_material'] = self._clean_malware_list(result)
        return stats

    @staticmethod
    def _clean_malware_list(input_list):
        tmp = []
        for item in input_list:
            if item[0] != 'not available' and item[0] != 'clean':
                tmp.append(item)
        return tmp

    def _get_firmware_meta_stats(self):
        stats = {}
        stats['vendor'] = self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, '$vendor', match=self.match)
        stats['device_class'] = self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, '$device_class', match=self.match)
        return stats

    def _get_file_type_stats(self):
        stats = {}
        if not self.match:
            stats['file_types'] = self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, '$processed_analysis.file_type.mime')
        stats['firmware_container'] = self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, '$processed_analysis.file_type.mime', match=self.match)
        return stats

    def _get_unpacking_stats(self):
        stats = {}
        stats['used_unpackers'] = self._get_objects_and_count_of_occurrence_firmware_and_file_db('$processed_analysis.unpacker.plugin_used')
        stats['packed_file_types'] = self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, '$processed_analysis.file_type.mime', match={'processed_analysis.unpacker.summary': 'packed'})
        stats['data_loss_file_types'] = self._get_objects_and_count_of_occurrence_firmware_and_file_db('$processed_analysis.file_type.mime', match={'processed_analysis.unpacker.summary': 'data lost'})
        fo_packing_stats = dict(self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, '$processed_analysis.unpacker.summary', unwind=True))
        firmware_packing_stats = dict(self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, '$processed_analysis.unpacker.summary', unwind=True))
        stats['overall_unpack_ratio'] = self._get_ratio(fo_packing_stats, firmware_packing_stats, ['unpacked', 'packed'])
        stats['overall_data_loss_ratio'] = self._get_ratio(fo_packing_stats, firmware_packing_stats, ['data lost', 'no data lost'])
        stats['average_packed_entropy'] = avg(dict(self._get_objects_and_count_of_occurrence_single_db(
            self.db.file_objects, '$processed_analysis.unpacker.entropy', unwind=True, match={'processed_analysis.unpacker.summary': 'packed'})).keys())
        stats['average_unpacked_entropy'] = avg(dict(self._get_objects_and_count_of_occurrence_single_db(
            self.db.file_objects, '$processed_analysis.unpacker.entropy', unwind=True, match={'processed_analysis.unpacker.summary': 'unpacked'})).keys())
        return stats

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

    def _get_architecture_stats(self):
        stats = {}
        aggregation_pipeline = self._get_file_object_filter_aggregation_pipeline(
            pipeline_group={'_id': '$parent_firmware_uids', 'architecture': {'$push': '$processed_analysis.cpu_architecture.summary'}},
            pipeline_match={'processed_analysis.cpu_architecture.summary': {'$exists': True, '$not': {'$size': 0}}},
            additional_projection={'processed_analysis.cpu_architecture.summary': 1}
        )
        result = [self._shorten_architecture_string(self._find_most_frequent_architecture(list(itertools.chain.from_iterable(item['architecture']))))
                  for item in self.db.file_objects.aggregate(aggregation_pipeline)]
        stats['cpu_architecture'] = self._count_occurrences(result)
        return stats

    def _find_most_frequent_architecture(self, arch_list):
        try:
            arch_frequency = sorted(self._count_occurrences(arch_list), key=lambda x: x[1], reverse=True)
            return arch_frequency[0][0]
        except Exception as e:
            logging.error('Could not get arch frequency: {} {}'.format(sys.exc_info()[0].__name__, e))
            return None

    @staticmethod
    def _count_occurrences(l):
        return [(item, l.count(item)) for item in set(l)]

    @staticmethod
    def _shorten_architecture_string(s):
        if s is None:
            return None
        logging.debug(s)
        string_parts = s.split(',')[:2]
        if len(string_parts) > 1:
            # long string with bitness and endianness and ' (M)' at the end
            return ','.join(s.split(',')[:2])
        else:
            # short string (without bitness and endianness but with ' (M)' at the end)
            return s[:-4]

    def _get_ip_stats(self):
        stats = {}
        stats['ips_v4'] = self._get_objects_and_count_of_occurrence_firmware_and_file_db('$processed_analysis.ip_and_uri_finder.ips_v4', unwind=True)
        stats['ips_v6'] = self._get_objects_and_count_of_occurrence_firmware_and_file_db('$processed_analysis.ip_and_uri_finder.ips_v6', unwind=True)
        stats['uris'] = self._get_objects_and_count_of_occurrence_firmware_and_file_db('$processed_analysis.ip_and_uri_finder.uris', unwind=True)
        return stats

    @staticmethod
    def _get_ratio(fo_stats, firmware_stats, values):
        for stats in [fo_stats, firmware_stats]:
            for v in values:
                if v not in stats:
                    stats[v] = 0
        try:
            return (fo_stats[values[0]] + firmware_stats[values[0]]) / \
                   (fo_stats[values[0]] + fo_stats[values[1]] + firmware_stats[values[0]] + firmware_stats[values[1]])
        except ZeroDivisionError:
            return 0

    def _get_time_stats(self):
        projection = {'month': {'$month': '$release_date'}, 'year': {'$year': '$release_date'}}
        query = get_objects_and_count_of_occurrence(self.db.firmwares, projection, match=self.match)
        histogram_data = self._build_stats_entry_from_date_query(query)
        return {'date_histogram_data': histogram_data}

    @staticmethod
    def _get_month_name(month_int):
        return datetime(1900, month_int, 1).strftime('%B')

    def _build_stats_entry_from_date_query(self, date_query):
        time_dict = build_time_dict(date_query)
        result = []
        for year in sorted(time_dict.keys()):
            for month in sorted(time_dict[year].keys()):
                result.append(('{} {}'.format(self._get_month_name(month), year), time_dict[year][month]))
        return result

# ---- internal stuff

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
            tmp = database.aggregate(aggregation_pipeline)
        else:
            tmp = get_objects_and_count_of_occurrence(database, object_path, unwind=unwind, match=merge_dict(match, self.match))
        chart_list = self._convert_dict_list_to_list(tmp)
        return self._filter_sanitzized_objects(chart_list)

    def _get_objects_and_count_of_occurrence_firmware_and_file_db(self, object_path, unwind=False, match=None):
        result_firmwares = self._get_objects_and_count_of_occurrence_single_db(self.db.firmwares, object_path, unwind=unwind, match=match)
        result_files = self._get_objects_and_count_of_occurrence_single_db(self.db.file_objects, object_path, unwind=unwind, match=match)
        combined_result = sum_up_lists(result_firmwares, result_files)
        return combined_result

    @staticmethod
    def _filter_sanitzized_objects(input_list):
        out_list = []
        for item in input_list:
            if not is_sanitized_entry(item[0]):
                out_list.append(item)
        return out_list
