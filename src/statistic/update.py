import logging
from configparser import ConfigParser
from time import time
from typing import Dict, List, Optional, Tuple

from common_helper_filter.time import time_format

from statistic.time_stats import build_stats_entry_from_date_query
from storage.db_interface_stats import RelativeStats, Stats, StatsUpdateDbInterface, count_occurrences
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry


class StatsUpdater:
    '''
    This class handles statistic generation
    '''

    def __init__(self, stats_db: Optional[StatsUpdateDbInterface] = None, config: Optional[ConfigParser] = None):
        self.db = stats_db if stats_db else StatsUpdateDbInterface(config=config)
        self.start_time = None
        self.match = {}

    def set_match(self, match):
        self.match = match or {}

    def update_all_stats(self):
        self.start_time = time()

        with self.db.get_read_only_session():
            self.db.update_statistic('firmware_meta', self.get_firmware_meta_stats())
            self.db.update_statistic('file_type', self.get_file_type_stats())
            self.db.update_statistic('crypto_material', self.get_crypto_material_stats())
            self.db.update_statistic('unpacking', self.get_unpacking_stats())
            self.db.update_statistic('architecture', self.get_architecture_stats())
            self.db.update_statistic('ips_and_uris', self.get_ip_stats())
            self.db.update_statistic('release_date', self.get_time_stats())
            self.db.update_statistic('exploit_mitigations', self.get_exploit_mitigations_stats())
            self.db.update_statistic('known_vulnerabilities', self.get_known_vulnerabilities_stats())
            self.db.update_statistic('software_components', self.get_software_components_stats())
            self.db.update_statistic('elf_executable', self.get_executable_stats())
            # should always be the last, because of the benchmark
            self.db.update_statistic('general', self.get_general_stats())

    # ---- get statistic functions

    def get_general_stats(self):
        if self.start_time is None:
            self.start_time = time()
        with self.db.get_read_only_session():
            stats = {
                'number_of_firmwares': self.db.get_count(q_filter=self.match, firmware=True),
                'total_firmware_size': self.db.get_sum(FileObjectEntry.size, q_filter=self.match, firmware=True),
                'average_firmware_size': self.db.get_avg(FileObjectEntry.size, q_filter=self.match, firmware=True),
                'number_of_unique_files': self.db.get_count(q_filter=self.match, firmware=False),
                'total_file_size': self.db.get_sum(FileObjectEntry.size, q_filter=self.match, firmware=False),
                'average_file_size': self.db.get_avg(FileObjectEntry.size, q_filter=self.match, firmware=False),
                'creation_time': time(),
            }
        benchmark = stats['creation_time'] - self.start_time
        stats['benchmark'] = benchmark
        logging.info(f'time to create stats: {time_format(benchmark)}')
        return stats

    @staticmethod
    def _filter_results(stats: Stats) -> Stats:
        blacklist = ['not available', 'clean']
        return [item for item in stats if not item[0] in blacklist]

    def get_exploit_mitigations_stats(self) -> Dict[str, RelativeStats]:
        result = self.db.count_values_in_summary(plugin='exploit_mitigations', q_filter=self.match)
        return {
            'exploit_mitigations': [
                *self.get_relative_stats(['NX enabled', 'NX disabled'], result),
                *self.get_relative_stats(['Canary enabled', 'Canary disabled'], result),
                *self.get_relative_stats(['RELRO fully enabled', 'RELRO partially enabled', 'RELRO disabled'], result),
                *self.get_relative_stats(
                    ['PIE enabled', 'PIE/DSO present', 'PIE disabled', 'PIE - invalid ELF file'], result
                ),
                *self.get_relative_stats(['FORTIFY_SOURCE enabled', 'FORTIFY_SOURCE disabled'], result),
            ]
        }

    @staticmethod
    def get_relative_stats(keywords: List[str], stats: Stats) -> RelativeStats:
        count_dict = {
            keyword: count
            for keyword in keywords
            for summary_item, count in stats
            if keyword.lower() in summary_item.lower()
        }
        total = sum(count_dict.values())
        return [(label, count, round(count / total, 5)) for label, count in count_dict.items()]

    def get_known_vulnerabilities_stats(self) -> Dict[str, Stats]:
        stats = self.db.count_values_in_summary(plugin='known_vulnerabilities', q_filter=self.match)
        return {'known_vulnerabilities': self._filter_results(stats)}

    def get_crypto_material_stats(self) -> Dict[str, Stats]:
        stats = self.db.count_values_in_summary(plugin='crypto_material', q_filter=self.match)
        return {'crypto_material': stats}

    def get_firmware_meta_stats(self) -> Dict[str, Stats]:
        return {
            'vendor': self.db.count_distinct_values(FirmwareEntry.vendor, q_filter=self.match),
            'device_class': self.db.count_distinct_values(FirmwareEntry.device_class, q_filter=self.match),
        }

    def get_file_type_stats(self) -> Dict[str, Stats]:
        return {
            label: self.db.count_distinct_in_analysis(
                AnalysisEntry.result['mime'], 'file_type', firmware=firmware, q_filter=self.match
            )
            for label, firmware in [('file_types', False), ('firmware_container', True)]
        }

    def get_unpacking_stats(self):
        fo_packing_stats = dict(self.db.count_values_in_summary(plugin='unpacker', q_filter=self.match))
        firmware_packing_stats = dict(
            self.db.count_values_in_summary(plugin='unpacker', q_filter=self.match, firmware=True)
        )
        return {
            'used_unpackers': self.db.get_used_unpackers(q_filter=self.match),
            'packed_file_types': self.db.get_unpacking_file_types('packed', q_filter=self.match),
            'data_loss_file_types': self.db.get_unpacking_file_types('data lost', q_filter=self.match),
            'overall_unpack_ratio': self._get_ratio(fo_packing_stats, firmware_packing_stats, ['unpacked', 'packed']),
            'overall_data_loss_ratio': self._get_ratio(
                fo_packing_stats, firmware_packing_stats, ['data lost', 'no data lost']
            ),
            'average_packed_entropy': self.db.get_unpacking_entropy('packed', q_filter=self.match),
            'average_unpacked_entropy': self.db.get_unpacking_entropy('unpacked', q_filter=self.match),
        }

    def get_architecture_stats(self):
        arch_stats_by_fw = {}
        for arch, count, uid in self.db.get_arch_stats(q_filter=self.match):
            arch_stats_by_fw.setdefault(uid, []).append((arch, count))
        arch_stats = [
            self._shorten_architecture_string(self._find_most_frequent_architecture(arch_count_list))
            for arch_count_list in arch_stats_by_fw.values()
        ]
        return {'cpu_architecture': count_occurrences(arch_stats)}

    @staticmethod
    def _find_most_frequent_architecture(arch_stats: Stats) -> str:
        return sorted(arch_stats, key=lambda tup: tup[1], reverse=True)[0][0]

    @staticmethod
    def _shorten_architecture_string(arch_string: str) -> str:
        string_parts = arch_string.split(',')[:2]
        if len(string_parts) > 1:
            # long string with bitness and endianness and ' (M)' at the end
            return ','.join(string_parts)
        # short string (without bitness and endianness but with ' (M)' at the end)
        return arch_string[:-4]

    @staticmethod
    def _get_ratio(fo_stats, firmware_stats, keywords) -> float:
        try:
            total = sum(stat.get(key, 0) for key in keywords for stat in [fo_stats, firmware_stats])
            return (fo_stats.get(keywords[0], 0) + firmware_stats.get(keywords[0], 0)) / total
        except ZeroDivisionError:
            return 0.0

    def get_executable_stats(self) -> Dict[str, List[Tuple[str, int, float, str]]]:
        total = self.db.get_regex_mime_match_count('^ELF.*executable')
        stats = []
        for label, query_match in [
            ('big endian', '^ELF.*MSB.*executable'),
            ('little endian', '^ELF.*LSB.*executable'),
            ('stripped', '^ELF.*executable.*, stripped'),
            ('not stripped', '^ELF.*executable.*, not stripped'),
            ('32-bit', '^ELF 32-bit.*executable'),
            ('64-bit', '^ELF 64-bit.*executable'),
            ('dynamically linked', '^ELF.*executable.*dynamically linked'),
            ('statically linked', '^ELF.*executable.*statically linked'),
            ('section info missing', '^ELF.*executable.*section header'),
        ]:
            count = self.db.get_regex_mime_match_count(query_match)
            stats.append((label, count, count / (total if total else 1), query_match))
        return {'executable_stats': stats}

    def get_ip_stats(self) -> Dict[str, Stats]:
        ip_stats = {
            key: self.db.count_distinct_values_in_array(
                AnalysisEntry.result[key], plugin='ip_and_uri_finder', q_filter=self.match
            )
            for key in ['ips_v4', 'ips_v6', 'uris']
        }
        self._remove_location_info(ip_stats)
        return ip_stats

    @staticmethod
    def _remove_location_info(ip_stats: Dict[str, Stats]):
        # IP data can contain location info -> just use the IP string (which is the first element in a list)
        for key in ['ips_v4', 'ips_v6']:
            for index, (ip, count) in enumerate(ip_stats[key]):
                if isinstance(ip, list):
                    ip_without_gps_info = ip[0]
                    ip_stats[key][index] = (ip_without_gps_info, count)

    def get_time_stats(self):
        release_date_stats = self.db.get_release_date_stats(q_filter=self.match)
        return {'date_histogram_data': build_stats_entry_from_date_query(release_date_stats)}

    def get_software_components_stats(self):
        return {'software_components': self.db.get_software_components(q_filter=self.match)}
