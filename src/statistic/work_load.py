'''
generate workload statistics
'''
import logging
import os
import sys
from time import time

import distro
import psutil

from config import cfg
from storage.db_interface_stats import StatsUpdateDbInterface
from version import __VERSION__


class WorkLoadStatistic:
    def __init__(self, component):
        self.component = component
        self.db = StatsUpdateDbInterface()
        self.platform_information = self._get_platform_information()
        logging.debug(f'{self.component}: Online')

    def shutdown(self):
        logging.debug(f'{self.component}: shutting down -> set offline message')
        self.db.update_statistic(self.component, {'status': 'offline', 'last_update': time()})

    def update(self, unpacking_workload=None, analysis_workload=None, compare_workload=None):
        stats = {
            'name': self.component,
            'status': 'online',
            'last_update': time(),
            'system': self._get_system_information(),
            'platform': self.platform_information,
        }
        if unpacking_workload:
            stats['unpacking'] = unpacking_workload
        if analysis_workload:
            stats['analysis'] = analysis_workload
        if compare_workload:
            stats['compare'] = compare_workload
        self.db.update_statistic(self.component, stats)

    def _get_system_information(self):
        memory_usage = psutil.virtual_memory()
        try:
            disk_usage = psutil.disk_usage(cfg.data_storage.firmware_file_storage_directory)
        except Exception:
            disk_usage = psutil.disk_usage('/')
        try:
            cpu_percentage = psutil.cpu_percent()
        except Exception:
            cpu_percentage = 'unknown'

        result = {
            'cpu_cores': psutil.cpu_count(logical=False),
            'virtual_cpu_cores': psutil.cpu_count(),
            'cpu_percentage': cpu_percentage,
            'load_average': ', '.join(str(x) for x in os.getloadavg()),
            'memory_total': memory_usage.total,
            'memory_used': memory_usage.used,
            'memory_percent': memory_usage.percent,
            'disk_total': disk_usage.total,
            'disk_used': disk_usage.used,
            'disk_percent': disk_usage.percent,
        }
        return result

    @staticmethod
    def _get_platform_information():
        operating_system = f'{distro.id()} {distro.version()}'
        python_version = '.'.join(str(x) for x in sys.version_info[0:3])
        fact_version = __VERSION__
        return {'os': operating_system, 'python': python_version, 'fact_version': fact_version}
