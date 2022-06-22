'''
generate workload statistics
'''
import logging
import os
import sys
from multiprocessing import Process, Value
from time import sleep, time

import distro
import psutil

from storage.db_interface_stats import StatsUpdateDbInterface
from version import __VERSION__


class WorkLoadStatistic:

    def __init__(self, config, component, analysis_workload_fn=None, comparison_workload_fn=None, unpacking_workload_fn=None):
        self.config = config
        self.component = component
        self.db = StatsUpdateDbInterface(config=self.config)
        self.platform_information = self._get_platform_information()
        self._analysis_workload_fn = analysis_workload_fn if analysis_workload_fn else lambda: None
        self._comparison_workload_fn = comparison_workload_fn if comparison_workload_fn else lambda: None
        self._unpacking_workload_fn = unpacking_workload_fn if unpacking_workload_fn else lambda: None

        self.process = Process(target=self._entrypoint)

        self.stop_condition = Value('i', 1)

    def start(self):
        self.stop_condition.value = 0
        self.process.start()
        logging.debug(f'{self.component}: Online')

    def shutdown(self):
        logging.debug(f'{self.component}: shutting down -> set offline message')
        self.stop_condition.value = 1
        self.db.update_statistic(self.component, {'status': 'offline', 'last_update': time()})

    def _entrypoint(self):
        while self.stop_condition.value == 0:
            self.update()
            sleep(5)

    def update(self):
        stats = {
            'name': self.component,
            'status': 'online',
            'last_update': time(),
            'system': self._get_system_information(),
            'platform': self.platform_information,
        }
        analyis_wl = self._analysis_workload_fn()
        if analyis_wl:
            stats['analysis'] = analyis_wl
        comparison_wl = self._comparison_workload_fn()
        if comparison_wl:
            stats['compare'] = comparison_wl
        unpacking_wl = self._unpacking_workload_fn()
        if unpacking_wl:
            stats['unpacking'] = unpacking_wl

        self.db.update_statistic(self.component, stats)

    def _get_system_information(self):
        memory_usage = psutil.virtual_memory()
        try:
            disk_usage = psutil.disk_usage(self.config['data-storage']['firmware-file-storage-directory'])
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
