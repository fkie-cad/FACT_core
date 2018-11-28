import logging
from concurrent.futures import ThreadPoolExecutor
from configparser import ConfigParser
from distutils.version import LooseVersion
from multiprocessing import Queue, Value
from random import shuffle

from queue import Empty
from time import sleep, time
from typing import Tuple, List, Optional, Set

from helperFunctions.compare_sets import substring_is_in_list
from helperFunctions.config import read_list_from_config
from helperFunctions.parsing import bcolors
from helperFunctions.plugin import import_plugins
from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from helperFunctions.tag import check_tags, add_tags_to_object
from objects.file import FileObject
from storage.db_interface_backend import BackEndDbInterface

MANDATORY_PLUGINS = ['file_type', 'file_hashes']


class AnalysisScheduler(object):
    '''
    This Scheduler performs analysis of firmware objects
    '''

    def __init__(self, config: Optional[ConfigParser]=None, pre_analysis=None, post_analysis=None, db_interface=None):
        self.config = config
        self.analysis_plugins = {}
        self.load_plugins()
        self.stop_condition = Value('i', 0)
        self.process_queue = Queue()
        self.tag_queue = Queue()
        self.db_backend_service = db_interface if db_interface else BackEndDbInterface(config=config)
        self.pre_analysis = pre_analysis if pre_analysis else self.db_backend_service.add_object
        self.post_analysis = post_analysis if post_analysis else self.db_backend_service.add_analysis
        self.start_scheduling_process()
        self.start_result_collector()
        logging.info('Analysis System online...')
        logging.info('Plugins available: {}'.format(self.get_list_of_available_plugins()))

    def shutdown(self):
        '''
        shutdown the scheduler and all loaded plugins
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        with ThreadPoolExecutor() as e:
            e.submit(self.schedule_process.join)
            e.submit(self.result_collector_process.join)
            for plugin in self.analysis_plugins:
                e.submit(self.analysis_plugins[plugin].shutdown)
        if getattr(self.db_backend_service, 'shutdown', False):
            self.db_backend_service.shutdown()
        self.tag_queue.close()
        self.process_queue.close()
        logging.info('Analysis System offline')

    def add_update_task(self, fo):
        for included_file in self.db_backend_service.get_list_of_all_included_files(fo):
            child = self.db_backend_service.get_object(included_file)
            child.scheduled_analysis = fo.scheduled_analysis
            shuffle(child.scheduled_analysis)
            self.check_further_process_or_complete(child)
        self.check_further_process_or_complete(fo)

    def add_task(self, fo: FileObject):
        '''
        This function should be used to add a new firmware object to the scheduler
        '''
        if fo.scheduled_analysis is None:
            fo.scheduled_analysis = MANDATORY_PLUGINS
        else:
            fo.scheduled_analysis = self._smart_shuffle(fo.scheduled_analysis + MANDATORY_PLUGINS)
        self.check_further_process_or_complete(fo)

    def _smart_shuffle(self, plugin_list: List[str]) -> List[str]:
        scheduled_plugins = []
        remaining_plugins = set(plugin_list)
        while len(remaining_plugins) > 0:
            next_plugins = self._get_plugins_without_unmet_dependencies(remaining_plugins, scheduled_plugins)
            if not next_plugins:
                logging.error('Error: Could not schedule plugins because dependencies cannot be fulfilled: {}'.format(remaining_plugins))
                return scheduled_plugins
            shuffle(next_plugins)
            scheduled_plugins[:0] = next_plugins
            remaining_plugins.difference_update(next_plugins)
        return scheduled_plugins

    def _get_plugins_without_unmet_dependencies(self, remaining_plugins: Set[str], scheduled_plugins: List[str]) -> List[str]:
        result = []
        for plugin in remaining_plugins:
            dependencies = self.analysis_plugins[plugin].DEPENDENCIES
            if not dependencies or all(d in scheduled_plugins for d in dependencies):
                result.append(plugin)
        return result

    def get_list_of_available_plugins(self):
        '''
        returns a list of all loaded plugins
        '''
        plugin_list = list(self.analysis_plugins.keys())
        plugin_list.sort(key=str.lower)
        return plugin_list

    def get_default_plugins_from_config(self):
        try:
            result = {}
            for plugin_set in self.config['default_plugins']:
                result[plugin_set] = read_list_from_config(self.config, 'default_plugins', plugin_set)
            return result
        except (TypeError, KeyError, AttributeError):
            logging.warning('default plug-ins not set in config')
            return []

# ---- internal functions ----

    def get_plugin_dict(self):
        '''
        returns a dictionary of plugins with the following form: names as keys and the respective description value
        {NAME: (DESCRIPTION, MANDATORY_FLAG, DEFAULT_FLAG, VERSION)}
        - mandatory plug-ins shall not be shown in the analysis selection but always exectued
        - default plug-ins shall be pre-selected in the analysis selection
        '''
        plugin_list = self.get_list_of_available_plugins()
        plugin_list = self._remove_unwanted_plugins(plugin_list)
        default_plugins = self.get_default_plugins_from_config()
        default_flag_dict = {}
        result = {}
        for plugin in plugin_list:
            mandatory_flag = plugin in MANDATORY_PLUGINS
            for key in default_plugins.keys():
                default_flag_dict[key] = plugin in default_plugins[key]
            result[plugin] = (self.analysis_plugins[plugin].DESCRIPTION, mandatory_flag, dict(default_flag_dict), self.analysis_plugins[plugin].VERSION)
        result['unpacker'] = ('Additional information provided by the unpacker', True, False)
        return result

    def get_scheduled_workload(self):
        workload = {'analysis_main_scheduler': self.process_queue.qsize()}
        for plugin in self.analysis_plugins:
            workload[plugin] = self.analysis_plugins[plugin].in_queue.qsize()
        return workload

# ---- scheduling functions ----

    def register_plugin(self, name, plugin_instance):
        '''
        This function is called upon plugin init to announce its presence
        '''
        self.analysis_plugins[name] = plugin_instance

    def load_plugins(self):
        source = import_plugins('analysis.plugins', 'plugins/analysis')
        for plugin_name in source.list_plugins():
            plugin = source.load_plugin(plugin_name)
            plugin.AnalysisPlugin(self, config=self.config)

    def start_scheduling_process(self):
        logging.debug('Starting scheduler...')
        self.schedule_process = ExceptionSafeProcess(target=self.scheduler)
        self.schedule_process.start()

    def scheduler(self):
        while self.stop_condition.value == 0:
            try:
                task = self.process_queue.get(timeout=int(self.config['ExpertSettings']['block_delay']))
            except Empty:
                pass
            else:
                self.process_next_analysis(task)

    def process_next_analysis(self, fw_object: FileObject):
        self.pre_analysis(fw_object)
        analysis_to_do = fw_object.scheduled_analysis.pop()
        if analysis_to_do not in self.analysis_plugins:
            logging.error('Plugin \'{}\' not available'.format(analysis_to_do))
            self.check_further_process_or_complete(fw_object)
        else:
            self._start_or_skip_analysis(analysis_to_do, fw_object)

    def _start_or_skip_analysis(self, analysis_to_do: str, fw_object: FileObject):
        if analysis_to_do not in MANDATORY_PLUGINS and self._next_analysis_is_blacklisted(analysis_to_do, fw_object):
            logging.debug('skipping analysis "{}" for {} (blacklisted file type)'.format(analysis_to_do, fw_object.get_uid()))
            fw_object.processed_analysis[analysis_to_do] = self._get_skipped_analysis_result(analysis_to_do)
            self.check_further_process_or_complete(fw_object)
        elif self._analysis_is_already_in_db_and_up_to_date(analysis_to_do, fw_object):
            logging.debug('skipping analysis "{}" for {} (analysis already in DB)'.format(analysis_to_do, fw_object.get_uid()))
            if analysis_to_do in self._get_cumulative_remaining_dependencies(fw_object):
                self._add_completed_analysis_results_to_file_object(analysis_to_do, fw_object)
            self.check_further_process_or_complete(fw_object)
        else:
            self.analysis_plugins[analysis_to_do].add_job(fw_object)

    # ---- blacklist and whitelist ----

    def _get_cumulative_remaining_dependencies(self, fw_object: FileObject) -> Set[str]:
        result = set()
        for plugin in fw_object.scheduled_analysis:
            result.update(self.analysis_plugins[plugin].DEPENDENCIES)
        return result

    def _add_completed_analysis_results_to_file_object(self, analysis_to_do: str, fw_object: FileObject):
        db_entry = self.db_backend_service.get_specific_fields_of_db_entry(
            fw_object.get_uid(), {'processed_analysis.{}'.format(analysis_to_do): 1}
        )
        # FIXME unsanitize sanitized analysis -> is_sanitized_entry
        fw_object.processed_analysis[analysis_to_do] = db_entry['processed_analysis'][analysis_to_do]

    def _analysis_is_already_in_db_and_up_to_date(self, analysis_to_do: str, fw_object: FileObject):
        db_entry = self.db_backend_service.get_specific_fields_of_db_entry(
            fw_object.get_uid(),
            {
                'processed_analysis.{}.plugin_version'.format(analysis_to_do): 1,
                'processed_analysis.{}.system_version'.format(analysis_to_do): 1
            }
        )
        if not db_entry or analysis_to_do not in db_entry['processed_analysis']:
            return False
        elif 'plugin_version' not in db_entry['processed_analysis'][analysis_to_do]:
            logging.error('Plugin Version missing: UID: {}, Plugin: {}'.format(fw_object.get_uid(), analysis_to_do))

        analysis_plugin_version = db_entry['processed_analysis'][analysis_to_do]['plugin_version']
        analysis_system_version = db_entry['processed_analysis'][analysis_to_do]['system_version'] \
            if 'system_version' in db_entry['processed_analysis'][analysis_to_do] else None
        plugin_version = self.analysis_plugins[analysis_to_do].VERSION
        system_version = self.analysis_plugins[analysis_to_do].SYSTEM_VERSION \
            if hasattr(self.analysis_plugins[analysis_to_do], 'SYSTEM_VERSION') else None

        if LooseVersion(analysis_plugin_version) < LooseVersion(plugin_version) or \
                LooseVersion(analysis_system_version or '0') < LooseVersion(system_version or '0'):
            return False
        return True

    def _get_skipped_analysis_result(self, analysis_to_do):
        return {
            'skipped': 'blacklisted file type',
            'summary': [],
            'analysis_date': time(),
            'plugin_version': self.analysis_plugins[analysis_to_do].VERSION
        }

# ---- result collector functions ----

    def _next_analysis_is_blacklisted(self, next_analysis: str, fw_object: FileObject):
        blacklist, whitelist = self._get_blacklist_and_whitelist(next_analysis)
        if not (blacklist or whitelist):
            return False
        if blacklist and whitelist:
            logging.error('{}Configuration of plugin "{}" erroneous{}: found blacklist and whitelist. Ignoring blacklist.'.format(
                bcolors.FAIL, next_analysis, bcolors.ENDC))

        try:
            file_type = fw_object.processed_analysis['file_type']['mime'].lower()
        except KeyError:  # FIXME file_type analysis is missing (probably due to problem with analysis caching) -> re-schedule
            fw_object.scheduled_analysis.extend([next_analysis, 'file_type'])
            fw_object.analysis_dependency.add('file_type')
            return True

        if whitelist:
            return not substring_is_in_list(file_type, whitelist)
        return substring_is_in_list(file_type, blacklist)

    def _get_blacklist_and_whitelist(self, next_analysis: str) -> Tuple[List, List]:
        blacklist, whitelist = self._get_blacklist_and_whitelist_from_config(next_analysis)
        if not (blacklist or whitelist):
            blacklist, whitelist = self._get_blacklist_and_whitelist_from_plugin(next_analysis)
        return blacklist, whitelist

    def _get_blacklist_and_whitelist_from_config(self, analysis_plugin: str) -> Tuple[List, List]:
        blacklist = read_list_from_config(self.config, analysis_plugin, 'mime_blacklist')
        whitelist = read_list_from_config(self.config, analysis_plugin, 'mime_whitelist')
        return blacklist, whitelist

# ---- miscellaneous functions ----

    def _get_blacklist_and_whitelist_from_plugin(self, analysis_plugin: str) -> Tuple[List, List]:
        blacklist = self.analysis_plugins[analysis_plugin].MIME_BLACKLIST if hasattr(self.analysis_plugins[analysis_plugin], 'MIME_BLACKLIST') else []
        whitelist = self.analysis_plugins[analysis_plugin].MIME_WHITELIST if hasattr(self.analysis_plugins[analysis_plugin], 'MIME_WHITELIST') else []
        return blacklist, whitelist

    def start_result_collector(self):
        logging.debug('Starting result collector')
        self.result_collector_process = ExceptionSafeProcess(target=self.result_collector)
        self.result_collector_process.start()

    def result_collector(self):
        while self.stop_condition.value == 0:
            nop = True
            for plugin in self.analysis_plugins:
                try:
                    fw = self.analysis_plugins[plugin].out_queue.get_nowait()
                    fw = self._handle_analysis_tags(fw, plugin)
                except Empty:
                    pass
                else:
                    nop = False
                    if plugin in fw.processed_analysis:
                        self.post_analysis(fw)
                    self.check_further_process_or_complete(fw)
            if nop:
                sleep(int(self.config['ExpertSettings']['block_delay']))

    def _handle_analysis_tags(self, fw, plugin):
        self.tag_queue.put(check_tags(fw, plugin))
        return add_tags_to_object(fw, plugin)

    def check_further_process_or_complete(self, fw_object):
        if not fw_object.scheduled_analysis:
            logging.info('Analysis Completed:\n{}'.format(fw_object))
        else:
            self.process_queue.put(fw_object)

    @staticmethod
    def _remove_unwanted_plugins(list_of_plugins):
        defaults = ['dummy_plugin_for_testing_only']
        for plugin in defaults:
            list_of_plugins.remove(plugin)
        return list_of_plugins

    def check_exceptions(self):
        for _, plugin in self.analysis_plugins.items():
            if plugin.check_exceptions():
                return True
        for process in [self.schedule_process, self.result_collector_process]:
            if process.exception:
                logging.error("{}Exception in scheduler process {}{}".format(bcolors.FAIL, bcolors.ENDC, process.name))
                logging.error(process.exception[1])
                terminate_process_and_childs(process)
                return True  # Error here means nothing will ever get scheduled again. Thing should just break !
        return False
