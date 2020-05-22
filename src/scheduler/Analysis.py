import logging
from concurrent.futures import ThreadPoolExecutor
from configparser import ConfigParser
from copy import copy
from distutils.version import LooseVersion
from multiprocessing import Manager, Queue, Value
from queue import Empty
from time import sleep, time
from typing import List, Optional, Set, Tuple, Union

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.compare_sets import substring_is_in_list
from helperFunctions.config import read_list_from_config
from helperFunctions.logging import TerminalColors, color_string
from helperFunctions.merge_generators import shuffled
from helperFunctions.plugin import import_plugins
from helperFunctions.process import ExceptionSafeProcess, check_worker_exceptions
from helperFunctions.tag import add_tags_to_object, check_tags
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_backend import BackEndDbInterface

MANDATORY_PLUGINS = ['file_type', 'file_hashes']


class AnalysisScheduler:  # pylint: disable=too-many-instance-attributes
    '''
    This Scheduler performs analysis of firmware objects
    '''

    def __init__(self, config: Optional[ConfigParser] = None, pre_analysis=None, post_analysis=None, db_interface=None):
        self.config = config
        self.analysis_plugins = {}
        self.load_plugins()
        self.stop_condition = Value('i', 0)
        self.process_queue = Queue()
        self.tag_queue = Queue()
        self.manager = Manager()
        self.currently_running = self.manager.dict()

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
        with ThreadPoolExecutor() as executor:
            executor.submit(self.schedule_process.join)
            executor.submit(self.result_collector_process.join)
            for plugin in self.analysis_plugins:
                executor.submit(self.analysis_plugins[plugin].shutdown)
        if getattr(self.db_backend_service, 'shutdown', False):
            self.db_backend_service.shutdown()
        self.tag_queue.close()
        self.process_queue.close()
        logging.info('Analysis System offline')

    def update_analysis_of_object_and_children(self, fo: FileObject):
        '''
        This function is used to recursively analyze an object without need of the unpacker
        '''
        for included_file in self.db_backend_service.get_list_of_all_included_files(fo):
            child = self.db_backend_service.get_object(included_file)
            self._schedule_analysis_tasks(child, fo.scheduled_analysis)
        self.check_further_process_or_complete(fo)

    def start_analysis_of_object(self, fo: FileObject):
        '''
        This function should be used to add a new firmware object to the scheduler
        '''
        self._add_to_current_analyses(fo)
        self._schedule_analysis_tasks(fo, fo.scheduled_analysis, mandatory=True)

    def update_analysis_of_single_object(self, fo: FileObject):
        '''
        This function is used to add analysis tasks for a single file
        '''
        self._schedule_analysis_tasks(fo, fo.scheduled_analysis)

    def _schedule_analysis_tasks(self, fo, scheduled_analysis, mandatory=False):
        scheduled_analysis = self._add_dependencies_recursively(copy(scheduled_analysis) or [])
        fo.scheduled_analysis = self._smart_shuffle(scheduled_analysis + MANDATORY_PLUGINS if mandatory else scheduled_analysis)
        self.check_further_process_or_complete(fo)

    def _smart_shuffle(self, plugin_list: List[str]) -> List[str]:
        scheduled_plugins = []
        remaining_plugins = set(plugin_list)

        while remaining_plugins:
            next_plugins = self._get_plugins_with_met_dependencies(remaining_plugins, scheduled_plugins)
            if not next_plugins:
                logging.error('Error: Could not schedule plugins because dependencies cannot be fulfilled: {}'.format(remaining_plugins))
                break
            scheduled_plugins[:0] = shuffled(next_plugins)
            remaining_plugins.difference_update(next_plugins)

        # assure file type is first for blacklist functionality
        if 'file_type' in scheduled_plugins and scheduled_plugins[-1] != 'file_type':
            scheduled_plugins.remove('file_type')
            scheduled_plugins.append('file_type')
        return scheduled_plugins

    def _get_plugins_with_met_dependencies(self, remaining_plugins: Set[str], scheduled_plugins: List[str]) -> List[str]:
        met_dependencies = scheduled_plugins
        return [
            plugin
            for plugin in remaining_plugins
            if all(dependency in met_dependencies for dependency in self.analysis_plugins[plugin].DEPENDENCIES)
        ]

    def get_list_of_available_plugins(self):
        '''
        returns a list of all loaded plugins
        '''
        plugin_list = list(self.analysis_plugins.keys())
        plugin_list.sort(key=str.lower)
        return plugin_list

# ---- internal functions ----

    def get_default_plugins_from_config(self):
        try:
            result = {}
            for plugin_set in self.config['default_plugins']:
                result[plugin_set] = read_list_from_config(self.config, 'default_plugins', plugin_set)
            return result
        except (TypeError, KeyError, AttributeError):
            logging.warning('default plug-ins not set in config')
            return []

    def get_plugin_dict(self):
        '''
        returns a dictionary of plugins with the following form: names as keys and the respective description value
        {NAME: (DESCRIPTION, mandatory, default, VERSION, DEPENDENCIES, MIME_BLACKLIST, MIME_WHITELIST, config.threads)}
        - mandatory plug-ins shall not be shown in the analysis selection but always executed
        - default plug-ins shall be pre-selected in the analysis selection
        '''
        plugin_list = self.get_list_of_available_plugins()
        plugin_list = self._remove_unwanted_plugins(plugin_list)
        default_plugins = self.get_default_plugins_from_config()
        default_flag_dict = {}
        result = {}
        for plugin in plugin_list:
            mandatory_flag = plugin in MANDATORY_PLUGINS
            for key in default_plugins:
                default_flag_dict[key] = plugin in default_plugins[key]
            blacklist, whitelist = self._get_blacklist_and_whitelist_from_plugin(plugin)
            result[plugin] = (
                self.analysis_plugins[plugin].DESCRIPTION,
                mandatory_flag,
                dict(default_flag_dict),
                self.analysis_plugins[plugin].VERSION,
                self.analysis_plugins[plugin].DEPENDENCIES,
                blacklist,
                whitelist,
                self.config[plugin].get('threads', 0)
            )
        result['unpacker'] = ('Additional information provided by the unpacker', True, False)
        return result

# ---- scheduling functions ----

    def get_scheduled_workload(self):
        workload = {
            'analysis_main_scheduler': self.process_queue.qsize(),
            'plugins': {},
            'current_analyses': {uid: len(included_files) for uid, included_files in self.currently_running.items()}
        }
        for plugin_name in self.analysis_plugins:
            plugin = self.analysis_plugins[plugin_name]
            workload['plugins'][plugin_name] = {
                'queue': plugin.in_queue.qsize(),
                'active': (sum(plugin.active[i].value for i in range(plugin.thread_count))),
            }
        return workload

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
                task = self.process_queue.get(timeout=float(self.config['ExpertSettings']['block_delay']))
            except Empty:
                pass
            else:
                self.process_next_analysis(task)

    def _reschedule_failed_analysis_task(self, fw_object: Union[Firmware, FileObject]):
        failed_plugin, cause = fw_object.analysis_exception
        fw_object.processed_analysis[failed_plugin] = {'failed': cause}
        for plugin in fw_object.scheduled_analysis[:]:
            if failed_plugin in self.analysis_plugins[plugin].DEPENDENCIES:
                fw_object.scheduled_analysis.remove(plugin)
                logging.warning('Unscheduled analysis {} for {} because dependency {} failed'.format(plugin, fw_object.uid, failed_plugin))
                fw_object.processed_analysis[plugin] = {'failed': 'Analysis of dependency {} failed'.format(failed_plugin)}
        fw_object.analysis_exception = None

    # ---- analysis skipping ----

    def process_next_analysis(self, fw_object: FileObject):
        self.pre_analysis(fw_object)
        analysis_to_do = fw_object.scheduled_analysis.pop()
        if analysis_to_do not in self.analysis_plugins:
            logging.error('Plugin \'{}\' not available'.format(analysis_to_do))
            self.check_further_process_or_complete(fw_object)
        else:
            self._start_or_skip_analysis(analysis_to_do, fw_object)

    def _start_or_skip_analysis(self, analysis_to_do: str, file_object: FileObject):
        if self._analysis_is_already_in_db_and_up_to_date(analysis_to_do, file_object.uid):
            logging.debug('skipping analysis "{}" for {} (analysis already in DB)'.format(analysis_to_do, file_object.uid))
            if analysis_to_do in self._get_cumulative_remaining_dependencies(file_object.scheduled_analysis):
                self._add_completed_analysis_results_to_file_object(analysis_to_do, file_object)
            self.check_further_process_or_complete(file_object)
        elif analysis_to_do not in MANDATORY_PLUGINS and self._next_analysis_is_blacklisted(analysis_to_do, file_object):
            logging.debug('skipping analysis "{}" for {} (blacklisted file type)'.format(analysis_to_do, file_object.uid))
            file_object.processed_analysis[analysis_to_do] = self._get_skipped_analysis_result(analysis_to_do)
            self.post_analysis(file_object)
            self.check_further_process_or_complete(file_object)
        else:
            self.analysis_plugins[analysis_to_do].add_job(file_object)

    def _add_completed_analysis_results_to_file_object(self, analysis_to_do: str, fw_object: FileObject):
        db_entry = self.db_backend_service.get_specific_fields_of_db_entry(
            fw_object.uid, {'processed_analysis.{}'.format(analysis_to_do): 1}
        )
        desanitized_analysis = self.db_backend_service.retrieve_analysis(db_entry['processed_analysis'])
        fw_object.processed_analysis[analysis_to_do] = desanitized_analysis[analysis_to_do]

    def _analysis_is_already_in_db_and_up_to_date(self, analysis_to_do: str, uid: str):
        db_entry = self.db_backend_service.get_specific_fields_of_db_entry(
            uid,
            {
                'processed_analysis.{plugin}.{key}'.format(plugin=analysis_to_do, key=key): 1
                for key in ['failed', 'file_system_flag', 'plugin_version', 'system_version']
            }
        )
        if not db_entry or analysis_to_do not in db_entry['processed_analysis'] or 'failed' in db_entry['processed_analysis'][analysis_to_do]:
            return False
        if 'plugin_version' not in db_entry['processed_analysis'][analysis_to_do]:
            logging.error('Plugin Version missing: UID: {}, Plugin: {}'.format(uid, analysis_to_do))
            return False

        if db_entry['processed_analysis'][analysis_to_do]['file_system_flag']:
            db_entry['processed_analysis'] = self.db_backend_service.retrieve_analysis(db_entry['processed_analysis'], analysis_filter=[analysis_to_do])
            if 'file_system_flag' in db_entry['processed_analysis'][analysis_to_do]:
                logging.warning('Desanitization of version string failed')
                return False

        return self._analysis_is_up_to_date(db_entry['processed_analysis'][analysis_to_do], self.analysis_plugins[analysis_to_do])

    @staticmethod
    def _analysis_is_up_to_date(analysis_db_entry: dict, analysis_plugin: AnalysisBasePlugin):
        old_plugin_version = analysis_db_entry['plugin_version']
        old_system_version = analysis_db_entry.get('system_version', None)
        current_plugin_version = analysis_plugin.VERSION
        current_system_version = getattr(analysis_plugin, 'SYSTEM_VERSION', None)
        try:
            if LooseVersion(old_plugin_version) < LooseVersion(current_plugin_version) or \
                    LooseVersion(old_system_version or '0') < LooseVersion(current_system_version or '0'):
                return False
        except TypeError:
            logging.error('plug-in or system version of "{}" plug-in is or was invalid!'.format(analysis_plugin.NAME))
            return False
        return True

# ---- blacklist and whitelist ----

    def _get_skipped_analysis_result(self, analysis_to_do):
        return {
            'skipped': 'blacklisted file type',
            'summary': [],
            'analysis_date': time(),
            'plugin_version': self.analysis_plugins[analysis_to_do].VERSION
        }

    def _next_analysis_is_blacklisted(self, next_analysis: str, fw_object: FileObject):
        blacklist, whitelist = self._get_blacklist_and_whitelist(next_analysis)
        if not (blacklist or whitelist):
            return False
        if blacklist and whitelist:
            message = color_string('Configuration of plugin "{}" erroneous'.format(next_analysis), TerminalColors.FAIL)
            logging.error('{}: found blacklist and whitelist. Ignoring blacklist.'.format(message))

        file_type = self._get_file_type_from_object_or_db(fw_object)

        if whitelist:
            return not substring_is_in_list(file_type, whitelist)
        return substring_is_in_list(file_type, blacklist)

    def _get_file_type_from_object_or_db(self, fw_object: FileObject) -> Optional[str]:
        if 'file_type' not in fw_object.processed_analysis:
            self._add_completed_analysis_results_to_file_object('file_type', fw_object)

        return fw_object.processed_analysis['file_type']['mime'].lower()

    def _get_blacklist_and_whitelist(self, next_analysis: str) -> Tuple[List, List]:
        blacklist, whitelist = self._get_blacklist_and_whitelist_from_config(next_analysis)
        if not (blacklist or whitelist):
            blacklist, whitelist = self._get_blacklist_and_whitelist_from_plugin(next_analysis)
        return blacklist, whitelist

    def _get_blacklist_and_whitelist_from_config(self, analysis_plugin: str) -> Tuple[List, List]:
        blacklist = read_list_from_config(self.config, analysis_plugin, 'mime_blacklist')
        whitelist = read_list_from_config(self.config, analysis_plugin, 'mime_whitelist')
        return blacklist, whitelist

# ---- result collector functions ----

    def _get_blacklist_and_whitelist_from_plugin(self, analysis_plugin: str) -> Tuple[List, List]:
        blacklist = getattr(self.analysis_plugins[analysis_plugin], 'MIME_BLACKLIST', [])
        whitelist = getattr(self.analysis_plugins[analysis_plugin], 'MIME_WHITELIST', [])
        return blacklist, whitelist

    def start_result_collector(self):
        logging.debug('Starting result collector')
        self.result_collector_process = ExceptionSafeProcess(target=self.result_collector)
        self.result_collector_process.start()

# ---- miscellaneous functions ----

    def result_collector(self):  # pylint: disable=too-complex
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
                        if fw.analysis_exception:
                            self._reschedule_failed_analysis_task(fw)

                        self.post_analysis(fw)
                    self.check_further_process_or_complete(fw)
            if nop:
                sleep(float(self.config['ExpertSettings']['block_delay']))

    def _handle_analysis_tags(self, fw, plugin):
        self.tag_queue.put(check_tags(fw, plugin))
        return add_tags_to_object(fw, plugin)

    def check_further_process_or_complete(self, fw_object):
        if not fw_object.scheduled_analysis:
            logging.info('Analysis Completed:\n{}'.format(fw_object))
            if not isinstance(fw_object, Firmware):
                self._remove_from_current_analyses(fw_object)
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
        return check_worker_exceptions([self.schedule_process, self.result_collector_process], 'Scheduler')

    def _add_dependencies_recursively(self, scheduled_analyses: List[str]) -> List[str]:
        scheduled_analyses_set = set(scheduled_analyses)
        while True:
            new_dependencies = self._get_cumulative_remaining_dependencies(scheduled_analyses_set)
            if not new_dependencies:
                break
            scheduled_analyses_set.update(new_dependencies)
        return list(scheduled_analyses_set)

    def _get_cumulative_remaining_dependencies(self, scheduled_analyses: Set[str]) -> Set[str]:
        return {
            dependency
            for plugin in scheduled_analyses
            for dependency in self.analysis_plugins[plugin].DEPENDENCIES
        }.difference(scheduled_analyses)

    # currently running analyses

    def _add_to_current_analyses(self, fw_object: Union[Firmware, FileObject]):
        if isinstance(fw_object, Firmware):
            self.currently_running[fw_object.uid] = list(fw_object.files_included)
        elif fw_object.files_included:
            for parent in self._find_currently_analyzed_parents(fw_object):
                union = set(fw_object.files_included).union(self.currently_running[parent])
                self.currently_running[parent] = list(union)

    def _remove_from_current_analyses(self, fw_object: Union[Firmware, FileObject]):
        for parent in self._find_currently_analyzed_parents(fw_object):
            self.currently_running[parent] = [uid for uid in self.currently_running[parent] if uid != fw_object.uid]
            if len(self.currently_running[parent]) == 0:
                self.currently_running.pop(parent)
                logging.info('Analysis of firmware {} completed'.format(parent))

    def _find_currently_analyzed_parents(self, fo):
        return set(self.currently_running.keys()).intersection(fo.parent_firmware_uids)
