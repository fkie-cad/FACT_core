import logging
from multiprocessing import Queue, Value
from queue import Empty
from time import sleep
from random import shuffle

from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from helperFunctions.config import load_config
from helperFunctions.parsing import bcolors
from helperFunctions.plugin import import_plugins
from storage.db_interface_backend import BackEndDbInterface

CONFIG_FILE = 'main.cfg'


MANDATORY_PLUGINS = ['file_type', 'file_hashes']


class AnalysisScheduler(object):
    '''
    This Scheduler performs analysis of firmware objects
    '''

    analysis_plugins = {}

    def __init__(self, config=None, post_analysis=None, db_interface=None):
        if config is None:
            self.config = load_config(CONFIG_FILE)
        else:
            self.config = config
        self.load_plugins()
        self.stop_condition = Value('i', 0)
        self.process_queue = Queue()
        self.db_backend_service = db_interface if db_interface else BackEndDbInterface(config=config)
        self.post_analysis = self.db_backend_service.add_object if post_analysis is None else post_analysis
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
        self.schedule_process.join()
        self.result_collector_process.join()
        for plugin in self.analysis_plugins:
            self.analysis_plugins[plugin].shutdown()
        if getattr(self.db_backend_service, 'shutdown', False):
            self.db_backend_service.shutdown()
        self.process_queue.close()
        logging.info('Analysis System offline')

    def add_task(self, fo):
        '''
        This function should be used to add a new firmware object to the scheduler
        '''
        if fo.scheduled_analysis is None:
            fo.scheduled_analysis = MANDATORY_PLUGINS
        else:
            shuffle(fo.scheduled_analysis)
            fo.scheduled_analysis = MANDATORY_PLUGINS + fo.scheduled_analysis
        self.check_further_process_or_complete(fo)

    def get_list_of_available_plugins(self):
        '''
        returns a list of all loaded plugins
        '''
        plugin_list = list(self.analysis_plugins.keys())
        plugin_list.sort(key=str.lower)
        return plugin_list

    def get_default_plugins_from_config(self):
        try:
            return self.config['default_plugins']['plugins'].split(', ')
        except (TypeError, KeyError, AttributeError):
            logging.warning('default plug-ins not set in config')
            return []

    def get_plugin_dict(self):
        '''
        returns a dictionary of plugins with the following form: names as keys and the respective description value
        {NAME: (DESCRIPTION, MANDATORY_FLAG, DEFAULT_FLAG)}
        - mandatory plug-ins shall not be shown in the analysis selection but always exectued
        - default plug-ins shall be pre-selected in the analysis selection
        '''
        plugin_list = self.get_list_of_available_plugins()
        plugin_list = self._remove_unwanted_plugins(plugin_list)
        default_plugins = self.get_default_plugins_from_config()
        result = {}
        for plugin in plugin_list:
            mandatory_flag = plugin in MANDATORY_PLUGINS
            default_flag = plugin in default_plugins
            result[plugin] = (self.analysis_plugins[plugin].DESCRIPTION, mandatory_flag, default_flag)
        result['unpacker'] = ('Additional information provided by the unpacker', True, False)
        return result

    def get_scheduled_workload(self):
        workload = {'analysis_main_scheduler': self.process_queue.qsize()}
        for plugin in self.analysis_plugins:
            workload[plugin] = self.analysis_plugins[plugin].in_queue.qsize()
        return workload

# ---- internal functions ----

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

# ---- scheduling functions ----

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

    def process_next_analysis(self, fw_object):
        analysis_to_do = fw_object.scheduled_analysis.pop()
        if analysis_to_do not in self.analysis_plugins:
            logging.error('Plugin \'{}\' not available'.format(analysis_to_do))
        else:
            self.analysis_plugins[analysis_to_do].add_job(fw_object)

# ---- result collector functions ----

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
                except Empty:
                    pass
                else:
                    nop = False
                    self.check_further_process_or_complete(fw)
            if nop:
                sleep(int(self.config['ExpertSettings']['block_delay']))

    def check_further_process_or_complete(self, fw_object):
        if not fw_object.scheduled_analysis:
            logging.info('Analysis Completed:\n{}'.format(fw_object))
            self.post_analysis(fw_object)
        else:
            self.process_queue.put(fw_object)

# ---- miscellaneous functions ----

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
