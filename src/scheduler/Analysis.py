import json
import logging
import random
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Queue, Value
from queue import Empty
from random import shuffle
from time import sleep

import pika

from helperFunctions.parsing import bcolors
from helperFunctions.plugin import import_plugins
from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from helperFunctions.tag import check_tags, add_tags_to_object
from storage.db_interface_backend import BackEndDbInterface

MANDATORY_PLUGINS = ['file_type', 'file_hashes']


class AnalysisScheduler(object):
    '''
    This Scheduler performs analysis of firmware objects
    '''

    analysis_plugins = {}

    def __init__(self, config=None, pre_analysis=None, post_analysis=None, db_interface=None):
        self.config = config
        self.load_plugins()
        self.stop_condition = Value('i', 0)
        self.process_queue = Queue()
        self.tag_queue = Queue()
        self.db_backend_service = db_interface if db_interface else BackEndDbInterface(config=config)
        self.pre_analysis = pre_analysis if pre_analysis else self.db_backend_service.add_object
        self.post_analysis = post_analysis if post_analysis else self.db_backend_service.add_analysis
        self.start_scheduling_process()

        self.init_rabbit()
        self.start_result_collector()
        logging.info('Analysis System online...')
        logging.info('Plugins available: {}'.format(self.get_list_of_available_plugins()))

    def shutdown(self):
        '''
        shutdown the scheduler and all loaded plugins
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        self.tear_down_rabbit()
        with ThreadPoolExecutor() as e:
            e.submit(self.schedule_process.join)
            e.submit(self.result_collector_process.join)
            e.submit(self.remote_collector_process.join)
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
        {NAME: (DESCRIPTION, MANDATORY_FLAG, DEFAULT_FLAG, VERSION)}
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
            result[plugin] = (self.analysis_plugins[plugin].DESCRIPTION, mandatory_flag, default_flag, self.analysis_plugins[plugin].VERSION)
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
        if not self.db_backend_service.existence_quick_check(fw_object.get_uid()):
            self.pre_analysis(fw_object)
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

        self.remote_collector_process = ExceptionSafeProcess(target=self.remote_result_collection)
        self.remote_collector_process.start()

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

# ---- remote result collection ----

    def init_rabbit(self):
        exchange = self.config.get('remote_tasks', 'write_back_exchange')
        exchange_host = self.config.get('remote_tasks', 'exchange_host')

        self._rabbit_connection = pika.BlockingConnection(pika.ConnectionParameters(exchange_host))
        self._rabbit_channel = self._rabbit_connection.channel()
        self._rabbit_channel.exchange_declare(exchange=exchange, exchange_type='direct')

        self._consumer_tag = hex(random.getrandbits(128))

    def remote_result_collection(self):
        exchange = self.config.get('remote_tasks', 'write_back_exchange')
        routing_key = self.config.get('remote_tasks', 'write_back_key')

        incoming_queue = self._rabbit_channel.queue_declare()
        self._rabbit_channel.queue_bind(exchange=exchange, queue=incoming_queue.method.queue, routing_key=routing_key)

        def fetch_next_result(ch: pika.adapters.blocking_connection.BlockingChannel, method: pika.spec.Basic.Deliver, properties: pika.BasicProperties, body: bytes):
            remote_task = json.loads(body.decode())

            task_id = remote_task['task_id']
            uid = remote_task['object_uid']
            analysis_system = remote_task['analysis_system']
            analysis_result = remote_task['analysis']
            self.db_backend_service.add_remote_analysis(uid=uid, result=analysis_result, task_id=task_id, system=analysis_system)

            ch.basic_ack(delivery_tag=method.delivery_tag)

        self._rabbit_channel.basic_consume(fetch_next_result, queue=incoming_queue.method.queue, consumer_tag=self._consumer_tag)

        try:
            self._rabbit_channel.start_consuming()
        except FileNotFoundError:
            logging.warning('Bad shutdown of rabbit consumer ..')

    def tear_down_rabbit(self):
        self._rabbit_channel.basic_cancel(consumer_tag=self._consumer_tag)
        self._rabbit_connection.close()


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
        for process in [self.schedule_process, self.result_collector_process, self.remote_collector_process]:
            if process.exception:
                logging.error("{}Exception in scheduler process {}{}".format(bcolors.FAIL, bcolors.ENDC, process.name))
                logging.error(process.exception[1])
                terminate_process_and_childs(process)
                return True  # Error here means nothing will ever get scheduled again. Thing should just break !
        return False
