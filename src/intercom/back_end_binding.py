import logging
import pickle
from multiprocessing import Process, Value
from time import sleep

from common_helper_mongo.gridfs import overwrite_file

from helperFunctions.database import ConnectTo
from helperFunctions.process import no_operation
from helperFunctions.yara_binary_search import YaraBinarySearchScanner
from intercom.common_mongo_binding import InterComListener, InterComListenerAndResponder, InterComMongoInterface
from storage.binary_service import BinaryService
from storage.db_interface_common import MongoInterfaceCommon
from storage.fs_organizer import FS_Organizer


class InterComBackEndBinding:
    '''
    Internal Communication Backend Binding
    '''

    def __init__(self, config=None, analysis_service=None, compare_service=None, unpacking_service=None, testing=False):
        self.config = config
        self.analysis_service = analysis_service
        self.compare_service = compare_service
        self.unpacking_service = unpacking_service
        self.poll_delay = self.config['ExpertSettings'].getfloat('intercom_poll_delay')

        self.stop_condition = Value('i', 0)
        self.process_list = []
        if not testing:
            self.startup()
        logging.info('InterCom started')

    def startup(self):
        InterComBackEndAnalysisPlugInsPublisher(config=self.config, analysis_service=self.analysis_service)
        self.start_analysis_listener()
        self.start_re_analyze_listener()
        self.start_compare_listener()
        self.start_raw_download_listener()
        self.start_tar_repack_listener()
        self.start_binary_search_listener()
        self.start_update_listener()
        self.start_delete_file_listener()
        self.start_single_analysis_listener()

    def shutdown(self):
        self.stop_condition.value = 1
        for item in self.process_list:
            item.join()
        logging.info('InterCom down')

    def start_analysis_listener(self):
        self._start_listener(InterComBackEndAnalysisTask, self.unpacking_service.add_task)

    def start_re_analyze_listener(self):
        self._start_listener(InterComBackEndReAnalyzeTask, self.unpacking_service.add_task)

    def start_update_listener(self):
        self._start_listener(InterComBackEndUpdateTask, self.analysis_service.update_analysis_of_object_and_children)

    def start_single_analysis_listener(self):
        self._start_listener(InterComBackEndSingleFileTask, self.analysis_service.update_analysis_of_single_object)

    def start_compare_listener(self):
        self._start_listener(InterComBackEndCompareTask, self.compare_service.add_task)

    def start_raw_download_listener(self):
        self._start_listener(InterComBackEndRawDownloadTask, no_operation)

    def start_tar_repack_listener(self):
        self._start_listener(InterComBackEndTarRepackTask, no_operation)

    def start_binary_search_listener(self):
        self._start_listener(InterComBackEndBinarySearchTask, no_operation)

    def start_delete_file_listener(self):
        self._start_listener(InterComBackEndDeleteFile, no_operation)

    def _start_listener(self, communication_backend, do_after_function):
        process = Process(target=self._backend_worker, args=(communication_backend, do_after_function))
        process.start()
        self.process_list.append(process)

    def _backend_worker(self, communication_backend, do_after_function):
        interface = communication_backend(config=self.config)
        logging.debug('{} listener started'.format(type(interface).__name__))
        while self.stop_condition.value == 0:
            task = interface.get_next_task()
            if task is None:
                sleep(self.poll_delay)
            else:
                do_after_function(task)
        interface.shutdown()
        logging.debug('{} listener stopped'.format(type(interface).__name__))


class InterComBackEndAnalysisPlugInsPublisher(InterComMongoInterface):

    def __init__(self, config=None, analysis_service=None):
        super().__init__(config=config)
        self.publish_available_analysis_plugins(analysis_service)
        self.client.close()

    def publish_available_analysis_plugins(self, analysis_service):
        available_plugin_dictionary = analysis_service.get_plugin_dict()
        overwrite_file(self.connections['analysis_plugins']['fs'], 'plugin_dictonary', pickle.dumps(available_plugin_dictionary))


class InterComBackEndAnalysisTask(InterComListener):

    CONNECTION_TYPE = 'analysis_task'

    def additional_setup(self, config=None):
        self.fs_organizer = FS_Organizer(config=config)

    def post_processing(self, task, task_id):
        self.fs_organizer.store_file(task)
        return task


class InterComBackEndReAnalyzeTask(InterComListener):

    CONNECTION_TYPE = 're_analyze_task'

    def additional_setup(self, config=None):
        self.fs_organizer = FS_Organizer(config=config)

    def post_processing(self, task, task_id):
        file_path = self.fs_organizer.generate_path(task)
        task.set_file_path(file_path)
        return task


class InterComBackEndUpdateTask(InterComBackEndReAnalyzeTask):

    CONNECTION_TYPE = 'update_task'


class InterComBackEndSingleFileTask(InterComBackEndReAnalyzeTask):

    CONNECTION_TYPE = 'single_file_task'


class InterComBackEndCompareTask(InterComListener):

    CONNECTION_TYPE = 'compare_task'


class InterComBackEndRawDownloadTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'raw_download_task'
    OUTGOING_CONNECTION_TYPE = 'raw_download_task_resp'

    def get_response(self, task):
        binary_service = BinaryService(config=self.config)
        result = binary_service.get_binary_and_file_name(task)
        return result


class InterComBackEndTarRepackTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'tar_repack_task'
    OUTGOING_CONNECTION_TYPE = 'tar_repack_task_resp'

    def get_response(self, task):
        binary_service = BinaryService(config=self.config)
        result = binary_service.get_repacked_binary_and_file_name(task)
        return result


class InterComBackEndBinarySearchTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'binary_search_task'
    OUTGOING_CONNECTION_TYPE = 'binary_search_task_resp'

    def get_response(self, task):
        yara_binary_searcher = YaraBinarySearchScanner(config=self.config)
        uid_list = yara_binary_searcher.get_binary_search_result(task)
        return uid_list, task


class InterComBackEndDeleteFile(InterComListener):

    CONNECTION_TYPE = 'file_delete_task'

    def additional_setup(self, config=None):
        self.fs_organizer = FS_Organizer(config=config)

    def post_processing(self, task, task_id):
        if self._entry_was_removed_from_db(task['_id']):
            logging.info('remove file: {}'.format(task['_id']))
            self.fs_organizer.delete_file(task['_id'])

    def _entry_was_removed_from_db(self, uid):
        with ConnectTo(MongoInterfaceCommon, self.config) as db:
            if db.existence_quick_check(uid):
                logging.debug('file not removed, because database entry exists: {}'.format(uid))
                return False
            if db.check_unpacking_lock(uid):
                logging.debug('file not removed, because it is processed by unpacker: {}'.format(uid))
                return False
        return True
