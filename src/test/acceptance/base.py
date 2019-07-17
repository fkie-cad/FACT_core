import gc
import logging
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory

from common_helper_files import create_dir_for_file

from helperFunctions.config import load_config
from intercom.back_end_binding import InterComBackEndBinding
from scheduler.Analysis import AnalysisScheduler
from scheduler.Compare import CompareScheduler
from scheduler.Unpacking import UnpackingScheduler
from storage.MongoMgr import MongoMgr
from test.common_helper import get_database_names, clean_test_database
from web_interface.frontend_main import WebFrontEnd


TMP_DIR = TemporaryDirectory(prefix='fact_test_')
TMP_DB_NAME = 'tmp_acceptance_tests'


class TestAcceptanceBase(unittest.TestCase):

    class TestFW:
        def __init__(self, uid, path, name):
            self.uid = uid
            self.path = path
            self.name = name
            self.file_name = os.path.basename(self.path)

    @classmethod
    def setUpClass(cls):
        cls._set_config()
        cls.mongo_server = MongoMgr(config=cls.config)

    def setUp(self):
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = not self.config.getboolean('ExpertSettings', 'authentication')
        self.test_client = self.frontend.app.test_client()

        self.test_fw_a = self.TestFW('418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787',
                                     'container/test.zip', 'test_fw_a')
        self.test_fw_b = self.TestFW('d38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319',
                                     'container/test.7z', 'test_fw_b')
        self.test_fw_c = self.TestFW('5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415',
                                     'regression_one', 'test_fw_c')

    def tearDown(self):
        clean_test_database(self.config, get_database_names(self.config))
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_server.shutdown()

    @classmethod
    def _set_config(cls):
        cls.config = load_config('main.cfg')
        cls.config.set('data_storage', 'main_database', TMP_DB_NAME)
        cls.config.set('data_storage', 'intercom_database_prefix', TMP_DB_NAME)
        cls.config.set('data_storage', 'statistic_database', TMP_DB_NAME)
        cls.config.set('data_storage', 'firmware_file_storage_directory', TMP_DIR.name)
        cls.config.set('ExpertSettings', 'authentication', 'false')
        cls.config.set('Logging', 'mongoDbLogFile', os.path.join(TMP_DIR.name, 'mongo.log'))

    def _stop_backend(self):
        with ThreadPoolExecutor(max_workers=4) as e:
            e.submit(self.intercom.shutdown)
            e.submit(self.compare_service.shutdown)
            e.submit(self.unpacking_service.shutdown)
            e.submit(self.analysis_service.shutdown)

    def _start_backend(self, post_analysis=None, compare_callback=None):
        self.analysis_service = AnalysisScheduler(config=self.config, post_analysis=post_analysis)
        self.unpacking_service = UnpackingScheduler(config=self.config, post_unpack=self.analysis_service.start_analysis_of_object)
        self.compare_service = CompareScheduler(config=self.config, callback=compare_callback)
        self.intercom = InterComBackEndBinding(config=self.config, analysis_service=self.analysis_service, compare_service=self.compare_service, unpacking_service=self.unpacking_service)

    def _setup_debugging_logging(self):
        # for debugging purposes only
        log_level = logging.DEBUG
        log_format = logging.Formatter(fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        logger = logging.getLogger('')
        logger.setLevel(logging.DEBUG)
        create_dir_for_file(self.config['Logging']['logFile'])
        file_log = logging.FileHandler(self.config['Logging']['logFile'])
        file_log.setLevel(log_level)
        file_log.setFormatter(log_format)
        console_log = logging.StreamHandler()
        console_log.setLevel(logging.DEBUG)
        console_log.setFormatter(log_format)
        logger.addHandler(file_log)
        logger.addHandler(console_log)
