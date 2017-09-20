import unittest
import os
import logging

from web_interface.frontend_main import WebFrontEnd
from storage.MongoMgr import MongoMgr
from scheduler.Analysis import AnalysisScheduler
from scheduler.Unpacking import UnpackingScheduler
from scheduler.Compare import CompareScheduler
from intercom.back_end_binding import InterComBackEndBinding
from test.unit.helperFunctions_setup_test_data import clean_test_database
from tempfile import TemporaryDirectory
from helperFunctions.config import load_config
from common_helper_files import create_dir_for_file


TMP_DIR = TemporaryDirectory(prefix="faf_test_")


class TestAcceptanceBase(unittest.TestCase):

    class TestFW:
        def __init__(self, uid, path, name):
            self.uid = uid
            self.path = path
            self.name = name
            self.file_name = os.path.basename(self.path)

    def setUp(self):
        self._set_config()
        self.mongo_server = MongoMgr(config=self.config)
        self.frontend = WebFrontEnd(config=self.config)
        self.frontend.app.config['TESTING'] = True
        self.test_client = self.frontend.app.test_client()

        self.test_fw_a = self.TestFW("418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787",
                                     "container/test.zip", "test_fw_a")
        self.test_fw_b = self.TestFW("d38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319",
                                     "container/test.7z", "test_fw_b")

    def tearDown(self):
        clean_test_database(self.config)
        self.mongo_server.shutdown()

    def _set_config(self):
        self.config = load_config("main.cfg")
        self.config.set('data_storage', 'main_database', 'tmp_acceptance_tests')
        self.config.set('data_storage', 'intercom_database_prefix', 'tmp_acceptance_tests')
        self.config.set('data_storage', 'statistic_database', 'tmp_acceptance_tests')
        self.config.set('data_storage', 'cve_database', 'tmp_acceptance_tests')
        self.config.set('data_storage', 'firmware_file_storage_directory', TMP_DIR.name)
        self.config.set('Logging', 'mongoDbLogFile', os.path.join(TMP_DIR.name, "mongo.log"))

    def _stop_backend(self):
        self.intercom.shutdown()
        self.compare_service.shutdown()
        self.unpacking_service.shutdown()
        self.analysis_service.shutdown()

    def _start_backend(self):
        self.analysis_service = AnalysisScheduler(config=self.config)
        self.unpacking_service = UnpackingScheduler(config=self.config, post_unpack=self.analysis_service.add_task)
        self.compare_service = CompareScheduler(config=self.config)
        self.intercom = InterComBackEndBinding(config=self.config, analysis_service=self.analysis_service, compare_service=self.compare_service,
                                               unpacking_service=self.unpacking_service)

    def _setup_debugging_logging(self):
        # for debugging purposes only
        log_level = logging.DEBUG
        log_format = logging.Formatter(fmt="[%(asctime)s][%(module)s][%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
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
