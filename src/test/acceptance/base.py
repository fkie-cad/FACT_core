# pylint: disable=too-many-instance-attributes,attribute-defined-outside-init

import gc
import logging
import os
import shutil
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from common_helper_files import create_dir_for_file

from helperFunctions.config import load_config
from intercom.back_end_binding import InterComBackEndBinding
from objects.file import FileObject
from scheduler.Analysis import AnalysisScheduler
from scheduler.Compare import CompareScheduler
from scheduler.Unpacking import UnpackingScheduler
from storage.binary_service import BinaryService
from storage.MongoMgr import MongoMgr
from test.common_helper import clean_test_database, get_database_names, get_test_data_dir
from web_interface.frontend_main import WebFrontEnd

TMP_DIR = TemporaryDirectory(prefix='fact_test_')
UPLOAD_DIR = Path(TMP_DIR.name) / 'upload_dir'
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
        cls.binary_service = BinaryService(config=cls.config)

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
        cls.config.set('data_storage', 'upload_storage_dir', str(UPLOAD_DIR))

    def _stop_backend(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.submit(self.intercom.shutdown)
            executor.submit(self.compare_service.shutdown)
            executor.submit(self.unpacking_service.shutdown)
            executor.submit(self.analysis_service.shutdown)

    def _start_backend(self, post_analysis=None, compare_callback=None):
        self.analysis_service = AnalysisScheduler(config=self.config, post_analysis=post_analysis)
        self.unpacking_service = UnpackingScheduler(config=self.config, post_unpack=self.analysis_service.start_analysis_of_object)
        self.compare_service = CompareScheduler(config=self.config, callback=compare_callback)
        self.intercom = InterComBackEndBinding(config=self.config, analysis_service=self.analysis_service, compare_service=self.compare_service, unpacking_service=self.unpacking_service)

    def upload_firmware(self, firmware: TestFW, release_date='2009-01-01'):
        testfile_path = Path(get_test_data_dir()) / firmware.path
        shutil.copy(testfile_path, UPLOAD_DIR / testfile_path.name)
        data = {
            'file_name': testfile_path.name,
            'device_name': firmware.name,
            'device_part': 'test_part',
            'device_class': 'test_class',
            'version': '1.0',
            'vendor': 'test_vendor',
            'release_date': release_date,
            'tags': '',
            'analysis_systems': []
        }
        rv = self.test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
        assert b'Upload Successful' in rv.data, 'upload not successful'
        assert firmware.uid.encode() in rv.data, 'uid not found on upload success page'

    def store_binary(self, file_object: FileObject):
        self.binary_service.fs_organizer.store_file(file_object)

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
