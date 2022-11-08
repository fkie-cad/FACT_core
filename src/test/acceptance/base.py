import gc
import logging
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

import pytest
from common_helper_files import create_dir_for_file

from config import configparser_cfg
from intercom.back_end_binding import InterComBackEndBinding
from scheduler.analysis import AnalysisScheduler
from scheduler.comparison_scheduler import ComparisonScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.db_interface_backend import BackendDbInterface
from storage.fsorganizer import FSOrganizer
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import clear_test_tables, setup_test_tables  # pylint: disable=wrong-import-order
from web_interface.frontend_main import WebFrontEnd

TMP_DB_NAME = 'tmp_acceptance_tests'


@pytest.mark.cfg_defaults(
    {
        'expert-settings': {
            'authentication': 'false',
        }
    }
)
class TestAcceptanceBase(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    class TestFW:
        def __init__(self, uid, path, name):
            self.uid = uid
            self.path = path
            self.name = name
            self.file_name = os.path.basename(self.path)

    def setUp(self):
        self.config = configparser_cfg
        setup_test_tables(self.config)

        self.frontend = WebFrontEnd()
        self.frontend.app.config['TESTING'] = not self.config.getboolean('expert-settings', 'authentication')
        self.test_client = self.frontend.app.test_client()

        self.test_fw_a = self.TestFW(
            '418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787', 'container/test.zip', 'test_fw_a'
        )
        self.test_fw_b = self.TestFW(
            'd38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319', 'container/test.7z', 'test_fw_b'
        )
        self.test_fw_c = self.TestFW(
            '5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415', 'regression_one', 'test_fw_c'
        )

    def tearDown(self):
        clear_test_tables(self.config)
        gc.collect()

    def _stop_backend(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            pool.submit(self.intercom.shutdown)
            pool.submit(self.compare_service.shutdown)
            pool.submit(self.unpacking_service.shutdown)
            pool.submit(self.analysis_service.shutdown)

    def _start_backend(self, post_analysis=None, compare_callback=None):
        # pylint: disable=attribute-defined-outside-init
        unpacking_locks = UnpackingLockManager()

        self.analysis_service = AnalysisScheduler(
            post_analysis=post_analysis,
            unpacking_locks=unpacking_locks,
        )
        self.unpacking_service = UnpackingScheduler(
            post_unpack=self.analysis_service.start_analysis_of_object,
            unpacking_locks=unpacking_locks,
        )
        self.compare_service = ComparisonScheduler(callback=compare_callback)
        self.intercom = InterComBackEndBinding(
            analysis_service=self.analysis_service,
            compare_service=self.compare_service,
            unpacking_service=self.unpacking_service,
            unpacking_locks=unpacking_locks,
        )
        self.fs_organizer = FSOrganizer()

    def _setup_debugging_logging(self):
        # for debugging purposes only
        log_level = logging.DEBUG
        log_format = logging.Formatter(
            fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        )
        logger = logging.getLogger('')
        logger.setLevel(logging.DEBUG)
        create_dir_for_file(self.config['logging']['logfile'])
        file_log = logging.FileHandler(self.config['logging']['logfile'])
        file_log.setLevel(log_level)
        file_log.setFormatter(log_format)
        console_log = logging.StreamHandler()
        console_log.setLevel(logging.DEBUG)
        console_log.setFormatter(log_format)
        logger.addHandler(file_log)
        logger.addHandler(console_log)


class TestAcceptanceBaseWithDb(TestAcceptanceBase):
    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend = BackendDbInterface()
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        super().tearDown()
