import unittest
from tempfile import TemporaryDirectory
from time import sleep
from unittest.mock import patch

from helperFunctions.dataConversion import unify_string_list
from helperFunctions.fileSystem import get_test_data_dir
from helperFunctions.web_interface import ConnectTo
from objects.firmware import Firmware
from scheduler.Analysis import AnalysisScheduler
from scheduler.Compare import CompareScheduler
from scheduler.Unpacking import UnpackingScheduler
from storage.MongoMgr import MongoMgr
from storage.db_interface_compare import CompareDbInterface
from test.common_helper import get_database_names
from test.integration.common import initialize_config, MockFSOrganizer
from test.unit.helperFunctions_setup_test_data import clean_test_database


class TestFileAddition(unittest.TestCase):
    @patch('unpacker.unpack.FS_Organizer', MockFSOrganizer)
    def setUp(self):
        self._tmp_dir = TemporaryDirectory()
        self._config = initialize_config(self._tmp_dir)

        self._mongo_server = MongoMgr(config=self._config, auth=False)
        self._compare_db_interface = CompareDbInterface(config=self._config)

        self._analysis_scheduler = AnalysisScheduler(config=self._config)
        self._unpack_scheduler = UnpackingScheduler(config=self._config, post_unpack=self._analysis_scheduler.add_task)
        self._compare_scheduler = CompareScheduler(config=self._config)

    def tearDown(self):
        self._compare_scheduler.shutdown()
        self._unpack_scheduler.shutdown()
        self._analysis_scheduler.shutdown()

        self._compare_db_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        self._compare_db_interface.shutdown()

        clean_test_database(self._config, get_database_names(self._config))
        self._mongo_server.shutdown()

        self._tmp_dir.cleanup()

    def test_unpack_analyse_and_compare(self):
        test_fw_1 = Firmware(file_path='{}/container/test.zip'.format(get_test_data_dir()))
        test_fw_1.release_date = '2017-01-01'
        test_fw_2 = Firmware(file_path='{}/container/test.7z'.format(get_test_data_dir()))
        test_fw_2.release_date = '2017-01-01'

        self._unpack_scheduler.add_task(test_fw_1)

        sleep(5)

        self._unpack_scheduler.add_task(test_fw_2)

        sleep(5)

        compare_id = unify_string_list(';'.join([fw.uid for fw in [test_fw_1, test_fw_2]]))

        self.assertIsNone(self._compare_scheduler.add_task((compare_id, False)), 'adding compare task creates error')

        sleep(10)

        with ConnectTo(CompareDbInterface, self._config) as sc:
            result = sc.get_compare_result(compare_id)

        self.assertFalse(isinstance(result, str), 'compare result should exist')
        self.assertEqual(result['plugins']['Software'], self._expected_result()['Software'])
        self.assertCountEqual(result['plugins']['File_Coverage']['exclusive_files'], self._expected_result()['File_Coverage']['exclusive_files'])

    @staticmethod
    def _expected_result():
        return {
            'File_Coverage': {
                'exclusive_files': {
                    '418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787': [],
                    'd38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319': [],
                    'collapse': False
                },
                'files_in_common': {
                    'all': [
                        'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28',
                        '289b5a050a83837f192d7129e4c4e02570b94b4924e50159fad5ed1067cfbfeb_20',
                        'd558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62'
                    ],
                    'collapse': False
                },
                'similar_files': {}
            },
            'Software': {
                'Compare Skipped': {
                    'all': 'Required analysis not present: [\'software_components\', \'software_components\']'
                }
            }
        }
