from pathlib import Path
from tempfile import TemporaryDirectory
from test.common_helper import clean_test_database, get_database_names
from test.integration.common import initialize_config
from time import sleep

import pytest
from helperFunctions.fileSystem import get_test_data_dir
from intercom.back_end_binding import InterComBackEndBinding
from objects.firmware import Firmware
from scheduler.Analysis import AnalysisScheduler
from scheduler.Unpacking import UnpackingScheduler
from storage.MongoMgr import MongoMgr
from web_interface.frontend_main import WebFrontEnd

first_root_id = '5fadb36c49961981f8d87cc21fc6df73a1b90aa1857621f2405d317afb994b64_68415'
second_root_id = '0383cac1dd8fbeb770559163edbd571c21696c435a4942bec6df151983719731_52143'
target_uid = '49543bc7128542b062d15419c90459be65ca93c3134554bc6224e307b359c021_9968'
TMP_DIR = TemporaryDirectory(prefix="fact_test_")


class MockScheduler:
    def __init__(self, *_, **__):
        pass

    def add_task(self, task):
        pass


@pytest.fixture(scope='module')
def test_config():
    return initialize_config(TMP_DIR)


@pytest.fixture(scope='module', autouse=True)
def test_server(test_config):
    mongo = MongoMgr(test_config)
    clean_test_database(test_config, get_database_names(test_config))
    yield None
    clean_test_database(test_config, get_database_names(test_config))
    mongo.shutdown()


@pytest.fixture(scope='module')
def test_app(test_config):
    frontend = WebFrontEnd(config=test_config)
    frontend.app.config['TESTING'] = True
    return frontend.app.test_client()


@pytest.fixture(scope='module')
def test_scheduler(test_config):
    analyzer = AnalysisScheduler(test_config)
    unpacker = UnpackingScheduler(config=test_config, post_unpack=analyzer.add_task)
    intercom = InterComBackEndBinding(config=test_config, analysis_service=analyzer, unpacking_service=unpacker, compare_service=MockScheduler())
    yield unpacker
    intercom.shutdown()
    unpacker.shutdown()
    analyzer.shutdown()


def add_test_file_and_wait(test_scheduler, path_in_test_dir):
    firmware = Firmware(file_path=str(Path(get_test_data_dir(), path_in_test_dir)))
    firmware.set_release_date('1990-01-16')
    test_scheduler.add_task(firmware)
    sleep(5)


@pytest.mark.skip(reason='does not terminate')
def test_check_collision(test_app, test_scheduler):
    add_test_file_and_wait(test_scheduler, 'regression_one')
    add_test_file_and_wait(test_scheduler, 'regression_two')

    first_response = test_app.get('/analysis/{}/ro/{}'.format(target_uid, first_root_id))
    assert b'insufficient information' not in first_response.data

    second_response = test_app.get('/analysis/{}/ro/{}'.format(target_uid, second_root_id))
    assert b'insufficient information' not in second_response.data
