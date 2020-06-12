import gc

from storage.db_interface_view_sync import ViewReader, ViewUpdater
from storage.MongoMgr import MongoMgr
from test.common_helper import get_config_for_testing

CONFIG = get_config_for_testing()
TEST_DATA = b'test data'


def test_view_sync_interface():
    mongo_server = MongoMgr(config=CONFIG)

    view_update_service = ViewUpdater(config=CONFIG)
    view_update_service.update_view('test', TEST_DATA)
    view_update_service.shutdown()

    view_read_service = ViewReader(config=CONFIG)
    assert view_read_service.get_view('none_existing') is None
    assert view_read_service.get_view('test') == TEST_DATA
    view_read_service.shutdown()

    mongo_server.shutdown()
    gc.collect()
