import gc
import unittest
from configparser import ConfigParser
from time import sleep
from unittest import mock

import pytest

from compare.PluginBase import CompareBasePlugin
from scheduler.comparison_scheduler import ComparisonScheduler
from test.common_helper import CommonDatabaseMock, create_test_file_object  # pylint: disable=wrong-import-order

# pylint: disable=unused-argument,protected-access,no-member


@pytest.fixture(autouse=True)
def no_compare_views(monkeypatch):
    monkeypatch.setattr(CompareBasePlugin, '_sync_view', value=lambda s, p: None)


class MockDbInterface(CommonDatabaseMock):
    def __init__(self, config=None):
        self.test_object = create_test_file_object()
        self.test_object.list_of_all_included_files = [self.test_object.uid]

    def get_complete_object_including_all_summaries(self, uid):
        if uid == self.test_object.uid:
            return self.test_object
        return None


class TestSchedulerCompare(unittest.TestCase):

    @mock.patch('plugins.base.ViewUpdater', lambda *_: None)
    def setUp(self):
        self.config = ConfigParser()
        self.config.add_section('expert-settings')
        self.config.set('expert-settings', 'block-delay', '2')
        self.config.set('expert-settings', 'ssdeep-ignore', '80')

        self.bs_patch_new = unittest.mock.patch(target='storage.binary_service.BinaryService.__new__', new=lambda *_, **__: MockDbInterface())
        self.bs_patch_init = unittest.mock.patch(target='storage.binary_service.BinaryService.__init__', new=lambda _: None)
        self.bs_patch_new.start()
        self.bs_patch_init.start()

        self.compare_scheduler = ComparisonScheduler(db_interface=MockDbInterface(config=self.config), testing=True)

    def tearDown(self):
        self.compare_scheduler.shutdown()
        self.bs_patch_new.stop()
        self.bs_patch_init.stop()

        gc.collect()

    def test_start_compare(self):
        self.compare_scheduler.add_task(('existing_id', True))
        uid, redo = self.compare_scheduler.in_queue.get(timeout=2)
        self.assertEqual(uid, 'existing_id', 'retrieved id not correct')
        self.assertTrue(redo, 'redo argument not correct')

    def test_start(self):
        self.compare_scheduler.start()
        sleep(2)

    def test_compare_single_run(self):
        compares_done = set()
        self.compare_scheduler.in_queue.put((self.compare_scheduler.db_interface.test_object.uid, False))
        self.compare_scheduler._compare_single_run(compares_done)
        self.assertEqual(len(compares_done), 1, 'compares done not set correct')
        self.assertIn(self.compare_scheduler.db_interface.test_object.uid, compares_done, 'correct uid not in compares done')

    def test_decide_whether_to_process(self):
        compares_done = set('a')
        self.assertTrue(self.compare_scheduler._comparison_should_start('b', False, compares_done), 'none existing should always be done')
        self.assertTrue(self.compare_scheduler._comparison_should_start('a', True, compares_done), 'redo is true so result should be true')
        self.assertFalse(self.compare_scheduler._comparison_should_start('a', False, compares_done), 'already done and redo no -> should be false')
