from time import sleep

import pytest

from fact.compare.PluginBase import CompareBasePlugin
from fact.test.common_helper import CommonDatabaseMock, create_test_file_object


@pytest.fixture(autouse=True)
def no_compare_views(monkeypatch):  # noqa: PT004
    monkeypatch.setattr(CompareBasePlugin, '_sync_view', value=lambda s, p: None)  # noqa: ARG005


class MockDbInterface(CommonDatabaseMock):
    def __init__(self):
        self.test_object = create_test_file_object()
        self.test_object.list_of_all_included_files = [self.test_object.uid]

    def get_complete_object_including_all_summaries(self, uid):
        if uid == self.test_object.uid:
            return self.test_object
        return None

    def get_vfp_of_included_text_files(self, root_uid, blacklist=None):
        return {}


@pytest.mark.backend_config_overwrite(
    {
        'ssdeep_ignore': 80,
    },
)
@pytest.mark.SchedulerTestConfig(start_processes=False, comparison_db_class=MockDbInterface)
class TestSchedulerCompare:
    def test_start_compare(self, comparison_scheduler):
        comparison_scheduler.add_task(('existing_id', True))
        uid, redo = comparison_scheduler.in_queue.get(timeout=2)
        assert uid == 'existing_id', 'retrieved id not correct'
        assert redo, 'redo argument not correct'

    def test_start(self, comparison_scheduler):
        comparison_scheduler.start()
        sleep(2)
        comparison_scheduler.shutdown()

    def test_compare_single_run(self, comparison_scheduler):
        compares_done = set()
        comparison_scheduler.in_queue.put((comparison_scheduler.db_interface.test_object.uid, False))
        comparison_scheduler._compare_single_run(compares_done)
        assert len(compares_done) == 1, 'compares done not set correct'
        assert comparison_scheduler.db_interface.test_object.uid in compares_done, 'correct uid not in compares done'

    def test_decide_whether_to_process(self, comparison_scheduler):
        compares_done = set('a')
        assert comparison_scheduler._comparison_should_start(
            'b', False, compares_done
        ), 'non-existing compare should always be done'
        assert comparison_scheduler._comparison_should_start(
            'a', True, compares_done
        ), 'redo is true so result should be true'
        assert not comparison_scheduler._comparison_should_start(
            'a', False, compares_done
        ), 'already done and redo no -> should be false'
