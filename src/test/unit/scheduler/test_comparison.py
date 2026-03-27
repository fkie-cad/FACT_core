from time import sleep

import pytest

from comparison.comparison_base_plugin import ComparisonBasePlugin
from test.common_helper import CommonDatabaseMock, create_test_file_object


@pytest.fixture(autouse=True)
def no_comparison_views(monkeypatch):  # noqa: PT004
    monkeypatch.setattr(ComparisonBasePlugin, '_sync_view', value=lambda s, p: None)  # noqa: ARG005


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
class TestSchedulerComparison:
    def test_start_comparison(self, comparison_scheduler):
        comparison_scheduler.add_task(('existing_id', True))
        uid, redo = comparison_scheduler.in_queue.get(timeout=2)
        assert uid == 'existing_id', 'retrieved id not correct'
        assert redo, 'redo argument not correct'

    def test_start(self, comparison_scheduler):
        comparison_scheduler.start()
        sleep(2)
        comparison_scheduler.shutdown()

    def test_run_single_comparison(self, comparison_scheduler):
        comparisons_done = set()
        comparison_scheduler.in_queue.put((comparison_scheduler.db_interface.test_object.uid, False))
        comparison_scheduler._comparison_worker(comparisons_done)
        assert len(comparisons_done) == 1, 'comparisons done not set correct'
        assert (
            comparison_scheduler.db_interface.test_object.uid in comparisons_done
        ), 'correct uid not in comparisons done'

    def test_decide_whether_to_process(self, comparison_scheduler):
        comparisons_done = set('a')
        assert comparison_scheduler._comparison_should_start(
            'b', False, comparisons_done
        ), 'non-existing comparison should always be done'
        assert comparison_scheduler._comparison_should_start(
            'a', True, comparisons_done
        ), 'redo is true so result should be true'
        assert not comparison_scheduler._comparison_should_start(
            'a', False, comparisons_done
        ), 'already done and redo no -> should be false'
