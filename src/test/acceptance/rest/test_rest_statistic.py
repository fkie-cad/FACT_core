# pylint: disable=wrong-import-order

from time import sleep

from statistic.work_load import WorkLoadStatistic
from test.acceptance.base import TestAcceptanceBase


class TestRestStatistic(TestAcceptanceBase):
    def setUp(self):
        super().setUp()
        self._start_backend()
        self.workload = WorkLoadStatistic(component='backend')
        sleep(1)  # wait for systems to start

    def tearDown(self):
        self.workload.shutdown()
        self._stop_backend()
        super().tearDown()

    def test_status(self):
        self.workload.update(
            unpacking_workload=self.unpacking_service.get_scheduled_workload(),
            analysis_workload=self.analysis_service.get_scheduled_workload(),
        )

        rv = self.test_client.get('/rest/status', follow_redirects=True)

        assert rv.status_code == 200
        assert all(key in rv.json for key in ['system_status', 'plugins'])
        assert 'backend' in rv.json['system_status']
        assert rv.json['system_status']['backend']['status'] == 'online'
        assert rv.json['system_status']['backend']['analysis']['plugins']['file_type']['queue'] == 0
