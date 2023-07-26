import pytest

from objects.firmware import Firmware
from test.common_helper import get_test_data_dir
from test.integration.common import MockDbInterface


@pytest.mark.SchedulerTestConfig(backend_db_class=MockDbInterface)
class TestFileAddition:
    def test_unpack_only(self, unpacking_scheduler, post_unpack_queue):
        test_fw = Firmware(file_path=f'{get_test_data_dir()}/container/test.zip')

        unpacking_scheduler.add_task(test_fw)

        processed_container = post_unpack_queue.get(timeout=5)

        assert len(processed_container.files_included) == 3, 'not all included files found'  # noqa: PLR2004
        included_uids = {
            '289b5a050a83837f192d7129e4c4e02570b94b4924e50159fad5ed1067cfbfeb_20',
            'd558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62',
            'faa11db49f32a90b51dfc3f0254f9fd7a7b46d0b570abd47e1943b86d554447a_28',
        }
        assert processed_container.files_included == included_uids, 'certain file missing after unpacking'
