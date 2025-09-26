from tempfile import NamedTemporaryFile

import pytest

from objects.firmware import Firmware

REGULAR_RESULT = {
    'dependant_analysis': {'full': 'ASCII text, with no line terminators', 'mime': 'text/plain'},
    'first_byte': '6e',
    'name': 'b55f174c36fd4f56ecc04931099300014d4014377c73af1fa433e258a9b38604_14',
    'number': 42,
    'virtual_file_path': {},
}


@pytest.mark.parametrize(
    ('content', 'expected_result'),
    [
        (b'normal content', REGULAR_RESULT),
        (b'\xeeException', {'failed': 'Exception occurred during analysis'}),
        (b'\xffFailed', {'failed': 'Analysis failed: reason for fail'}),
    ],
)
def test_analysis_fail(content, expected_result, analysis_scheduler, post_analysis_queue):
    with NamedTemporaryFile() as tmp_file:
        tmp_file.write(content)
        tmp_file.flush()
        test_fw = Firmware(file_path=tmp_file.name)
        test_fw.release_date = '1970-01-01'
        test_fw.scheduled_analysis = ['ExamplePlugin']

        analysis_scheduler.start_analysis_of_object(test_fw)

        processed_container = {}
        for _ in range(3):  # container with 3 included files times 2 mandatory plugins run
            uid, plugin, analysis_result = post_analysis_queue.get(timeout=3)
            processed_container.setdefault(uid, {}).setdefault(plugin, {})
            processed_container[uid][plugin] = analysis_result

        assert len(processed_container) == 1, '1 files should have been analyzed'
        assert all(
            set(processed_analysis) == {'ExamplePlugin', 'file_hashes', 'file_type'}
            for processed_analysis in processed_container.values()
        ), 'at least one analysis not done'
        assert processed_container[test_fw.uid]['ExamplePlugin']['result'] == expected_result
