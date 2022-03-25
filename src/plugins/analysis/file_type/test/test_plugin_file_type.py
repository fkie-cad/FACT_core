import pytest

from objects.file import FileObject
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order

from ..code.file_type import AnalysisPlugin


@pytest.mark.AnalysisPluginClass.with_args(AnalysisPlugin)
def test_detect_type_of_file(analysis_plugin):
    test_file = FileObject(file_path=f'{get_test_data_dir()}/container/test.zip')
    test_file = analysis_plugin.process_object(test_file)
    assert test_file.processed_analysis[analysis_plugin.NAME]['mime'] == 'application/zip', 'mime-type not detected correctly'
    assert test_file.processed_analysis[analysis_plugin.NAME]['full'].startswith('Zip archive data, at least'), 'full type not correct'
    assert test_file.processed_analysis[analysis_plugin.NAME]['summary'] == ['application/zip']
