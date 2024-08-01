import pytest

from tests.common_helper import create_test_file_object

from ..code.string_eval import AnalysisPlugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_find_strings(analysis_plugin):
    fo = create_test_file_object()
    fo.processed_analysis['printable_strings'] = {
        'result': {
            'strings': ['reasonable', 'still_reasonable', "n123ot'(§rea'§&son##+able"],
        },
    }

    fo = analysis_plugin.process_object(fo)
    results = fo.processed_analysis[analysis_plugin.NAME]

    assert isinstance(results, dict), 'Result of wrong type'
    assert results['string_eval'] == ['still_reasonable', 'reasonable', "n123ot'(§rea'§&son##+able"]
