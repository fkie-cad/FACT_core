from test.common_helper import CommonIntercomMock
from web_interface.components.analysis_routes import AnalysisRoutes


def test_overwrite_default_plugins():
    plugins_that_should_be_checked = ['optional_plugin']
    plugin_dict = CommonIntercomMock.get_available_analysis_plugins()
    result = AnalysisRoutes._overwrite_default_plugins(plugin_dict, plugins_that_should_be_checked)  # pylint: disable=protected-access
    assert len(result.keys()) == 4, 'number of plug-ins changed'
    assert result['default_plugin'][2]['default'] is False, 'default plugin still checked'
    assert result['optional_plugin'][2]['default'] is True, 'optional plugin not checked'
