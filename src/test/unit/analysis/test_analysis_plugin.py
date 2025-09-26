from __future__ import annotations

from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisPluginV0, Tag
from helperFunctions.tag import TagColor


class DummyPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        foo: str

    def __init__(self):
        metadata = self.MetaData(name='DummyPlugin', description='', Schema=self.Schema, version=Version(0, 1, 0))
        super().__init__(metadata)

    def analyze(self, file_handle, virtual_file_path, analyses):
        return self.Schema(foo='foo')


class ExtendedDummyPlugin(DummyPlugin):
    def summarize(self, result):
        return [result.foo]

    def get_tags(self, result, summary):
        return [Tag(name=result.foo, value=result.foo, color=TagColor.GREEN)]


def test_get_analysis():
    plugin = DummyPlugin()

    result = plugin.get_analysis(None, {}, {})
    expected_keys = ['analysis_date', 'plugin_version', 'result', 'summary', 'system_version', 'tags']
    assert all(k in result for k in expected_keys)
    assert 'foo' in result['result']
    assert result['summary'] == []
    assert result['tags'] == {}


def test_get_analysis_extended():
    plugin = ExtendedDummyPlugin()

    result = plugin.get_analysis(None, {}, {})
    expected_keys = ['analysis_date', 'plugin_version', 'result', 'summary', 'system_version', 'tags']
    assert all(k in result for k in expected_keys)
    assert 'foo' in result['result']
    assert result['summary'] == ['foo']
    assert len(result['tags']) == 1
    assert result['tags']['foo'] == {'color': TagColor.GREEN, 'propagate': False, 'value': 'foo'}


def test_summarize():
    plugin = DummyPlugin()
    extended_plugin = ExtendedDummyPlugin()

    assert (
        plugin.summarize(plugin.Schema(foo='foo')) == []
    ), 'if the plugin does not implement summarize, it should return an empty list'
    assert extended_plugin.summarize(plugin.Schema(foo='foo')) == ['foo']
