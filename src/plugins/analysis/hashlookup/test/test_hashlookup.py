# pylint: disable=redefined-outer-name,unused-argument,protected-access,wrong-import-order

import pytest

from test.common_helper import create_test_file_object, get_config_for_testing

from ..code.hashlookup import AnalysisPlugin

KNOWN_ZSH_HASH = 'A6F2177402114FC8B5E7ECF924FFA61A2AC25BD347BC3370FB92E07B76E0B44C'

'''
{
  "message": "Non existing SHA-256",
  "query": "331a1d23e1e83ae87fb88f2f10e7fe9cfc0020ef4adc3c17ba91bd8bb4929fe2"
}

{
  "FileName": "./bin/zsh",
  "FileSize": "878288",
  "MD5": "00B7C6FD436350029530D8E6A309D0A4",
  "SHA-1": "B2D8664FA218B0E49203E1B63CD4E4D205A5F900",
  "SHA-256": "A6F2177402114FC8B5E7ECF924FFA61A2AC25BD347BC3370FB92E07B76E0B44C",
  "SSDEEP": "12288:NEiomGLt0fJe6p0c5fCTNAmrApeBWjJGliuH4IyAznXGk+m163T0jCIAyYj:eiwLt0vKgftx002y",
  "TLSH": "T186155C0BFAA39CFCC465D4F08A7B92736C31B49411326A7B2F4495301DE2E6C2B6D766",
  "hashlookup:parent-total": 1,
  "parents": [
    {
      "FileSize": "706888",
      "MD5": "33BD87DF7D004CCF8713588E3D83AEB3",
      "PackageDescription": "shell with lots of features\n Zsh is a UNIX command interpreter (shell) usable as [...]",
      "PackageMaintainer": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "PackageName": "zsh",
      "PackageSection": "shells",
      "PackageVersion": "5.8-3ubuntu1",
      "SHA-1": "F81D77395A7D008116C492C13A000ABAACFB2239",
      "SHA-256": "11C782AB178DE6A3EEC1C326E9437431930120B94687FFDDF792EA7B11815CB4"
    }
  ],
  "hashlookup:trust": 55
}
'''


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


@pytest.fixture(scope='function')
def test_config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def test_object():
    return create_test_file_object()


@pytest.fixture(scope='function')
def stub_plugin(test_config, monkeypatch):
    monkeypatch.setattr('plugins.base.BasePlugin._sync_view', lambda self, plugin_path: None)
    return AnalysisPlugin(MockAdmin(), test_config, offline_testing=True)


def test_process_object_unknown_hash(stub_plugin, monkeypatch):
    test_file = create_test_file_object()
    test_file.processed_analysis['file_hashes'] = {'sha256': test_file.sha256}
    monkeypatch.setattr('storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_file.file_path)
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert 'message' in result
    assert 'sha256 hash unknown' in result['message']


def test_process_object_known_hash(stub_plugin, monkeypatch):
    test_file = create_test_file_object()
    test_file.processed_analysis['file_hashes'] = {'sha256': KNOWN_ZSH_HASH}
    monkeypatch.setattr('storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_file.file_path)
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert 'FileName' in result
    assert result['FileName'] == './bin/zsh'


def test_process_object_missing_hash(stub_plugin, monkeypatch):
    test_file = create_test_file_object()
    monkeypatch.setattr('storage.fsorganizer.FSOrganizer.generate_path_from_uid', lambda _self, _: test_file.file_path)
    stub_plugin.process_object(test_file)
    result = test_file.processed_analysis[stub_plugin.NAME]
    assert 'message' in result
    assert result['message'].startswith('Lookup needs sha256 hash')
