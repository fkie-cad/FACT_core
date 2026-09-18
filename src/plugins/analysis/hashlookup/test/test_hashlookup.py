from pathlib import Path

import pytest

from plugins.analysis.hash.code.hash import AnalysisPlugin as HashPlugin
from plugins.analysis.hashlookup.code.hashlookup import AnalysisPlugin, HashLookupError

TEST_BLOOM = Path(__file__).parent / 'data' / 'test.bloom'

KNOWN_HASH = 'DEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEF'
SAMPLE_RESULT = {
    'db': 'nsrl_legacy',
    'MD5': 'DEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEF',
    'TLSH': 'DEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEF',
    'CRC32': 'DEADBEEF',
    'SHA-1': 'DEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEF',
    'SSDEEP': '1337:deadbeef++BAADF00D:DEADBEEF+/1337',
    'source': 'db.sqlite',
    'SHA-256': 'DEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEFDEAFBEEF',
    'parents': [
        {
            'MD5': 'BAADF00DBAADF00DBAADF00DBAADF00D',
            'SHA-1': 'BAADF00DBAADF00DBAADF00DBAADF00DBAADF00D',
            'SHA-256': 'BAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00DBAADF00D',
            'FileSize': '1337',
            'PackageName': 'foobar',
            'PackageSection': 'admin',
            'PackageVersion': '1337',
            'PackageMaintainer': 'Debian systemd Maintainers',
            'PackageDescription': 'description',
        }
    ],
    'FileName': 'foobar.service',
    'FileSize': '1337',
    'ProductCode': {
        'MfgCode': '1337',
        'Language': 'English',
        'ProductCode': '1337',
        'ProductName': 'FooBar',
        'OpSystemCode': '1337',
        'ProductVersion': 'November 2020',
        'ApplicationType': 'software collection',
    },
    'SpecialCode': '',
    'OpSystemCode': {'MfgCode': '1337', 'OpSystemCode': '1337', 'OpSystemName': 'TBD', 'OpSystemVersion': 'none'},
    'RDS:package_id': '1337',
    'hashlookup:trust': 100,
    'insert-timestamp': '1696459415.71279',
    'hashlookup:parent-total': 1,
}


def mock_look_up_hash(_self, sha1_hash):
    if sha1_hash == KNOWN_HASH:
        return SAMPLE_RESULT
    if sha1_hash == 'unknown_hash'.upper():
        return {'message': 'Non existing SHA-256'}
    return {}


@pytest.fixture
def _dont_get(monkeypatch):
    monkeypatch.setattr('plugins.analysis.hashlookup.code.hashlookup.AnalysisPlugin._look_up_hash', mock_look_up_hash)
    monkeypatch.setattr(
        'plugins.analysis.hashlookup.code.hashlookup.AnalysisPlugin._init_bloom_filter', lambda _self: None
    )


@pytest.mark.usefixtures('_dont_get')
@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestHashLookup:
    def test_process_object_known_hash(self, analysis_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='', sha1=KNOWN_HASH.lower())}
        result = analysis_plugin.analyze(None, {}, dependencies)
        assert result is not None
        assert result.known is True
        assert result.lookup_result.SHA_256 == KNOWN_HASH
        assert result.lookup_result.ProductCode.ProductName == 'FooBar'

    def test_process_object_unknown_hash(self, analysis_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='', sha1='unknown_hash')}
        result = analysis_plugin.analyze(None, {}, dependencies)
        assert result is not None
        assert result.known is False
        assert result.lookup_result is None

    def test_process_object_error(self, analysis_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='', sha1='connection_error')}
        with pytest.raises(HashLookupError):
            analysis_plugin.analyze(None, {}, dependencies)


def mock_look_up_hash_in_bloom(_self, sha1_hash):
    if sha1_hash == 'FOO':
        return SAMPLE_RESULT
    return {}


@pytest.fixture
def _use_test_bloom(monkeypatch):
    # Use the small test bloom filter instead of the CIRCL one in bin/ (which might not be installed)
    monkeypatch.setattr('plugins.analysis.hashlookup.code.hashlookup.BLOOM_FILTER_PATH', TEST_BLOOM)


@pytest.fixture
def bloom_plugin(monkeypatch, _use_test_bloom):
    monkeypatch.setattr(
        'plugins.analysis.hashlookup.code.hashlookup.AnalysisPlugin._look_up_hash', mock_look_up_hash_in_bloom
    )
    return AnalysisPlugin()


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestBloomLookup:
    def test_hash_not_in_bloom(self, bloom_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='', sha1='NOPE')}
        result = bloom_plugin.analyze(None, {}, dependencies)
        assert result.known is False
        assert result.lookup_result is None

    def test_hash_in_bloom_continues_to_api(self, bloom_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='', sha1='FOO')}
        result = bloom_plugin.analyze(None, {}, dependencies)
        assert result.known is True
        assert result.lookup_result.SHA_256 == KNOWN_HASH

    @pytest.mark.backend_config_overwrite({'plugin': {'hashlookup': {'name': 'hashlookup', 'local_only': True}}})
    def test_hash_in_bloom_local_only(self, bloom_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='', sha1='FOO')}
        result = bloom_plugin.analyze(None, {}, dependencies)
        assert result.known is True
        # no API call is made for local-only analysis
        assert result.lookup_result is None
