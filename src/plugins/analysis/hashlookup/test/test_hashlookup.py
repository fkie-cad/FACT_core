import pytest

from analysis.plugin import AnalysisFailedError
from plugins.analysis.hash.code.hash import AnalysisPlugin as HashPlugin
from plugins.analysis.hashlookup.code.hashlookup import AnalysisPlugin, HashLookupError

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


def mock_look_up_hash(sha2_hash):
    if sha2_hash == KNOWN_HASH:
        return SAMPLE_RESULT
    if sha2_hash == 'unknown_hash'.upper():
        return {'message': 'Non existing SHA-256'}
    return {}


@pytest.fixture
def _dont_get(monkeypatch):
    monkeypatch.setattr('plugins.analysis.hashlookup.code.hashlookup._look_up_hash', mock_look_up_hash)


@pytest.mark.usefixtures('_dont_get')
@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestHashLookup:
    def test_process_object_known_hash(self, analysis_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256=KNOWN_HASH.lower())}
        result = analysis_plugin.analyze(None, {}, dependencies)
        assert result is not None
        assert result.SHA_256 == KNOWN_HASH
        assert result.ProductCode.ProductName == 'FooBar'

    def test_process_object_unknown_hash(self, analysis_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='unknown_hash')}
        with pytest.raises(AnalysisFailedError, match='No record found'):
            analysis_plugin.analyze(None, {}, dependencies)

    def test_process_object_error(self, analysis_plugin):
        dependencies = {'file_hashes': HashPlugin.Schema(md5='', sha256='connection_error')}
        with pytest.raises(HashLookupError):
            analysis_plugin.analyze(None, {}, dependencies)
