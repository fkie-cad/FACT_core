from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ..code.crypto_material import AnalysisPlugin

if TYPE_CHECKING:
    from analysis.plugin import AnalysisPluginV0

TEST_DATA_DIR = Path(__file__).parent / 'data'


def _rule_match(
    analysis_plugin: AnalysisPlugin,
    filename: str,
    expected_count: int = 1,
    expected_rule: str | None = None,
):
    test_file = TEST_DATA_DIR / filename
    assert test_file.is_file(), 'test file is missing'
    with test_file.open('rb') as fp:
        result = analysis_plugin.analyze(fp, None, None)
    number_of_rules = len(result.matches)
    assert number_of_rules == expected_count, f'Number of results is {number_of_rules} but should be {expected_count}'
    if expected_rule is not None:
        matching_rules = {m.rule for m in result.matches}
        assert expected_rule in matching_rules, f'Expected rule {expected_rule} missing'
    assert all(bool(item) for m in result.matches for item in m.material)


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestCryptoMaterial:
    def test_gnupg(self, analysis_plugin):
        _rule_match(analysis_plugin, '0x6C2DF2C5-pub.asc', expected_count=2, expected_rule='PgpPublicKeyBlock')

    def test_ssh_public(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa.pub', expected_rule='SshRsaPublicKeyBlock')

    def test_ssh_private(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa', expected_rule='SshRsaPrivateKeyBlock')

    def test_ssh_private_encrypted(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa_encrypted', expected_rule='SshEncryptedRsaPrivateKeyBlock')

    def test_pkcs8(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs', expected_rule='Pkcs8PrivateKey')

    def test_pkcs12(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs12', expected_rule='Pkcs12Certificate')

    def test_ssl_key(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ssl.key', expected_rule='SSLPrivateKey')

    def test_ssl_cert(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ssl.crt', expected_rule='SSLCertificate')

    def test_generic_public_key(self, analysis_plugin):
        _rule_match(analysis_plugin, 'generic_public_key', expected_rule='genericPublicKey')

    def test_no_false_positives(self, analysis_plugin):
        _rule_match(analysis_plugin, 'FP_test', 0)

    def test_der_error(self, analysis_plugin):
        _rule_match(analysis_plugin, 'error.der', 0)

    def test_false_positive_ssl_cert(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ssl_fp.file', 0)

    def test_false_positive_pkcs_cert(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs_fp.file', 0)

    def test_summary_and_tags(self, analysis_plugin: AnalysisPluginV0):
        test_file = TEST_DATA_DIR / 'id_rsa'
        assert test_file.is_file(), 'test file is missing'
        with test_file.open('rb') as fp:
            result = analysis_plugin.analyze(fp, None, None)
            summary = analysis_plugin.summarize(result)
            tags = analysis_plugin.get_tags(result, summary)
        assert summary == ['SshRsaPrivateKeyBlock']
        assert len(tags) == 1
        assert tags[0].name == 'private_key_inside'
