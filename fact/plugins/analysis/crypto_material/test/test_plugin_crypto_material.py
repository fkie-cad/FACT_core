import os

import pytest
from common_helper_files import get_dir_of_file

from fact.objects.file import FileObject

from ..code.crypto_material import AnalysisPlugin

TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')  # noqa: PTH118


def _rule_match(analysis_plugin, filename, expected_rule_name, expected_number_of_rules=1):
    path = os.path.join(TEST_DATA_DIR, filename)  # noqa: PTH118
    test_file = FileObject(file_path=path)
    analysis_plugin.process_object(test_file)
    number_of_rules = len(test_file.processed_analysis[analysis_plugin.NAME]) - 1
    assert (
        number_of_rules == expected_number_of_rules
    ), f'Number of results is {number_of_rules} but should be {expected_number_of_rules}'
    if expected_rule_name is not None:
        assert (
            expected_rule_name in test_file.processed_analysis[analysis_plugin.NAME]
        ), f'Expected rule {expected_rule_name} missing'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestCryptoMaterial:
    def test_gnupg(self, analysis_plugin):
        _rule_match(
            analysis_plugin,
            '0x6C2DF2C5-pub.asc',
            'PgpPublicKeyBlock',
            len(['PgpPublicKeyBlock', 'PgpPublicKeyBlock_GnuPG']),
        )

    def test_ssh_public(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa.pub', 'SshRsaPublicKeyBlock')

    def test_ssh_private(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa', 'SshRsaPrivateKeyBlock', expected_number_of_rules=2)

    def test_ssh_private_encrypted(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa_encrypted', 'SshEncryptedRsaPrivateKeyBlock', expected_number_of_rules=2)

    def test_PKCS8(self, analysis_plugin):  # noqa: N802
        _rule_match(analysis_plugin, 'pkcs', 'Pkcs8PrivateKey', expected_number_of_rules=2)

    def test_PKCS12(self, analysis_plugin):  # noqa: N802
        _rule_match(analysis_plugin, 'pkcs12', 'Pkcs12Certificate')

    def test_SSL_key(self, analysis_plugin):  # noqa: N802
        _rule_match(analysis_plugin, 'ssl.key', 'SSLPrivateKey', expected_number_of_rules=2)

    def test_SSL_cert(self, analysis_plugin):  # noqa: N802
        _rule_match(analysis_plugin, 'ssl.crt', 'SSLCertificate')

    def test_generic_public_key(self, analysis_plugin):
        _rule_match(analysis_plugin, 'generic_public_key', 'genericPublicKey')

    def test_no_false_positives(self, analysis_plugin):
        _rule_match(analysis_plugin, 'FP_test', None, 0)

    def test_der_error(self, analysis_plugin):
        _rule_match(analysis_plugin, 'error.der', None, 0)

    def test_false_positive_ssl_cert(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ssl_fp.file', None, 0)

    def test_false_positive_pkcs_cert(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs_fp.file', None, 0)
