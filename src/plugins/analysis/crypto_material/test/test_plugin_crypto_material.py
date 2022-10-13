import os

from common_helper_files import get_dir_of_file

from test.unit.analysis.AbstractSignatureTest import AbstractSignatureTest  # pylint: disable=wrong-import-order

from ..code.crypto_material import AnalysisPlugin


class CryptoCodeMaterialTest(AbstractSignatureTest):
    PLUGIN_NAME = 'crypto_material'
    PLUGIN_CLASS = AnalysisPlugin
    TEST_DATA_DIR = os.path.join(get_dir_of_file(__file__), 'data')

    def test_gnupg(self):
        self._rule_match('0x6C2DF2C5-pub.asc', 'PgpPublicKeyBlock', len(['PgpPublicKeyBlock', 'PgpPublicKeyBlock_GnuPG']))

    def test_ssh_public(self):
        self._rule_match('id_rsa.pub', 'SshRsaPublicKeyBlock')

    def test_ssh_private(self):
        self._rule_match('id_rsa', 'SshRsaPrivateKeyBlock', expected_number_of_rules=2)

    def test_ssh_private_encrypted(self):
        self._rule_match('id_rsa_encrypted', 'SshEncryptedRsaPrivateKeyBlock', expected_number_of_rules=2)

    def test_PKCS8(self):
        self._rule_match('pkcs', 'Pkcs8PrivateKey', expected_number_of_rules=2)

    def test_PKCS12(self):
        self._rule_match('pkcs12', 'Pkcs12Certificate')

    def test_SSL_key(self):
        self._rule_match('ssl.key', 'SSLPrivateKey', expected_number_of_rules=2)

    def test_SSL_cert(self):
        self._rule_match('ssl.crt', 'SSLCertificate')

    def test_generic_public_key(self):
        self._rule_match('generic_public_key', 'genericPublicKey')

    def test_no_false_positives(self):
        self._rule_match('FP_test', None, 0)

    def test_der_error(self):
        self._rule_match('error.der', None, 0)

    def test_false_positive_ssl_cert(self):
        self._rule_match('ssl_fp.file', None, 0)

    def test_false_positive_pkcs_cert(self):
        self._rule_match('pkcs_fp.file', None, 0)
