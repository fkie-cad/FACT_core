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
        _rule_match(analysis_plugin, 'id_rsa.pub', expected_rule='SshPublicKey')

    def test_ssh_private(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa', expected_rule='SshRsaPrivateKeyBlock')

    def test_ssh_dsa_private(self, analysis_plugin):
        _rule_match(analysis_plugin, 'dsa_priv.pem', expected_rule='SshDsaPrivateKeyBlock')

    def test_ssh_private_encrypted(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_rsa_encrypted', expected_rule='SshEncryptedRsaPrivateKeyBlock')

    def test_openssh_private_ed25519(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_ed25519', expected_rule='OpenSshPrivateKey')

    def test_openssh_private_ecdsa(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_ecdsa', expected_rule='OpenSshPrivateKey')

    def test_openssh_private_rsa(self, analysis_plugin):
        _rule_match(analysis_plugin, 'openssh_key', expected_rule='OpenSshPrivateKey')

    def test_ssh_public_ed25519(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_ed25519.pub', expected_rule='SshPublicKey')

    def test_ssh_public_ecdsa(self, analysis_plugin):
        _rule_match(analysis_plugin, 'id_ecdsa.pub', expected_rule='SshPublicKey')

    def test_ec_private_pem(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ec_priv.pem', expected_rule='EcPrivateKey')

    def test_ec_private_der(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ec_priv.der', expected_rule='EcPrivateKeyDer')

    def test_encrypted_pkcs8_pem(self, analysis_plugin):
        _rule_match(analysis_plugin, 'enc_pkcs8.pem', expected_rule='EncryptedPrivateKey')

    def test_encrypted_pkcs8_der(self, analysis_plugin):
        _rule_match(analysis_plugin, 'enc_pkcs8.der', expected_rule='EncryptedPrivateKeyDer')

    def test_pkcs7_signed_data(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs7.der', expected_rule='Pkcs7SignedData')

    def test_certificate_request(self, analysis_plugin):
        _rule_match(analysis_plugin, 'csr.pem', expected_rule='CertificateRequest')

    def test_pkcs1_rsa_der(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs1_rsa.der', expected_rule='Pkcs1RsaPrivateKey')

    def test_pkcs1_rsa(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs', expected_rule='Pkcs1RsaPrivateKey')

    def test_pkcs8(self, analysis_plugin):
        # PKCS#8 wraps a PKCS#1 key, so the embedded key is detected as well
        _rule_match(analysis_plugin, 'pkcs8_priv.der', expected_count=2, expected_rule='Pkcs8PrivateKey')

    def test_pkcs12(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs12', expected_rule='Pkcs12Certificate')

    def test_ssl_key(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ssl.key', expected_rule='SSLPrivateKey')

    def test_ssl_cert(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ssl.crt', expected_rule='SSLCertificate')

    def test_ssl_cert_ca_variant(self, analysis_plugin):
        _rule_match(analysis_plugin, 'ca_cert.crt', expected_rule='SSLCertificate')

    def test_ssl_cert_trusted_variant(self, analysis_plugin):
        _rule_match(analysis_plugin, 'trusted_cert.crt', expected_rule='SSLCertificate')

    def test_ssl_cert_x509_variant(self, analysis_plugin):
        _rule_match(analysis_plugin, 'x509_cert.crt', expected_rule='SSLCertificate')

    def test_pkcs7_pem(self, analysis_plugin):
        _rule_match(analysis_plugin, 'pkcs7.pem', expected_rule='Pkcs7Pem')

    def test_tss2_private_key(self, analysis_plugin):
        _rule_match(analysis_plugin, 'tss2_private_key.pem', expected_rule='Tss2PrivateKey')

    def test_tss2_key_blob(self, analysis_plugin):
        _rule_match(analysis_plugin, 'tss2_key_blob.pem', expected_rule='Tss2KeyBlob')

    def test_openvpn_static_key(self, analysis_plugin):
        _rule_match(analysis_plugin, 'openvpn_static.key', expected_rule='OpenVpnStaticKey')

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

    def test_no_private_tag_on_certificate_request(self, analysis_plugin: AnalysisPluginV0):
        test_file = TEST_DATA_DIR / 'csr.pem'
        assert test_file.is_file(), 'test file is missing'
        with test_file.open('rb') as fp:
            result = analysis_plugin.analyze(fp, None, None)
            summary = analysis_plugin.summarize(result)
            tags = analysis_plugin.get_tags(result, summary)
        assert summary == ['CertificateRequest']
        assert tags == []

    def test_tss2_private_key_has_private_tag(self, analysis_plugin: AnalysisPluginV0):
        test_file = TEST_DATA_DIR / 'tss2_private_key.pem'
        assert test_file.is_file(), 'test file is missing'
        with test_file.open('rb') as fp:
            result = analysis_plugin.analyze(fp, None, None)
            summary = analysis_plugin.summarize(result)
            tags = analysis_plugin.get_tags(result, summary)
        assert 'Tss2PrivateKey' in summary
        assert any(tag.name == 'private_key_inside' for tag in tags)

    def test_tss2_key_blob_no_private_tag(self, analysis_plugin: AnalysisPluginV0):
        test_file = TEST_DATA_DIR / 'tss2_key_blob.pem'
        assert test_file.is_file(), 'test file is missing'
        with test_file.open('rb') as fp:
            result = analysis_plugin.analyze(fp, None, None)
            summary = analysis_plugin.summarize(result)
            tags = analysis_plugin.get_tags(result, summary)
        assert 'Tss2KeyBlob' in summary
        assert tags == []
