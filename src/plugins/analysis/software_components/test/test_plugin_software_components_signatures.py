from pathlib import Path

import pytest
import yara

from helperFunctions.yara import compile_rules
from test.yara_signature_testing import SignatureTestingMatching, SignatureTestingMeta

from ..code.software_components import get_version_for_component

TEST_DATA_DIR = Path(__file__).parent / 'data'
SIGNATURE_PATH = Path(__file__).parent.parent / 'signatures/'
TEST_SIGNATURE_PATH = Path(__file__).parent.parent / 'test/data/signatures/'


class TestSoftwareSignatureMeta:
    @classmethod
    def setup_class(cls):
        cls.sigTest = SignatureTestingMeta()

    def test_check_meta_fields(self):
        missing_fields, rule_errors = self.sigTest.check_meta_fields(SIGNATURE_PATH)
        assert not missing_fields, f'Missing meta fields: {missing_fields.__str__()}'
        assert rule_errors == []

    def test_check_meta_fields_missing(self):
        missing_fields, rule_errors = self.sigTest.check_meta_fields(TEST_SIGNATURE_PATH)
        assert len(missing_fields) == 3
        assert all(
            entry in missing_fields
            for entry in ['website in missing_meta_1', 'description in missing_meta_1', 'ALL in missing_meta_2']
        )
        assert rule_errors == []


class TestAllSoftwareSignaturesMatched:
    def setup_method(self):
        self.sig_tester = SignatureTestingMatching()

    def test_all_signatures_matched(self):
        diff = self.sig_tester.check(SIGNATURE_PATH, TEST_DATA_DIR / 'software_component_test_list.txt')
        assert diff == set(), f'Missing signature for {diff}'


# strings from the gpg binaries of Debian packages (and Ubuntu's gpg 2.4.8), separated as in their .rodata
GNUPG_SAMPLES = [
    pytest.param(
        [b'gpg (GnuPG)', b'1.4.6', b'gpg.conf-1.4.6', b'Version: GnuPG v1.4.6 (GNU/Linux)'],
        '1.4.6',
        id='gnupg 1.4.6-2 mipsel',
    ),
    pytest.param(  # the version is only in the name of the versioned config file
        [b'gpg (GnuPG)', b'GNU/Linux', b'gpg.conf-1.4.23', b'Version: GnuPG v'],
        '1.4.23',
        id='gnupg1 1.4.23-1 amd64',
    ),
    pytest.param(
        [
            b'2.0.9',
            b'gpg (GnuPG)',
            b'gpg.conf-2.0.9',
            b"GNU Privacy Guard's OpenPGP server 2.0.9 ready",
            b'Version: GnuPG v2.0.9 (GNU/Linux)',
        ],
        '2.0.9',
        id='gnupg2 2.0.9-3.1 mipsel',
    ),
    pytest.param(  # gpgv2: only the ASCII armor header
        [b'2.0.9', b'gpgv (GnuPG)', b'Version: GnuPG v2.0.9 (GNU/Linux)'],
        '2.0.9',
        id='gnupg2 2.0.9-3.1 mipsel gpgv2',
    ),
    pytest.param(
        [
            b'gpg (GnuPG)',
            b'2.0.26',
            b'gpg.conf-2.0.26',
            b"GNU Privacy Guard's OpenPGP server 2.0.26 ready",
            b'Version: GnuPG v',
        ],
        '2.0.26',
        id='gnupg2 2.0.26-6 armel',
    ),
    pytest.param(
        [
            b'@GPG@ (@GNUPG@)',
            b'gpg.conf-2.2.12',
            b"GNU Privacy Guard's OpenPGP server 2.2.12 ready",
            b'Version: GnuPG v',
        ],
        '2.2.12',
        id='gpg 2.2.12-1 mipsel',
    ),
    pytest.param(  # no versioned config file any more
        [b'@GPG@ (@GNUPG@)', b'2.4.8', b"GNU Privacy Guard's OpenPGP server 2.4.8 ready", b'Version: GnuPG v'],
        '2.4.8',
        id='gpg 2.4.8-4ubuntu3.1 amd64',
    ),
]
ELF_HEADER = b'\x7fELF\x01\x01\x01\x00'
# keys, signatures, and signed images exported by GnuPG carry its version in the armor header
ARMORED_KEY = (
    b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
    b'Version: GnuPG v1.4.7 (GNU/Linux)\n\n'
    b'mQGiBEZ7+2wRBADPm1p9Yx9cJ1PqzD3n\n'
    b'-----END PGP PUBLIC KEY BLOCK-----\n'
)


class TestGnuPGSignature:
    @pytest.fixture(scope='class')
    def rules(self, tmp_path_factory):
        compiled = tmp_path_factory.mktemp('signatures') / 'software_components.yc'
        compile_rules(SIGNATURE_PATH, compiled)
        return yara.load(str(compiled))

    @pytest.mark.parametrize(('strings', 'version'), GNUPG_SAMPLES)
    def test_gnupg_version(self, rules, tmp_path, strings, version):
        binary = tmp_path / 'gpg'
        binary.write_bytes(ELF_HEADER + b'\x00'.join(strings) + b'\x00')

        matches = [match for match in rules.match(str(binary)) if match.rule == 'GnuPG']

        assert len(matches) == 1
        assert matches[0].meta['software_name'] == 'GnuPG'
        with binary.open('rb') as file_handle:
            assert get_version_for_component(matches[0], file_handle) == [version]

    @pytest.mark.parametrize(
        'contents',
        [
            pytest.param(ARMORED_KEY, id='exported key'),
            pytest.param(ELF_HEADER + b'\x00/usr/sbin/fwkey\x00' + ARMORED_KEY + b'\x00', id='updater with a key'),
        ],
    )
    def test_armored_key_is_not_gnupg(self, rules, tmp_path, contents):
        file = tmp_path / 'file'
        file.write_bytes(contents)

        assert [match.rule for match in rules.match(str(file)) if match.rule == 'GnuPG'] == []
