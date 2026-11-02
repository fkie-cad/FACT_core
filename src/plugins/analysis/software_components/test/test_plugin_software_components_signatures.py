from pathlib import Path

import yara

from test.yara_signature_testing import SignatureTestingMatching, SignatureTestingMeta

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


def test_clash_configuration_signature():
    rules = yara.compile(str(SIGNATURE_PATH / 'network.yara'))
    active_configs = (
        b'external-controller: 127.0.0.1:9090\nproxy-groups:\n',
        b'external-controller: :9090\nproxies: []\n',
        b'external-controller: localhost:9090\r\nrule-providers: {}\r\n',
        b'external-controller: "[::1]:65535" # local API\nproxies: []\n',
        b"external-controller: '0.0.0.0:1'\nproxy-groups: []\n",
        b'external-controller: localhost:0\nproxies: []\n',
        b'\xef\xbb\xbfexternal-controller: 127.0.0.1:9090\nproxies: []\n',
        b'---\nexternal-controller: 127.0.0.1:9090\nproxies: []\n',
        b'external-controller: router.local:9090\nproxies: []\n',
        b'external-controller: localhost:09090\nproxies: []\n',
        b'external-controller: 127.0.0.1:9090\nproxies: []\n---\nnotes: second document\n',
        b'"external-controller": 127.0.0.1:9090\n\'proxies\': []\n',
        b"external-controller: '[1:2:3:4:5:6:7:8]:9090'\nproxies: []\n",
        b'external-controller: "[1:2:3:4:5:6:7::]:9090"\nproxies: []\n',
        b'external-controller: "[1:2:3:4:5:6::8]:9090"\nproxies: []\n',
        b'external-controller: "[1:2:3:4:5::7:8]:9090"\nproxies: []\n',
        b'external-controller: "[1:2:3:4::6:7:8]:9090"\nproxies: []\n',
        b'external-controller: "[1:2:3::5:6:7:8]:9090"\nproxies: []\n',
        b'external-controller: "[1:2::4:5:6:7:8]:9090"\nproxies: []\n',
        b'external-controller: "[1::3:4:5:6:7:8]:9090"\nproxies: []\n',
    )
    inactive_configs = (
        b'external-controller:\nproxy-groups:\n',
        b'external-controller: # disabled\nproxy-groups:\n',
        b'external-controller: ""\nproxy-groups:\n',
        b"external-controller: ''\nproxy-groups:\n",
        b'external-controller: null\nproxies: []\n',
        b'external-controller: ~\nproxies: []\n',
        b'external-controller: false\nproxies: []\n',
        b'external-controller: 0\nproxies: []\n',
        b'external-controller: localhost:65536\nproxies: []\n',
        b'external-controller: 256.1.1.1:9090\nproxies: []\n',
        b'external-controller: 999.999.999.999:9090\nproxies: []\n',
        b'external-controller: 001.002.003.004:9090\nproxies: []\n',
        b'external-controller: "[:::]:9090"\nproxies: []\n',
        b'external-controller: "[:]:9090"\nproxies: []\n',
        b'external-controller: "[dead.beef]:9090"\nproxies: []\n',
        b'external-controller: -router.local:9090\nproxies: []\n',
        b'external-controller: router..local:9090\nproxies: []\n',
        b'external-controller: 127.0.0.1:9090#not-a-comment\nproxies: []\n',
        b'external-controller: enabled\nproxies: documented below\n',
        b'external-controller: "localhost:9090\nproxies: []\n',
        b'EXTERNAL-CONTROLLER: localhost:9090\nPROXIES: []\n',
        b'# external-controller: 127.0.0.1:9090\nproxy-groups:\n',
        b'external-controller: 127.0.0.1:9090\n# proxy-groups:\n',
        b'example:\n  external-controller: 127.0.0.1:9090\n  proxies: []\n',
        b'notes: |\n  external-controller: 127.0.0.1:9090\n  proxies: []\n',
        b'\texternal-controller: 127.0.0.1:9090\n\tproxies: []\n',
        b'external-controller: 127.0.0.1:9090\n---\nproxies: []\n',
        b'external-controller: 127.0.0.1:9090\n--- # next document\nproxies: []\n',
    )

    for config in active_configs:
        matches = [match for match in rules.match(data=config) if match.rule == 'ClashConfiguration']
        assert len(matches) == 1

    for config in inactive_configs:
        assert not any(match.rule == 'ClashConfiguration' for match in rules.match(data=config))
