from pathlib import Path

import pytest

from objects.file import FileObject
from ..internal.busybox_cve_filter import filter_busybox_cves

TEST_DIR = Path(__file__).parent / 'data'


@pytest.fixture(
    params=[
        (
            'busybox_1.32.0_x86_small',
            '1.32.0',
            {
                'CVE-2021-42385': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42379': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42381': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.21.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42386': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42380': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.28.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42384': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42378': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42382': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.26.0 ≤ version ≤ 1.33.1'},
            },
            {
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
            },
        ),
        (
            'busybox_1.32.0_x86_full',
            '1.32.0',
            {
                'CVE-2021-42385': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42379': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42381': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.21.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42386': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42380': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.28.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42384': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42378': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42382': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.26.0 ≤ version ≤ 1.33.1'},
            },
            {
                'CVE-2021-42385': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42379': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42381': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.21.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42386': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42380': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.28.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42384': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42378': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42382': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.26.0 ≤ version ≤ 1.33.1'},
            },
        ),
        (
            'busybox_1.35.0_x86_small',
            '1.35.0',
            {
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2022-30065': {'score2': '6.8', 'score3': '7.8', 'cpe_version': '1.35.0'},
            },
            dict(),
        ),
        (
            'busybox_1.35.0_x86_full',
            '1.35.0',
            {
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2022-30065': {'score2': '6.8', 'score3': '7.8', 'cpe_version': '1.35.0'},
            },
            {
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2022-30065': {'score2': '6.8', 'score3': '7.8', 'cpe_version': '1.35.0'},
            },
        ),
        (
            'busybox_1.32.0_arm_small',
            '1.32.0',
            {
                'CVE-2021-42385': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42379': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42381': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.21.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42386': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42380': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.28.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42384': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42378': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42382': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.26.0 ≤ version ≤ 1.33.1'},
            },
            {
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
            },
        ),
        (
            'busybox_1.32.0_arm_full',
            '1.32.0',
            {
                'CVE-2021-42385': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42379': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42381': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.21.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42386': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42380': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.28.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42384': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42378': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42382': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.26.0 ≤ version ≤ 1.33.1'},
            },
            {
                'CVE-2021-42385': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42379': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42381': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.21.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-28831': {'score2': '5.0', 'score3': '7.5', 'cpe_version': '1.32.0 ≤ version ≤ 1.32.1'},
                'CVE-2021-42386': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42380': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.28.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42376': {'score2': '1.9', 'score3': '5.5', 'cpe_version': '1.16.0 ≤ version < 1.34.0'},
                'CVE-2022-28391': {'score2': '6.8', 'score3': '8.8', 'cpe_version': 'version ≤ 1.35.0'},
                'CVE-2021-42384': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.18.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42374': {'score2': '3.3', 'score3': '5.3', 'cpe_version': '1.27.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42378': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.16.0 ≤ version ≤ 1.33.1'},
                'CVE-2021-42382': {'score2': '6.5', 'score3': '7.2', 'cpe_version': '1.26.0 ≤ version ≤ 1.33.1'},
            },
        ),
    ]
)
def busybox_sample(request):
    test_file, version, version_vulnerabilities, expected_vulnerabilities = request.param
    test_object = FileObject(file_path=str((TEST_DIR / test_file).resolve()))
    return test_object, version, version_vulnerabilities, expected_vulnerabilities


def test_filter_busybox_cves(busybox_sample):
    test_object, version, version_vulnerabilities, expected_vulnerabilities = busybox_sample
    assert expected_vulnerabilities == filter_busybox_cves(test_object, version_vulnerabilities, version)
