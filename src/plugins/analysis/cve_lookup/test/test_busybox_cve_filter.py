import pytest
from pathlib import Path

from objects.file import FileObject
from ..internal.database.schema import Cve
from ..internal.busybox_cve_filter import filter_busybox_cves

TEST_DIR = Path(__file__).parent / 'data'


@pytest.fixture(
    params=[
        (
            'busybox_1.32.0_x86_small',
            [
                Cve(
                    cve_id='CVE-2021-42385',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the evaluate function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42379',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the next_input_file function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42381',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the hash_init function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-28831',
                    year='2021',
                    summary='decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.',
                    cvss_v2_score='5.0',
                    cvss_v3_score='7.5',
                ),
                Cve(
                    cve_id='CVE-2021-42386',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the nvalloc function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42380',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the clrvar function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42376',
                    year='2021',
                    summary="A NULL pointer dereference in Busybox's hush applet leads to denial of service when processing a crafted shell command, due to missing validation after a \\x03 delimiter character. This may be used for DoS under very rare conditions of filtered command input.",
                    cvss_v2_score='1.9',
                    cvss_v3_score='5.5',
                ),
                Cve(
                    cve_id='CVE-2022-28391',
                    year='2021',
                    summary="BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record's value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal's colors.",
                    cvss_v2_score='6.8',
                    cvss_v3_score='8.8',
                ),
                Cve(
                    cve_id='CVE-2021-42384',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the handle_special function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42374',
                    year='2021',
                    summary="An out-of-bounds heap read in Busybox's unlzma applet leads to information leak and denial of service when crafted LZMA-compressed input is decompressed. This can be triggered by any applet/format that",
                    cvss_v2_score='3.3',
                    cvss_v3_score='5.3',
                ),
                Cve(
                    cve_id='CVE-2021-42378',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the getvar_i function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42382',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the getvar_s function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
            ],
            ['CVE-2021-28831', 'CVE-2021-42376', 'CVE-2022-28391', 'CVE-2021-42374'],
        ),
        (
            'busybox_1.32.0_x86_full',
            [
                Cve(
                    cve_id='CVE-2021-42385',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the evaluate function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42379',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the next_input_file function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42381',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the hash_init function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-28831',
                    year='2021',
                    summary='decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, with a resultant invalid free or segmentation fault, via malformed gzip data.',
                    cvss_v2_score='5.0',
                    cvss_v3_score='7.5',
                ),
                Cve(
                    cve_id='CVE-2021-42386',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the nvalloc function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42380',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the clrvar function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42376',
                    year='2021',
                    summary="A NULL pointer dereference in Busybox's hush applet leads to denial of service when processing a crafted shell command, due to missing validation after a \\x03 delimiter character. This may be used for DoS under very rare conditions of filtered command input.",
                    cvss_v2_score='1.9',
                    cvss_v3_score='5.5',
                ),
                Cve(
                    cve_id='CVE-2022-28391',
                    year='2021',
                    summary="BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record's value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal's colors.",
                    cvss_v2_score='6.8',
                    cvss_v3_score='8.8',
                ),
                Cve(
                    cve_id='CVE-2021-42384',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the handle_special function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42374',
                    year='2021',
                    summary="An out-of-bounds heap read in Busybox's unlzma applet leads to information leak and denial of service when crafted LZMA-compressed input is decompressed. This can be triggered by any applet/format that",
                    cvss_v2_score='3.3',
                    cvss_v3_score='5.3',
                ),
                Cve(
                    cve_id='CVE-2021-42378',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the getvar_i function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
                Cve(
                    cve_id='CVE-2021-42382',
                    year='2021',
                    summary="A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the getvar_s function",
                    cvss_v2_score='6.5',
                    cvss_v3_score='7.2',
                ),
            ],
            [
                'CVE-2021-42385',
                'CVE-2021-42379',
                'CVE-2021-42381',
                'CVE-2021-28831',
                'CVE-2021-42386',
                'CVE-2021-42380',
                'CVE-2021-42376',
                'CVE-2022-28391',
                'CVE-2021-42384',
                'CVE-2021-42374',
                'CVE-2021-42378',
                'CVE-2021-42382',
            ],
        ),
        (
            'busybox_1.35.0_x86_small',
            [
                Cve(
                    cve_id='CVE-2022-28391',
                    year='2022',
                    summary="BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record's value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal's colors.",
                    cvss_v2_score='6.8',
                    cvss_v3_score='8.8',
                ),
                Cve(
                    cve_id='CVE-2022-30065',
                    year='2022',
                    summary="A use-after-free in Busybox 1.35-x's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function.",
                    cvss_v2_score='6.8',
                    cvss_v3_score='7.8',
                ),
            ],
            [],
        ),
        (
            'busybox_1.35.0_x86_full',
            [
                Cve(
                    cve_id='CVE-2022-28391',
                    year='2022',
                    summary="BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a DNS PTR record's value to a VT compatible terminal. Alternatively, the attacker could choose to change the terminal's colors.",
                    cvss_v2_score='6.8',
                    cvss_v3_score='8.8',
                ),
                Cve(
                    cve_id='CVE-2022-30065',
                    year='2022',
                    summary="A use-after-free in Busybox 1.35-x's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function.",
                    cvss_v2_score='6.8',
                    cvss_v3_score='7.8',
                ),
            ],
            ['CVE-2022-28391', 'CVE-2022-30065'],
        ),
    ]
)
def busybox_sample(request):
    test_file, cves, expected_cve_ids = request.param
    test_object = FileObject(file_path=str((TEST_DIR / test_file).resolve()))
    return test_object, cves, expected_cve_ids


def test_filter_busybox_cves(busybox_sample):
    test_object, cves, expected_cve_ids = busybox_sample
    filtered_cves = filter_busybox_cves(test_object, cves)
    assert len(filtered_cves) == len(expected_cve_ids)
    for cve in filtered_cves:
        assert cve.cve_id in expected_cve_ids
