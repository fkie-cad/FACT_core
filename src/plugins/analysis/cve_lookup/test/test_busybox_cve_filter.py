import pytest

from ..internal.busybox_cve_filter import filter_cves_by_component
from ..internal.database.schema import Cve

CVE_DICT = {
    'CVE-2021-42385': Cve(
        cve_id='CVE-2021-42385',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            "processing a crafted awk pattern in the evaluate function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2021-42379': Cve(
        cve_id='CVE-2021-42379',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            " processing a crafted awk pattern in the next_input_file function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2021-42381': Cve(
        cve_id='CVE-2021-42381',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            "processing a crafted awk pattern in the hash_init function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2021-28831': Cve(
        cve_id='CVE-2021-28831',
        year='2021',
        summary=(
            'decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer, '
            'with a resultant invalid free or segmentation fault, via malformed gzip data.'
        ),
        cvss_v2_score='5.0',
        cvss_v3_score='7.5',
    ),
    'CVE-2021-42386': Cve(
        cve_id='CVE-2021-42386',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            "processing a crafted awk pattern in the nvalloc function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2021-42380': Cve(
        cve_id='CVE-2021-42380',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            "processing a crafted awk pattern in the clrvar function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2021-42376': Cve(
        cve_id='CVE-2021-42376',
        year='2021',
        summary=(
            "A NULL pointer dereference in Busybox's hush applet leads to denial of service when processing a "
            "crafted shell command, due to missing validation after a \\x03 delimiter character. This may be used "
            "for DoS under very rare conditions of filtered command input."
        ),
        cvss_v2_score='1.9',
        cvss_v3_score='5.5',
    ),
    'CVE-2022-28391': Cve(
        cve_id='CVE-2022-28391',
        year='2021',
        summary=(
            "BusyBox through 1.35.0 allows remote attackers to execute arbitrary code if netstat is used to print a "
            "DNS PTR record's value to a VT compatible terminal. Alternatively, the attacker could choose to change "
            "the terminal's colors."
        ),
        cvss_v2_score='6.8',
        cvss_v3_score='8.8',
    ),
    'CVE-2021-42384': Cve(
        cve_id='CVE-2021-42384',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            "processing a crafted awk pattern in the handle_special function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2021-42374': Cve(
        cve_id='CVE-2021-42374',
        year='2021',
        summary=(
            "An out-of-bounds heap read in Busybox's unlzma applet leads to information leak and denial of service "
            "when crafted LZMA-compressed input is decompressed. This can be triggered by any "
            "applet/format that"
        ),
        cvss_v2_score='3.3',
        cvss_v3_score='5.3',
    ),
    'CVE-2021-42378': Cve(
        cve_id='CVE-2021-42378',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            "processing a crafted awk pattern in the getvar_i function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2021-42382': Cve(
        cve_id='CVE-2021-42382',
        year='2021',
        summary=(
            "A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when "
            "processing a crafted awk pattern in the getvar_s function"
        ),
        cvss_v2_score='6.5',
        cvss_v3_score='7.2',
    ),
    'CVE-2022-30065': Cve(
        cve_id='CVE-2022-30065',
        year='2022',
        summary=(
            "A use-after-free in Busybox 1.35-x's awk applet leads to denial of service and possibly code execution "
            "when processing a crafted awk pattern in the copyvar function."
        ),
        cvss_v2_score='6.8',
        cvss_v3_score='7.8',
    ),
}


@pytest.mark.parametrize(
    ('components', 'expected_cve_ids'),
    [
        ([], set()),
        (
            ['gzip', 'hush', 'netstat', 'unlzma'],
            {'CVE-2021-28831', 'CVE-2021-42374', 'CVE-2021-42376', 'CVE-2022-28391'},
        ),
        (
            ['awk', 'gzip', 'hush', 'netstat', 'unlzma'],
            {
                'CVE-2021-28831',
                'CVE-2021-42374',
                'CVE-2021-42376',
                'CVE-2021-42378',
                'CVE-2021-42379',
                'CVE-2021-42380',
                'CVE-2021-42381',
                'CVE-2021-42382',
                'CVE-2021-42384',
                'CVE-2021-42385',
                'CVE-2021-42386',
                'CVE-2022-28391',
                'CVE-2022-30065',
            },
        ),
        (
            ['netstat', 'unlzma'],
            {'CVE-2021-42374', 'CVE-2022-28391'},
        ),
    ],
)
def test_filter_cves_by_component(components, expected_cve_ids):
    filtered_cves = filter_cves_by_component(None, CVE_DICT, components)
    assert set(filtered_cves) == expected_cve_ids
