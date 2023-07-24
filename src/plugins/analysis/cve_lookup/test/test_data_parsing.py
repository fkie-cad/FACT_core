import json
from pathlib import Path

from ..internal import data_parsing
from ..internal.helper_functions import CveEntry


with open(Path(__file__).parent / 'test_resources/CVE-2012-0010.json') as file:  # noqa: PTH123
    CVE_ITEM = json.load(file)

CVE_ENTRY = CveEntry(
    cve_id='CVE-2012-0010',
    summary='Microsoft Internet Explorer 6 through 9 does not properly perform copy-and-paste operations, which allows user-assisted remote attackers to read content from a different (1) domain or (2) zone via a crafted web site, aka "Copy and Paste Information Disclosure Vulnerability."',  # noqa: E501
    impact={'cvssMetricV2': 4.3},
    cpe_entries=[
        ('cpe:2.3:a:microsoft:internet_explorer:6:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:a:microsoft:internet_explorer:9:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:a:microsoft:internet_explorer:7:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:a:microsoft:internet_explorer:8:*:*:*:*:*:*:*', '', '', '', ''),
    ],
)


def test_extract_data_from_cve():
    assert data_parsing.extract_data_from_cve(CVE_ITEM) == CVE_ENTRY
