from pathlib import Path

from fact_helper_file import get_file_type_from_binary

from helperFunctions.pdf import build_pdf_report
from test.common_helper import TEST_FW


def test_build_pdf_report(tmpdir):
    pdf_path = build_pdf_report(TEST_FW, Path(str(tmpdir)))

    assert get_file_type_from_binary(pdf_path.read_bytes())['mime'] == 'application/pdf'
    assert pdf_path.name == '{}_analysis_report.pdf'.format(TEST_FW.device_name.replace(' ', '_'))
