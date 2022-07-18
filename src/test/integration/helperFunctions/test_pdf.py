import grp
import os
from pathlib import Path

from fact_helper_file import get_file_type_from_binary

from helperFunctions.pdf import build_pdf_report
from test.common_helper import TEST_FW


def test_build_pdf_report():
    docker_mount_base_dir = Path('/tmp/fact-docker-mount-base-dir')
    try:
        docker_mount_base_dir.mkdir(0o770)
    except FileExistsError:
        # We don't want to change permissions if the directory already exists
        pass
    else:
        docker_gid = grp.getgrnam('docker').gr_gid
        os.chown(docker_mount_base_dir, -1, docker_gid)

    pdf_path = build_pdf_report(TEST_FW, docker_mount_base_dir)

    assert get_file_type_from_binary(pdf_path.read_bytes())['mime'] == 'application/pdf'
    assert pdf_path.name == f"{TEST_FW.device_name.replace(' ', '_')}_analysis_report.pdf"
