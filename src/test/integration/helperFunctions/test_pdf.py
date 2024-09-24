import grp
import os
from pathlib import Path

from helperFunctions import magic
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

    assert magic.from_buffer(pdf_path.read_bytes(), mime=True) == 'application/pdf'
    assert pdf_path.name == f"{TEST_FW.device_name.replace(' ', '_')}_analysis_report.pdf"
