import json
import logging
from os import getgid, getuid, makedirs
from pathlib import Path
from typing import Tuple

from common_helper_encoder import ReportEncoder
from common_helper_process import execute_shell_command_get_return_code
from helperFunctions.object_conversion import create_meta_dict
from objects.firmware import Firmware


def build_pdf_report(firmware: Firmware, folder: Path) -> Tuple[bytes, Path]:
    _initialize_subfolder(folder, firmware)

    output, return_code = execute_shell_command_get_return_code(
        'docker run -m 512m -v {}:/tmp/interface --rm fkiecad/fact_pdf_report'.format(folder)
    )

    if return_code != 0:
        logging.error('Failed to execute pdf generator with code {}:\n{}'.format(return_code, output))
        raise RuntimeError('Could not create PDF report')

    _claim_folder_contents(folder)
    pdf_path = _find_pdf(folder)

    return pdf_path.read_bytes(), pdf_path


def _initialize_subfolder(folder, firmware):
    for subpath in ['data', 'pdf']:
        makedirs(str(Path(folder, subpath)), exist_ok=True)

    Path(folder, 'data', 'meta.json').write_text(
        json.dumps(create_meta_dict(firmware), cls=ReportEncoder)
    )
    Path(folder, 'data', 'analysis.json').write_text(
        json.dumps(firmware.processed_analysis, cls=ReportEncoder)
    )


def _claim_folder_contents(tmp_dir):
    execute_shell_command_get_return_code('sudo chown -R {}:{} {}'.format(getuid(), getgid(), tmp_dir))


def _find_pdf(tmp_dir):
    pdf_path = None
    for file_path in Path(tmp_dir, 'pdf').rglob('*.pdf'):
        if pdf_path:
            logging.warning('Indistinct pdf name. Found: {}'.format(file_path.name))
        pdf_path = file_path
    return pdf_path
