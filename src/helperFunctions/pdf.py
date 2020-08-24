import json
import logging
from os import getgid, getuid, makedirs
from pathlib import Path

from common_helper_encoder import ReportEncoder
from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.object_conversion import create_meta_dict
from objects.firmware import Firmware


def build_pdf_report(firmware: Firmware, folder: Path) -> Path:
    '''
    Creates a pdf report for the given firmware by calling the fact_pdf_report docker container.

    .. admonition:: About the pdf report

        The pdf report tool is based on the jinja2 templating engine and renders a
        latex file that is build into a one page overview of the analysis results.
        For all technical details refer to the
        `implementation <https://github.com/fkie-cad/fact_pdf_report>`_.

    :param firmware: The firmware to generate the pdf report for
    :param folder: An empty folder in which to generate the resulting pdf in
    :return: The path to the generated pdf file inside the given folder
    '''
    _initialize_subfolder(folder, firmware)

    output, return_code = execute_shell_command_get_return_code(
        'docker run -m 512m -v {}:/tmp/interface --rm fkiecad/fact_pdf_report'.format(folder)
    )

    if return_code != 0:
        logging.error('Failed to execute pdf generator with code {}:\n{}'.format(return_code, output))
        raise RuntimeError('Could not create PDF report')

    _claim_folder_contents(folder)
    pdf_path = _find_pdf(folder)

    return pdf_path


def _initialize_subfolder(folder: Path, firmware: Firmware) -> None:
    for subpath in ['data', 'pdf']:
        makedirs(str(Path(folder, subpath)), exist_ok=True)

    Path(folder, 'data', 'meta.json').write_text(
        json.dumps(create_meta_dict(firmware), cls=ReportEncoder)
    )
    Path(folder, 'data', 'analysis.json').write_text(
        json.dumps(firmware.processed_analysis, cls=ReportEncoder)
    )


def _claim_folder_contents(folder: Path) -> None:
    execute_shell_command_get_return_code('sudo chown -R {}:{} {}'.format(getuid(), getgid(), folder))


def _find_pdf(folder: Path) -> Path:
    pdf_path = None
    for file_path in Path(folder, 'pdf').rglob('*.pdf'):
        if pdf_path:
            logging.warning('Indistinct pdf name. Found: {}'.format(file_path.name))
        pdf_path = file_path
    return pdf_path
