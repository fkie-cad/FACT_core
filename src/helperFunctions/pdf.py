import json
import logging
from pathlib import Path
from subprocess import CalledProcessError

from common_helper_encoder import ReportEncoder
from docker.errors import DockerException
from docker.types import Mount

from helperFunctions.docker import run_docker_container
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

    try:
        result = run_docker_container(
            'fkiecad/fact_pdf_report',
            combine_stderr_stdout=True,
            mem_limit='512m',
            mounts=[
                Mount('/tmp/interface/', str(folder), type='bind'),
            ],
        )
    except (DockerException, TimeoutError):
        logging.error('Failed to execute pdf generator.')
        raise RuntimeError('Could not create PDF report')

    try:
        result.check_returncode()
    except CalledProcessError as err:
        logging.error(f'Failed to execute pdf generator with code {err.returncode}:\n{result.stdout}')
        raise RuntimeError('Could not create PDF report')

    pdf_path = _find_pdf(folder)

    return pdf_path


def _initialize_subfolder(folder: Path, firmware: Firmware) -> None:
    for subpath in ['data', 'pdf']:
        (folder / subpath).mkdir(parents=True, exist_ok=True)

    (folder / 'data' / 'meta.json').write_text(
        json.dumps(create_meta_dict(firmware), cls=ReportEncoder)
    )
    (folder / 'data' / 'analysis.json').write_text(
        json.dumps(firmware.processed_analysis, cls=ReportEncoder)
    )


def _find_pdf(folder: Path) -> Path:
    pdf_path = None
    for file_path in (folder / 'pdf').rglob('*.pdf'):
        if pdf_path:
            logging.warning(f'Indistinct pdf name. Found: {file_path.name}')
        pdf_path = file_path
    return pdf_path
