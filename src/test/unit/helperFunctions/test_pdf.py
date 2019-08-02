from os import makedirs
from pathlib import Path

import pytest
from helperFunctions.pdf import _find_pdf, _initialize_subfolder, build_pdf_report
from test.common_helper import TEST_FW

# pylint: disable=redefined-outer-name


@pytest.fixture(scope='function')
def common_tmpdir(tmpdir):
    makedirs(str(Path(str(tmpdir), 'pdf', 'any').parent))
    return tmpdir


@pytest.fixture(scope='function')
def mock_pdf_file(common_tmpdir):
    pdf_file = Path(str(common_tmpdir), 'pdf', 'any.pdf')
    return pdf_file


def test_find_pdf_no_folder():
    assert not _find_pdf('/non/existing/directory')


def test_find_pdf_no_file(common_tmpdir):
    assert not _find_pdf(str(common_tmpdir))

    Path(str(common_tmpdir), 'pdf', 'anyfile').write_bytes(b'\x00')
    assert not _find_pdf(str(common_tmpdir))


def test_find_pdf_success(common_tmpdir, mock_pdf_file):
    mock_pdf_file.write_bytes(b'\x00')
    assert _find_pdf(str(common_tmpdir)) == mock_pdf_file


def test_find_pdf_multiple_pdfs(common_tmpdir, mock_pdf_file):
    mock_pdf_file.write_bytes(b'\x00')
    Path(str(common_tmpdir), 'pdf', 'else.pdf').write_bytes(b'\xFF')
    assert _find_pdf(str(common_tmpdir))


def test_initialize_subfolder(tmpdir):
    assert list(Path(str(tmpdir)).iterdir()) == list()

    _initialize_subfolder(str(tmpdir), TEST_FW)

    assert Path(str(tmpdir), 'pdf').is_dir()
    assert Path(str(tmpdir), 'data').is_dir()
    assert Path(str(tmpdir), 'data', 'meta.json').is_file()
    assert Path(str(tmpdir), 'data', 'analysis.json').is_file()


def test_build_pdf_report(tmpdir, monkeypatch):
    def create_stub_file(_):
        Path(str(tmpdir), 'pdf', 'any.pdf').write_bytes(b'\x00')
        return '', 0

    monkeypatch.setattr('helperFunctions.pdf.execute_shell_command_get_return_code', create_stub_file)

    binary, pdf_path = build_pdf_report(TEST_FW, Path(str(tmpdir)))

    assert binary == b'\x00'
    assert pdf_path == Path(str(tmpdir), 'pdf', 'any.pdf')


def test_build_pdf_error(tmpdir, monkeypatch):
    monkeypatch.setattr('helperFunctions.pdf.execute_shell_command_get_return_code', lambda _: ('', 1))

    with pytest.raises(RuntimeError):
        build_pdf_report(TEST_FW, Path(str(tmpdir)))
