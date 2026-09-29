from pathlib import Path
from unittest.mock import Mock

import pytest

import config
from unpacker.extraction_container import ExtractionContainer, ExtractorOutdatedError
from unpacker.unpack_base import _get_path_relative_to_storage


@pytest.fixture
def container(monkeypatch):
    def _mock_status_response(response_json):
        response = Mock(status_code=200)
        response.json.return_value = response_json
        monkeypatch.setattr(ExtractionContainer, '_check_connection', lambda *_, **__: response)
        return ExtractionContainer(id_=0, tmp_dir=Mock(), value=Mock())

    return _mock_status_response


def test_check_compatibility(container):
    container({'features': ['input_path']}).check_compatibility()


@pytest.mark.parametrize('response_json', ['', {}, {'features': []}])
def test_check_compatibility_outdated(container, response_json):
    with pytest.raises(ExtractorOutdatedError, match='is outdated'):
        container(response_json).check_compatibility()


def test_get_path_relative_to_storage(tmp_path):
    storage_dir = Path(config.backend.firmware_file_storage_directory)
    file_in_storage = storage_dir / 'ab' / 'abc_123'
    file_in_storage.parent.mkdir(parents=True, exist_ok=True)
    file_in_storage.write_bytes(b'foo')
    file_outside_storage = tmp_path / 'abc_123'
    file_outside_storage.write_bytes(b'foo')

    assert _get_path_relative_to_storage(file_in_storage) == 'ab/abc_123'
    assert _get_path_relative_to_storage(file_outside_storage) is None
    assert _get_path_relative_to_storage(storage_dir / 'ab' / 'not_found') is None
