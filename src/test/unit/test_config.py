import pydantic
import pytest

import config

# We explicitly don't want the patch_cfg fixture to be able to patch this function
# This is why we import it here
from config import load
from test.common_helper import get_test_data_dir


def test_load(monkeypatch):
    # Undo all monkeypatching which includes what `patch_config` patched.
    monkeypatch.undo()
    cfg_path = f'{get_test_data_dir()}/fact-core-config.toml'
    load(path=cfg_path)

    assert config.common is not None, 'common global was not set'
    assert config.backend is not None, 'backend global was not set'
    assert config.frontend is not None, 'frontend global was not set'
    assert config.common.temp_dir_path == '/tmp', 'default value was not set'
    assert config.backend.plugin['cpu_architecture'].processes == 4  # noqa: PLR2004


def test_load_missing_entrys(monkeypatch):  # noqa: ARG001
    cfg_path = get_test_data_dir() + '/fact-core-config.toml-missing-entrys'

    with pytest.raises(pydantic.error_wrappers.ValidationError, match='server'):
        load(path=cfg_path)
