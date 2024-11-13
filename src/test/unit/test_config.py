from pathlib import Path
from tempfile import TemporaryDirectory

import pydantic
import pytest

import config

# We explicitly don't want the patch_cfg fixture to be able to patch this function
# This is why we import it here
from config import load
from helperFunctions.fileSystem import get_config_dir

CONFIG_PATH = Path(get_config_dir()) / 'fact-core-config.toml'


def test_load(monkeypatch):
    # Undo all monkeypatching which includes what `patch_config` patched.
    monkeypatch.undo()
    load(path=CONFIG_PATH)

    assert config.common is not None, 'common global was not set'
    assert config.backend is not None, 'backend global was not set'
    assert config.frontend is not None, 'frontend global was not set'
    assert config.common.temp_dir_path == '/tmp', 'default value was not set'
    assert config.backend.plugin['cpu_architecture'].processes == 4  # noqa: PLR2004


def test_load_missing_entries():
    cfg_contents = CONFIG_PATH.read_text()
    assert '[common.postgres]\nserver =' in cfg_contents
    # comment out server
    cfg_contents = cfg_contents.replace('[common.postgres]\nserver =', '[common.postgres]\n# server =')
    with TemporaryDirectory() as tmp_dir:
        cfg_path = Path(tmp_dir) / 'config.toml'
        cfg_path.write_text(cfg_contents)
        with pytest.raises(pydantic.ValidationError, match='server'):
            load(path=cfg_path)
