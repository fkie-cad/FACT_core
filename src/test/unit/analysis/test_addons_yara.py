from pathlib import Path

import yara

from helperFunctions.fileSystem import get_src_dir


def test_compile():
    test_file = Path(get_src_dir()) / 'test/data/yara_magic.yara'
    assert test_file.is_file()
    rules = yara.compile(str(test_file))
    assert rules
