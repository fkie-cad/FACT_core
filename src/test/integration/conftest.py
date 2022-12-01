from dataclasses import dataclass
from pathlib import Path

import pytest

from objects.file import FileObject
from objects.firmware import Firmware
from test.common_helper import get_test_data_dir
from test.conftest import SchedulerTestConfig


# TODO have a look at create_test_firmware of test.common_helper
# Note that there is a difference between Firwmare and Fileobject
# What about using the underlying FileObject of a Firmware
# Make it possible to define what FileObjects shall be part of this
# Have a look at insert_test_fo
@pytest.fixture
def insert_test_firmware(backend_db):
    """Returns a factory of firmwares.
    Firmwares creates by this factory are automatically inserted in the backend_db
    """

    # Same kwargs as Fimrware constructor
    # Does it even make sense to set these things here?
    # Not if we have to put extra logic here.
    # If we just give all kwargs to the firmware constructor this is fine.
    # Before this we do some sanitation
    #
    # As an alternative to accepting this much kwargs we could also just let the defaults be and let the user modify
    def _insert_test_firmware(**kwargs):
        # TODO
        # assert that the binary exists
        fw = Firmware()
        backend_db.insert_object(fw)
        # fo.parent_firmware_uids
        # fo.parents
        # fw.files_included
        # fo.virtual_file_path
        # fw.virtual_file_path
        return fw

    yield _insert_test_firmware


@pytest.fixture
def insert_test_fileobject(backend_db):
    """Returns a factory of FileObjects.
    FileObjects creates by this factory are automatically inserted in the backend_db
    """
    # Same kwargs as FileObject but some defaults are set
    # Also some more kwargs
    def _insert_test_fileobject(**kwargs):
        assert 'binary' not in kwargs, 'TODO This was not used in tests before, should it?!'
        kwargs.setdefault(
            'processed_analysis',
            {
                'dummy': {
                    'summary': ['sum a', 'file exclusive sum b'],
                    'content': 'file abcd',
                    'plugin_version': '0',
                    'analysis_date': '0',
                },
                'file_type': {'full': 'Not a PE file', 'plugin_version': '1.0', 'analysis_date': '0'},
                'unpacker': {
                    'file_system_flag': False,
                    'plugin_used': 'unpacker_name',
                    'plugin_version': '1.0',
                    'analysis_date': '0',
                },
            },
        )
        # Not needed since insert_test_firmware should handle this
        # kwargs.setdefault(
        #    "vritual_file_path",
        #    None,
        # )
        kwargs.setdefault(
            'uid',
            None,
        )
        kwargs.setdefault(
            'file_path',
            # Document this
            Path(get_test_data_dir()) / Path(kwargs.pop('file_path', 'get_files_test/testfile1')),
        )

        processed_analysis = kwargs.pop('processed_analysis')
        uid = kwargs.pop('uid')

        fo = FileObject(**kwargs)
        fo.processed_analysis = processed_analysis
        fo.uid = uid

        backend_db.insert_object(fo)

        return fo

    yield _insert_test_fileobject


@dataclass
class SchedulerIntegrationTestConfig(SchedulerTestConfig):
    pipeline: bool = False
