from pathlib import Path
from subprocess import CompletedProcess

import pytest

from fact.objects.file import FileObject

from ..code.kernel_config import AnalysisPlugin
from ..internal.checksec_check_kernel import check_kernel_config
from ..internal.decomp import GZDecompressor
from ..internal.kernel_config_hardening_check import check_kernel_hardening

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class ExtractIKConfigTest:
    def test_probably_kernel_config_true(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

        assert analysis_plugin.probably_kernel_config(test_file.binary)

    def test_probably_kernel_config_false(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG_MAGIC_CORRUPT'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

        assert not analysis_plugin.probably_kernel_config(test_file.binary)

    def test_probably_kernel_config_utf_error(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'random_invalid/a.image'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

        assert not analysis_plugin.probably_kernel_config(test_file.binary)

    def test_process_configs_ko_success(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'synthetic/configs.ko'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

        analysis_plugin.process_object(test_file)

        assert test_file.processed_analysis[analysis_plugin.NAME]['is_kernel_config']
        assert len(test_file.processed_analysis[analysis_plugin.NAME]['kernel_config']) > 0

    def test_process_configs_ko_failure(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'synthetic/ko_failure/configs.ko'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

        analysis_plugin.process_object(test_file)

        assert 'is_kernel_config' not in test_file.processed_analysis[analysis_plugin.NAME]
        assert 'kernel_config' not in test_file.processed_analysis[analysis_plugin.NAME]

    def test_process_valid_plain_text(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

        analysis_plugin.process_object(test_file)

        assert test_file.processed_analysis[analysis_plugin.NAME]['is_kernel_config']
        assert test_file.processed_analysis[analysis_plugin.NAME]['kernel_config'] == test_file.binary.decode()

    def test_process_invalid_plain_text(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'random_invalid/c.image'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

        analysis_plugin.process_object(test_file)

        assert 'is_kernel_config' not in test_file.processed_analysis[analysis_plugin.NAME]
        assert 'kernel_config' not in test_file.processed_analysis[analysis_plugin.NAME]

    def test_extract_ko_success(self, analysis_plugin):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'synthetic/configs.ko'))
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
        test_file.processed_analysis['software_components'] = {'summary': ['Linux Kernel']}

        result = AnalysisPlugin.try_object_extract_ikconfig(test_file.binary)

        assert len(result) > 0
        assert analysis_plugin.probably_kernel_config(result)

    def test_process_objects_kernel_image(self, analysis_plugin):
        for valid_image in (TEST_DATA_DIR / 'synthetic').glob('*.image'):
            test_file = FileObject(file_path=str(valid_image))
            test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
            test_file.processed_analysis['software_components'] = {'summary': ['Linux Kernel']}

            analysis_plugin.process_object(test_file)

            assert test_file.processed_analysis[analysis_plugin.NAME]['is_kernel_config']
            assert len(test_file.processed_analysis[analysis_plugin.NAME]['kernel_config']) > 0

        for bad_image in (TEST_DATA_DIR / 'random_invalid').glob('*.image'):
            test_file = FileObject(file_path=str(bad_image))
            test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
            test_file.processed_analysis['software_components'] = {'summary': ['Linux Kernel']}

            analysis_plugin.process_object(test_file)

            assert 'is_kernel_config' not in test_file.processed_analysis[analysis_plugin.NAME]
            assert 'kernel_config' not in test_file.processed_analysis[analysis_plugin.NAME]


def test_plaintext_mime_true():
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG'))
    test_file.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}

    assert AnalysisPlugin.object_mime_is_plaintext(test_file)


def test_plaintext_mime_false():
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG'))
    test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/json'}}

    assert not AnalysisPlugin.object_mime_is_plaintext(test_file)


def test_try_extract_decompress_fail():
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'synthetic/configs.ko.corrupted'))
    test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
    test_file.processed_analysis['software_components'] = {'summary': ['Linux Kernel']}

    assert AnalysisPlugin.try_object_extract_ikconfig(test_file.binary) == b''


def test_is_kernel_image_true():
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG'))
    test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
    test_file.processed_analysis['software_components'] = {'summary': ['Linux Kernel']}

    assert AnalysisPlugin.object_is_kernel_image(test_file)


def test_is_kernel_image_false():
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG'))
    test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
    test_file.processed_analysis['software_components'] = {'summary': ['FreeBSD Kernel']}

    assert not AnalysisPlugin.object_is_kernel_image(test_file)


def test_try_extract_fail():
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG'))
    test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
    test_file.processed_analysis['software_components'] = {'summary': ['Linux Kernel']}

    assert AnalysisPlugin.try_object_extract_ikconfig(test_file.binary) == b''


def test_try_extract_random_fail():
    for fp in (TEST_DATA_DIR / 'random_invalid').glob('*.image'):
        test_file = FileObject(file_path=fp)
        test_file.processed_analysis['file_type'] = {'result': {'mime': 'application/octet-stream'}}
        test_file.processed_analysis['software_components'] = {'summary': ['Linux Kernel']}
        assert AnalysisPlugin.try_object_extract_ikconfig(test_file.binary) == b''


def test_gz_break_on_true():
    test_file = FileObject(file_path=str(TEST_DATA_DIR / 'configs/CONFIG.gz'))
    decompressor = GZDecompressor()
    assert decompressor.decompress(test_file.binary) != b''


def test_checksec_existing_config():
    test_file = TEST_DATA_DIR / 'configs/CONFIG'
    kernel_config = test_file.read_text()
    result = check_kernel_config(kernel_config)
    assert result != {}
    assert 'kernel' in result
    assert 'selinux' in result
    assert 'randomize_va_space' not in result['kernel']
    assert result['kernel']['kernel_heap_randomization'] == 'yes'


def test_checksec_no_valid_json(monkeypatch):
    monkeypatch.setattr(
        'plugins.analysis.kernel_config.internal.checksec_check_kernel.subprocess.run',
        lambda *_, **__: CompletedProcess('DONT_CARE', 0, stdout='invalid json'),
    )
    assert check_kernel_config('no_real_config') == {}


def test_check_kernel_hardening():
    test_file = TEST_DATA_DIR / 'configs/CONFIG'
    kernel_config = test_file.read_text()
    result = check_kernel_hardening(kernel_config)
    assert isinstance(result, list)
    assert all(isinstance(tup, tuple) for tup in result)
    assert len(result) > 50  # noqa: PLR2004
    assert all(len(tup) == 7 for tup in result), 'all results should have 6 elements'  # noqa: PLR2004
    assert any(len(tup[5]) > 0 for tup in result), 'some "protection against" info shouldn\'t be empty'


def test_check_hardening_no_results():
    assert check_kernel_hardening('CONFIG_FOOBAR=y') == []


@pytest.mark.parametrize(
    ('full_type', 'expected_output'),
    [
        ('foobar 123', False),
        ('Linux make config build file, ASCII text', True),
        ('Linux make config build file (old)', True),
    ],
)
def test_foo1(full_type, expected_output):
    test_file = FileObject()
    test_file.processed_analysis['file_type'] = {'result': {'full': full_type}}

    assert AnalysisPlugin.has_kconfig_type(test_file) == expected_output
