from io import FileIO
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from plugins.analysis.file_type.code.file_type import AnalysisPlugin as FileTypePlugin
from plugins.analysis.software_components.code.software_components import AnalysisPlugin as SoftwarePlugin
from plugins.analysis.software_components.code.software_components import SoftwareMatch

from ..code.kernel_config import AnalysisPlugin, object_is_kernel_image, try_extracting_kconfig
from ..internal.checksec_check_kernel import check_kernel_config
from ..internal.decomp import GZDecompressor
from ..internal.kernel_config_hardening_check import HardeningCheckResult, check_kernel_hardening

TEST_DATA_DIR = Path(__file__).parent / 'data'

VALID_DEPENDENCIES_KO = {
    'file_type': FileTypePlugin.Schema(
        mime='application/x-object',
        full='ELF 64-bit LSB relocatable',
    ),
    'software_components': SoftwarePlugin.Schema(
        software_components=[
            SoftwareMatch(
                name='linux kernel',
                versions=['1.2.3'],
                rule='foo',
                matching_strings=[],
            ),
        ]
    ),
}
VALID_DEPENDENCIES_IMG = {
    'file_type': FileTypePlugin.Schema(
        mime='application/octet-stream',
        full='Linux kernel',
    ),
    'software_components': SoftwarePlugin.Schema(
        software_components=[
            SoftwareMatch(
                name='linux kernel',
                versions=['1.2.3'],
                rule='foo',
                matching_strings=[],
            ),
        ]
    ),
}
VALID_DEPENDENCIES_CFG = {
    'file_type': FileTypePlugin.Schema(
        mime='text/plain',
        full='ASCII text',
    ),
    'software_components': SoftwarePlugin.Schema(software_components=[]),
}


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestExtractIKConfig:
    def test_probably_kernel_config_true(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'configs' / 'CONFIG'
        assert analysis_plugin._is_probably_kconfig(test_file.read_bytes())

    def test_probably_kernel_config_false(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'configs' / 'CONFIG_MAGIC_CORRUPT'
        assert not analysis_plugin._is_probably_kconfig(test_file.read_bytes())

    def test_probably_kernel_config_utf_error(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'random_invalid' / 'a.image'
        assert not analysis_plugin._is_probably_kconfig(test_file.read_bytes())

    def test_process_configs_ko_success(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'synthetic' / 'configs.ko'
        result = analysis_plugin.analyze(FileIO(test_file), {}, VALID_DEPENDENCIES_KO)
        _assert_is_kconfig(result)

    def test_process_configs_ko_failure(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'synthetic' / 'ko_failure' / 'configs.ko'

        result = analysis_plugin.analyze(FileIO(test_file), {}, VALID_DEPENDENCIES_KO)
        _assert_is_not_kconfig(result)

    def test_process_valid_plain_text(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'configs' / 'CONFIG'

        result = analysis_plugin.analyze(FileIO(test_file), {}, VALID_DEPENDENCIES_CFG)
        _assert_is_kconfig(result)

    def test_process_invalid_plain_text(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'random_invalid' / 'c.image'

        result = analysis_plugin.analyze(FileIO(test_file), {}, VALID_DEPENDENCIES_CFG)

        _assert_is_not_kconfig(result)

    def test_extract_ko_success(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'synthetic' / 'configs.ko'

        result = try_extracting_kconfig(test_file.read_bytes())

        assert len(result) > 0
        assert analysis_plugin._is_probably_kconfig(result)

    def test_analyze_kernel_image(self, analysis_plugin):
        test_file = TEST_DATA_DIR / 'synthetic' / 'gz.image'
        result = analysis_plugin.analyze(FileIO(test_file), {}, VALID_DEPENDENCIES_IMG)
        _assert_is_kconfig(result)

    @pytest.mark.parametrize('file', (TEST_DATA_DIR / 'random_invalid').glob('*.image'))
    def test_analyze_kernel_image_fail(self, analysis_plugin, file):
        result = analysis_plugin.analyze(FileIO(file), {}, VALID_DEPENDENCIES_IMG)
        _assert_is_not_kconfig(result)


def _assert_is_kconfig(result: AnalysisPlugin.Schema):
    assert result.is_kernel_config is True
    assert isinstance(result.kernel_config, str)
    assert len(result.kernel_config) > 0


def _assert_is_not_kconfig(result: AnalysisPlugin.Schema):
    assert result.is_kernel_config is False
    assert not isinstance(result.kernel_config, str)


def test_try_extract_decompress_fail():
    test_file = TEST_DATA_DIR / 'synthetic' / 'configs.ko.corrupted'
    result = try_extracting_kconfig(test_file.read_bytes())
    assert result == b''


@pytest.mark.parametrize(
    ('deps', 'expected'),
    [
        (VALID_DEPENDENCIES_KO, True),
        (VALID_DEPENDENCIES_IMG, True),
        (VALID_DEPENDENCIES_CFG, False),
    ],
)
def test_is_kernel_image(deps, expected):
    assert object_is_kernel_image(deps['software_components']) is expected


def test_try_extract_fail():
    test_file = TEST_DATA_DIR / 'configs' / 'CONFIG'
    result = try_extracting_kconfig(test_file.read_bytes())
    assert result == b''


@pytest.mark.parametrize('file', (TEST_DATA_DIR / 'random_invalid').glob('*.image'))
def test_try_extract_random_fail(file):
    assert try_extracting_kconfig(file.read_bytes()) == b''


def test_gz_break_on_true():
    test_file = TEST_DATA_DIR / 'configs' / 'CONFIG.gz'
    decompressor = GZDecompressor()
    assert decompressor.decompress(test_file.read_bytes()) != b''


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
    assert all(isinstance(tup, HardeningCheckResult) for tup in result)
    assert len(result) > 50


def test_check_hardening_no_results():
    assert check_kernel_hardening('CONFIG_FOOBAR=y') == []
