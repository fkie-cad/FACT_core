from dataclasses import dataclass
from pathlib import Path

import pytest

from plugins.analysis.cpu_architecture.code.cpu_architecture import AnalysisPlugin
from plugins.analysis.cpu_architecture.internal import dt, elf, kconfig, metadata
from plugins.analysis.file_type.code.file_type import AnalysisPlugin as TypePlugin
from plugins.analysis.kernel_config.code.kernel_config import AnalysisPlugin as KConfPlugin

dt_file = Path(__file__).parent / 'data/dt.dts'
dts = dt_file.read_text()


@dataclass
class MockDeviceTree:
    string: str


@dataclass
class MockDeviceTreeSchema:
    device_trees: list


_mock_device_tree_analysis = MockDeviceTreeSchema(device_trees=[MockDeviceTree(string=dts)])

_mock_kernel_config_analysis_mips = KConfPlugin.Schema(is_kernel_config=True, kernel_config='CONFIG_CPU_MIPS32_R2=y\n')
_mock_kernel_config_analysis_arm = KConfPlugin.Schema(is_kernel_config=True, kernel_config='CONFIG_CPU_V7=y\n')


def test_dt_construct_result():
    result = dt.construct_result({'device_tree': _mock_device_tree_analysis})
    assert 'arm,cortex-a9' in result


def test_kconfig_construct_result():
    result = kconfig.construct_result({'kernel_config': _mock_kernel_config_analysis_mips})
    for key in result:
        assert 'mips_v2' in key
        assert '64-bit' not in key

    result = kconfig.construct_result({'kernel_config': _mock_kernel_config_analysis_arm})
    for key in result:
        assert 'armv7' in key
        assert '64-bit' not in key


@pytest.mark.parametrize(
    ('expected_str', 'path'),
    [
        ('v8', 'data/hello_world_arm32'),
        ('v8', 'data/hello_world_arm64'),
        # 'data/hello_world_arm64' # TODO Make the plugin work with arm64
        ('MIPS III', 'data/hello_world_mips3'),
    ],
)
def test_elf_construct_result(expected_str, path):
    exe_path = Path(__file__).parent / path
    result = elf.construct_result(exe_path)
    for key in result:
        assert expected_str in key


@pytest.mark.parametrize(
    ('architecture', 'bitness', 'endianness', 'full_file_type'),
    [
        (
            'x86',
            '64-bit',
            'little endian',
            'ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-'
            '64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2f69d48004509acdb1c638868b1381ffaf88aaac, stripped',
        ),
        (
            'ARM',
            '64-bit',
            'little endian',
            'ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-a'
            'arch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=9c4a9cc7ac6393770f18e9be03594070aacf8e24, stripped',
        ),
        (
            'ARM',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.'
            '3, for GNU/Linux 3.2.0, BuildID[sha1]=4bc3bf7160dc2eafca4d10faba3d0ce94e55a04d, stripped',
        ),
        (
            'x86',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.s'
            'o.2, for GNU/Linux 2.6.32, BuildID[sha1]=92a161be3bce24083e4d01e0b5bca11f6bf29183, stripped',
        ),
        (
            'MIPS',
            '32-bit',
            'big endian',
            'ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld.so'
            '.1, for GNU/Linux 3.2.0, BuildID[sha1]=fc902b222050e5a263b4e625b3bae0eeb02d819a, stripped',
        ),
        (
            'MIPS',
            '64-bit',
            'little endian',
            'ELF 64-bit LSB executable, MIPS, MIPS64 rel2 version 1 (SYSV), dynamically linked, interpreter /lib64/ld.'
            'so.1, BuildID[sha1]=dc21edd86ba29b1da6c40818e6e270331cb69983, for GNU/Linux 3.2.0, stripped',
        ),
        (
            'MIPS',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, MIPS, MIPS-II version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, '
            'for GNU/Linux 3.2.0, BuildID[sha1]=dbaed109ca31197a3695a2b97cbf2b0cc03088da, stripped',
        ),
        (
            'PPC',
            '32-bit',
            'big endian',
            'ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), dynamically linked, interpreter /lib/'
            'ld.so.1, for GNU/Linux 3.2.0, BuildID[sha1]=7a4e7eb0aab4954a3f1ad0f2cfe89c3a2c90e836, stripped',
        ),
        (
            'PPC',
            '64-bit',
            'little endian',
            'ELF 64-bit LSB executable, 64-bit PowerPC or cisco 7500, version 1 (SYSV), dynamically linked, interprete'
            'r /lib64/ld64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4c262c29f0325745ff1ca2b6a9b501a56ceb79c0, stripped',
        ),
        (
            'S/390',
            '64-bit',
            'big endian',
            'ELF 64-bit MSB executable, IBM S/390, version 1 (SYSV), dynamically linked, interpreter /lib/ld64.so.1, f'
            'or GNU/Linux 3.2.0, BuildID[sha1]=63609cb3b11e7b51ac277799facb7349fae52728, stripped',
        ),
        (
            'SPARC',
            '32-bit',
            'big endian',
            'ELF 32-bit MSB executable, SPARC32PLUS, V8+ Required, total store ordering, version 1 (SYSV), dynamically'
            ' linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, BuildID[sha1]=c4191615108b0bfd45d5be2d7d016e08ad9145bf, stripped',  # noqa: E501
        ),
        (
            'SPARC',
            '64-bit',
            'big endian',
            'ELF 64-bit MSB shared object, SPARC V9, relaxed memory ordering, version 1 (SYSV), dynamically linked, in'
            'terpreter /lib64/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cca3aeb88f01cf7b49779fb2b58673c586aa9219, stripped',  # noqa: E501
        ),
        (
            'SuperH',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, Renesas SH, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so'
            '.2, BuildID[sha1]=d62b1cf018fe6ad749724020e948cf28a762c26f, for GNU/Linux 3.2.0, stripped',
        ),
        (
            'RISC',
            '32-bit',
            'big endian',
            'ELF 32-bit MSB executable, PA-RISC, *unknown arch 0xf* version 1 (GNU/Linux), dynamically linked, interpr'
            'eter /lib/ld.so.1, for GNU/Linux 3.2.0, BuildID[sha1]=45b625d0d19134a63ed9f22e9bcec9b24187babb, stripped',
        ),
        (
            'Alpha',
            '64-bit',
            'little endian',
            'ELF 64-bit LSB shared object, Alpha (unofficial), version 1 (SYSV), dynamically linked, interpreter /lib/'
            'ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=8604fb8d006884a3305eeb6127b281692ee2e57c, stripped',
        ),
        (
            'RISC-V',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, UCB RISC-V, version 1 (SYSV), statically linked, not stripped',
        ),
        (
            'AVR',
            '8-bit',
            'little endian',
            'ELF 32-bit LSB executable, Atmel AVR 8-bit, version 1 (SYSV), statically linked, not stripped',
        ),
        (
            'ARC',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, ARC Cores Tangent-A5, version 1 (SYSV), dynamically linked, '
            'interpreter /lib/ld-uClibc.so.0, for GNU/Linux 4.8.0, not stripped',
        ),
        (
            'ESP',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, Tensilica Xtensa, version 1 (SYSV), statically linked, with debug_info, not stripped',  # noqa: E501
        ),
        (
            'Tilera',
            '32-bit',
            'little endian',
            'ELF 32-bit LSB executable, Tilera TILE-Gx, version 1 (SYSV), dynamically linked, interpreter /lib32/ld.so.1, '  # noqa: E501
            'for GNU/Linux 2.6.32, stripped',
        ),
    ],
)
def test_metadatadetector_get_device_architecture(architecture, bitness, endianness, full_file_type):
    dependency_result = {'file_type': TypePlugin.Schema(mime='x-executable', full=full_file_type)}
    result = metadata.construct_result(dependency_result)
    assert (
        f'{architecture}, {bitness}, {endianness} (M)' in result
    ), f'architecture not correct: expected {architecture}'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginsSoftwareComponents:
    def test_analyze(self, analysis_plugin):
        dependencies = {
            'kernel_config': _mock_kernel_config_analysis_arm,
            'device_tree': _mock_device_tree_analysis,
            'file_type': TypePlugin.Schema(
                full=(
                    'ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, '
                    'interpreter /lib/ld-linux.so.3, for GNU/Linux 3.2.0, stripped'
                ),
                mime='application/x-executable',
            ),
        }
        with dt_file.open('rb') as fp:
            results: AnalysisPlugin.Schema = analysis_plugin.analyze(fp, {}, dependencies)
        summary = analysis_plugin.summarize(results)

        assert len(results.architectures) == 3
        assert sorted(summary) == ['ARM, 32-bit, little endian (M)', 'arm,cortex-a9', 'armv7']
