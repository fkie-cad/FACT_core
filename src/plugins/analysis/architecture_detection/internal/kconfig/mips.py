from .utils import kconfig_contains

# Based on Linux Kernel 5.9

# arch/mips/Kconfig
# menu 'CPU selection'
_mips32_v1 = ['CPU_MIPS32_R1']
_mips32_v2 = ['CPU_MIPS32_R2']
_mips32_v5 = ['CPU_MIPS32_R5']
_mips32_v6 = ['CPU_MIPS32_R6']

_mips64_v1 = ['CPU_MIPS64_R1']
_mips64_v2 = ['CPU_MIPS64_R2']
_mips64_v5 = ['CPU_MIPS64_R5']
_mips64_v6 = ['CPU_MIPS64_R6']

_mips_v1 = ['CPU_MIPSR1']
_mips_v2 = ['CPU_MIPSR2']
_mips_v5 = ['CPU_MIPSR5']
_mips_v6 = ['CPU_MIPSR6']

mips_v1 = _mips32_v1 + _mips64_v1 + _mips_v1
mips_v2 = _mips32_v2 + _mips64_v2 + _mips_v2
mips_v5 = _mips32_v5 + _mips64_v5 + _mips_v5
mips_v6 = _mips32_v6 + _mips64_v6 + _mips_v6

has64bit = _mips64_v1 + _mips64_v2 + _mips64_v5 + _mips64_v6


def construct_result(kconfig_str):
    result_str = ''

    if kconfig_contains(kconfig_str, mips_v1):
        result_str += ', mips_v1'
    if kconfig_contains(kconfig_str, mips_v2):
        result_str += ', mips_v2'
    if kconfig_contains(kconfig_str, mips_v5):
        result_str += ', mips_v5'
    if kconfig_contains(kconfig_str, mips_v6):
        result_str += ', mips_v6'

    if kconfig_contains(kconfig_str, has64bit):
        result_str += ', 64-bit'

    if len(result_str) == 0:
        return {}

    return {result_str[2:]: 'Kconfig mips'}
