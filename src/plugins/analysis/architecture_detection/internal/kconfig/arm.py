from .utils import kconfig_contains

# Based on Linux Kernel 5.9

# arch/arm/mm/Kconfig
# comment 'Processor Type'
_armv6 = [
    'CPU_V6',
]

_armv6k = [
    'CPU_V6K',
]

_armv7 = [
    'CPU_V7',
]

_armv7m = [
    'CPU_V7M',
]

# arch/arm/mm/Kconfig
# menu 'Multiple platform selection'
_armv4_multi = [
    'ARCH_MULTI_V4',
]
_armv4t_multi = [
    'ARCH_MULTI_V4T',
]
_armv5_multi = [
    'ARCH_MULTI_V5',
]
_armv6_multi = [
    'ARCH_MULTI_V6',
]
_armv7_multi = [
    'ARCH_MULTI_V7',
]


# arch/arm64/Kconfig
# menu 'ARMv8.x architectural features'
_armv8_1 = [
    'ARM64_HW_AFDBM',
    'ARM64_PAN'
    'ARM64_LSE_ATOMICS',
    'ARM64_USE_LSE_ATOMICS',
    'ARM64_VHE',
]

_armv8_2 = [
    'ARM64_UAO',
    'ARM64_PMEM',
    'ARM64_RAS_EXTN',
    'ARM64_RAS_EXTN',
    'ARM64_CNP',
]

_armv8_3 = [
    'ARM64_PTR_AUTH',
]

_armv8_4 = [
    'ARM64_AMU_EXTN',
    'ARM64_TLB_RANGE',
]

_armv8_5 = [
    'ARM64_BTI',
    'ARM64_BTI_KERNEL',
    'ARM64_E0PD',
    'ARCH_RANDOM',
]

# arch/arm64/Kconfig
_arm64 = [
    'ARM64',
    '64BIT'
]

armv4 = _armv4_multi + _armv4t_multi
armv5 = _armv5_multi
armv6 = _armv6 + _armv6k + _armv6_multi
armv7 = _armv7 + _armv7m + _armv7_multi
armv8 = _armv8_1 + _armv8_2 + _armv8_3 + _armv8_4 + _armv8_5

has64bit = _arm64


def construct_result(kconfig_str):
    result_str = ''
    if kconfig_contains(kconfig_str, armv4):
        result_str += ', armv4'
    if kconfig_contains(kconfig_str, armv5):
        result_str += ', armv5'
    if kconfig_contains(kconfig_str, armv6):
        result_str += ', armv6'
    if kconfig_contains(kconfig_str, armv7):
        result_str += ', armv7'
    if kconfig_contains(kconfig_str, armv8):
        result_str += ', armv8'

    if kconfig_contains(kconfig_str, has64bit):
        result_str += ', 64-bit'

    if len(result_str) == 0:
        return {}

    return {result_str[2:]: 'Kconfig arm'}
