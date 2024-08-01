from __future__ import annotations

import json
import logging
import subprocess
from json import JSONDecodeError
from subprocess import PIPE, STDOUT
from tempfile import NamedTemporaryFile
from typing import NamedTuple

# Based on https://github.com/a13xp0p0v/kconfig-hardened-check and
# https://github.com/a13xp0p0v/linux-kernel-defence-map by Alexander Popov
PROTECTS_AGAINST = {
    'CONFIG_RANDOMIZE_BASE': ['Finding Kernel Objects'],
    'CONFIG_RANDOMIZE_MEMORY': ['Finding Kernel Objects'],
    'CONFIG_GCC_PLUGIN_RANDSTRUCT': ['Finding Kernel Objects'],
    'CONFIG_GCC_PLUGIN_LATENT_ENTROPY ': ['Finding Kernel Objects'],
    'CONFIG_REFCOUNT_FULL': ['Int Overflow/Underflow (CWE-190, CWE-191)'],
    'CONFIG_SCHED_STACK_END_CHECK': ['Stack Depth Overflow (CWE-674)'],
    'CONFIG_VMAP_STACK': ['Stack Depth Overflow (CWE-674)'],
    'CONFIG_THREAD_INFO_IN_TASK': ['Stack Depth Overflow (CWE-674)'],
    'CONFIG_HARDENED_USERCOPY': ['Stack Depth Overflow (CWE-674)'],
    'CONFIG_GCC_PLUGIN_STACKLEAK': [
        'Stack Depth Overflow (CWE-674)',
        'Uninitialized Memory Usage (CWE-908)',
        'Info Exposure (CWE-200)',
    ],
    'CONFIG_FORTIFY_SOURCE': [
        'Heap Out-of-Bounds Access (CWE-122)',
        'Stack Out-of-Bounds Access (CWE-121)',
        'Global Variable Out-of-Bounds Access',
    ],
    'CONFIG_UBSAN_BOUNDS': [
        'Heap Out-of-Bounds Access (CWE-122)',
        'Stack Out-of-Bounds Access (CWE-121)',
        'Global Variable Out-of-Bounds Access',
    ],
    'CONFIG_SLAB_FREELIST_HARDENED': ['Allocator Data Corruption', 'Double Free (CWE-415)'],
    'CONFIG_PAGE_POISONING': [
        'Use-After-Free (CWE-416)',
        'Uninitialized Memory Usage (CWE-908)',
        'Info Exposure (CWE-200)',
    ],
    'CONFIG_X86_UMIP': ['Info Exposure (CWE-200)'],
    'CONFIG_SECURITY_DMESG_RESTRICT': ['Info Exposure (CWE-200)'],
    'CONFIG_INIT_STACK_ALL_ZERO ': ['Uninitialized Memory Usage (CWE-908)', 'Info Exposure (CWE-200)'],
    'CONFIG_STRUCTLEAK_BYREF_ALL ': ['Uninitialized Memory Usage (CWE-908)', 'Info Exposure (CWE-200)'],
    'CONFIG_MODULE_SIG': ['Bad Module Loading'],
    'CONFIG_MODULE_SIG_ALL': ['Bad Module Loading'],
    'CONFIG_MODULE_SIG_SHA512': ['Bad Module Loading'],
    'CONFIG_MODULE_SIG_FORCE': ['Bad Module Loading'],
    'CONFIG_SECURITY_LOADPIN': ['Bad Module Loading'],
    'CONFIG_LDISC_AUTOLOAD': ['Bad Module Loading'],
    'CONFIG_DEBUG_WX': ['WX Area Abuse'],
    'CONFIG_RODATA_FULL_DEFAULT_ENABLED': ['WX Area Abuse'],
    'CONFIG_STRICT_KERNEL_RWX': ['WX Area Abuse'],
    'CONFIG_STRICT_MODULE_RWX': ['WX Area Abuse'],
    'CONFIG_STACKPROTECTOR': ['Return Address Overwrite'],
    'CONFIG_STACKPROTECTOR_STRONG': ['Return Address Overwrite'],
    'CONFIG_CC_STACKPROTECTOR': ['Return Address Overwrite'],
    'CONFIG_SHADOW_CALL_STACK': ['Return Address Overwrite'],
    'CONFIG_CPU_SW_DOMAIN_PAN': [
        'ret2usr',
        'ret2usr + ROP',
        'Userspace Data Access',
        'NULL Pointer Dereference (CWE-476)',
    ],
    'CONFIG_ARM64_SW_TTBR0_PAN': [
        'ret2usr',
        'ret2usr + ROP',
        'Userspace Data Access',
        'NULL Pointer Dereference (CWE-476)',
    ],
    'CONFIG_DEFAULT_MMAP_MIN_ADDR': ['NULL Pointer Dereference (CWE-476)'],
    'CONFIG_PAGE_TABLE_ISOLATION': ['ret2usr', 'Spectre v3 / RDCL / CVE-2017-5754 / Meltdown'],
    'CONFIG_UNMAP_KERNEL_AT_EL0': ['ret2usr', 'Spectre v3 / RDCL / CVE-2017-5754 / Meltdown'],
    'CONFIG_MICROCODE': [
        'Spectre v3 / RDCL / CVE-2017-5754 / Meltdown',
        'Spectre v3a / RSRE / CVE-2018-3640',
        'Spectre v1 / BCB / CVE-2017-5753',
        'Spectre v1.1 / BCBS / CVE-2018-3693',
        'Spectre v1 swapgs / CVE-2019-1125',
        'Spectre v2 / BTI / CVE-2017-5715',
        'Spectre RSB / CVE-2018-15572',
        'Spectre v4 / SSB / CVE-2018-3639',
        'MFBDS / CVE-2018-12130 / ZombieLoad',
        'MLPDS / CVE-2018-12127',
        'MDSUM / CVE-2019-11091',
        'TAA / CVE-2019-11135 / ZombieLoad v2',
        'MSBDS / CVE-2018-12126 / Fallout',
        'VRS / CVE-2020-0548',
        'SRBDS / CVE-2020-0543 / CROSSTalk',
        'L1DES / CVE-2020-0549 / CacheOut',
        'Snoop / CVE-2020-0550',
        'L1TF / CVE-2018-3620,3646 / Foreshadow',
        'Lazy FP State Restore / CVE-2018-3665',
    ],
    'CONFIG_RETPOLINE': ['Spectre RSB / CVE-2018-15572', 'Spectre v2 / BTI / CVE-2017-5715'],
    'CONFIG_HARDEN_BRANCH_PREDICTOR': ['Spectre RSB / CVE-2018-15572', 'Spectre v2 / BTI / CVE-2017-5715'],
    'CONFIG_SLAB_FREELIST_RANDOM': ['Heap Layout Control'],
    'CONFIG_SHUFFLE_PAGE_ALLOCATOR': ['Heap Layout Control'],
    'CONFIG_DEBUG_LIST': ['Metadata Corruption'],
    'CONFIG_DEBUG_SG': ['Metadata Corruption'],
    'CONFIG_DEBUG_CREDENTIALS': ['Metadata Corruption'],
    'CONFIG_DEBUG_NOTIFIERS': ['Metadata Corruption'],
    'CONFIG_DEBUG_VIRTUAL': ['Metadata Corruption'],
    'CONFIG_BUG_ON_DATA_CORRUPTION': ['Metadata Corruption'],
    'CONFIG_STATIC_USERMODEHELPER': ['Metadata Corruption'],
    'CONFIG_SECURITY_LOCKDOWN_LSM': ['Changing Kernel Image'],
}


class HardeningCheckResult(NamedTuple):
    option_name: str
    desired_value: str
    decision: str
    reason: str
    check_result: str
    actual_value: str
    vulnerabilities: list[str]


def check_kernel_hardening(kernel_config: str) -> list[HardeningCheckResult]:
    hardening_data = _get_kernel_hardening_data(kernel_config)
    result = _add_protection_info(hardening_data)
    return [item for item in result if 'CONFIG_' not in item.actual_value]  # filter redundant entries


def _get_kernel_hardening_data(kernel_config: str) -> list[list[str]]:
    try:
        with NamedTemporaryFile() as fp:
            fp.write(kernel_config.encode())
            fp.seek(0)
            kconfig_process = subprocess.run(
                f'kconfig-hardened-check -c {fp.name} -m json 2>/dev/null',
                shell=True,
                stdout=PIPE,
                stderr=STDOUT,
                text=True,
                check=False,
            )
            return json.loads(kconfig_process.stdout)
    except (JSONDecodeError, KeyError):
        logging.warning('kconfig-hardened-check analysis failed')
    return []


def _add_protection_info(hardening_result: list[list[str]]) -> list[HardeningCheckResult]:
    full_result = []
    for single_result in hardening_result:
        config_key = single_result[0]
        actual_value = _detach_actual_value_from_result(single_result)
        protection_info = PROTECTS_AGAINST.get(config_key, [])
        full_result.append(HardeningCheckResult(*single_result, actual_value, protection_info))
    return full_result


def _detach_actual_value_from_result(single_result: list[str]) -> str:
    """
    the result may contain the actual value after a colon
    e.g. 'FAIL: not found' or 'FAIL: "y"'
    removes actual value and returns it (or empty string if missing)
    """
    split_result = single_result[4].split(': ')
    single_result[4] = split_result[0]
    return ': '.join(split_result[1:]).replace('"', '')
