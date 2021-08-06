import json
import logging
from json import JSONDecodeError
from pathlib import Path
from tempfile import NamedTemporaryFile

from common_helper_process import execute_shell_command

from helperFunctions.fileSystem import get_src_dir

CHECKSEC_PATH = Path(get_src_dir()) / 'bin' / 'checksec'

KERNEL_WHITELIST = [
    'kernel_heap_randomization', 'gcc_stack_protector', 'gcc_stack_protector_strong',
    'gcc_structleak', 'gcc_structleak_byref', 'slab_freelist_randomization', 'cpu_sw_domain',
    'virtually_mapped_stack', 'restrict_dev_mem_access', 'restrict_io_dev_mem_access',
    'ro_kernel_data', 'ro_module_data', 'full_refcount_validation', 'hardened_usercopy',
    'fortify_source', 'restrict_dev_kmem_access', 'strict_user_copy_check',
    'random_address_space_layout', 'arm_kernmem_perms', 'arm_strict_rodata',
    'unmap_kernel_in_userspace', 'harden_branch_predictor', 'harden_el2_vector_mapping',
    'speculative_store_bypass_disable', 'emulate_privileged_access_never',
    'randomize_kernel_address', 'randomize_module_region_full'
]

GRSECURITY_WHITELIST = [
    'grsecurity_config', 'config_pax_kernexec', 'config_pax_noexec', 'config_pax_pageexec',
    'config_pax_mprotect', 'config_pax_aslr', 'config_pax_randkstack', 'config_pax_randustack',
    'config_pax_randmmap', 'config_pax_memory_sanitize', 'config_pax_memory_stackleak',
    'config_pax_memory_uderef', 'config_pax_refcount', 'config_pax_usercopy',
    'config_grkernsec_jit_harden', 'config_bpf_jit', 'config_grkernsec_rand_threadstack',
    'config_grkernsec_kmem', 'config_grkernsec_io', 'config_grkernsec_modharden',
    'config_modules', 'config_grkernsec_chroot', 'config_grkernsec_harden_ptrace',
    'config_grkernsec_randnet', 'config_grkernsec_blackhole', 'config_grkernsec_brute',
    'config_grkernsec_hidesym'
]


def check_kernel_config(kernel_config: str) -> dict:
    try:
        with NamedTemporaryFile() as fp:
            fp.write(kernel_config.encode())
            fp.seek(0)
            command = f'{CHECKSEC_PATH} --kernel={fp.name} --output=json 2>/dev/null'
            result = json.loads(execute_shell_command(command))
            whitelist_configs(result)
            return result
    except (JSONDecodeError, KeyError):
        logging.warning('Checksec kernel analysis failed')
    return {}


def whitelist_configs(config_results: dict):
    for key in config_results['kernel'].copy():
        if key not in KERNEL_WHITELIST:
            del config_results['kernel'][key]

    for key in config_results['grsecurity'].copy():
        if key not in GRSECURITY_WHITELIST:
            del config_results['grsecurity'][key]
