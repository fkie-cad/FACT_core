import json
import logging
import subprocess
from json import JSONDecodeError
from pathlib import Path
from subprocess import DEVNULL, PIPE
from tempfile import NamedTemporaryFile

from helperFunctions.fileSystem import get_src_dir

CHECKSEC_PATH = Path(get_src_dir()) / 'bin' / 'checksec'

KERNEL_WHITELIST = [
    'kernel_heap_randomization',
    'gcc_stack_protector',
    'gcc_stack_protector_strong',
    'gcc_structleak',
    'gcc_structleak_byref',
    'slab_freelist_randomization',
    'cpu_sw_domain',
    'virtually_mapped_stack',
    'restrict_dev_mem_access',
    'restrict_io_dev_mem_access',
    'ro_kernel_data',
    'ro_module_data',
    'full_refcount_validation',
    'hardened_usercopy',
    'fortify_source',
    'restrict_dev_kmem_access',
    'strict_user_copy_check',
    'random_address_space_layout',
    'arm_kernmem_perms',
    'arm_strict_rodata',
    'unmap_kernel_in_userspace',
    'harden_branch_predictor',
    'harden_el2_vector_mapping',
    'speculative_store_bypass_disable',
    'emulate_privileged_access_never',
    'randomize_kernel_address',
    'randomize_module_region_full',
]


def check_kernel_config(kernel_config: str) -> dict:
    try:
        with NamedTemporaryFile() as fp:
            fp.write(kernel_config.encode())
            fp.seek(0)
            command = f'{CHECKSEC_PATH} --kernel={fp.name} --output=json'
            checksec_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=DEVNULL, text=True, check=False)
            result = json.loads(checksec_process.stdout)
            whitelist_configs(result)
            return result
    except (JSONDecodeError, KeyError):
        logging.warning('Checksec kernel analysis failed', exc_info=True)
    return {}


def whitelist_configs(config_results: dict):
    for key in config_results['kernel'].copy():
        if key not in KERNEL_WHITELIST:
            del config_results['kernel'][key]
