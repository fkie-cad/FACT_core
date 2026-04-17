from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path
from subprocess import DEVNULL, PIPE
from tempfile import NamedTemporaryFile

import yaml


def _get_compatible_entry(dts: str) -> str | None:
    """
    Returns the node name of /cpus/cpu*/compatible and its value from a device tree.
    May return None because the spec does not guarantee the existence of this node.

    See the DeviceTree spec for more information https://www.devicetree.org/specifications/
    """

    # Replace every property that is very long (>256 bytes)
    # This speeds up dtc and should only affect binary data
    dts = re.sub(r'\t*[0-9a-zA-Z,._+?#-]+ = .{256,}\n', '', dts)
    with NamedTemporaryFile() as tmp:
        Path(tmp.name).write_text(dts)
        dtc_process = subprocess.run(
            shlex.split(f'dtc -I dts -O yaml {tmp.name}'),
            input=dts,
            stdout=PIPE,
            stderr=DEVNULL,
            text=True,
            check=True,
        )

    # FixMe: Why do we need this?
    dt = dtc_process.stdout.replace('!u8', '')

    dt_yaml = yaml.load(dt, Loader=yaml.SafeLoader)

    compatible = None

    # The yaml output is a bit weird, we have to 'unpack' one level to get to the actual nodes
    for item in dt_yaml:
        if 'cpus' not in item:
            continue

        cpus = item['cpus']

        cpu_name = None
        # According to the naming convention such a key should always exist
        for key in cpus:
            if 'cpu@' in key:
                cpu_name = key
                break

        cpu = cpus[cpu_name]
        if 'compatible' not in cpu:
            continue

        compatible = cpu['compatible']
        break

    # Some device-trees seem to not have a '/cpus' node
    if compatible is None:
        return None

    return compatible[0].replace('\0', ' ')


def construct_result(dependency_results: dict):
    device_tree_result = dependency_results['device_tree']
    if not device_tree_result:
        return {}

    result = {}
    for dt_entry in device_tree_result.device_trees:
        compatible_entry = _get_compatible_entry(dt_entry.string)
        if compatible_entry is None:
            continue
        result |= {compatible_entry: 'DeviceTree'}

    return result
