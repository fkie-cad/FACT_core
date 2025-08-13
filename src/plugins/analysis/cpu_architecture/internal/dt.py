from __future__ import annotations

import re
import shlex
import subprocess
from subprocess import DEVNULL, PIPE

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

    # TODO ideally this should use helperFunctions.docker.run_docker_container
    # Passing stdin via docker-py is really hard.
    # The approaches described in [1] don't work for some reason.
    # See also [2].
    #
    # [1] https://github.com/docker/docker-py/issues/1507
    # [2] https://github.com/docker/docker-py/issues/983
    dtc_process = subprocess.run(
        shlex.split('docker run -i --rm fact/dtc -I dts -O yaml'),
        input=dts,
        stdout=PIPE,
        stderr=DEVNULL,
        text=True,
        check=True,
    )

    # TODO Why do we need this?
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
