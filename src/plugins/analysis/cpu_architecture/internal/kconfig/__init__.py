from __future__ import annotations

from plugins.analysis.cpu_architecture.internal.kconfig.arm import construct_result as construct_result_arm
from plugins.analysis.cpu_architecture.internal.kconfig.mips import construct_result as construct_result_mips


def construct_result(dependency_results: dict) -> dict[str, str]:
    result = {}
    kconfig_str = dependency_results['kernel_config'].kernel_config

    if not kconfig_str:
        return {}

    result.update(construct_result_arm(kconfig_str))
    result.update(construct_result_mips(kconfig_str))

    return result
